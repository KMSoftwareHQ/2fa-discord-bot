import type { VaultDatabase } from "../db";
import { open, seal, wipe } from "../core/crypto";
import { assertValidSecretName } from "../core/names";
import {
  DENIED_MESSAGE,
  accessibleNames,
  isAllowed,
  type Acl,
} from "../core/acl";
import {
  formatCode,
  generateCode,
  msUntilNextStep,
  secondsRemaining,
  validateTotpParams,
  type TotpAlgorithm,
  type TotpParams,
} from "../core/totp";
import { checkRateLimit } from "./ratelimit";
import { recordAudit } from "./audit";

export { DENIED_MESSAGE };

export interface SecretMetadata extends TotpParams {
  name: string;
  issuer: string;
  account: string;
  note: string;
  createdAt: number;
  updatedAt: number;
}

interface SecretRow extends SecretMetadata {
  encVersion: number;
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

interface RawRow {
  name: string;
  issuer: string;
  account: string;
  note: string;
  algorithm: string;
  digits: number;
  period: number;
  enc_version: number;
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
  created_at: number;
  updated_at: number;
}

function toRow(r: RawRow): SecretRow {
  return {
    name: r.name,
    issuer: r.issuer,
    account: r.account,
    note: r.note,
    algorithm: r.algorithm as TotpAlgorithm,
    digits: r.digits,
    period: r.period,
    encVersion: r.enc_version,
    nonce: r.nonce,
    ciphertext: r.ciphertext,
    tag: r.tag,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

const SELECT_COLUMNS = `name, issuer, account, note, algorithm, digits, period,
  enc_version, nonce, ciphertext, tag, created_at, updated_at`;

export interface StoreSecretInput extends TotpParams {
  name: string;
  /** Canonical base32, as produced by normalizeBase32Secret. */
  secret: string;
  issuer?: string;
  account?: string;
  note?: string;
}

/** Insert or replace a secret. The plaintext seed is wiped before returning. */
export function storeSecret(
  db: VaultDatabase,
  key: Buffer,
  input: StoreSecretInput,
  nowMs: number = Date.now(),
): void {
  assertValidSecretName(input.name);
  validateTotpParams(input);

  const plaintext = Buffer.from(input.secret, "utf8");
  try {
    const sealed = seal(plaintext, key, input.name);
    const existing = db
      .prepare("SELECT created_at FROM secrets WHERE name = ?")
      .get(input.name) as { created_at: number } | undefined;

    db.prepare(
      `INSERT INTO secrets
         (name, issuer, account, note, algorithm, digits, period,
          enc_version, nonce, ciphertext, tag, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET
         issuer = excluded.issuer, account = excluded.account,
         note = excluded.note, algorithm = excluded.algorithm,
         digits = excluded.digits, period = excluded.period,
         enc_version = excluded.enc_version, nonce = excluded.nonce,
         ciphertext = excluded.ciphertext, tag = excluded.tag,
         updated_at = excluded.updated_at`,
    ).run(
      input.name,
      input.issuer ?? "",
      input.account ?? "",
      input.note ?? "",
      input.algorithm,
      input.digits,
      input.period,
      sealed.version,
      sealed.nonce,
      sealed.ciphertext,
      sealed.tag,
      existing?.created_at ?? nowMs,
      nowMs,
    );
  } finally {
    wipe(plaintext);
  }
}

export function getSecretRow(db: VaultDatabase, name: string): SecretRow | null {
  const row = db
    .prepare(`SELECT ${SELECT_COLUMNS} FROM secrets WHERE name = ?`)
    .get(name) as RawRow | undefined;
  return row ? toRow(row) : null;
}

export function listSecretMetadata(db: VaultDatabase): SecretMetadata[] {
  const rows = db
    .prepare(`SELECT ${SELECT_COLUMNS} FROM secrets ORDER BY name`)
    .all() as RawRow[];
  return rows.map(toRow);
}

export function deleteSecret(db: VaultDatabase, name: string): boolean {
  return db.prepare("DELETE FROM secrets WHERE name = ?").run(name).changes > 0;
}

export function secretExists(db: VaultDatabase, name: string): boolean {
  return (
    db.prepare("SELECT 1 FROM secrets WHERE name = ?").get(name) !== undefined
  );
}

/**
 * Decrypt, use, and wipe. The seed never escapes this function as a Buffer.
 *
 * It does become a string inside `fn` because otplib takes one, and JS strings
 * are immutable and cannot be wiped. SECURITY.md states that rather than
 * implying the zeroization is complete.
 */
function withSeed<T>(row: SecretRow, key: Buffer, fn: (seed: string) => T): T {
  const plaintext = open(
    {
      version: row.encVersion,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      tag: row.tag,
    },
    key,
    row.name,
  );
  try {
    return fn(plaintext.toString("utf8"));
  } finally {
    wipe(plaintext);
  }
}

/** Generate a code for a stored secret. Used by the CLI's verify path. */
export function generateForSecret(
  row: SecretRow,
  key: Buffer,
  nowMs: number = Date.now(),
): { code: string; expiresInSeconds: number } {
  return withSeed(row, key, (seed) =>
    generateCode(seed, {
      algorithm: row.algorithm,
      digits: row.digits,
      period: row.period,
    }, nowMs),
  );
}

/**
 * The result handed back to the Discord layer.
 *
 * `denied` carries NO fields — deliberately. The reason is written to the audit
 * table inside resolveCodeRequest and is unrepresentable in the value that
 * crosses this boundary. Making the leak impossible to express is stronger than
 * remembering to use the same string at four call sites.
 */
export type CodeRequestResult =
  | {
      kind: "code";
      name: string;
      issuer: string;
      account: string;
      code: string;
      formattedCode: string;
      expiresAtMs: number;
      expiresInSeconds: number;
      waitedMs: number;
    }
  | { kind: "denied" }
  | { kind: "rate_limited"; retryAfterSeconds: number; rule: string }
  | { kind: "error" };

export interface CodeRequest {
  userId: string;
  userLabel?: string;
  name: string;
  context?: string;
}

export interface VaultDeps {
  db: VaultDatabase;
  acl: Acl;
  key: Buffer;
  nowMs?: number;
  /** Injected so the boundary-wait is testable without real time passing. */
  sleep?: (ms: number) => Promise<void>;
  /** Wait out the step boundary when fewer than this many seconds remain. */
  minRemainingSeconds?: number;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export async function resolveCodeRequest(
  deps: VaultDeps,
  req: CodeRequest,
): Promise<CodeRequestResult> {
  const {
    db,
    acl,
    key,
    sleep = defaultSleep,
    minRemainingSeconds = 5,
  } = deps;
  let now = deps.nowMs ?? Date.now();

  const audit = (
    outcome: "allowed" | "denied" | "not_found" | "rate_limited" | "error",
    detail: string,
  ): void => {
    recordAudit(
      db,
      {
        actor: `discord:${req.userId}`,
        actorLabel: req.userLabel ?? "",
        command: "get",
        secretName: req.name,
        outcome,
        detail,
        context: req.context ?? "",
      },
      now,
    );
  };

  // 1. The per-user limit is consumed FIRST, before authorization, and applies
  //    to denied requests too. It is the anti-enumeration limiter: if it ran
  //    after the ACL check, someone with no grants at all could probe names as
  //    fast as the gateway allows.
  const userLimit = checkRateLimit("2fa:get", req.userId, now);
  if (!userLimit.allowed) {
    audit("rate_limited", `bucket=2fa:get retry_after=${userLimit.retryAfterSeconds}s`);
    return {
      kind: "rate_limited",
      retryAfterSeconds: userLimit.retryAfterSeconds,
      rule: userLimit.rule,
    };
  }

  // 2. Resolve BOTH the grant and the row before branching, so the
  //    not-authorized and not-found paths do the same work and return the same
  //    sentence.
  const granted = isAllowed(acl, req.name, req.userId);
  const row = getSecretRow(db, req.name);

  if (!granted || !row) {
    audit(row ? "denied" : "not_found", granted ? "no row" : "not granted");
    return { kind: "denied" };
  }

  // 3. Only now the per-secret limit. Consuming it before authorization would
  //    turn it into an existence oracle: an unauthorized caller could tell a
  //    real name from a fake one by whether this bucket ever exhausted.
  const secretLimit = checkRateLimit(
    "2fa:get:secret",
    `${req.userId}:${req.name}`,
    now,
  );
  if (!secretLimit.allowed) {
    audit(
      "rate_limited",
      `bucket=2fa:get:secret retry_after=${secretLimit.retryAfterSeconds}s`,
    );
    return {
      kind: "rate_limited",
      retryAfterSeconds: secretLimit.retryAfterSeconds,
      rule: secretLimit.rule,
    };
  }

  // 4. A code with 3 seconds left is worse than useless — the user types it and
  //    it is rejected. The interaction is already deferred and deferred
  //    interactions have 15 minutes, so waiting out the boundary is free.
  let waitedMs = 0;
  const remaining = secondsRemaining(row.period, now);
  if (remaining < minRemainingSeconds) {
    waitedMs = msUntilNextStep(row.period, now) + 250;
    await sleep(waitedMs);
    // With an injected clock, advance it by what we "slept"; with the real one,
    // just re-read it.
    now = deps.nowMs !== undefined ? deps.nowMs + waitedMs : Date.now();
  }

  try {
    const { code, expiresInSeconds } = generateForSecret(row, key, now);
    // The step index, not the code: it pins the request to a 30-second slot so
    // it can be correlated with the provider's own login log, and it is not
    // itself a credential.
    audit("allowed", `step=${Math.floor(now / 1000 / row.period)}`);
    return {
      kind: "code",
      name: row.name,
      issuer: row.issuer,
      account: row.account,
      code,
      formattedCode: formatCode(code),
      expiresAtMs: now + expiresInSeconds * 1000,
      expiresInSeconds,
      waitedMs,
    };
  } catch {
    // Most likely a wrong master key or a tampered row. The user gets nothing
    // useful; the operator gets a row to look at.
    audit("error", "decrypt or generate failed");
    return { kind: "error" };
  }
}

export interface AccessibleSecret {
  name: string;
  issuer: string;
  account: string;
}

/** The names this user may request AND that actually exist. */
export function listAccessible(
  db: VaultDatabase,
  acl: Acl,
  userId: string,
): AccessibleSecret[] {
  const granted = new Set(accessibleNames(acl, userId));
  return listSecretMetadata(db)
    .filter((s) => granted.has(s.name))
    .map((s) => ({ name: s.name, issuer: s.issuer, account: s.account }));
}
