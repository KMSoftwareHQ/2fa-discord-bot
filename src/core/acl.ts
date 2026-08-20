import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { assertValidSecretName, isValidSnowflake } from "./names";

/**
 * The allowlist: which Discord user IDs may request which secrets.
 *
 * This file is the offboarding story. Deleting one line ends someone's access
 * to every secret immediately, with nothing re-enrolled at any provider — which
 * is not true of a seed that has been scanned into a phone.
 */

/**
 * The single message every failure returns. It is true in all of them and
 * distinguishes none: unknown name, known-but-not-granted, wrong guild.
 *
 * Anyone can otherwise map the vault by watching which names produce a
 * different error.
 */
export const DENIED_MESSAGE = "No secret by that name is available to you.";

export interface AclEntry {
  allowed: readonly string[];
  note: string;
}

export interface Acl {
  version: number;
  secrets: ReadonlyMap<string, AclEntry>;
  warnings: readonly string[];
}

/**
 * Validate a parsed JSON value into an Acl. Pure — no file access — so the
 * validation rules are directly testable.
 */
export function parseAcl(raw: unknown): Acl {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("ACL must be a JSON object");
  }
  const root = raw as Record<string, unknown>;

  if (root["version"] !== 1) {
    throw new Error(
      `ACL "version" must be 1, got ${JSON.stringify(root["version"])}`,
    );
  }

  const secretsRaw = root["secrets"];
  if (
    secretsRaw === null ||
    typeof secretsRaw !== "object" ||
    Array.isArray(secretsRaw)
  ) {
    throw new Error('ACL "secrets" must be an object');
  }

  const warnings: string[] = [];
  const secrets = new Map<string, AclEntry>();

  for (const [name, valueRaw] of Object.entries(
    secretsRaw as Record<string, unknown>,
  )) {
    assertValidSecretName(name);

    if (
      valueRaw === null ||
      typeof valueRaw !== "object" ||
      Array.isArray(valueRaw)
    ) {
      throw new Error(`ACL entry "${name}" must be an object`);
    }
    const value = valueRaw as Record<string, unknown>;

    const allowedRaw = value["allowed"];
    if (!Array.isArray(allowedRaw)) {
      throw new Error(`ACL entry "${name}" must have an "allowed" array`);
    }

    const seen = new Set<string>();
    for (const id of allowedRaw) {
      // The precision trap. A JSON number above 2^53 silently loses its low
      // digits, so an unquoted snowflake parses to a DIFFERENT id — one that
      // matches nobody, or worse, somebody else. Reject it by type, loudly.
      if (typeof id === "number") {
        // Deliberately does NOT say `quote it as "${id}"`. By the time we see
        // this value JSON.parse has already rounded it — 123456789012345678
        // arrives as 123456789012345680 — so echoing it back would tell the
        // operator to grant access to a different account than they meant.
        // The original digits are unrecoverable here; they have to be re-read
        // from Discord.
        throw new Error(
          `ACL entry "${name}" has a Discord ID written as a JSON number, ` +
            `which arrived as ${id}. Discord IDs exceed JavaScript's safe ` +
            `integer range, so the digits you typed have already been rounded ` +
            `and cannot be recovered from the file. Re-copy the ID from ` +
            `Discord and wrap it in quotes: "123456789012345678".`,
        );
      }
      if (typeof id !== "string") {
        throw new Error(
          `ACL entry "${name}" has a non-string entry in "allowed"`,
        );
      }
      if (!isValidSnowflake(id)) {
        throw new Error(
          `ACL entry "${name}" has "${id}", which is not a Discord user ID ` +
            `(expected 17-20 digits). Enable Developer Mode in Discord, or ` +
            `run /2fa whoami, to get yours.`,
        );
      }
      if (seen.has(id)) {
        warnings.push(`ACL entry "${name}" lists ${id} more than once`);
        continue;
      }
      seen.add(id);
    }

    const noteRaw = value["note"];
    if (noteRaw !== undefined && typeof noteRaw !== "string") {
      throw new Error(`ACL entry "${name}" has a non-string "note"`);
    }

    for (const key of Object.keys(value)) {
      if (key !== "allowed" && key !== "note") {
        warnings.push(`ACL entry "${name}" has an unknown field "${key}"`);
      }
    }

    if (seen.size === 0) {
      warnings.push(`ACL entry "${name}" grants nobody access`);
    }

    secrets.set(name, { allowed: [...seen], note: noteRaw ?? "" });
  }

  return { version: 1, secrets, warnings };
}

export function parseAclJson(text: string): Acl {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw new Error(
      `ACL is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseAcl(value);
}

export function isAllowed(acl: Acl, name: string, userId: string): boolean {
  const entry = acl.secrets.get(name);
  if (!entry) return false;
  return entry.allowed.includes(userId);
}

/** Every secret name this user may request, sorted. */
export function accessibleNames(acl: Acl, userId: string): string[] {
  const names: string[] = [];
  for (const [name, entry] of acl.secrets) {
    if (entry.allowed.includes(userId)) names.push(name);
  }
  return names.sort();
}

export interface AclLoadResult {
  acl: Acl;
  /** True when the file on disk is currently broken and this is the last-good copy. */
  stale: boolean;
  /** Set when the most recent reload attempt failed. */
  error?: string;
}

/**
 * Caches the parsed ACL and re-parses only when the file's CONTENT changes.
 *
 * Not fs.watch: it is unreliable across editors that save via rename, it
 * double-fires, and it silently stops working through container bind mounts —
 * which is exactly how this file is mounted in the Docker deployment.
 *
 * Not mtime+size either, which is the tempting cheap option and is wrong here.
 * Two different allowlists can be byte-identical in length (dropping a "note"
 * while adding a user is enough), and a scripted edit can land in the same
 * millisecond as the previous one. That combination makes a real grant change
 * invisible. The file is a kilobyte; hashing it is microseconds, and it cannot
 * miss.
 */
export class AclStore {
  private cached: Acl | null = null;
  private digest: string | null = null;
  private lastCheckMs = 0;
  private lastError: string | null = null;

  constructor(
    private readonly path: string,
    /** Floor between re-reads; autocomplete fires per keystroke. */
    private readonly minRecheckMs = 1000,
  ) {}

  /** Load for the first time. Throws — the caller should refuse to start. */
  loadOrThrow(nowMs: number = Date.now()): Acl {
    const acl = this.readAndParse();
    this.cached = acl;
    this.lastCheckMs = nowMs;
    this.lastError = null;
    return acl;
  }

  /**
   * Get the current ACL, re-reading if the file changed.
   *
   * A broken file here keeps the last known-good copy rather than denying
   * everyone. A stray comma saved mid-edit should not lock the team out of
   * production during the incident they are editing the file to handle — and
   * last-good is a list that was already vetted, never a broader one. The
   * trade-off, spelled out in the README: if you are REMOVING someone and you
   * break the file, the removal does not take effect until you fix it.
   */
  get(nowMs: number = Date.now()): AclLoadResult {
    if (!this.cached) {
      return { acl: this.loadOrThrow(nowMs), stale: false };
    }
    if (nowMs - this.lastCheckMs < this.minRecheckMs) {
      return this.result();
    }
    this.lastCheckMs = nowMs;

    try {
      this.cached = this.readAndParse();
      this.lastError = null;
    } catch (err) {
      this.lastError = err instanceof Error ? err.message : String(err);
    }
    return this.result();
  }

  private result(): AclLoadResult {
    if (!this.cached) throw new Error("ACL has never loaded successfully");
    return this.lastError
      ? { acl: this.cached, stale: true, error: this.lastError }
      : { acl: this.cached, stale: false };
  }

  /** Re-parses only when the bytes actually differ, so warnings do not re-log. */
  private readAndParse(): Acl {
    const text = readFileSync(this.path, "utf8");
    const digest = createHash("sha256").update(text).digest("hex");
    if (this.cached && digest === this.digest) {
      return this.cached;
    }
    const acl = parseAclJson(text);
    this.digest = digest;
    return acl;
  }
}
