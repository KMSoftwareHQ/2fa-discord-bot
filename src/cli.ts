import { copyFileSync, existsSync } from "node:fs";
import { userInfo } from "node:os";
import { config, getMasterKey, getNewMasterKey } from "./config";
import { openDatabase, type VaultDatabase } from "./db";
import { generateMasterKeyHex, open, seal, wipe } from "./core/crypto";
import { assertValidSecretName } from "./core/names";
import { AclStore, accessibleNames } from "./core/acl";
import {
  DEFAULT_TOTP_PARAMS,
  formatCode,
  normalizeBase32Secret,
  parseOtpauthUri,
  validateTotpParams,
  type TotpAlgorithm,
  type TotpParams,
} from "./core/totp";
import {
  deleteSecret,
  generateForSecret,
  getSecretRow,
  listSecretMetadata,
  storeSecret,
} from "./services/vault";
import { queryAudit, recordAudit } from "./services/audit";
import { confirm, readSeedInput } from "./cli/prompt";

/**
 * The admin CLI. This is the ONLY way seed material enters the vault — there is
 * no Discord command that accepts a seed, by design. Putting a seed through
 * Discord to store it would defeat the entire point of storing it here.
 */

const USAGE = `2FA vault admin CLI

Usage: npm run vault -- <command> [options]

  genkey                      Print a fresh 32-byte master key as hex
  add <name> [options]        Add or replace a secret (reads seed from stdin)
  list [--json]               List secrets and their parameters (never the seed)
  rm <name> [--yes]           Delete a secret
  verify [name]               Prove the key and ciphertext are intact
  rotate-key                  Re-encrypt everything under VAULT_NEW_MASTER_KEY
  audit [options]             Review the access log
  acl-check                   Validate the ACL file and show effective grants

add options:
  --issuer <s> --account <s> --note <s>
  --digits 6|7|8   --period <seconds>   --algorithm SHA1|SHA256|SHA512
  These are ignored when the input is an otpauth:// URI, which carries its own.

audit options:
  --limit <n>  --actor <discord id>  --secret <name>  --since <24h|7d|30d>  --json

The seed is read from a hidden prompt, or from a pipe:
  npm run vault -- add aws-root
  pass show aws-root/totp | npm run vault -- add aws-root

There is deliberately no --secret flag: it would put the seed in your shell
history and in ps output for every user on this host.
`;

interface Args {
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[key] = next;
      i += 1;
    } else {
      flags[key] = true;
    }
  }
  return { positional, flags };
}

function str(flags: Args["flags"], key: string): string | undefined {
  const v = flags[key];
  return typeof v === "string" ? v : undefined;
}

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

function withDatabase<T>(fn: (db: VaultDatabase) => T): T {
  const db = openDatabase(config.vault.databasePath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

/**
 * Who to record in the audit trail.
 *
 * Resolved lazily and defensively: userInfo() throws ENOENT when the process
 * runs as a uid with no /etc/passwd entry, which is exactly what happens in the
 * container once its user is overridden to the host's uid. Evaluating this at
 * module load took the whole CLI down with it.
 */
function currentActor(): string {
  try {
    return `cli:${userInfo().username}`;
  } catch {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    return uid === null ? "cli:unknown" : `cli:uid-${uid}`;
  }
}

// --- commands --------------------------------------------------------------

function cmdGenkey(): void {
  process.stdout.write(`${generateMasterKeyHex()}\n`);
  process.stderr.write(
    "\nPut this in .env as VAULT_MASTER_KEY.\n" +
      "Back it up somewhere that is NOT alongside data/vault.db — a backup\n" +
      "holding both the key and the database is not encrypted in any useful\n" +
      "sense. If you lose it, every stored seed is gone permanently.\n",
  );
}

async function cmdAdd(args: Args): Promise<void> {
  const name = args.positional[0];
  if (!name) fail("add requires a name: npm run vault -- add <name>");
  assertValidSecretName(name);

  if (args.flags["secret"] !== undefined) {
    fail(
      "--secret is not supported, on purpose. A seed passed as an argument " +
        "lands in your shell history and is visible in `ps` to every user on " +
        "this host. Pipe it in, or let the hidden prompt read it.",
    );
  }

  const key = getMasterKey();
  const input = await readSeedInput(`Seed or otpauth:// URI for "${name}": `);

  try {
    const text = input.toString("utf8");
    let params: TotpParams;
    let secret: string;
    let issuer = str(args.flags, "issuer") ?? "";
    let account = str(args.flags, "account") ?? "";

    if (text.toLowerCase().startsWith("otpauth://")) {
      const parsed = parseOtpauthUri(text);
      // The URI is authoritative; a conflicting flag is a mistake worth
      // surfacing rather than silently resolving in one direction.
      for (const flag of ["digits", "period", "algorithm"]) {
        if (args.flags[flag] !== undefined) {
          fail(
            `--${flag} conflicts with the otpauth:// URI, which already ` +
              `specifies it. Remove the flag.`,
          );
        }
      }
      params = {
        algorithm: parsed.algorithm,
        digits: parsed.digits,
        period: parsed.period,
      };
      secret = parsed.secret;
      issuer = issuer || parsed.issuer;
      account = account || parsed.account;
    } else {
      secret = normalizeBase32Secret(text);
      params = {
        algorithm: (
          str(args.flags, "algorithm") ?? DEFAULT_TOTP_PARAMS.algorithm
        ).toUpperCase() as TotpAlgorithm,
        digits: Number(str(args.flags, "digits") ?? DEFAULT_TOTP_PARAMS.digits),
        period: Number(str(args.flags, "period") ?? DEFAULT_TOTP_PARAMS.period),
      };
      validateTotpParams(params);
    }

    withDatabase((db) => {
      const replacing = getSecretRow(db, name) !== null;
      storeSecret(db, key, {
        name,
        secret,
        issuer,
        account,
        note: str(args.flags, "note") ?? "",
        ...params,
      });
      recordAudit(db, {
        actor: currentActor(),
        command: replacing ? "update" : "add",
        secretName: name,
        outcome: "allowed",
        detail: `${params.algorithm}/${params.digits}/${params.period}s`,
      });

      process.stdout.write(
        `${replacing ? "Replaced" : "Added"} "${name}" ` +
          `(${params.algorithm}, ${params.digits} digits, ${params.period}s)\n`,
      );

      // Print one code so the operator can confirm the seed transcribed
      // correctly before anyone depends on it. A TOTP code is not seed
      // material, and an enrolment you cannot verify is worse than none.
      const row = getSecretRow(db, name);
      if (row && args.flags["no-verify-code"] === undefined) {
        const { code, expiresInSeconds } = generateForSecret(row, key);
        process.stderr.write(
          `\nCurrent code: ${formatCode(code)} (${expiresInSeconds}s left)\n` +
            `Check it matches what the provider shows right now.\n`,
        );
      }

      process.stderr.write(
        `\nNext: add Discord user IDs to ${config.vault.aclPath} under "${name}".\n` +
          `Store the provider's recovery codes somewhere that is NOT this vault.\n`,
      );
    });
  } finally {
    wipe(input, key);
  }
}

function cmdList(args: Args): void {
  withDatabase((db) => {
    const secrets = listSecretMetadata(db);
    if (args.flags["json"]) {
      process.stdout.write(`${JSON.stringify(secrets, null, 2)}\n`);
      return;
    }
    if (secrets.length === 0) {
      process.stdout.write("No secrets stored.\n");
      return;
    }
    const width = Math.max(...secrets.map((s) => s.name.length), 4);
    process.stdout.write(
      `${"NAME".padEnd(width)}  PARAMS          ISSUER / ACCOUNT\n`,
    );
    for (const s of secrets) {
      const params = `${s.algorithm}/${s.digits}d/${s.period}s`.padEnd(14);
      const label = [s.issuer, s.account].filter(Boolean).join(" / ");
      process.stdout.write(`${s.name.padEnd(width)}  ${params}  ${label}\n`);
    }
  });
}

async function cmdRemove(args: Args): Promise<void> {
  const name = args.positional[0];
  if (!name) fail("rm requires a name");
  if (
    args.flags["yes"] === undefined &&
    !(await confirm(`Delete "${name}"? The seed cannot be recovered.`))
  ) {
    process.stderr.write("Aborted.\n");
    return;
  }
  withDatabase((db) => {
    const removed = deleteSecret(db, name);
    recordAudit(db, {
      actor: currentActor(),
      command: "remove",
      secretName: name,
      outcome: removed ? "allowed" : "not_found",
    });
    process.stdout.write(
      removed ? `Deleted "${name}".\n` : `No secret named "${name}".\n`,
    );
    if (removed) {
      process.stderr.write(
        `Remove "${name}" from ${config.vault.aclPath} too.\n`,
      );
    }
  });
}

function cmdVerify(args: Args): void {
  const key = getMasterKey();
  try {
    withDatabase((db) => {
      const only = args.positional[0];
      const secrets = only
        ? listSecretMetadata(db).filter((s) => s.name === only)
        : listSecretMetadata(db);

      if (secrets.length === 0) {
        process.stdout.write(only ? `No secret named "${only}".\n` : "No secrets stored.\n");
        return;
      }

      let failures = 0;
      for (const meta of secrets) {
        const row = getSecretRow(db, meta.name)!;
        try {
          const { code, expiresInSeconds } = generateForSecret(row, key);
          // Only print the code when one secret was named. A bulk verify
          // should prove integrity without spraying live credentials.
          process.stdout.write(
            only
              ? `OK  ${meta.name}  ${formatCode(code)} (${expiresInSeconds}s left)\n`
              : `OK  ${meta.name}\n`,
          );
        } catch {
          failures += 1;
          process.stdout.write(`FAIL ${meta.name}  cannot decrypt\n`);
        }
      }
      if (failures > 0) {
        process.stderr.write(
          `\n${failures} secret(s) failed. Either VAULT_MASTER_KEY is wrong, or\n` +
            `the rows were tampered with.\n`,
        );
        process.exitCode = 1;
      }
    });
  } finally {
    wipe(key);
  }
}

function cmdRotateKey(): void {
  const oldKey = getMasterKey();
  const newKey = getNewMasterKey();
  if (oldKey.equals(newKey)) {
    fail("VAULT_NEW_MASTER_KEY is the same as VAULT_MASTER_KEY");
  }

  try {
    const dbPath = config.vault.databasePath;
    if (!existsSync(dbPath)) fail(`No database at ${dbPath}`);

    // Timestamped copy first: if rotation goes wrong, the old ciphertext under
    // the old key is still recoverable.
    const backup = `${dbPath}.bak-${new Date().toISOString().replace(/[:.]/g, "-")}`;
    copyFileSync(dbPath, backup);
    process.stderr.write(`Backed up to ${backup}\n`);

    withDatabase((db) => {
      const rows = listSecretMetadata(db);
      // One transaction: every row moves to the new key, or none do. There is
      // never a database that is half under each key.
      const rotate = db.transaction(() => {
        for (const meta of rows) {
          const row = getSecretRow(db, meta.name)!;
          const plaintext = open(
            { version: row.encVersion, nonce: row.nonce, ciphertext: row.ciphertext, tag: row.tag },
            oldKey,
            row.name,
          );
          try {
            const sealed = seal(plaintext, newKey, row.name);
            db.prepare(
              `UPDATE secrets SET enc_version = ?, nonce = ?, ciphertext = ?, tag = ?
               WHERE name = ?`,
            ).run(sealed.version, sealed.nonce, sealed.ciphertext, sealed.tag, row.name);
          } finally {
            wipe(plaintext);
          }
        }
      });
      rotate();

      recordAudit(db, {
        actor: currentActor(),
        command: "rotate-key",
        outcome: "allowed",
        detail: `${rows.length} secrets`,
      });
      process.stdout.write(`Re-encrypted ${rows.length} secret(s).\n`);
      process.stderr.write(
        "\nNow move VAULT_NEW_MASTER_KEY into VAULT_MASTER_KEY in .env, clear\n" +
          "VAULT_NEW_MASTER_KEY, and restart the bot. Keep the backup until you\n" +
          "have confirmed the bot works, then delete it — it holds the old\n" +
          "ciphertext and is readable with the old key.\n",
      );
    });
  } finally {
    wipe(oldKey, newKey);
  }
}

function parseSince(value: string | undefined, now: number): number | undefined {
  if (!value) return undefined;
  const match = /^(\d+)([hd])$/.exec(value);
  if (!match) fail(`--since expects a value like 24h or 7d, got "${value}"`);
  const amount = Number(match[1]);
  const ms = match[2] === "h" ? 3_600_000 : 86_400_000;
  return now - amount * ms;
}

function cmdAudit(args: Args): void {
  withDatabase((db) => {
    const rows = queryAudit(db, {
      actor: str(args.flags, "actor"),
      secretName: str(args.flags, "secret"),
      sinceMs: parseSince(str(args.flags, "since"), Date.now()),
      limit: Number(str(args.flags, "limit") ?? 50),
    });

    if (args.flags["json"]) {
      process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
      return;
    }
    if (rows.length === 0) {
      process.stdout.write("No matching audit entries.\n");
      return;
    }
    // Oldest first reads better for a trail.
    for (const r of [...rows].reverse()) {
      const ts = new Date(r.ts).toISOString();
      const who = r.actorLabel ? `${r.actor} (${r.actorLabel})` : r.actor;
      process.stdout.write(
        `${ts}  ${r.outcome.padEnd(12)} ${r.command.padEnd(10)} ` +
          `${(r.secretName ?? "-").padEnd(20)} ${who}` +
          `${r.detail ? `  ${r.detail}` : ""}\n`,
      );
    }
  });
}

function cmdAclCheck(): void {
  const store = new AclStore(config.vault.aclPath, 0);
  let acl;
  try {
    acl = store.loadOrThrow();
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  for (const warning of acl.warnings) {
    process.stderr.write(`warning: ${warning}\n`);
  }

  withDatabase((db) => {
    const stored = new Set(listSecretMetadata(db).map((s) => s.name));
    const users = new Set<string>();
    for (const entry of acl.secrets.values()) {
      for (const id of entry.allowed) users.add(id);
    }

    process.stdout.write(
      `ACL is valid: ${acl.secrets.size} secret(s), ${users.size} user(s).\n\n`,
    );
    for (const [name, entry] of acl.secrets) {
      const missing = stored.has(name) ? "" : "  <- no such secret in the vault";
      process.stdout.write(`${name}${missing}\n`);
      for (const id of entry.allowed) process.stdout.write(`    ${id}\n`);
    }

    const unreachable = [...stored].filter((n) => !acl.secrets.has(n));
    if (unreachable.length > 0) {
      process.stdout.write(
        `\nStored but in no ACL entry (nobody can request these):\n` +
          unreachable.map((n) => `    ${n}\n`).join(""),
      );
    }
    for (const id of users) {
      process.stdout.write(`\n${id} can access: ${accessibleNames(acl, id).join(", ")}\n`);
    }
  });
}

// --- dispatch --------------------------------------------------------------

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];
  const args = parseArgs(argv.slice(1));

  switch (command) {
    case "genkey":
      return cmdGenkey();
    case "add":
    case "import":
      return cmdAdd(args);
    case "list":
      return cmdList(args);
    case "rm":
    case "remove":
      return cmdRemove(args);
    case "verify":
      return cmdVerify(args);
    case "rotate-key":
      return cmdRotateKey();
    case "audit":
      return cmdAudit(args);
    case "acl-check":
      return cmdAclCheck();
    case undefined:
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(USAGE);
      return;
    default:
      process.stderr.write(`Unknown command: ${command}\n\n${USAGE}`);
      process.exit(1);
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
