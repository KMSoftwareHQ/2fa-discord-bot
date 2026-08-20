import type { Database } from "better-sqlite3";

/**
 * Numbered, forward-only migrations applied at boot.
 *
 * Tracked with `PRAGMA user_version` rather than a table: it is atomic with the
 * transaction that applies the migration, so a crash mid-migration cannot leave
 * the version and the schema disagreeing.
 */

interface Migration {
  version: number;
  name: string;
  sql: string;
}

/**
 * STRICT tables so a type confusion is an error rather than a silent coercion —
 * writing a string into `digits` should fail, not become the number 0 later.
 */
const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "initial schema",
    sql: `
      CREATE TABLE secrets (
        name        TEXT PRIMARY KEY,          -- also the ACL key and the AAD binding
        issuer      TEXT NOT NULL DEFAULT '',  -- display only
        account     TEXT NOT NULL DEFAULT '',  -- display only
        note        TEXT NOT NULL DEFAULT '',
        algorithm   TEXT NOT NULL,             -- SHA1 | SHA256 | SHA512
        digits      INTEGER NOT NULL,          -- 6 | 7 | 8
        period      INTEGER NOT NULL,          -- seconds
        enc_version INTEGER NOT NULL,
        nonce       BLOB NOT NULL,             -- 12 bytes, fresh per write
        ciphertext  BLOB NOT NULL,             -- AES-256-GCM of the base32 seed
        tag         BLOB NOT NULL,             -- 16-byte GCM auth tag
        created_at  INTEGER NOT NULL,          -- ms since epoch
        updated_at  INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE audit_log (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        ts               INTEGER NOT NULL,
        actor            TEXT NOT NULL,        -- 'discord:<id>' | 'cli:<os user>'
        actor_label      TEXT NOT NULL DEFAULT '',
        command          TEXT NOT NULL,
        secret_name      TEXT,                 -- the REAL requested name, even on denial
        outcome          TEXT NOT NULL,        -- allowed|denied|not_found|rate_limited|error
        detail           TEXT NOT NULL DEFAULT '',
        context          TEXT NOT NULL DEFAULT ''
      ) STRICT;

      CREATE INDEX idx_audit_ts        ON audit_log(ts);
      CREATE INDEX idx_audit_actor_ts  ON audit_log(actor, ts);
      CREATE INDEX idx_audit_secret_ts ON audit_log(secret_name, ts);
    `,
  },
];

export const LATEST_VERSION = MIGRATIONS[MIGRATIONS.length - 1]?.version ?? 0;

export function migrate(db: Database): number {
  const current = db.pragma("user_version", { simple: true }) as number;
  let applied = 0;

  for (const migration of MIGRATIONS) {
    if (migration.version <= current) continue;
    // DDL plus the version bump in one transaction: a crash rolls back both.
    db.transaction(() => {
      db.exec(migration.sql);
      db.pragma(`user_version = ${migration.version}`);
    })();
    applied += 1;
  }

  return applied;
}
