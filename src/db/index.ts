import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { migrate } from "./migrations";

/**
 * The vault database. Small, write-rare, and holding the encrypted seeds —
 * durability matters far more here than throughput.
 */

export type VaultDatabase = Database.Database;

let handle: VaultDatabase | null = null;

export function openDatabase(path: string): VaultDatabase {
  const dir = dirname(path);
  if (dir && dir !== "." && !existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const db = new Database(path);

  // 0600 before anything is written. The rows are ciphertext, but there is no
  // reason for another account on the host to be able to copy them and wait.
  if (path !== ":memory:") {
    chmodSync(path, 0o600);
  }

  db.pragma("journal_mode = WAL");
  // FULL, not the more common NORMAL: this database is tiny and written a few
  // times a minute at most, and an audit row that survives a power cut is worth
  // more than the fsync we would save.
  db.pragma("synchronous = FULL");
  db.pragma("foreign_keys = ON");

  migrate(db);
  return db;
}

/** Process-wide handle for the bot. The CLI opens its own and closes it. */
export function initDatabase(path: string): VaultDatabase {
  if (!handle) handle = openDatabase(path);
  return handle;
}

export function getDatabase(): VaultDatabase {
  if (!handle) {
    throw new Error("Database not initialised — call initDatabase() first");
  }
  return handle;
}

export function closeDatabase(): void {
  if (handle) {
    handle.close();
    handle = null;
  }
}
