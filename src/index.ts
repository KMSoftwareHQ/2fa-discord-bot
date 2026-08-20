import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { config, getMasterKey } from "./config";
import { logger } from "./logger";
import { closeDatabase, initDatabase } from "./db";
import { AclStore } from "./core/acl";
import { wipe } from "./core/crypto";
import { generateForSecret, getSecretRow, listSecretMetadata } from "./services/vault";
import { sweep } from "./services/ratelimit";
import { createBot, startBot, stopBot } from "./discord/bot";
import type { BotContext } from "./discord/context";

const HEARTBEAT_INTERVAL_MS = 60_000;
const RATELIMIT_SWEEP_INTERVAL_MS = 600_000;

/**
 * Startup order matters: everything that can fail on a misconfiguration fails
 * before the bot connects, so a bad deploy is a clean exit rather than a bot
 * that is online and answering every request with an error.
 */
async function main(): Promise<void> {
  const masterKey = getMasterKey();

  const db = initDatabase(config.vault.databasePath);
  logger.info("database ready", { path: config.vault.databasePath });

  // Fail closed at boot. An operator is watching a deploy; a hard stop is the
  // loudest possible signal, and the bot being down is a nuisance rather than
  // a breach.
  const aclStore = new AclStore(config.vault.aclPath);
  const acl = aclStore.loadOrThrow();
  for (const warning of acl.warnings) logger.warn("acl", { warning });
  logger.info("acl loaded", {
    // Named to avoid the logger's "secret" redaction rule, which is
    // deliberately broad. A count is not sensitive, but the backstop should
    // not be narrowed just to let one field through.
    aclEntries: acl.secrets.size,
    path: config.vault.aclPath,
  });

  // Probe every row now rather than discovering a wrong key at 3am on the one
  // request that mattered.
  const stored = listSecretMetadata(db);
  const undecryptable: string[] = [];
  for (const meta of stored) {
    const row = getSecretRow(db, meta.name);
    if (!row) continue;
    try {
      generateForSecret(row, masterKey);
    } catch {
      undecryptable.push(meta.name);
    }
  }
  if (stored.length > 0 && undecryptable.length === stored.length) {
    throw new Error(
      "Every stored secret failed to decrypt — VAULT_MASTER_KEY is wrong for " +
        "this database. Refusing to start.",
    );
  }
  if (undecryptable.length > 0) {
    logger.error("some entries cannot be decrypted", { names: undecryptable });
  }
  logger.info("vault ready", {
    storedEntries: stored.length,
    undecryptable: undecryptable.length,
  });

  if (!config.discord.token) {
    throw new Error("DISCORD_BOT_TOKEN is not set");
  }

  const ctx: BotContext = {
    db,
    aclStore,
    masterKey,
    guildId: config.discord.guildId,
    minRemainingSeconds: 5,
  };

  const client = createBot(ctx);
  await startBot(client, config.discord.token);

  // The bot serves no HTTP, so a process-liveness check would miss the failure
  // that actually happens: a wedged gateway connection with the process still
  // alive. The heartbeat file only advances while the client is ready, so the
  // container healthcheck can see the difference.
  const heartbeatPath = join(dirname(config.vault.databasePath), "heartbeat");
  const heartbeat = setInterval(() => {
    if (client.isReady()) {
      try {
        writeFileSync(heartbeatPath, `${Date.now()}\n`);
      } catch (err) {
        logger.warn("heartbeat write failed", { err });
      }
    }
  }, HEARTBEAT_INTERVAL_MS);
  heartbeat.unref();

  const sweeper = setInterval(() => {
    const removed = sweep();
    if (removed > 0) logger.debug("rate limit sweep", { removed });
  }, RATELIMIT_SWEEP_INTERVAL_MS);
  sweeper.unref();

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("shutting down", { signal });
    clearInterval(heartbeat);
    clearInterval(sweeper);
    try {
      await stopBot(client);
      closeDatabase();
    } finally {
      wipe(masterKey);
    }
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  // For a process holding credentials, crash rather than limp. The supervisor
  // restarts it; an unknown-state vault should not keep answering.
  process.on("uncaughtException", (err) => {
    logger.error("uncaught exception", { err });
    wipe(masterKey);
    process.exit(1);
  });
  process.on("unhandledRejection", (err) => {
    logger.error("unhandled rejection", { err });
    wipe(masterKey);
    process.exit(1);
  });
}

main().catch((err: unknown) => {
  // `reason`, not `message`: winston merges a meta `message` key into the log
  // message itself, which silently concatenates the two.
  logger.error("fatal during startup", {
    reason: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
