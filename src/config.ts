import dotenv from "dotenv";
dotenv.config();

function required(name: string): string {
  const val = process.env[name];
  if (!val) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return val;
}

/**
 * The master key is 64 hex characters = 32 bytes for AES-256-GCM.
 *
 * Validated here rather than at first use so a typo fails at boot, in front of
 * whoever just deployed, instead of at 3am on the first `/2fa get`.
 */
function masterKey(name: string): Buffer {
  const raw = required(name).trim();
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(
      `${name} must be exactly 64 hex characters (32 bytes). ` +
        `Generate one with: npm run vault -- genkey`,
    );
  }
  return Buffer.from(raw, "hex");
}

export const config = {
  discord: {
    token: process.env.DISCORD_BOT_TOKEN ?? "",
    applicationId: process.env.DISCORD_APPLICATION_ID ?? "",
    /** Register commands to this guild only. Empty = global registration. */
    guildId: process.env.DISCORD_GUILD_ID ?? "",
  },
  vault: {
    databasePath: process.env.DATABASE_PATH ?? "data/vault.db",
    aclPath: process.env.ACL_PATH ?? "config/acl.json",
  },
  logLevel: process.env.LOG_LEVEL ?? "info",
} as const;

/**
 * Resolved lazily: the bot and the CLI both need it, but `genkey` must run
 * before one exists. Reading it at module load would make the one command that
 * creates a key require a key.
 */
export function getMasterKey(): Buffer {
  return masterKey("VAULT_MASTER_KEY");
}

/** Only used by `vault rotate-key`. */
export function getNewMasterKey(): Buffer {
  return masterKey("VAULT_NEW_MASTER_KEY");
}
