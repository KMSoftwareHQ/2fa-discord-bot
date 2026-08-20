import { REST, Routes, SlashCommandBuilder } from "discord.js";
import { config } from "../config";

/**
 * Registers the slash commands. A separate script, never run at boot.
 *
 *   npm run deploy-commands
 *   npm run deploy-commands -- --clear
 *
 * Registration defaults to a single guild when DISCORD_GUILD_ID is set. That
 * is deliberate: a global
 * command appears in every server the bot is ever invited to, which advertises
 * that a 2FA vault exists to a much wider audience than intended, and global
 * registration takes up to an hour to propagate while guild registration is
 * instant.
 *
 * Scope is NOT a security control — the handler enforces the guild check
 * independently.
 */

const twofa = new SlashCommandBuilder()
  .setName("2fa")
  .setDescription("Get a time-based code for a shared account")
  .addSubcommand((sub) =>
    sub
      .setName("get")
      .setDescription("Get the current code for a secret you have access to")
      .addStringOption((opt) =>
        opt
          .setName("name")
          .setDescription("Which secret")
          .setRequired(true)
          .setAutocomplete(true),
      ),
  )
  .addSubcommand((sub) =>
    sub.setName("list").setDescription("List the secrets you can access"),
  )
  .addSubcommand((sub) =>
    sub
      .setName("whoami")
      .setDescription("Show your Discord user ID, for the access list"),
  );

async function main(): Promise<void> {
  const clear = process.argv.includes("--clear");

  if (!config.discord.token) {
    process.stderr.write("DISCORD_BOT_TOKEN is not set\n");
    process.exit(1);
  }
  if (!config.discord.applicationId) {
    process.stderr.write("DISCORD_APPLICATION_ID is not set\n");
    process.exit(1);
  }

  const rest = new REST({ version: "10" }).setToken(config.discord.token);
  const body = clear ? [] : [twofa.toJSON()];

  const route = config.discord.guildId
    ? Routes.applicationGuildCommands(
        config.discord.applicationId,
        config.discord.guildId,
      )
    : Routes.applicationCommands(config.discord.applicationId);

  await rest.put(route, { body });

  const scope = config.discord.guildId
    ? `guild ${config.discord.guildId}`
    : "globally (may take up to an hour to appear)";
  process.stdout.write(
    clear
      ? `Cleared all commands for ${scope}.\n`
      : `Registered /2fa for ${scope}.\n`,
  );

  if (!config.discord.guildId) {
    process.stderr.write(
      "\nNote: registered globally. Set DISCORD_GUILD_ID to keep the command\n" +
        "out of every other server this bot is in.\n",
    );
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `error: ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(1);
});
