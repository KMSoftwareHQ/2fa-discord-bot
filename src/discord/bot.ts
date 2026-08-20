import {
  Client,
  GatewayIntentBits,
  MessageFlags,
  type ChatInputCommandInteraction,
  type Interaction,
} from "discord.js";
import { logger } from "../logger";
import { handleTwoFa, handleTwoFaAutocomplete } from "./commands/twofa";
import type { BotContext } from "./context";

/**
 * Client lifecycle: createBot / startBot / stopBot.
 */

type CommandHandler = (
  ctx: BotContext,
  interaction: ChatInputCommandInteraction,
) => Promise<void>;

const commandHandlers: Record<string, CommandHandler> = {
  "2fa": handleTwoFa,
};

export function createBot(ctx: BotContext): Client {
  // Guilds ONLY. Slash commands arrive over the gateway without any message
  // intent, and a vault that holds 2FA seeds has no business also being able
  // to read message content, so GuildMessages and MessageContent are
  // deliberately not requested.
  const client = new Client({ intents: [GatewayIntentBits.Guilds] });

  client.once("clientReady", () => {
    logger.info("Discord bot ready", {
      user: client.user?.tag,
      guilds: client.guilds.cache.size,
    });
  });

  client.on("interactionCreate", async (interaction: Interaction) => {
    if (interaction.isAutocomplete()) {
      await handleTwoFaAutocomplete(ctx, interaction);
      return;
    }
    if (!interaction.isChatInputCommand()) return;

    const handler = commandHandlers[interaction.commandName];
    if (!handler) {
      await interaction.reply({
        content: "Unknown command.",
        flags: MessageFlags.Ephemeral,
      });
      return;
    }

    try {
      await handler(ctx, interaction);
    } catch (err) {
      logger.error("command handler threw", {
        command: interaction.commandName,
        user: interaction.user.id,
        err,
      });
      const content =
        "Something went wrong handling that. The operator has the details.";
      try {
        if (interaction.replied || interaction.deferred) {
          await interaction.followUp({ content, flags: MessageFlags.Ephemeral });
        } else {
          await interaction.reply({ content, flags: MessageFlags.Ephemeral });
        }
      } catch {
        // The interaction token may already have expired; nothing to do.
      }
    }
  });

  client.on("error", (err) => logger.error("discord client error", { err }));
  client.on("shardError", (err) => logger.error("discord shard error", { err }));

  return client;
}

export async function startBot(client: Client, token: string): Promise<void> {
  await client.login(token);
}

export async function stopBot(client: Client): Promise<void> {
  await client.destroy();
}
