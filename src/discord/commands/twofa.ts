import {
  MessageFlags,
  type AutocompleteInteraction,
  type ChatInputCommandInteraction,
} from "discord.js";
import { logger } from "../../logger";
import { DENIED_MESSAGE } from "../../core/acl";
import {
  listAccessible,
  resolveCodeRequest,
  type VaultDeps,
} from "../../services/vault";
import { checkRateLimit } from "../../services/ratelimit";
import { recordAudit } from "../../services/audit";
import type { BotContext } from "../context";

/**
 * The Discord adapter. Deliberately thin: every decision that matters happens
 * in services/vault.ts, which knows nothing about discord.js and is tested
 * without a gateway connection.
 */

function replyFlags(): number {
  // Ephemeral everywhere. Not a DM: a DM is a real, persistent message that
  // syncs to every logged-in client, shows in lock-screen notification
  // previews, and lands in a Discord data export. An ephemeral reply is not
  // written to channel history and is gone on client restart, which is a
  // better fit for a value that dies in 30 seconds.
  return MessageFlags.Ephemeral | MessageFlags.SuppressEmbeds;
}

function contextLabel(interaction: ChatInputCommandInteraction): string {
  return interaction.guildId ? `guild:${interaction.guildId}` : "dm";
}

export async function handleTwoFa(
  ctx: BotContext,
  interaction: ChatInputCommandInteraction,
): Promise<void> {
  const subcommand = interaction.options.getSubcommand();

  if (subcommand === "whoami") {
    // Every new person needs their Discord ID to be added to the ACL, and
    // hunting for Developer Mode is a pointless detour. This reveals nothing
    // they could not already read off their own profile.
    await interaction.reply({
      content:
        `Your Discord user ID is \`${interaction.user.id}\`.\n` +
        `Send it to whoever administers the vault to be granted access.`,
      flags: replyFlags(),
    });
    return;
  }

  await interaction.deferReply({ flags: MessageFlags.Ephemeral });

  const { acl, stale, error } = ctx.aclStore.get();
  if (stale) {
    logger.error("ACL file is broken; serving the last known-good copy", {
      error,
    });
  }

  if (subcommand === "list") {
    const limit = checkRateLimit("2fa:list", interaction.user.id);
    if (!limit.allowed) {
      await interaction.editReply({
        content: `Slow down — ${limit.rule}. Try again in ${limit.retryAfterSeconds}s.`,
      });
      return;
    }

    const secrets = listAccessible(ctx.db, acl, interaction.user.id);
    recordAudit(ctx.db, {
      actor: `discord:${interaction.user.id}`,
      actorLabel: interaction.user.username,
      command: "list",
      outcome: "allowed",
      detail: `${secrets.length} accessible`,
      context: contextLabel(interaction),
    });

    const body =
      secrets.length === 0
        ? "You do not have access to any secrets."
        : secrets
            .map((s) => {
              const label = [s.issuer, s.account].filter(Boolean).join(" / ");
              return `• \`${s.name}\`${label ? ` — ${label}` : ""}`;
            })
            .join("\n");

    await interaction.editReply({
      content:
        `**Secrets you can access**\n${body}` +
        (stale ? "\n\n⚠️ The access list is currently unreadable; this may be out of date." : ""),
    });
    return;
  }

  if (subcommand !== "get") {
    await interaction.editReply({ content: "Unknown subcommand." });
    return;
  }

  // If a guild is configured, requests from anywhere else get the SAME
  // denial as an unauthorized name. Registration scope is not a security
  // control; this is.
  if (
    ctx.guildId &&
    interaction.guildId !== null &&
    interaction.guildId !== ctx.guildId
  ) {
    recordAudit(ctx.db, {
      actor: `discord:${interaction.user.id}`,
      actorLabel: interaction.user.username,
      command: "get",
      secretName: interaction.options.getString("name", true),
      outcome: "denied",
      detail: "wrong guild",
      context: contextLabel(interaction),
    });
    await interaction.editReply({ content: DENIED_MESSAGE });
    return;
  }

  const name = interaction.options.getString("name", true).trim().toLowerCase();

  const deps: VaultDeps = {
    db: ctx.db,
    acl,
    key: ctx.masterKey,
    minRemainingSeconds: ctx.minRemainingSeconds,
  };

  const result = await resolveCodeRequest(deps, {
    userId: interaction.user.id,
    userLabel: interaction.user.username,
    name,
    context: contextLabel(interaction),
  });

  switch (result.kind) {
    case "denied":
      await interaction.editReply({ content: DENIED_MESSAGE });
      return;

    case "rate_limited":
      await interaction.editReply({
        content:
          `Slow down — ${result.rule}. Try again in ${result.retryAfterSeconds}s.`,
      });
      return;

    case "error":
      await interaction.editReply({
        content:
          "That secret could not be read. The operator has been given the details.",
      });
      return;

    case "code": {
      const expiresAtSec = Math.floor(result.expiresAtMs / 1000);
      const label = [result.issuer, result.account].filter(Boolean).join(" / ");
      await interaction.editReply({
        content:
          `**${result.name}**${label ? ` — ${label}` : ""}\n` +
          // Bare code span, ungrouped, so tap-to-copy on mobile yields exactly
          // the digits the provider wants.
          `## \`${result.code}\`\n` +
          `Expires <t:${expiresAtSec}:R>` +
          (result.waitedMs > 0
            ? `\n_Waited ${Math.round(result.waitedMs / 1000)}s for a fresh code._`
            : ""),
      });
      return;
    }
  }
}

/**
 * Autocomplete the `name` option from the caller's own grants.
 *
 * This is a CONVENIENCE, never the authorization check — /2fa get re-resolves
 * the ACL from scratch. The interaction API happily accepts a name that was
 * never offered here, so treating this list as the boundary is the classic way
 * to build an ACL that does not actually hold.
 */
export async function handleTwoFaAutocomplete(
  ctx: BotContext,
  interaction: AutocompleteInteraction,
): Promise<void> {
  try {
    const limit = checkRateLimit("2fa:autocomplete", interaction.user.id);
    if (!limit.allowed) {
      await interaction.respond([]);
      return;
    }

    const { acl } = ctx.aclStore.get();
    const typed = interaction.options.getFocused().toLowerCase();
    const choices = listAccessible(ctx.db, acl, interaction.user.id)
      .filter((s) => s.name.includes(typed))
      .slice(0, 25)
      .map((s) => ({
        name: s.issuer ? `${s.name} — ${s.issuer}` : s.name,
        value: s.name,
      }));

    await interaction.respond(choices);
  } catch (err) {
    // Never surface an error here — an autocomplete that behaves differently
    // for a real name than a fake one is a side channel.
    logger.warn("autocomplete failed", { err });
    await interaction.respond([]).catch(() => undefined);
  }
}
