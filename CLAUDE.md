# CLAUDE.md

Notes for anyone — human or agent — working in this repository.

## What this is

A Discord bot that issues TOTP codes from an encrypted local vault to a
per-secret allowlist of Discord user IDs. Public repo, so nothing real is ever
committed: no seeds, no keys, no Discord IDs, no host paths.

## Invariants — do not break these

1. **Seeds never travel through Discord.** They enter via `src/cli.ts` only,
   from a hidden TTY prompt or a pipe, never from argv. There is no `--secret`
   flag; the CLI rejects it with an explanation.
2. **`src/core` and `src/services` never import discord.js.** That is what keeps
   the entire test suite runnable with no gateway connection.
3. **Unauthorized and nonexistent are indistinguishable to the caller.**
   `resolveCodeRequest` returns `{ kind: "denied" }` with no fields, so a reason
   is unrepresentable at that boundary. The audit table records which it really
   was.
4. **Rate-limit ordering is a security property.** Per-user is consumed *before*
   authorization (so unauthorized probing is bounded); per-secret is consumed
   *after* (so its state is not an existence oracle). Both have tests.
5. **The crypto AAD is `v1|<name>`.** It binds a ciphertext to its row, which is
   what stops someone with database write access from moving a blob into a row
   they can read. The name regex in `src/core/names.ts` must never allow `|`.
6. **Never log a seed or an issued code.** `src/logger.ts` redacts as a
   backstop; the rule is that they do not reach a log call in the first place.
7. **Per-secret TOTP parameters are stored, never assumed.** 8-digit and SHA256
   accounts are real and common.

## Layout

```
src/core/      pure: crypto.ts, totp.ts, acl.ts, names.ts  (+ colocated tests)
src/db/        index.ts (open/pragmas), migrations.ts
src/services/  vault.ts (the core), audit.ts, ratelimit.ts
src/discord/   bot.ts, deploy-commands.ts, commands/twofa.ts, context.ts
src/cli.ts     admin surface;  src/cli/prompt.ts is the no-echo reader
scripts/       check-clean.sh (leak guard) + cron supervision set
```

## Commands

```bash
npm run build && npm test      # node --test dist
npm run typecheck
npm run check:clean            # MUST pass before any commit
npm run vault -- <cmd>         # genkey|add|list|rm|verify|rotate-key|audit|acl-check
npm run deploy-commands        # [-- --clear] to unregister
```

## Gotchas discovered the hard way

- Winston formats must **mutate `info` in place**. Returning a new object drops
  `Symbol.for("level")` / `Symbol.for("message")` and the logger silently stops
  emitting anything.
- A winston meta key named `message` is merged into the log message itself. Use
  `reason` for error detail.
- `better-sqlite3` is a native addon: `npm ci --omit=dev` in a Docker runtime
  stage **fails** (no compiler). Build, then `npm prune --omit=dev`, then copy
  `node_modules` — and keep both stages on the same base image for ABI
  compatibility.
- ACL change detection hashes the file contents. mtime+size is not enough: two
  different allowlists can be byte-identical in length and land in the same
  millisecond.
- `HashAlgorithms` is exported from `@otplib/core`, not from `otplib`.
- Discord snowflakes exceed 2^53. Unquoted in JSON they are silently rounded;
  the ACL parser rejects numbers and does *not* echo the rounded value back,
  because that would be wrong advice.

## Testing conventions

Inject the clock (`nowMs`) rather than reading it. Use `:memory:` SQLite or
`mkdtempSync`. RFC 6238 vectors live in `src/core/totp.test.ts` and are derived
from a base32 encoder in the test file rather than pasted, so the two check each
other.
