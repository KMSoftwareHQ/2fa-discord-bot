# Contributing

## Before you push

```bash
npm run typecheck
npm test
npm run check:clean
```

CI runs the same four steps. `check:clean` is the one that matters most here:
it refuses base32 seeds, 64-hex master keys, Discord bot tokens, real Discord
snowflakes, and personal paths. Install it as a commit gate:

```bash
printf '#!/bin/sh\nbash scripts/check-clean.sh --staged\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Ground rules specific to this project

- **Never put real secret material in a test or a doc.** Use the RFC 6238
  example seed `JBSWY3DPEHPK3PXP` and the placeholder IDs already in
  `config/acl.example.json`. The leak guard allows exactly those.
- **Keep discord.js out of `src/core` and `src/services`.** The whole test suite
  runs without a gateway connection because the decisions live in modules that
  do not import it. A single import breaks that.
- **Do not add a Discord command that accepts seed material.** Seeds enter
  through the CLI or not at all. This is the central design constraint, not a
  convention.
- **Do not widen the secret-name regex** in `src/core/names.ts` without reading
  the comment there first. The crypto AAD is built as `v1|<name>` and is only
  unambiguous because a name cannot contain `|`.
- **Never log a seed or an issued code.** `src/logger.ts` has a redaction
  backstop, but it is a backstop — the rule is that they never reach a log call.
- **Preserve the uniform denial.** Unauthorized and nonexistent must stay
  byte-identical to the user. `{ kind: "denied" }` carries no fields on purpose,
  so a reason cannot leak across that boundary even by accident. There is a test.

## Tests

`node:test` and `node:assert/strict`, colocated as `*.test.ts`, run against
compiled output (`npm test` builds first). Deterministic: inject the clock
rather than reading it, and use `:memory:` SQLite or a temp directory.

Anything touching crypto, TOTP, or authorization needs a test that would fail if
the property were removed — not just one that exercises the happy path.

## Style

TypeScript, `strict`, ES2022, two-space indent (see `.editorconfig`). Comments
explain *why*, particularly where a choice is security-relevant and would
otherwise look arbitrary to whoever reads it next.
