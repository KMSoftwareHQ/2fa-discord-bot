# 2fa-discord-bot

A Discord bot that hands out time-based one-time codes to an explicit allowlist
of Discord user IDs, without ever revealing the underlying seed.

Some accounts cannot be shared any other way. A root account, an org owner, a
billing portal — one login, 2FA required, and several people who legitimately
need it. The usual answer is to pass the seed around until it lives in five
authenticator apps on five personal phones, where it stays forever, including
after someone leaves.

This keeps the seed in one place, encrypted, and gives out only the six digits
that are valid for the next thirty seconds. Access is a line in a file: adding
someone takes effect immediately, and so does removing them, with nothing to
re-enrol at the provider.

**Before you deploy this, read [SECURITY.md](SECURITY.md).** It is deliberately
blunt about what this design does not protect against — most importantly, that
a compromised Discord account gets codes, and that this is the wrong tool for
an individual person's own accounts.

## Features

- **Codes, never seeds.** The seed is decrypted in memory, used, and wiped. No
  command exposes it, and there is no way to ask the bot for one.
- **Encrypted at rest.** AES-256-GCM with a 32-byte master key held only in the
  environment, a fresh nonce per write, and the secret's name bound in as
  additional authenticated data so a ciphertext cannot be moved between rows.
- **Per-secret allowlists.** A gitignored JSON file maps each secret to the
  Discord user IDs that may request it. Edits apply without a restart.
- **No enumeration.** An unauthorized name and a nonexistent one produce the
  same message, so nobody can map the vault by guessing.
- **A real audit trail.** Every request — allowed, denied, or rate-limited — is
  recorded in SQLite with the actual secret name, written before the code is
  handed over. The code itself is never recorded.
- **Correct for real providers.** Per-secret algorithm, digit count, and period
  are stored and honoured, not assumed. 8-digit and SHA256 accounts work.
  Verified against the RFC 6238 test vectors.
- **Seeds enter locally, or not at all.** A hidden CLI prompt or a pipe — never
  a command-line argument, never through Discord.
- **Publish-safe.** A pre-commit/CI guard greps for base32 seeds, master keys,
  bot tokens, and real Discord IDs before any of them can reach the repo.

## Requirements

- Node.js 20 or newer (see `.nvmrc`), or Docker.
- A Discord application with a bot user.
- **An accurate system clock.** TOTP is time-based; a host more than ~30
  seconds off will produce codes that every provider rejects.

## Quick start

### From source

```bash
npm ci
npm run build

# 1. Generate a master key and put it in .env
cp .env.example .env
npm run vault -- genkey        # paste the output into VAULT_MASTER_KEY

# 2. Add a secret. You will be prompted; nothing is echoed.
npm run vault -- add aws-root
#    Paste either a base32 seed or the full otpauth:// URI from the QR code.
#    Check the code it prints against the provider before relying on it.

# 3. Grant access
cp config/acl.example.json config/acl.json
#    Put your own Discord user ID in it — /2fa whoami will tell you yours,
#    or enable Developer Mode in Discord and right-click your name.
npm run vault -- acl-check     # validates the file and shows effective grants

# 4. Register the command and start
npm run deploy-commands
npm start
```

### With Docker

```bash
cp .env.example .env           # fill in the token and master key
cp config/acl.example.json config/acl.json
docker compose up -d --build
```

The database lives in a named volume. `config/acl.json` is bind-mounted
read-only, so you edit it on the host and the bot picks it up — and a
compromised container cannot grant itself more access.

Set `APP_UID`/`APP_GID` in `.env` to your own `id -u`/`id -g`. The image
defaults to uid 1000; if your account is anything else the read-only ACL mount
is unreadable and the bot will not start.

Once you are running in Docker, the admin CLI runs **inside** the container, so
it operates on the same vault:

```bash
docker compose exec bot node dist/cli.js list
docker compose exec bot node dist/cli.js audit --since 24h
docker compose exec -it bot node dist/cli.js add <name>
```

Back the volume up with:

```bash
docker run --rm -v 2fa-discord-bot_vault_data:/d -v "$PWD/backups":/b \
  node:20-bookworm-slim cp /d/vault.db /b/vault.db.$(date +%%F)
```

## Configuration

All via `.env`; see `.env.example` for the annotated list.

| Variable | Required | Purpose |
| --- | --- | --- |
| `DISCORD_BOT_TOKEN` | yes | Bot token |
| `DISCORD_APPLICATION_ID` | yes | For registering slash commands |
| `DISCORD_GUILD_ID` | strongly advised | Register the command to one guild only |
| `VAULT_MASTER_KEY` | yes | 64 hex characters. `npm run vault -- genkey` |
| `VAULT_NEW_MASTER_KEY` | only to rotate | Target key for `rotate-key` |
| `DATABASE_PATH` | no | Default `data/vault.db` |
| `ACL_PATH` | no | Default `config/acl.json` |
| `LOG_LEVEL` | no | Default `info` |
| `APP_UID` / `APP_GID` | Docker only | The uid/gid the container runs as. Must own `config/acl.json` and the data volume — set to your `id -u` / `id -g` |

Set `DISCORD_GUILD_ID`. Without it the command registers globally, which means
it appears in every server the bot is ever added to and takes up to an hour to
propagate. The bot enforces the guild restriction independently of where the
command happens to be registered.

## Managing secrets

Seed material only ever enters through the CLI. There is no Discord command
that accepts a seed, and there is deliberately no `--secret` flag — an argument
would land in your shell history and be visible in `ps` to every user on the
host.

```bash
npm run vault -- add <name>            # hidden prompt
pass show aws-root/totp | npm run vault -- add aws-root    # or a pipe

npm run vault -- list                  # names and parameters, never seeds
npm run vault -- verify                # prove every row still decrypts
npm run vault -- verify aws-root       # and print one code to check it
npm run vault -- rm <name>
npm run vault -- audit --since 7d
npm run vault -- acl-check
```

`add` accepts either a bare base32 seed or a full `otpauth://totp/...` URI. Use
the URI when you have it: it carries the algorithm, digit count, and period, so
an 8-digit or SHA256 account is configured correctly instead of silently
producing codes the provider will reject.

Secret names are lowercase `[a-z0-9._-]`, up to 64 characters.

## Access control

`config/acl.json` is gitignored. `config/acl.example.json` is the template.

```json
{
  "version": 1,
  "secrets": {
    "aws-root": {
      "note": "prod root account — break-glass only",
      "allowed": ["123456789012345678"]
    }
  }
}
```

Discord IDs **must be quoted strings**. They exceed JavaScript's safe integer
range, so an unquoted number silently loses its last digits and becomes a
different, valid-looking ID. The bot rejects this rather than guessing.

Changes are picked up within a second, no restart needed. If you save a broken
file, the bot keeps serving the last valid version and logs an error — a stray
comma should not lock everyone out during the incident they are editing the
file to handle. **The trade-off:** if you are *removing* someone and you break
the file, the removal does not take effect until you fix it. Run
`npm run vault -- acl-check` after any edit you care about.

## Using it in Discord

| Command | What it does |
| --- | --- |
| `/2fa get <name>` | The current code. Autocompletes to what you can access |
| `/2fa list` | The secrets you can access |
| `/2fa whoami` | Your Discord user ID, for the allowlist |

Replies are always ephemeral — visible only to you, not written to channel
history, and gone on client restart. If a code has under 5 seconds left the bot
waits for the next window rather than handing you one that will be rejected
mid-typing.

Autocomplete only offers names you are allowed to request, but it is a
convenience, not the security boundary: `/2fa get` re-checks the allowlist from
scratch on every call.

The bot requests the `Guilds` gateway intent only. It cannot read messages.
Invite it with the `bot` and `applications.commands` scopes and **no permission
bits** — interaction replies need none.

## Audit log

Every request is recorded before the code is issued: who asked, for what, when,
from where, and what happened. Denied requests record the real name that was
requested even though the reply named nothing — the requester learns nothing,
the operator learns everything.

```bash
npm run vault -- audit --since 24h
npm run vault -- audit --secret aws-root --limit 100
npm run vault -- audit --actor 123456789012345678 --json
```

The issued code is never written to the log or the database. The 30-second step
index is, which lets you line a request up against the provider's own login
record without storing a credential.

## Key rotation and recovery

```bash
# put the new key in VAULT_NEW_MASTER_KEY, then:
npm run vault -- rotate-key
```

Every row is re-encrypted in a single transaction after a timestamped backup, so
the database is never half under each key. Afterwards, move the new value into
`VAULT_MASTER_KEY`, clear `VAULT_NEW_MASTER_KEY`, restart, and delete the backup
once you have confirmed things work — it is still readable with the old key.

**There is no recovery if you lose the master key.** Every seed becomes
permanently unreadable and each account has to be re-enrolled at its provider.
Back the key up somewhere separate from `data/vault.db`; a backup holding both
is not meaningfully encrypted. Keep each provider's own recovery codes outside
this vault.

## Architecture

```
src/core/      pure logic, no I/O — crypto envelope, TOTP, otpauth parsing, ACL
src/db/        SQLite open, pragmas, migrations
src/services/  vault (authorization + issuing), audit, rate limiting
src/discord/   the adapter: ~250 lines, no decisions of its own
src/cli.ts     the admin surface — the only path seeds take into the vault
```

Everything that matters is in `core` and `services`, which import nothing from
discord.js. That is why the whole test suite runs with no gateway connection and
no network.

Storage is one SQLite file (`better-sqlite3`, WAL, `synchronous = FULL`): no
daemon to run, and an audit row that survives a power cut.

## Running as a persistent service

Pick exactly one of these. Running both means two bots on one vault.

**Docker** (recommended): `docker compose up -d --build`. Restarts on boot via
`restart: unless-stopped`, provided the Docker daemon itself starts at boot
(`systemctl is-enabled docker`). Add `bash scripts/install-cron.sh docker` as a
safety net for the case where the daemon comes up before this filesystem is
mounted. Health is a heartbeat file the bot only touches while
its gateway connection is live, so a wedged-but-alive process is still reported
unhealthy.

**Cron + supervisor**, where there is no systemd:

```bash
npm run build
bash scripts/install-cron.sh node   # @reboot + a per-minute watchdog
bash scripts/status.sh
bash scripts/stop.sh
bash scripts/uninstall-cron.sh
```

`install-cron.sh` takes the mode explicitly — `docker` or `node` — and clears
any entry the other mode left behind, so the two cannot end up running at once.
In `docker` mode the only entry is an `@reboot` that re-asserts
`docker compose up -d`; the Docker daemon does the actual supervising.

The supervisor elects itself with `flock` and holds the lock for its lifetime,
so the watchdog cannot start a second bot however often it fires. Crashes
restart with capped exponential backoff.

## Operating it safely

- Put the master key and the database in different backups.
- Keep the allowlist short, and keep `DISCORD_GUILD_ID` set.
- Require 2FA on the Discord accounts that appear in the allowlist. They are now
  a path to your other second factors.
- Review `npm run vault -- audit` periodically. Repeated `denied` rows from one
  user are worth a conversation.
- Do not use this for personal accounts. See [SECURITY.md](SECURITY.md).

## Development

```bash
npm run typecheck
npm test               # node --test over dist; no network, no Discord
npm run check:clean    # the pre-publish leak guard
```

`npm run check:clean` greps for base32 seeds, 64-hex master keys, Discord bot
tokens, real snowflakes, and personal identifiers, and refuses to let secret
files be tracked. It runs in CI and supports `--staged` as a commit hook.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
