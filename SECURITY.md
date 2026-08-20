# Security

## Reporting a vulnerability

Open a GitHub issue for anything non-sensitive. For a vulnerability that would
expose stored seeds, use GitHub's private vulnerability reporting rather than a
public issue.

## What this tool is

A Discord bot that stores TOTP seeds encrypted on one host and hands out the
current code to an explicit allowlist of Discord user IDs. The seed never leaves
the server and is never shown to a Discord user.

Read the next two sections before deciding to run it. The threat model is
narrower than it first appears, and the tool is a poor fit for some of the
things people will reach for it to do.

## What it protects against

- **Seed sprawl.** Without something like this, a shared account's TOTP seed
  ends up in N authenticator apps on N personal devices, plus a screenshot in a
  chat somewhere, plus a copy in someone's notes. Here it exists in one place.
- **Offboarding.** Delete a line from `config/acl.json` and that person loses
  access immediately, to every secret, with nothing re-enrolled at any provider.
  Someone who once scanned the QR code keeps working codes forever unless you
  rotate the seed at the provider and re-enrol everyone.
- **Least privilege per secret.** The on-call engineer gets `status-page` and
  never `aws-root`.
- **Not knowing who did what.** Every request — allowed, denied, or
  rate-limited — is recorded with the real secret name and the requesting user.
  An authenticator app on someone's phone cannot answer "who pulled the root
  code at 03:00" at all.
- **Theft of the database at rest.** A leaked backup, a snapshotted volume, a
  mis-set bucket permission: all inert without the master key, which is not
  stored in the database.

## What it does NOT protect against

Stated plainly, because these are the things that will actually bite you.

- **A compromised Discord account gets codes.** This is the big one. A stolen
  session token yields every code that user is allowed to request, on demand,
  and it looks exactly like normal use. The bot cannot tell the difference.
  Require 2FA on the Discord accounts, and keep the allowlist short.
- **It weakens the second factor by construction.** The point of TOTP is that
  it lives on a device separate from the password. Anyone who takes over a
  user's Discord now has a path to both factors. That trade is defensible for
  shared service accounts nobody can enrol individually. It is **not**
  defensible for an individual person's own accounts — use a normal
  authenticator app for those.
- **Discord is inside the trust boundary.** Codes transit and are rendered by
  Discord's infrastructure. Ephemeral replies are a product behaviour, not a
  cryptographic property: they are not written to channel history and vanish on
  client restart, but Discord still handles them. If your threat model includes
  Discord itself, do not use this.
- **Host compromise is total.** The master key is in the environment of a
  process running on the same host as the database. Anyone who can read
  `/proc/<pid>/environ`, the `.env` file, or take a root shell has every seed.
  Encryption at rest defends the backup, the stolen disk, and the stray file
  copy — not a live attacker on the box.
- **The operator is inside the trust boundary.** Whoever administers the host
  can add themselves to the allowlist or read the seeds directly, and the audit
  log lives on the same machine under the same account. It is tamper-evident to
  nobody.
- **It is not phishing-resistant.** TOTP is a shared secret typed into a box. A
  convincing phishing page harvests it from a bot as readily as from a phone.
  Where a provider supports WebAuthn or passkeys, use those instead — this tool
  exists for the accounts that only offer TOTP.
- **No key escrow.** Lose `VAULT_MASTER_KEY` and every stored seed is
  permanently unrecoverable. There is no hint, no recovery code, no backdoor.
- **Memory hygiene is best-effort.** Decrypted seeds live in `Buffer`s that are
  zeroed after use, but the TOTP library takes a `string`, and JavaScript
  strings are immutable and cannot be wiped. Seed material can persist in the
  V8 heap, in a core dump, or in swap. Use encrypted swap if that matters to
  you.
- **Rate limits are in-memory** and reset when the process restarts.
- **This is access control, not data-loss prevention.** Anyone authorized can
  screenshot a code, or pull codes indefinitely.

## Operational requirements

- **Back up the master key separately from the database.** A backup containing
  both is not encrypted in any useful sense.
- **Keep the provider's own recovery codes** somewhere that is not this vault.
  If the vault is lost, those are how you get back in.
- **Keep the host clock accurate.** TOTP is time-based; a clock more than about
  30 seconds off makes every code wrong. This is the most common cause of "the
  bot gives bad codes".
- **Do not add this bot to a large or public server.** Set `DISCORD_GUILD_ID` so
  the command is registered to one guild only.

## Design decisions worth knowing

- Seeds are sealed with AES-256-GCM under a 32-byte key, with a fresh 12-byte
  nonce per write, and the secret's name bound in as additional authenticated
  data. That binding means a ciphertext cannot be moved between rows: an
  attacker with write access to the database cannot copy the `aws-root` blob
  into a row they are allowed to read.
- Unauthorized and nonexistent secrets return a byte-identical message, so the
  set of stored names cannot be enumerated by probing. The audit log records
  which of the two actually happened.
- The per-user rate limit is consumed *before* the authorization check, so an
  unauthorized user cannot probe names quickly. The per-secret limit is consumed
  *after*, so that its state cannot be used as an existence oracle.
- Seed material can only enter through the local CLI, never through Discord, and
  never as a command-line argument.
