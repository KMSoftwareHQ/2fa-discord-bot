#!/usr/bin/env bash
#
# check-clean.sh — pre-publish guard.
#
# Greps the tree for personal / infrastructure identifiers AND for secret
# material that must never reach the public repository. Exits non-zero on any
# hit so it can gate a commit or CI.
#
#   bash scripts/check-clean.sh              # scan the working tree
#   bash scripts/check-clean.sh --staged     # scan only what git has staged
#
# This repository handles TOTP seeds, so the patterns below matter more than in
# an ordinary project: a single committed base32 string is a permanently
# compromised second factor.
set -uo pipefail

cd "$(dirname "$0")/.."

# Identifiers that must have ZERO occurrences.
DENY=(
	nimblewimble
	phylex
	vm-hosted-by
	valamore
	purple-unicorn
	ccnodes
	wdingo
	dingocoin
	dingo-tip
	rustcodes
	code-raider
	'/home/claude'
	'/mnt/bulk'
	'/mnt/nvme'
	'0x8c8f61a4'
	'75.188.129.42'
	'proton.me'
	# Unfilled template placeholder — replace with the real GitHub owner in
	# package.json before publishing.
	'github.com/OWNER'
)

# "kmsoftware" is deliberate authorship credit, but only in these files.
# package.json is on the list because the repository URL contains the org name;
# leaving it off fails CI on the very first commit.
# The optional ./ prefix matters: the working-tree scan uses `grep -r .` and
# yields "./LICENSE", while --staged reads `git diff --cached --name-only` and
# yields "LICENSE". Anchoring to one form silently disables this allowlist in
# the other mode — which is the mode that gates commits.
CREDIT_FILES='^(\./)?(LICENSE|package\.json|package-lock\.json|README\.md)$'

# This script necessarily contains every term it looks for, so it excludes
# itself from every scan.
SELF="scripts/check-clean.sh"

# Gitignored files are SUPPOSED to hold real values — the live allowlist has
# real Discord IDs in it and .env has the master key. Scanning them would make
# this guard fail on every correctly-configured deployment, which trains people
# to ignore it. What actually matters is that they are never committed, and the
# `git ls-files` check at the bottom enforces exactly that.
COMMON_EXCLUDES=(
	--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist
	--exclude-dir=data --exclude-dir=logs --exclude-dir=run
	--exclude-dir=backups
	--exclude=".env" --exclude=".env.*" --exclude="acl.json"
	--exclude="$(basename "$SELF")"
)

if [ "${1:-}" = "--staged" ]; then
	mapfile -t FILES < <(git diff --cached --name-only --diff-filter=ACM | grep -v "^${SELF}$")
	[ "${#FILES[@]}" -eq 0 ] && { echo "check-clean: nothing staged"; exit 0; }
	scan() { grep -nIH --fixed-strings -i -- "$1" "${FILES[@]}" 2>/dev/null; }
	scan_re() { grep -nIHE -- "$1" "${FILES[@]}" 2>/dev/null; }
else
	scan() { grep -rnIH --fixed-strings -i "${COMMON_EXCLUDES[@]}" -- "$1" . 2>/dev/null; }
	scan_re() { grep -rnIHE "${COMMON_EXCLUDES[@]}" --exclude=package-lock.json -- "$1" . 2>/dev/null; }
fi

fail=0

report() {
	echo "LEAK: $1"
	printf '%s\n' "$2" | sed 's/^/  /'
	fail=1
}

for term in "${DENY[@]}"; do
	if hits="$(scan "$term")" && [ -n "$hits" ]; then
		report "'$term'" "$hits"
	fi
done

# --- secret material -------------------------------------------------------
# A base32 run of 16+ characters is what a TOTP seed looks like. The RFC 4648 /
# RFC 6238 example seeds are allowed: they appear throughout the docs and tests
# and are published in the RFCs themselves.
# Allowed: the RFC 4648 / RFC 6238 example seeds (published in the RFCs and used
# throughout the docs and tests) and the base32 alphabet itself.
ALLOWED_SEEDS='JBSWY3DPEHPK3PXP|GEZDGNBVGY3TQOJQ|ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
if hits="$(scan_re '\b[A-Z2-7]{16,}\b' | grep -Eiv "$ALLOWED_SEEDS")" && [ -n "$hits" ]; then
	report "possible base32 TOTP seed" "$hits"
fi

# A 64-hex run is the shape of VAULT_MASTER_KEY.
if hits="$(scan_re '\b[0-9a-f]{64}\b')" && [ -n "$hits" ]; then
	report "possible 32-byte master key (64 hex chars)" "$hits"
fi

# Discord bot tokens.
if hits="$(scan_re '[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}')" && [ -n "$hits" ]; then
	report "possible Discord bot token" "$hits"
fi

# An enrolment URI carries a live seed.
# Deliberately obvious non-secrets in the parser tests are allowed alongside the
# RFC example seeds: a literal placeholder or an interpolated test constant.
ALLOWED_URI_SECRETS="$ALLOWED_SEEDS|not-base32|\\\$\\{"
if hits="$(scan_re 'otpauth://[^ "'"'"']*secret=' | grep -Eiv "$ALLOWED_URI_SECRETS")" && [ -n "$hits" ]; then
	report "otpauth:// URI with a secret parameter" "$hits"
fi

# Real Discord snowflakes. The documented placeholders are the only ones
# allowed to appear anywhere in the tree.
# The documented placeholders, plus the value 123456789012345678 rounds to when
# JSON.parse mangles it — which the ACL error path documents and tests.
ALLOWED_IDS='123456789012345678|123456789012345680|234567890123456789|345678901234567890|999999999999999999'
if hits="$(scan_re '\b[0-9]{17,20}\b' | grep -Ev "$ALLOWED_IDS")" && [ -n "$hits" ]; then
	report "possible real Discord ID (use a placeholder in docs)" "$hits"
fi

# The credit string: allowed, but only in the known files.
credit="$(scan 'kmsoftware' || true)"
n=0
if [ -n "$credit" ]; then
	n="$(printf '%s\n' "$credit" | wc -l | tr -d ' ')"
	stray="$(printf '%s\n' "$credit" | while IFS= read -r line; do
		f="${line%%:*}"
		printf '%s\n' "$f" | grep -qE "$CREDIT_FILES" || printf '%s\n' "$line"
	done)"
	if [ -n "$stray" ]; then
		report "'kmsoftware' outside the allowed credit files:" "$stray"
	fi
fi

# Data/secret files must never be tracked, whatever .gitignore says.
if git rev-parse --git-dir >/dev/null 2>&1; then
	if bad="$(git ls-files | grep -E '(^|/)\.env$|\.env\.[^e]|\.db($|-wal|-shm)|^data/|^logs/|^run/|^backups/|^config/acl\.json$|\.bak|\.key$' || true)"; then
		if [ -n "$bad" ]; then
			report "forbidden files are tracked by git:" "$bad"
		fi
	fi
fi

if [ "$fail" -eq 0 ]; then
	echo "check-clean: OK — no stray identifiers or secret material (credit string in $n allowed location(s))"
else
	echo
	echo "check-clean: FAILED — resolve the above before publishing." >&2
fi
exit "$fail"
