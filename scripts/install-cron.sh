#!/usr/bin/env bash
#
# Idempotently install this project's cron wiring.
#
#   bash scripts/install-cron.sh docker   # re-assert `docker compose up -d` at boot
#   bash scripts/install-cron.sh node     # @reboot + per-minute supervisor watchdog
#
# Pick ONE. Running both would put two bots on one vault, which double-counts
# rate limits and interleaves audit rows.
#
# Every managed line carries a tag, so this rewrites only its own entries and
# leaves every other crontab line on the host untouched. Safe to run repeatedly.
set -euo pipefail

MODE="${1:-}"
if [ "$MODE" != "docker" ] && [ "$MODE" != "node" ]; then
	echo "usage: $0 docker|node" >&2
	echo >&2
	echo "  docker  container is supervised by the Docker daemon; cron only" >&2
	echo "          re-asserts state at boot" >&2
	echo "  node    no Docker; cron runs the flock-arbitrated supervisor" >&2
	exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="# 2fa-vault-managed"

current="$(crontab -l 2>/dev/null || true)"
# Drop any previously-managed lines, whichever mode installed them, so
# switching modes cannot leave both running.
filtered="$(printf '%s\n' "$current" | grep -vF "$TAG" || true)"

{
	printf '%s\n' "$filtered" | sed '/^$/d'
	if [ "$MODE" = "docker" ]; then
		echo "@reboot $ROOT/scripts/boot.sh $TAG"
	else
		echo "@reboot $ROOT/scripts/ensure-running.sh $TAG"
		echo "* * * * * $ROOT/scripts/ensure-running.sh $TAG"
	fi
} | crontab -

echo "Cron installed ($MODE mode). Managed entries:"
crontab -l | grep -F "$TAG"
