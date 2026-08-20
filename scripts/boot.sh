#!/usr/bin/env bash
#
# Re-assert the desired Docker state at boot.
#
# `restart: unless-stopped` already brings the container back when the Docker
# daemon starts, so this is a safety net rather than the mechanism: it covers a
# daemon that came up before this filesystem was mounted, and a container that
# was left stopped by a previous manual `docker compose down`.
#
# Idempotent — running it when everything is already up is a no-op.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

mkdir -p logs
exec >>"$ROOT/logs/boot.log" 2>&1
echo "$(date -Is) boot.sh: asserting compose state"

# Wait for the Docker daemon; at boot cron can fire before it is listening.
for _ in $(seq 1 30); do
	docker info >/dev/null 2>&1 && break
	sleep 2
done

docker compose up -d
echo "$(date -Is) boot.sh: done"
