#!/usr/bin/env bash
#
# Is it up, and is the gateway actually connected?
#
# Process liveness alone is not enough: the failure that happens in practice is
# a wedged gateway with the process still running. The heartbeat file only
# advances while the Discord client reports ready.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PIDFILE="$ROOT/run/supervisor.pid"
DATA_DIR="${DATABASE_PATH:-data/vault.db}"
HEARTBEAT="$(dirname "$DATA_DIR")/heartbeat"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
	echo "supervisor: running (pid $(cat "$PIDFILE"))"
else
	echo "supervisor: not running"
fi

if pgrep -f "node dist/index.js" >/dev/null 2>&1; then
	echo "bot process: running"
else
	echo "bot process: not running"
fi

if [ -f "$HEARTBEAT" ]; then
	age=$(( $(date +%s) - $(stat -c%Y "$HEARTBEAT") ))
	if [ "$age" -lt 180 ]; then
		echo "gateway: connected (heartbeat ${age}s ago)"
	else
		echo "gateway: STALE — heartbeat ${age}s ago (expected under 180s)"
	fi
else
	echo "gateway: no heartbeat file yet"
fi

echo
echo "last log lines:"
tail -n 5 "$ROOT/logs/bot.log" 2>/dev/null || echo "  (no log yet)"
