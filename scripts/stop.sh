#!/usr/bin/env bash
#
# Stop the supervisor and the bot. The supervisor forwards SIGTERM to node,
# which shuts down gracefully (closes the database, wipes the key in memory).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDFILE="$ROOT/run/supervisor.pid"

if [ -f "$PIDFILE" ]; then
	pid="$(cat "$PIDFILE")"
	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid"
		echo "Sent SIGTERM to supervisor $pid"
		for _ in $(seq 1 20); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.5
		done
	fi
	rm -f "$PIDFILE"
fi

pkill -TERM -f "node dist/index.js" 2>/dev/null && echo "Stopped bot process"
echo "Stopped."
