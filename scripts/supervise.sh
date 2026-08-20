#!/usr/bin/env bash
#
# Self-restarting, self-arbitrating supervisor for the 2FA vault bot.
#
# Singleton guarantee: on startup we grab a non-blocking flock and HOLD it for
# our entire lifetime (fd 9 stays open). If another supervisor already holds it
# we exit immediately. Because exactly one process can hold an flock, launching
# many supervisors concurrently still results in just one survivor — no pidfiles
# or timing windows involved. The node child inherits the lock too, so if this
# supervisor is hard-killed while node lives on, the lock stays held and the
# watchdog will not start a conflicting second bot.
#
# Two bots on one vault would double-count rate limits and interleave audit
# rows, so the singleton property is a correctness requirement, not tidiness.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# Cron gives a bare PATH; make sure the user-local node is reachable.
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

RUN_DIR="$ROOT/run"
LOG_DIR="$ROOT/logs"
mkdir -p "$RUN_DIR" "$LOG_DIR"
LOCK="$RUN_DIR/supervisor.lock"
PIDFILE="$RUN_DIR/supervisor.pid"
LOG="$LOG_DIR/bot.log"
MAX_LOG=10485760   # 10 MB

# --- Singleton election ------------------------------------------------
exec 9>>"$LOCK"
if ! flock -n 9; then
	exit 0   # another supervisor is already running
fi

NODE="${VAULT_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ ! -x "$NODE" ]; then
	echo "supervise: node not found on PATH; set VAULT_NODE=/path/to/node" >&2
	exit 1
fi
echo $$ > "$PIDFILE"

if [ ! -f "$ROOT/dist/index.js" ]; then
	echo "supervise: dist/index.js missing — run 'npm run build' first" >&2
	exit 1
fi

child=""
cleanup() {
	[ -n "$child" ] && kill -TERM "$child" 2>/dev/null
	rm -f "$PIDFILE"
	exit 0
}
trap cleanup SIGTERM SIGINT

rotate_log() {
	if [ -f "$LOG" ] && [ "$(stat -c%s "$LOG" 2>/dev/null || echo 0)" -gt "$MAX_LOG" ]; then
		mv -f "$LOG" "$LOG.1"
	fi
}

backoff=1
while true; do
	rotate_log
	start=$(date +%s)
	"$NODE" dist/index.js >>"$LOG" 2>&1 &
	child=$!
	wait "$child"
	code=$?
	child=""
	elapsed=$(( $(date +%s) - start ))

	# A clean exit is a deliberate shutdown; do not fight it.
	if [ "$code" -eq 0 ]; then
		echo "$(date -Is) bot exited cleanly" >>"$LOG"
		break
	fi

	# Ran long enough to be healthy? Then this is a fresh fault, not a loop.
	if [ "$elapsed" -ge 60 ]; then
		backoff=1
	fi

	echo "$(date -Is) bot exited with $code after ${elapsed}s; restarting in ${backoff}s" >>"$LOG"
	sleep "$backoff"
	backoff=$(( backoff * 2 ))
	[ "$backoff" -gt 30 ] && backoff=30
done

rm -f "$PIDFILE"
