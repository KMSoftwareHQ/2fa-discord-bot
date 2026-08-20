#!/usr/bin/env bash
#
# Start the supervisor if it is not already running.
#
# Idempotent by construction: the supervisor arbitrates with an flock, so
# running this every minute from cron cannot produce a second bot. Safe to call
# as often as you like.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
setsid "$ROOT/scripts/supervise.sh" >/dev/null 2>&1 &
exit 0
