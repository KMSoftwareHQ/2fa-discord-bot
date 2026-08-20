#!/usr/bin/env bash
# Remove only this project's tagged crontab entries.
set -euo pipefail
TAG="# 2fa-vault-managed"
current="$(crontab -l 2>/dev/null || true)"
printf '%s\n' "$current" | grep -vF "$TAG" | sed '/^$/d' | crontab -
echo "Removed managed cron entries."
