#!/bin/bash
# MultiLLM plugin: check for new versions on session start
# Compares local plugin.json version against the latest from GitHub.
# Non-blocking — prints a notice if an update is available, never fails the session.

set -euo pipefail

PLUGIN_DIR="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PLUGIN_JSON="$PLUGIN_DIR/.claude-plugin/plugin.json"
CACHE_DIR="${MULTILLM_HOME:-$HOME/.multillm}"
CACHE_FILE="$CACHE_DIR/.update-check"

# GitHub API (no CDN cache, unlike raw.githubusercontent.com)
REMOTE_URL="https://api.github.com/repos/adibirzu/adibirzu-plugins/contents/plugins/multillm/.claude-plugin/plugin.json"

mkdir -p "$CACHE_DIR"

# ── Read local version ──────────────────────────────────────────────
LOCAL_VERSION=""
if [[ -f "$PLUGIN_JSON" ]]; then
    LOCAL_VERSION=$(python3 -c "import json; print(json.load(open('$PLUGIN_JSON')).get('version',''))" 2>/dev/null || echo "")
fi

if [[ -z "$LOCAL_VERSION" ]]; then
    exit 0
fi

# ── Rate-limit: check at most once per hour ─────────────────────────
if [[ -f "$CACHE_FILE" ]]; then
    LAST_CHECK=$(head -1 "$CACHE_FILE" 2>/dev/null || echo "0")
    NOW=$(date +%s)
    if [[ -n "$LAST_CHECK" ]] && (( NOW - LAST_CHECK < 3600 )); then
        # Show cached result if update was available
        CACHED_REMOTE=$(sed -n '2p' "$CACHE_FILE" 2>/dev/null || echo "")
        if [[ -n "$CACHED_REMOTE" && "$CACHED_REMOTE" != "$LOCAL_VERSION" ]]; then
            echo "MultiLLM update available: $LOCAL_VERSION -> $CACHED_REMOTE  (cd \"$(dirname "$PLUGIN_DIR")\" && git pull)" >&2
        fi
        exit 0
    fi
fi

# ── Fetch remote version (2s timeout, silent on failure) ────────────
# Use GitHub API + base64 decode to avoid CDN cache
REMOTE_VERSION=$(curl -sf --max-time 2 \
    -H "Accept: application/vnd.github.v3+json" \
    "$REMOTE_URL" 2>/dev/null \
    | python3 -c "
import sys, json, base64
try:
    data = json.load(sys.stdin)
    content = base64.b64decode(data['content']).decode()
    parsed = json.loads(content)
    print(parsed.get('version', ''))
except Exception:
    print('')
" 2>/dev/null || echo "")

# Save timestamp + remote version for rate-limiting
printf '%s\n%s\n' "$(date +%s)" "$REMOTE_VERSION" > "$CACHE_FILE"

if [[ -z "$REMOTE_VERSION" ]]; then
    exit 0
fi

# ── Compare versions ────────────────────────────────────────────────
if [[ "$REMOTE_VERSION" != "$LOCAL_VERSION" ]]; then
    # Simple tuple-based semver comparison (no external deps)
    HIGHER=$(python3 -c "
local = tuple(int(x) for x in '$LOCAL_VERSION'.split('.'))
remote = tuple(int(x) for x in '$REMOTE_VERSION'.split('.'))
print('yes' if remote > local else 'no')
" 2>/dev/null || echo "yes")

    if [[ "$HIGHER" == "yes" ]]; then
        echo "MultiLLM update available: $LOCAL_VERSION -> $REMOTE_VERSION  (cd \"$(dirname "$PLUGIN_DIR")\" && git pull)" >&2
    fi
fi

exit 0
