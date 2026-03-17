#!/bin/bash
# MultiLLM plugin: check for new versions on session start
# Compares local plugin.json version against the latest from GitHub.
# Non-blocking — prints a notice if an update is available, never fails the session.

set -euo pipefail

PLUGIN_DIR="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PLUGIN_JSON="$PLUGIN_DIR/.claude-plugin/plugin.json"
CACHE_DIR="${MULTILLM_HOME:-$HOME/.multillm}"
CACHE_FILE="$CACHE_DIR/.update-check"
REPO_RAW="https://raw.githubusercontent.com/adibirzu/multillm/main/skills/llm-orchestrator/agents/openai.yaml"
REMOTE_PLUGIN_JSON="https://raw.githubusercontent.com/adibirzu/adibirzu-plugins/main/plugins/multillm/.claude-plugin/plugin.json"

mkdir -p "$CACHE_DIR"

# ── Read local version ──────────────────────────────────────────────
LOCAL_VERSION=""
if [[ -f "$PLUGIN_JSON" ]]; then
    LOCAL_VERSION=$(python3 -c "import json; print(json.load(open('$PLUGIN_JSON')).get('version','unknown'))" 2>/dev/null || echo "unknown")
fi

if [[ -z "$LOCAL_VERSION" || "$LOCAL_VERSION" == "unknown" ]]; then
    exit 0
fi

# ── Rate-limit: check at most once per hour ─────────────────────────
if [[ -f "$CACHE_FILE" ]]; then
    LAST_CHECK=$(cat "$CACHE_FILE" 2>/dev/null | head -1)
    NOW=$(date +%s)
    if [[ -n "$LAST_CHECK" ]] && (( NOW - LAST_CHECK < 3600 )); then
        # Show cached result if update was available
        CACHED_REMOTE=$(sed -n '2p' "$CACHE_FILE" 2>/dev/null)
        if [[ -n "$CACHED_REMOTE" && "$CACHED_REMOTE" != "$LOCAL_VERSION" ]]; then
            echo "⬆ MultiLLM update available: $LOCAL_VERSION → $CACHED_REMOTE (run: cd $PLUGIN_DIR && git pull)" >&2
        fi
        exit 0
    fi
fi

# ── Fetch remote version (2s timeout, silent on failure) ────────────
REMOTE_VERSION=$(curl -sf --max-time 2 "$REMOTE_PLUGIN_JSON" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',''))" 2>/dev/null \
    || echo "")

# Save timestamp + remote version for rate-limiting
echo "$(date +%s)" > "$CACHE_FILE"
echo "$REMOTE_VERSION" >> "$CACHE_FILE"

if [[ -z "$REMOTE_VERSION" ]]; then
    exit 0
fi

# ── Compare versions ────────────────────────────────────────────────
if [[ "$REMOTE_VERSION" != "$LOCAL_VERSION" ]]; then
    # Semantic version comparison: is remote > local?
    HIGHER=$(python3 -c "
from packaging.version import Version
try:
    print('yes' if Version('$REMOTE_VERSION') > Version('$LOCAL_VERSION') else 'no')
except Exception:
    # Fallback: simple string comparison
    print('yes' if '$REMOTE_VERSION' != '$LOCAL_VERSION' else 'no')
" 2>/dev/null || echo "yes")

    if [[ "$HIGHER" == "yes" ]]; then
        echo "⬆ MultiLLM update available: $LOCAL_VERSION → $REMOTE_VERSION" >&2
        echo "  Run: cd $(dirname "$PLUGIN_DIR") && git pull" >&2
    fi
fi

exit 0
