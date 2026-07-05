#!/usr/bin/env bash
# scaffold_opencode_demo.sh — create/update deadpush-sandbox for OpenCode + guardian testing
set -euo pipefail

DEADPUSH_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX="${DEADPUSH_SANDBOX:-$HOME/Documents/personal/deadpush-sandbox}"
DP_CMD="$DEADPUSH_ROOT/.venv/bin/deadpush"

if [[ ! -x "$DP_CMD" ]]; then
  echo "Run: cd $DEADPUSH_ROOT && uv sync --extra dev" >&2
  exit 1
fi

mkdir -p "$SANDBOX/src"
cd "$SANDBOX"

if [[ ! -d .git ]]; then
  git init -q
  git config user.email "demo@deadpush.dev"
  git config user.name "Deadpush Demo"
fi

cat > README.md <<'EOF'
# deadpush sandbox demo

Minimal repo for testing deadpush + OpenCode integration.

See **DEMO.md** for terminal commands. The agent prompt is in the chat / AGENT_PROMPT.md
(do not commit prompts containing exploit patterns — guardian will quarantine them).
EOF

cat > DEMO.md <<'EOF'
# deadpush × OpenCode live demo

## Terminals

### Terminal 1 — GPC listener (after protect)
```bash
cd ~/Documents/personal/deadpush-sandbox
~/Documents/personal/deadpush/.venv/bin/deadpush gpc-listen
```

### Terminal 2 — Guardian logs
```bash
tail -f ~/.deadpush/guardian.eb581d839a53.log
```
(Use `deadpush status` to print the exact log path for your repo.)

### Terminal 3 — OpenCode
```bash
cd ~/Documents/personal/deadpush-sandbox
opencode
```

Paste the **agent prompt** from your deadpush chat session (not from a file in this repo).

## Verify after demo
```bash
~/Documents/personal/deadpush/.venv/bin/deadpush verify-audit
~/Documents/personal/deadpush/.venv/bin/deadpush status
~/Documents/personal/deadpush/.venv/bin/deadpush quarantine list
```
EOF

cat > AGENT_PROMPT.md <<'EOF'
# DO NOT SAVE THIS FILE — guardian will quarantine it

Copy the prompt from the deadpush setup chat instead.
EOF

cat > src/app.py <<'EOF'
"""Tiny demo app for deadpush sandbox testing."""


def greet(name: str) -> str:
    return f"Hello, {name}!"


if __name__ == "__main__":
    print(greet("world"))
EOF

cat > deadpush.toml <<'EOF'
[test]
enabled = false
EOF

cat > .gitignore <<'EOF'
.deadpush/
.deadpush-quarantine/
__pycache__/
.venv/
*.pyc
.claudeignore
.cursorignore
.vscode/
EOF

cat > opencode.json <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "mcp": {
    "deadpush": {
      "type": "local",
      "command": ["$DP_CMD", "mcp"],
      "enabled": true
    }
  }
}
EOF

mkdir -p .cursor
cat > .cursor/mcp.json <<EOF
{
  "mcpServers": {
    "deadpush": {
      "command": "$DP_CMD",
      "args": ["mcp"]
    }
  }
}
EOF

git add README.md DEMO.md AGENT_PROMPT.md src/app.py deadpush.toml .gitignore opencode.json .cursor/mcp.json 2>/dev/null || true
git diff --cached --quiet || git commit -qm "update: opencode demo scaffold" || true

echo ""
echo "=== Sandbox ready: $SANDBOX ==="
echo "Run: cd $SANDBOX && $DP_CMD protect --daemon --enable"
echo ""
