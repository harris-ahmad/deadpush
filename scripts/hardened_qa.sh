#!/usr/bin/env bash
#
# hardened_qa.sh — end-to-end validation of deadpush HARDENED mode.
#
# Hardened mode makes claims that CI cannot verify (they need root + a real
# service manager): privilege separation, an agent-unkillable daemon, root-
# immutable (schg) hooks, repo ACLs, real-time quarantine, hook self-heal, and a
# clean teardown. This script provisions a THROWAWAY git repo, runs
# `deadpush protect --hardened`, asserts each guarantee against live system
# state, then fully uninstalls and verifies nothing is left behind.
#
# ─ SAFETY ──────────────────────────────────────────────────────────────────
#   * Run as your NORMAL user (NOT root/sudo). The whole point is to prove that
#     a same-UID "agent" cannot defeat the guardian; running as root invalidates
#     every negative test. The script escalates with `sudo` only where needed.
#   * The `_deadpush` account and /var/db/deadpush are SHARED by all hardened
#     repos. To avoid disturbing a real hardened install, this script refuses to
#     run if `_deadpush` already exists (override with --allow-existing, which
#     then will NOT delete the shared account on teardown).
#   * It creates and destroys its own repo and (when it created it) the
#     `_deadpush` account/ACLs. It never touches your current directory.
#
# Usage:
#   scripts/hardened_qa.sh [-y] [--keep] [--allow-existing]
#     -y, --yes         skip the confirmation prompt
#     --keep            don't tear down at the end (for manual inspection)
#     --allow-existing  proceed even if _deadpush already exists (won't delete it)
#
# Env:
#   DEADPUSH   override the deadpush entrypoint (default: auto-detect
#              `deadpush`, else `python3 -m deadpush_bootstrap`).
#
# Exit status: 0 if every check passed, 1 otherwise.

set -uo pipefail  # intentionally NOT -e: we run every check and report a summary

# ── options ─────────────────────────────────────────────────────────────────
ASSUME_YES=0
KEEP=0
ALLOW_EXISTING=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --keep) KEEP=1 ;;
    --allow-existing) ALLOW_EXISTING=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# ── pretty output ─────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLU=$'\033[34m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; DIM=""; RST=""
fi
PASS=0; FAIL=0; FAILED=()
info() { echo "${BLU}==>${RST} $*"; }
warn() { echo "${YEL}!  $*${RST}"; }
pass() { PASS=$((PASS + 1)); echo "  ${GRN}✓${RST} $*"; }
fail() { FAIL=$((FAIL + 1)); FAILED+=("$*"); echo "  ${RED}✗ $*${RST}"; }

# check DESC CMD...        → expects CMD to succeed (exit 0)
check() {
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then pass "$desc"
  else fail "$desc"; [[ -n "$out" ]] && echo "      ${DIM}${out%%$'\n'*}${RST}"; fi
}

# check_fails DESC CMD...  → expects CMD to FAIL (non-zero); used for negatives
check_fails() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$desc (command unexpectedly succeeded)"
  else pass "$desc"; fi
}

# poll SECONDS DESC CMD... → passes as soon as CMD succeeds within SECONDS
poll() {
  local secs="$1" desc="$2"; shift 2
  local i=0
  while (( i < secs )); do
    if "$@" >/dev/null 2>&1; then pass "$desc (after ${i}s)"; return 0; fi
    sleep 1; i=$((i + 1))
  done
  fail "$desc (still failing after ${secs}s)"; return 1
}

OS="$(uname)"

# ── entrypoint detection ──────────────────────────────────────────────────────
detect_deadpush() {
  if [[ -n "${DEADPUSH:-}" ]]; then echo "$DEADPUSH"; return; fi
  if command -v deadpush >/dev/null 2>&1; then echo "deadpush"; return; fi
  if python3 -c 'import deadpush_bootstrap' >/dev/null 2>&1; then echo "python3 -m deadpush_bootstrap"; return; fi
  echo ""
}
DP_CMD="$(detect_deadpush)"
# shellcheck disable=SC2086  # DP_CMD is intentionally word-split
dp() { $DP_CMD "$@"; }

# ── state shared with the cleanup trap ────────────────────────────────────────
REPO=""
CREATED_ACCOUNT=0     # 1 if _deadpush did NOT pre-exist (so we own its lifecycle)
TEARDOWN_DONE=0

acct_exists() { id -u _deadpush >/dev/null 2>&1; }

repo_hooks_present() { [[ -n "$REPO" && -f "$REPO/.git/hooks/pre-push" ]]; }

do_uninstall() {
  [[ -z "$REPO" ]] && return 0
  ( cd "$REPO" && dp uninstall --hardened --force ) >/dev/null 2>&1 || true
}

cleanup() {
  # Safety net: only run if the explicit teardown phase didn't already handle it.
  if [[ "$KEEP" == "1" ]]; then
    warn "--keep set: leaving repo at $REPO and hardened state in place."
    [[ "$CREATED_ACCOUNT" == "1" ]] && warn "Remember: 'cd $REPO && $DP_CMD uninstall --hardened --force' to remove the _deadpush account."
    return
  fi
  if [[ "$TEARDOWN_DONE" != "1" && -n "$REPO" ]]; then
    warn "Emergency cleanup (script exited early)…"
    do_uninstall
  fi
  [[ -n "$REPO" && -d "$REPO" ]] && rm -rf "$REPO" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 — Preflight
# ══════════════════════════════════════════════════════════════════════════════
info "Preflight"

if [[ -z "$DP_CMD" ]]; then
  echo "${RED}error:${RST} could not find the 'deadpush' CLI. Install it (pip install -e .) or set DEADPUSH." >&2
  exit 2
fi
echo "  deadpush entrypoint: ${DIM}${DP_CMD}${RST}"

if [[ "$OS" != "Darwin" && "$OS" != "Linux" ]]; then
  echo "${RED}error:${RST} hardened mode supports macOS and Linux only (found $OS)." >&2
  exit 2
fi

if [[ "$(id -u)" == "0" ]]; then
  echo "${RED}error:${RST} do NOT run this as root. Hardened mode's guarantees are about a" >&2
  echo "       non-root agent; running as root makes every negative test meaningless." >&2
  exit 2
fi

for tool in git sudo pgrep; do
  command -v "$tool" >/dev/null 2>&1 || { echo "${RED}error:${RST} required tool '$tool' not found." >&2; exit 2; }
done
if [[ "$OS" == "Linux" ]]; then
  command -v setfacl >/dev/null 2>&1 || warn "setfacl not found; hardened ACLs need the 'acl' package."
fi

if acct_exists; then
  if [[ "$ALLOW_EXISTING" == "1" ]]; then
    warn "_deadpush already exists — proceeding, but will NOT delete it on teardown."
    CREATED_ACCOUNT=0
  else
    echo "${RED}error:${RST} a '_deadpush' account already exists on this machine." >&2
    echo "       This QA is destructive and would delete the shared account/ACLs on teardown," >&2
    echo "       disrupting any real hardened guardian. Run on a clean machine/VM, or pass" >&2
    echo "       --allow-existing to proceed without deleting it." >&2
    exit 2
  fi
else
  CREATED_ACCOUNT=1
fi

echo
echo "${YEL}This will:${RST}"
echo "  • create a throwaway git repo under \$HOME"
echo "  • run 'deadpush protect --hardened' (creates the _deadpush user, ACLs, a root"
echo "    launchd/systemd daemon, and root-immutable git hooks — requires sudo)"
echo "  • assert the hardened guarantees, then uninstall and verify a clean teardown"
if [[ "$ASSUME_YES" != "1" ]]; then
  read -r -p "Proceed? [y/N] " reply
  [[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "Aborted."; exit 0; }
fi

info "Priming sudo (you may be prompted once)…"
sudo -v || { echo "${RED}error:${RST} sudo is required." >&2; exit 2; }

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Provision a throwaway repo + protect --hardened
# ══════════════════════════════════════════════════════════════════════════════
# Under $HOME so setup also exercises parent-dir traverse ACLs (realistic path).
REPO="$HOME/.deadpush-qa-$$-$RANDOM"
info "Creating throwaway repo: $REPO"
mkdir -p "$REPO"
git -C "$REPO" init -q
git -C "$REPO" config user.email qa@deadpush.local
git -C "$REPO" config user.name "deadpush QA"
printf 'print("hello")\n' > "$REPO/app.py"
git -C "$REPO" add -A
git -C "$REPO" commit -qm "init"

info "Running: deadpush protect --hardened --daemon"
if ! ( cd "$REPO" && dp protect --hardened --daemon ); then
  echo "${RED}error:${RST} 'deadpush protect --hardened' failed; cannot continue." >&2
  exit 1
fi
sleep 3  # let launchd/systemd bring the daemon up

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — Verify the hardened guarantees
# ══════════════════════════════════════════════════════════════════════════════
info "Privilege separation"
check "the _deadpush system account exists" acct_exists
DP_UID="$(id -u _deadpush 2>/dev/null || echo -1)"

guardian_pids() { pgrep -u "$DP_UID" -f "deadpush_bootstrap guard" 2>/dev/null; }
poll 15 "guardian daemon is running as _deadpush" bash -c 'pgrep -u '"$DP_UID"' -f "deadpush_bootstrap guard" >/dev/null'

GPID="$(guardian_pids | head -n1)"
if [[ -n "$GPID" ]]; then
  owner="$(ps -o user= -p "$GPID" | tr -d ' ')"
  check "daemon PID $GPID is owned by _deadpush (got: ${owner:-none})" test "$owner" = "_deadpush"
else
  fail "could not locate a guardian daemon PID"
fi

info "Agent cannot kill the guardian (unkillable daemon)"
if [[ -n "$GPID" ]]; then
  # As the normal user, SIGTERM/SIGKILL against a _deadpush-owned process must be denied.
  check_fails "SIGTERM from agent is rejected (EPERM)" kill -TERM "$GPID"
  check_fails "SIGKILL from agent is rejected (EPERM)" kill -KILL "$GPID"
  check "daemon is still alive after agent's kill attempts" ps -p "$GPID"
fi

info "Daemon respawns after a privileged kill (launchd/systemd KeepAlive)"
if [[ -n "$GPID" ]]; then
  sudo kill -9 $(guardian_pids) 2>/dev/null || true
  sleep 1
  poll 25 "a fresh guardian was respawned" bash -c '
    for p in $(pgrep -u '"$DP_UID"' -f "deadpush_bootstrap guard" 2>/dev/null); do
      [ "$p" != "'"$GPID"'" ] && exit 0
    done
    exit 1'
fi

info "Root-immutable git hooks (agent cannot tamper)"
HOOK="$REPO/.git/hooks/pre-push"
if [[ "$OS" == "Darwin" ]]; then
  check "pre-push hook carries the schg (system-immutable) flag" bash -c "ls -lO '$HOOK' | grep -q schg"
else
  check "pre-push hook carries the immutable (+i) flag" bash -c "lsattr '$HOOK' 2>/dev/null | awk '{print \$1}' | grep -q i"
fi
check_fails "agent cannot delete the pre-push hook" rm -f "$HOOK"
check_fails "agent cannot append to the pre-push hook" bash -c "echo '# tamper' >> '$HOOK'"

info "Repo ACLs grant _deadpush intervention rights"
if [[ "$OS" == "Darwin" ]]; then
  check "repo root has a _deadpush ACL entry" bash -c "ls -led '$REPO' | grep -q _deadpush"
  check "\$HOME has a _deadpush traverse ACL entry" bash -c "ls -led '$HOME' | grep -q _deadpush"
else
  check "repo root has a _deadpush ACL entry" bash -c "getfacl -p '$REPO' 2>/dev/null | grep -q 'user:_deadpush:'"
  check "\$HOME has a _deadpush traverse ACL entry" bash -c "getfacl -p '$HOME' 2>/dev/null | grep -q 'user:_deadpush:'"
fi

info "Real-time enforcement (daemon quarantines dangerous writes)"
printf 'eval(user_input)\n' > "$REPO/qa_violation.py"
poll 20 "dangerous file was quarantined into .deadpush-quarantine" \
  bash -c "ls '$REPO'/.deadpush-quarantine/*qa_violation.py >/dev/null 2>&1"

info "Dangerous content cannot reach a commit (hook + daemon)"
printf 'import os\nos.system("rm -rf /")\n' > "$REPO/qa_commit.py"
( cd "$REPO" && git add qa_commit.py && git commit -qm "try danger" ) >/dev/null 2>&1 || true
check_fails "the dangerous content is NOT present in HEAD" \
  bash -c "git -C '$REPO' show HEAD:qa_commit.py 2>/dev/null | grep -q 'rm -rf'"

info "core.hooksPath hijack self-heal"
git -C "$REPO" config core.hooksPath /dev/null
poll 30 "guardian reset a hijacked core.hooksPath" bash -c "
  v=\$(git -C '$REPO' config --get core.hooksPath 2>/dev/null || true)
  [ -z \"\$v\" ] || [ \"\$(cd '$REPO' && git rev-parse --git-path hooks)\" = \"\$v\" ]"

# ── Tier 0 hardening: hardened interpreter, root-owned policy, control token ──
info "Tier 0: root-owned interpreter, policy, and control-token auth"
# Resolve the repo id deadpush used (match either the literal or realpath form).
POL_ID=""
for cand in "$REPO" "$(cd "$REPO" && pwd -P)"; do
  _id="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$cand")"
  if sudo test -d "/var/db/deadpush/policy/$_id" 2>/dev/null; then POL_ID="$_id"; break; fi
  [[ -z "$POL_ID" ]] && POL_ID="$_id"
done
POL_DIR="/var/db/deadpush/policy/$POL_ID"

# H2 — hooks run the root-owned interpreter, which the agent cannot modify.
check "pre-push hook runs the root-owned hardened interpreter" \
  bash -c "grep -q '/var/db/deadpush/venv/bin/python' '$HOOK'"
check_fails "agent cannot write into the hardened venv (root-owned)" \
  bash -c "touch /var/db/deadpush/venv/qa_tamper"

# H1/H5 — policy + fail-closed marker live in a root-owned dir the agent can't touch.
check "root-owned policy dir exists ($POL_DIR)" test -d "$POL_DIR"
check "root-owned hardened marker exists" test -f "$POL_DIR/installed"
check_fails "agent cannot write into the root-owned policy dir" \
  bash -c "touch '$POL_DIR/qa_tamper'"
check_fails "agent cannot delete the root-owned marker" rm -f "$POL_DIR/installed"

# H1 (functional) — an agent lowering in-repo rules must NOT weaken enforcement.
mkdir -p "$REPO/.deadpush"
printf '{"guardrail_levels":{"security":"off","secret":"off","destructive":"off"}}\n' > "$REPO/.deadpush/rules.json"
printf 'import os\nos.system("rm -rf /")\n' > "$REPO/qa_bypass.py"
( cd "$REPO" && git add qa_bypass.py && git commit -qm "attempt bypass via rules.json" ) >/dev/null 2>&1 || true
check_fails "in-repo rules.json cannot disable enforcement (danger absent from HEAD)" \
  bash -c "git -C '$REPO' show HEAD:qa_bypass.py 2>/dev/null | grep -q 'rm -rf'"

# H2 (functional) — a benign commit must still succeed: this proves the user's
# git hook can actually execute the root-owned hardened interpreter + package.
printf 'x = 1\n' > "$REPO/qa_benign.py"
check "a benign commit still succeeds under the hardened interpreter" \
  bash -c "cd '$REPO' && git add qa_benign.py && git commit -qm 'benign change'"

# H3 — control token is root-only and unauthenticated mutations are rejected.
TOKEN_FILE="/var/db/deadpush/guardian.control.token.$POL_ID"
check "control token file exists (root-owned)" sudo test -f "$TOKEN_FILE"
check_fails "agent cannot read the control token (0600, root-owned)" bash -c "cat '$TOKEN_FILE'"
if command -v curl >/dev/null 2>&1; then
  PORT="$(sudo cat "/var/db/deadpush/guardian.control.port.$POL_ID" 2>/dev/null || true)"
  if [[ -n "$PORT" ]]; then
    CODE="$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/quarantine/restore" -d '{}' 2>/dev/null || true)"
    check "unauthenticated control mutation is rejected (HTTP 401; got ${CODE:-none})" test "$CODE" = "401"
  else
    warn "could not read control port; skipping unauthenticated-mutation check"
  fi
else
  warn "curl not found; skipping unauthenticated-mutation HTTP check"
fi

info "High-level status"
check "'deadpush status --hardened' reports RUNNING" \
  bash -c "cd '$REPO' && $DP_CMD status --hardened 2>&1 | grep -qi running"

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2b — T2 sandbox (Seatbelt / git-wrapper / GPC; platform-dependent)
# ══════════════════════════════════════════════════════════════════════════════
info "T2 sandbox checks"

check "deadpush run --sandbox reports Tier T2" \
  bash -c "cd '$REPO' && $DP_CMD run --sandbox -- echo sandbox_ok 2>&1 | grep -qi 'Tier T2'"

printf 'eval("qa_evil")\n' > "$REPO/qa_gitwrap_evil.py"
( cd "$REPO" && git add qa_gitwrap_evil.py ) >/dev/null 2>&1 || true
check_fails "git-wrapper blocks commit with guardrail violation" \
  bash -c "cd '$REPO' && DEADPUSH_REPO_ROOT='$REPO' $DP_CMD git-wrapper commit -m 'evil' 2>&1 | grep -qi block"

GPC_SOCK="$REPO/.deadpush/gpc.sock"
if [[ "$OS" == "Darwin" ]]; then
  HARD_GPC="/var/db/deadpush/gpc.${POL_ID}.sock"
  if [[ -S "$HARD_GPC" ]]; then
    check "GPC socket present (hardened path)" test -S "$HARD_GPC"
  elif [[ -S "$GPC_SOCK" ]]; then
    check "GPC socket present (repo path)" test -S "$GPC_SOCK"
  else
    warn "GPC socket not found (optional if guardian still starting)"
  fi
else
  if [[ -S "$GPC_SOCK" ]]; then
    check "GPC socket present" test -S "$GPC_SOCK"
  else
    warn "GPC socket not found (optional)"
  fi
fi

if [[ -f "$REPO/.cursor/mcp.json" ]]; then
  check "configure cursor wraps MCP servers with mcp-proxy" \
    bash -c "cd '$REPO' && $DP_CMD configure cursor 2>&1 && grep -q mcp-proxy '$REPO/.cursor/mcp.json'"
fi

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Teardown & verify a clean uninstall
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$KEEP" == "1" ]]; then
  warn "--keep set: skipping teardown verification."
else
  info "Uninstall & verify clean teardown"
  ( cd "$REPO" && dp uninstall --hardened --force ) >/dev/null 2>&1 || true
  TEARDOWN_DONE=1
  sleep 2

  check_fails "no guardian daemon remains" bash -c "pgrep -u '$DP_UID' -f 'deadpush_bootstrap guard' >/dev/null 2>&1"
  check_fails "pre-push hook was removed" test -f "$HOOK"
  if [[ "$CREATED_ACCOUNT" == "1" ]]; then
    check_fails "the _deadpush account was removed" acct_exists
    if [[ "$OS" == "Darwin" ]]; then
      check_fails "repo _deadpush ACL was cleared" bash -c "test -d '$REPO' && ls -led '$REPO' | grep -q _deadpush"
      check_fails "\$HOME _deadpush traverse ACL was cleared" bash -c "ls -led '$HOME' | grep -q _deadpush"
    else
      check_fails "\$HOME _deadpush traverse ACL was cleared" bash -c "getfacl -p '$HOME' 2>/dev/null | grep -q 'user:_deadpush:'"
    fi
  else
    warn "Skipping account/ACL removal checks (_deadpush pre-existed; left intact)."
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
echo
info "Summary: ${GRN}${PASS} passed${RST}, $([[ $FAIL -gt 0 ]] && echo "${RED}${FAIL} failed${RST}" || echo "${FAIL} failed")"
if [[ $FAIL -gt 0 ]]; then
  echo "Failed checks:"
  for f in "${FAILED[@]}"; do echo "  ${RED}✗${RST} $f"; done
  exit 1
fi
echo "${GRN}Hardened mode validated end-to-end.${RST}"
exit 0
