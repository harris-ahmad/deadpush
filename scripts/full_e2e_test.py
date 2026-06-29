#!/usr/bin/env python3
"""
Guardian E2E test script for deadpush.

Automates validation of the AI Agent Guardian in a target repository:
- protect / doctor / status
- Background guardian + filesystem interventions
- Quarantine list
- Pre-push hook blocking
- MCP enforce_content kernel (same as write_file)

Usage:
  cd /path/to/your/repo
  python /path/to/deadpush/scripts/full_e2e_test.py --repo-dir . --simulate-agent

Use a git clone or copy of your repo for first runs.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

DEADPUSH_CMD = "deadpush"
SANDBOX = "e2e-test-sandbox"
PIDFILE = Path.home() / ".deadpush" / "guardian.log".parent / "guardian.pid"
LOGFILE = Path.home() / ".deadpush" / "guardian.log"
TIMEOUT = 30
POLL_INTERVAL = 0.5

DANGEROUS_FILES = [
    "claude.md", ".cursorrules", "agents.md", "windsurf_rules.md",
    "llm_context.txt", "temp-agent-output.py",
]

SECRET_FILES = [
    (".env.test", "OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef\n"),
    ("config.secret.json", '{"api_key": "sk_live_abcdefghijklmnopqrstuvwxyz"}'),
]


def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def kill_guardian() -> None:
    try:
        if PIDFILE.exists():
            pid = int(PIDFILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            PIDFILE.unlink(missing_ok=True)
    except Exception as e:
        print(f"[warn] Error killing guardian: {e}")
    subprocess.run(["pkill", "-f", "deadpush.*guard"], check=False)


def wait_for_file(path: Path, timeout: int = TIMEOUT) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if path.exists():
            return True
        time.sleep(0.5)
    return False


def get_status() -> str:
    res = run_cmd([DEADPUSH_CMD, "status"])
    return (res.stdout or "") + (res.stderr or "")


def get_quarantine_list() -> str:
    res = run_cmd([DEADPUSH_CMD, "quarantine", "list"])
    return res.stdout or ""


def tail_log(n: int = 20) -> str:
    if LOGFILE.exists():
        return "\n".join(LOGFILE.read_text(errors="ignore").splitlines()[-n:])
    return "(no log yet)"


def poll_for_reaction(timeout: int = 25) -> bool:
    print(f"[poll] Waiting up to {timeout}s for guardian reactions...")
    start = time.time()
    while time.time() - start < timeout:
        log = tail_log(25)
        qlist = get_quarantine_list()
        if "INTERVENTION" in log or "QUARANTINED" in log or "Quarantined Name" in qlist:
            print("[poll] Reaction detected.")
            print(log[-600:] if len(log) > 600 else log)
            return True
        time.sleep(POLL_INTERVAL)
    print("[poll] No reaction detected within timeout.")
    return False


def simulate_agent_activity(repo: Path, burst: bool = False) -> None:
    sandbox = repo / SANDBOX
    sandbox.mkdir(parents=True, exist_ok=True)
    print("\n=== Simulating agent file writes ===")
    for name in DANGEROUS_FILES:
        fpath = sandbox / name
        fpath.write_text(f"# agent write {name}\nupdated {time.time()}\n")
        print(f"  wrote {fpath}")
    for name, content in SECRET_FILES:
        fpath = sandbox / name
        fpath.write_text(content)
        print(f"  wrote {fpath}")
    if burst:
        for i in range(6):
            (sandbox / f"burst-{i}.py").write_text(f"eval('x{i}')\n")
            time.sleep(0.15)
    time.sleep(2)


def test_enforce_kernel(repo: Path) -> bool:
    """Run enforce_content checks (same kernel as MCP write_file)."""
    print("\n=== MCP kernel (enforce_content) smoke test ===")
    script = f"""
import sys
sys.path.insert(0, {repr(str(Path(__file__).resolve().parent.parent))})
from pathlib import Path
from deadpush.config import load_config
from deadpush.intercept import enforce_content

config = load_config(explicit_root=Path({repr(str(repo))}))

cases = [
    ("CLAUDE.md", "# instructions", False),
    ("debug.py", "import subprocess\\nsubprocess.run('ls', shell=True)\\n", False),
    ("hello.py", "x = 1\\n", True),
]
ok = True
for path, content, should_pass in cases:
    r = enforce_content(path, content, config)
    if r.allowed != should_pass:
        print(f"FAIL {{path}}: expected allowed={{should_pass}}, got {{r.allowed}}")
        ok = False
    else:
        print(f"  OK {{path}} -> allowed={{r.allowed}}")
sys.exit(0 if ok else 1)
"""
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    print(res.stdout)
    if res.returncode != 0:
        print(res.stderr)
    return res.returncode == 0


def test_prepush_hook(repo: Path) -> bool:
    print("\n=== Pre-push hook test ===")
    hook = repo / ".git" / "hooks" / "pre-push"
    if not hook.exists():
        print("[hook] No pre-push hook — run protect first.")
        return False
    bad = repo / SANDBOX / "hook-test-claude.md"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("# should block\n")
    try:
        run_cmd(["git", "checkout", "-b", "e2e-hook-test"], cwd=repo)
        run_cmd(["git", "add", str(bad)], cwd=repo)
        run_cmd(["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad"], cwd=repo)
        res = run_cmd(["python3", str(hook), "origin", "main"], cwd=repo, timeout=60)
        blocked = res.returncode != 0
        print(f"[hook] exit={res.returncode}, blocked={blocked}")
        run_cmd(["git", "reset", "--hard", "HEAD~1"], cwd=repo)
        run_cmd(["git", "checkout", "-"], cwd=repo)
        run_cmd(["git", "branch", "-D", "e2e-hook-test"], cwd=repo)
        bad.unlink(missing_ok=True)
        return blocked
    except Exception as e:
        print(f"[hook] error: {e}")
        run_cmd(["git", "checkout", "-"], cwd=repo)
        return False


def cleanup_sandbox(repo: Path) -> None:
    sandbox = repo / SANDBOX
    if sandbox.exists():
        shutil.rmtree(sandbox, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian E2E test for deadpush")
    parser.add_argument("--repo-dir", default=".", help="Repo to test in")
    parser.add_argument("--simulate-agent", action="store_true", help="Write dangerous test files")
    parser.add_argument("--burst", action="store_true", help="Burst of bad writes")
    parser.add_argument("--no-clean", action="store_true", help="Leave guardian running and sandbox in place")
    args = parser.parse_args()

    repo = Path(args.repo_dir).resolve()
    if not repo.exists():
        print(f"ERROR: {repo} does not exist")
        sys.exit(1)

    print(f"=== deadpush Guardian E2E ===\nRepo: {repo}\nTime: {datetime.now().isoformat()}\n")

    res = run_cmd([DEADPUSH_CMD, "--version"])
    if res.returncode != 0:
        print("ERROR: deadpush not in PATH. Activate venv and pip install -e .")
        sys.exit(1)
    print(f"Version: {res.stdout.strip()}")

    kill_guardian()
    cleanup_sandbox(repo)

    results: dict[str, bool] = {}

    print("\n=== 1. deadpush protect ===")
    run_cmd([DEADPUSH_CMD, "protect"], cwd=repo, timeout=120)

    print("\n=== 2. deadpush doctor ===")
    doc = run_cmd([DEADPUSH_CMD, "doctor"], cwd=repo, timeout=60)
    results["doctor"] = doc.returncode == 0
    print(doc.stdout[-800:] if doc.stdout else "")

    results["enforce_kernel"] = test_enforce_kernel(repo)
    results["prepush_hook"] = test_prepush_hook(repo) if (repo / ".git").exists() else False

    sandbox = repo / SANDBOX
    sandbox.mkdir(parents=True, exist_ok=True)
    for name in DANGEROUS_FILES[:3]:
        (sandbox / name).write_text("# prep\n")

    print("\n=== 3. deadpush protect --daemon ===")
    run_cmd([DEADPUSH_CMD, "protect", "--daemon"], cwd=repo, timeout=30)
    wait_for_file(PIDFILE, timeout=15)

    print("\n=== 4. deadpush status ===")
    print(get_status()[:1500])

    if args.simulate_agent:
        simulate_agent_activity(repo, burst=args.burst)
        results["guardian_reaction"] = poll_for_reaction(timeout=25)
        print("\n=== 5. quarantine list ===")
        print(get_quarantine_list())

    if not args.no_clean:
        print("\n=== 6. stop guardian ===")
        kill_guardian()
        cleanup_sandbox(repo)

    print("\n" + "=" * 60)
    print("RESULTS")
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print("=" * 60)

    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
