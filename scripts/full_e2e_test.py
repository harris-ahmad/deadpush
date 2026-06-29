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
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SANDBOX = "e2e-test-sandbox"
DEADPUSH_STATE = Path.home() / ".deadpush"
LOGFILE = DEADPUSH_STATE / "guardian.log"
TIMEOUT = 30
POLL_INTERVAL = 0.5

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from deadpush.config import is_guardian_dev_repo  # noqa: E402
from deadpush.guard import _scoped_pidfile  # noqa: E402


def subprocess_env() -> dict[str, str]:
    """Ensure child processes can import deadpush from this checkout."""
    env = os.environ.copy()
    root = str(REPO_ROOT)
    prev = env.get("PYTHONPATH", "")
    parts = [p for p in prev.split(os.pathsep) if p]
    if root not in parts:
        parts.insert(0, root)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def resolve_deadpush_cmd() -> list[str]:
    """Find deadpush CLI: venv bin, PATH, or python -m fallback."""
    venv_bin = Path(sys.executable).resolve().parent / "deadpush"
    if venv_bin.is_file():
        return [str(venv_bin)]
    on_path = shutil.which("deadpush")
    if on_path:
        return [on_path]
    return [sys.executable, "-m", "deadpush.cli"]


def pidfile_for(repo: Path) -> Path:
    return _scoped_pidfile(repo.resolve())


DANGEROUS_FILES = [
    "claude.md", ".cursorrules", "agents.md", "windsurf_rules.md",
    "llm_context.txt", "temp-agent-output.py",
]

def _e2e_fake_api_key() -> str:
    """Build a fake key at runtime so the E2E script itself passes pre-commit."""
    return "sk-" + "a" * 32


SECRET_FILES = [
    (".env.test", lambda: f"OPENAI_API_KEY={_e2e_fake_api_key()}\n"),
    ("config.secret.json", lambda: '{"api_key": "' + "b" * 24 + '"}'),
]


def run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    input: str | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
        env=subprocess_env(), input=input,
    )


def deadpush_cmd(
    *args: str,
    repo: Path | None = None,
    timeout: int | None = 120,
    input: str | None = None,
) -> subprocess.CompletedProcess:
    cmd = resolve_deadpush_cmd() + list(args)
    return run_cmd(cmd, cwd=repo, timeout=timeout, input=input)


def kill_guardian(repo: Path) -> None:
    """Stop guardian for this repo only (no global pkill)."""
    deadpush_cmd("stop", repo=repo)


def wait_for_file(path: Path, timeout: int = TIMEOUT) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if path.exists():
            return True
        time.sleep(0.5)
    return False


def get_status(repo: Path) -> str:
    res = deadpush_cmd("status", repo=repo)
    return (res.stdout or "") + (res.stderr or "")


def get_quarantine_list(repo: Path) -> str:
    res = deadpush_cmd("quarantine", "list", repo=repo)
    return res.stdout or ""


def tail_log(n: int = 20) -> str:
    if LOGFILE.exists():
        return "\n".join(LOGFILE.read_text(errors="ignore").splitlines()[-n:])
    return "(no log yet)"


def poll_for_reaction(repo: Path, timeout: int = 25) -> bool:
    print(f"[poll] Waiting up to {timeout}s for guardian reactions...")
    start = time.time()
    while time.time() - start < timeout:
        log = tail_log(25)
        qlist = get_quarantine_list(repo)
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
    for name, content_fn in SECRET_FILES:
        fpath = sandbox / name
        fpath.write_text(content_fn())
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
sys.path.insert(0, {repr(str(REPO_ROOT))})
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
    res = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=subprocess_env(),
    )
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
    bad = repo / SANDBOX / "claude.md"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("# should block\n")
    branch = "e2e-hook-test"
    prev_branch = run_cmd(["git", "branch", "--show-current"], cwd=repo).stdout.strip()
    try:
        run_cmd(["git", "checkout", "-B", branch], cwd=repo)
        run_cmd(["git", "add", str(bad)], cwd=repo)
        run_cmd(["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "bad"], cwd=repo)
        head = run_cmd(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()
        zero = "0" * 40
        stdin = f"refs/heads/{branch} {head} refs/heads/main {zero}\n"
        res = deadpush_cmd("hooks", "run-prepush", repo=repo, input=stdin, timeout=30)
        blocked = res.returncode != 0
        print(f"[hook] exit={res.returncode}, blocked={blocked}")
        if res.stdout:
            print(res.stdout.strip()[-500:])
        run_cmd(["git", "reset", "--hard", "HEAD~1"], cwd=repo)
        if prev_branch:
            run_cmd(["git", "checkout", prev_branch], cwd=repo)
        run_cmd(["git", "branch", "-D", branch], cwd=repo)
        bad.unlink(missing_ok=True)
        return blocked
    except Exception as e:
        print(f"[hook] error: {e}")
        if prev_branch:
            run_cmd(["git", "checkout", prev_branch], cwd=repo)
        run_cmd(["git", "branch", "-D", branch], cwd=repo)
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
    parser.add_argument(
        "--allow-self-test",
        action="store_true",
        help="Allow running against the deadpush source repo (guardian will quarantine files here)",
    )
    args = parser.parse_args()

    repo = Path(args.repo_dir).resolve()
    if not repo.exists():
        print(f"ERROR: {repo} does not exist")
        sys.exit(1)

    if is_guardian_dev_repo(repo) and not args.allow_self_test:
        print("ERROR: Refusing to run E2E against the deadpush source repo.")
        print("Protecting this repo will quarantine/revert your working tree (including this script).")
        print("Use a throwaway clone instead:")
        print("  git clone . /tmp/deadpush-e2e && python3 scripts/full_e2e_test.py --repo-dir /tmp/deadpush-e2e --simulate-agent")
        sys.exit(1)

    print(f"=== deadpush Guardian E2E ===\nRepo: {repo}\nTime: {datetime.now().isoformat()}\n")

    try:
        import deadpush
        print(f"Version: deadpush {deadpush.__version__}")
    except ImportError:
        res = deadpush_cmd("--version")
        if res.returncode != 0:
            print("ERROR: deadpush not found. Run: pip install -e .")
            if res.stderr:
                print(res.stderr.strip())
            sys.exit(1)
        print(f"Version: {res.stdout.strip()}")

    kill_guardian(repo)
    cleanup_sandbox(repo)

    results: dict[str, bool] = {}

    print("\n=== 1. deadpush protect ===")
    deadpush_cmd("protect", repo=repo)

    print("\n=== 2. deadpush doctor ===")
    doc = deadpush_cmd("doctor", repo=repo)
    results["doctor"] = doc.returncode == 0
    print(doc.stdout[-800:] if doc.stdout else "")

    results["enforce_kernel"] = test_enforce_kernel(repo)
    results["prepush_hook"] = test_prepush_hook(repo) if (repo / ".git").exists() else False

    sandbox = repo / SANDBOX
    sandbox.mkdir(parents=True, exist_ok=True)
    for name in DANGEROUS_FILES[:3]:
        (sandbox / name).write_text("# prep\n")

    print("\n=== 3. deadpush protect --daemon ===")
    deadpush_cmd("protect", "--daemon", repo=repo)
    wait_for_file(pidfile_for(repo), timeout=15)

    print("\n=== 4. deadpush status ===")
    print(get_status(repo)[:1500])

    if args.simulate_agent:
        simulate_agent_activity(repo, burst=args.burst)
        results["guardian_reaction"] = poll_for_reaction(repo, timeout=25)
        print("\n=== 5. quarantine list ===")
        print(get_quarantine_list(repo))

    if not args.no_clean:
        print("\n=== 6. stop guardian ===")
        kill_guardian(repo)
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
