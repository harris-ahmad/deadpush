"""Regression tests for the Tier-0 hardened-mode security fixes (H1-H5).

These lock in the behaviors that make hardened mode a real boundary against a
same-UID adversarial agent:

- H1: enforcement reads guardrail policy from the root-owned dir, so editing
  in-repo `.deadpush/rules.json` / `learned_patterns.json` cannot weaken it.
- H2: hardened git hooks execute the root-owned hardened interpreter, not the
  user's (agent-writable) interpreter/package.
- H3: the guardian control server enforces a bearer token on mutations.
- H4: quarantine restore is confined to the repo tree (no arbitrary writes).
- H5: fail-closed also honors a root-owned marker (covered via H1 marker tests).

Everything here runs without root by redirecting the hardened roots to a temp
dir; the true end-to-end guarantees are validated by scripts/hardened_qa.sh.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deadpush import config, hooks  # noqa: E402
from deadpush.rules import RuntimeConfig  # noqa: E402


@pytest.fixture
def hardened_roots(tmp_path, monkeypatch):
    """Redirect the hardened state/policy/venv roots into a temp dir."""
    state = tmp_path / "var_db_deadpush"
    monkeypatch.setattr(config, "HARDENED_STATE_DIR", state)
    monkeypatch.setattr(config, "HARDENED_POLICY_ROOT", state / "policy")
    monkeypatch.setattr(config, "HARDENED_VENV_DIR", state / "venv")
    return state


def _mark_hardened(repo: Path) -> Path:
    """Create the trustworthy root-owned marker for a repo and return the dir."""
    hp = config.hardened_policy_dir(repo)
    hp.mkdir(parents=True, exist_ok=True)
    (hp / "installed").write_text('{"mode": "hardened"}', encoding="utf-8")
    return hp


# ---------------------------------------------------------------------------
# H1 — policy is read from the root-owned dir in hardened mode
# ---------------------------------------------------------------------------
class TestHardenedPolicyLocation:
    def test_soft_uses_in_repo_policy(self, hardened_roots, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".deadpush").mkdir(parents=True)
        assert config.is_hardened_install(repo) is False
        assert config.policy_dir(repo) == repo / ".deadpush"
        assert RuntimeConfig(repo).rules_path == repo / ".deadpush" / "rules.json"

    def test_hardened_marker_switches_policy_dir(self, hardened_roots, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".deadpush").mkdir(parents=True)
        hp = _mark_hardened(repo)
        assert config.is_hardened_install(repo) is True
        assert config.policy_dir(repo) == hp
        assert RuntimeConfig(repo).rules_path == hp / "rules.json"

    def test_agent_inrepo_rules_ignored_when_hardened(self, hardened_roots, tmp_path):
        """The core H1 guarantee: an agent turning guardrails off in-repo is ignored."""
        repo = tmp_path / "repo"
        (repo / ".deadpush").mkdir(parents=True)
        # Agent tries to disable enforcement via the in-repo file.
        (repo / ".deadpush" / "rules.json").write_text(
            json.dumps({"guardrail_levels": {"security": "off", "secret": "off"}}),
            encoding="utf-8",
        )
        _mark_hardened(repo)  # root-owned policy dir has no rules.json -> defaults
        rc = RuntimeConfig(repo)
        assert rc.get_guardrail_level("security") == "block"
        assert rc.get_guardrail_level("secret") == "block"

    def test_agent_inrepo_learned_patterns_ignored_when_hardened(
        self, hardened_roots, tmp_path, monkeypatch
    ):
        import deadpush.intercept as intercept
        monkeypatch.setattr(intercept, "_LEARNED_PATTERNS", None)
        repo = tmp_path / "repo"
        (repo / ".deadpush").mkdir(parents=True)
        # Agent seeds an in-repo suppression of a dangerous pattern.
        (repo / ".deadpush" / "learned_patterns.json").write_text(
            json.dumps({"patterns": [{"pattern": "Shell command execution"}]}),
            encoding="utf-8",
        )
        _mark_hardened(repo)
        learned = intercept._load_learned_patterns(repo)
        assert learned == {"patterns": [], "suppressed_categories": {}}


# ---------------------------------------------------------------------------
# H2 — hardened hooks execute the root-owned interpreter
# ---------------------------------------------------------------------------
class TestHardenedHookInterpreter:
    @pytest.fixture(autouse=True)
    def _noop_immutability(self, monkeypatch):
        # Keep temp hook files removable (no chflags/chattr in unit tests).
        monkeypatch.setattr(hooks, "_make_immutable", lambda p, system=False: True)
        monkeypatch.setattr(hooks, "_make_mutable", lambda p, system=False: True)

    def test_system_hook_embeds_hardened_python(self, hardened_roots, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        hooks.install_hook(repo, system=True)
        content = (repo / ".git" / "hooks" / "pre-push").read_text()
        assert str(config.hardened_python()) in content
        assert "deadpush_bootstrap" in content
        # Must NOT fall back to the user interpreter in hardened mode.
        assert sys.executable not in content

    def test_soft_hook_embeds_user_python(self, hardened_roots, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        hooks.install_hook(repo, system=False)
        content = (repo / ".git" / "hooks" / "pre-push").read_text()
        assert sys.executable in content
        assert str(config.hardened_python()) not in content

    def test_repair_preserves_hardened_system_flag(self, hardened_roots, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        _mark_hardened(repo)
        captured = {}

        def fake_install(rr, *, system=False):
            captured["system"] = system

        monkeypatch.setattr(hooks, "install_hook", fake_install)
        monkeypatch.setattr(hooks, "install_precommit_hook", lambda rr, *, system=False: None)
        monkeypatch.setattr(hooks, "install_postcommit_hook", lambda rr, *, system=False: None)
        monkeypatch.setattr(hooks, "verify_hooks_installed", lambda rr: ["pre-push (missing)"])
        monkeypatch.setattr(hooks, "detect_hookspath_hijack", lambda rr: None)
        hooks.repair_deadpush_hooks(repo)  # system auto-detected from hardened marker
        assert captured.get("system") is True


# ---------------------------------------------------------------------------
# H3 — control server enforces a bearer token on mutations
# ---------------------------------------------------------------------------
class TestControlServerAuth:
    def test_token_created_with_0600(self, tmp_path, monkeypatch):
        import deadpush.guard as guard
        tf = tmp_path / "control.token"
        monkeypatch.setattr(guard, "_scoped_token_file", lambda r, h=False: tf)
        tok = guard._load_or_create_control_token(tmp_path, hardened=True)
        assert tok
        assert tf.exists()
        assert (tf.stat().st_mode & 0o777) == 0o600
        # Stable across calls.
        assert guard._load_or_create_control_token(tmp_path, hardened=True) == tok

    def test_verify_token_required_when_set(self):
        import deadpush.guard as guard
        H = guard.GuardianControlHandler
        fake = types.SimpleNamespace(
            control_server=types.SimpleNamespace(token="s3cret"), headers={}
        )
        assert H._verify_token(fake) is False
        fake.headers = {"Authorization": "Bearer s3cret"}
        assert H._verify_token(fake) is True
        fake.headers = {"Authorization": "Bearer wrong"}
        assert H._verify_token(fake) is False

    def test_verify_token_open_when_unset(self):
        import deadpush.guard as guard
        fake = types.SimpleNamespace(
            control_server=types.SimpleNamespace(token=None), headers={}
        )
        assert guard.GuardianControlHandler._verify_token(fake) is True

    def test_server_requires_auth_when_token_given(self, tmp_path):
        import deadpush.guard as guard
        cs = guard.GuardianControlServer(
            guardian_handler=None, repo_root=tmp_path, token="abc"
        )
        assert cs.require_auth is True
        assert cs.token == "abc"


# ---------------------------------------------------------------------------
# H4 — quarantine restore is confined to the repo tree
# ---------------------------------------------------------------------------
class TestQuarantineRestoreConfinement:
    def _seed(self, repo: Path, name: str, original: str):
        import deadpush.guard as guard
        qm = guard.QuarantineManager(repo)
        q = qm.quarantine_dir
        (q / name).write_text("payload", encoding="utf-8")
        (q / f"{name}.reason").write_text(f"Original path: {original}\n", encoding="utf-8")
        return qm

    def test_restore_outside_repo_refused(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "outside_evil.py"  # sibling of repo -> outside repo_root
        qm = self._seed(repo, "20200101_000000_evil.py", str(outside))
        result = qm.restore("20200101_000000_evil.py")
        assert result is None
        assert not outside.exists()
        # Quarantined file stays put (not moved out).
        assert (qm.quarantine_dir / "20200101_000000_evil.py").exists()

    def test_restore_inside_repo_allowed(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        target = repo / "src" / "ok.py"
        qm = self._seed(repo, "20200101_000000_ok.py", str(target))
        result = qm.restore("20200101_000000_ok.py")
        assert result == target.resolve()
        assert target.exists()

    def test_restore_traversal_escape_refused(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        escape = f"{repo}/../outside_traversal.py"
        qm = self._seed(repo, "20200101_000000_esc.py", escape)
        result = qm.restore("20200101_000000_esc.py")
        assert result is None
        assert not (tmp_path / "outside_traversal.py").exists()
