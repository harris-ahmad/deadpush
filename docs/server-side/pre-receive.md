# Server-side enforcement with a `pre-receive` hook

The client-side deadpush layers (pre-commit / pre-push hooks and the guardian
daemon) all run on the developer's machine, so a determined agent can bypass them
with `git push --no-verify`, git plumbing, or by killing the daemon. A
**`pre-receive` hook runs on the git server**, off the developer's machine, so a
push carrying secrets or dangerous code is rejected no matter what happened
locally. This is the only *fully uncircumventable* enforcement point for
self-hosted git (bare repos, Gitea, GitLab).

> Hosted GitHub/GitLab.com don't let you install custom `pre-receive` hooks on
> individual repos. There, use the GitHub Actions check instead
> (`examples/github/deadpush.yml`) plus branch protection.

## What it does

`deadpush hooks run-prereceive` reads the ref updates git delivers on stdin
(`<old-value> <new-value> <ref-name>`), and for each updated ref scans the
incoming commits:

- Existing branch: diffs `old..new` (the server's current tip is a trustworthy
  boundary the client cannot forge).
- New branch/ref (`old` is all zeros): scans the **entire pushed tree**, so the
  boundary cannot be poisoned.
- Branch deletion (`new` is all zeros): nothing to scan.

If any incoming file has a block-level violation, the hook exits non-zero and git
rejects the **entire push** (atomic — no refs are updated).

## Install on a bare repo

```bash
# On the git server, as the user the git service runs as:
pip install deadpush

# For each repository you want to protect:
cp pre-receive /srv/git/myrepo.git/hooks/pre-receive
chmod +x /srv/git/myrepo.git/hooks/pre-receive
```

The hook template lives at [`examples/server-side/pre-receive`](../../examples/server-side/pre-receive).

If `deadpush` is not on the git user's `PATH`, either install it into that user's
environment or point the hook at it explicitly:

```bash
# In the hook environment (or edit the script):
export DEADPUSH_BIN=/opt/venvs/deadpush/bin/deadpush
```

## Gitea

Gitea supports server-side hooks per repository:

1. Enable them once in `app.ini`:
   ```ini
   [security]
   DISABLE_GIT_HOOKS = false
   ```
2. In the repo: Settings -> Git Hooks -> `pre-receive`, and paste the contents of
   `examples/server-side/pre-receive`.

Make sure `deadpush` is installed for the user running Gitea (or set
`DEADPUSH_BIN`).

## GitLab (self-managed)

Use a [server hook](https://docs.gitlab.com/administration/server_hooks/):

```bash
# Gitaly-managed repos — create the hook directory and drop the script in:
sudo -u git mkdir -p /var/opt/gitlab/git-data/repositories/<repo>.git/custom_hooks
sudo -u git cp pre-receive /var/opt/gitlab/git-data/repositories/<repo>.git/custom_hooks/pre-receive
sudo -u git chmod +x /var/opt/gitlab/git-data/repositories/<repo>.git/custom_hooks/pre-receive
```

For a global hook (all repos), place it under the configured
`custom_hooks_dir/pre-receive.d/` directory instead.

## Verify

Push a commit containing an obvious secret to a test repo; the push should be
rejected with a `deadpush — Pre-receive guardrails REJECTED this push` message.
A clean push should succeed unchanged.

## Notes

- Fail-closed: if `deadpush` is missing or errors, the hook rejects the push.
- The hook is stateless and read-only against the incoming objects; it does not
  modify history.
- To scan an existing range manually (e.g. in CI or ad hoc), use
  `deadpush scan --base <sha> --head <sha>` or `deadpush scan --all`.
