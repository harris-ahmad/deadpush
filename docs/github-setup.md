# GitHub Actions setup (5 minutes)

Wire **T3 Ship** enforcement so violating commits cannot merge to protected branches —
regardless of what happens locally (`--no-verify`, killed daemon, etc.).

## Prerequisites

- A GitHub repository
- Branch protection enabled on your main branch (Settings → Branches)

## Step 1: Add the workflow

Copy the example workflow to your repo:

```bash
mkdir -p .github/workflows
curl -o .github/workflows/deadpush.yml \
  https://raw.githubusercontent.com/harris-ahmad/deadpush/main/examples/github/deadpush.yml
```

Or create `.github/workflows/deadpush.yml`:

```yaml
name: deadpush

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: harris-ahmad/deadpush/.github/actions/scan@main
```

Commit and push. The `deadpush` check will appear on PRs and pushes to `main`.

## Step 2: Require the check

1. Go to **Settings → Branches → Branch protection rules**
2. Edit your rule for `main` (or create one)
3. Enable **Require status checks to pass before merging**
4. Search for and select **`deadpush`** (or the job name from your workflow)
5. Save

## Step 3: Verify

Open a test PR that adds a file with a fake secret:

```bash
echo 'OPENAI_API_KEY=sk-test123456789012345678901234567890' > .deadpush-test.env
git add .deadpush-test.env && git commit -m "test scan" && git push
```

The PR check should fail. Delete the test file afterward.

## Self-hosted git

For Gitea, GitLab self-hosted, or bare repos, use a `pre-receive` hook instead:

See [server-side/pre-receive.md](server-side/pre-receive.md).

## Combine with local tiers

| Tier | Where | Purpose |
|------|-------|---------|
| T0 | `deadpush protect --daemon` | Catch accidents locally |
| T1 | `deadpush protect --hardened` | Unkillable guardian + tamper-resistant policy |
| T2 | `deadpush run --sandbox -- …` | Confined agent session |
| **T3** | This guide | **Uncircumventable ship gate** |

T3 alone is valuable. T0+T3 is the recommended default. Add T1/T2 when agents run unattended.

## Troubleshooting

- **Check not appearing:** Ensure the workflow ran at least once on a PR.
- **False positives in test files:** deadpush lowers secret severity in test/mock paths; see [guarantees.md](guarantees.md).
- **Advisory vs required:** The deadpush dev repo runs scan as advisory (its source contains detector patterns). Your app repo should use a **required** check.
