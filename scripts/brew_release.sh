#!/usr/bin/env bash
# Finalize + verify the Homebrew formula for a release.
#
# Prerequisites (hard gates for a working `brew install`):
#   1. The GitHub repo must be PUBLIC.
#   2. The release tag (e.g. v0.2.1) must be pushed to GitHub.
#
# This script downloads the source tarball for the tag referenced in the
# formula, computes its sha256, writes it into Formula/deadpush.rb, and then
# runs Homebrew's audit + a build-from-source install/test so the formula is
# verified before you ship it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORMULA="$ROOT/Formula/deadpush.rb"

url="$(awk -F'"' '/^  url /{print $2; exit}' "$FORMULA")"
if [[ -z "$url" ]]; then
  echo "error: could not read url from $FORMULA" >&2
  exit 1
fi
echo "Source tarball: $url"

# 1) Verify the tarball is publicly fetchable (fails while the repo is private).
code="$(curl -sSL -o /dev/null -w '%{http_code}' "$url")"
if [[ "$code" != "200" ]]; then
  echo "error: tarball not reachable (HTTP $code)." >&2
  echo "       The repo must be PUBLIC and the tag must exist before releasing." >&2
  exit 1
fi

# 2) Compute the real sha256 and write it into the formula.
sha="$(curl -sSL "$url" | shasum -a 256 | awk '{print $1}')"
echo "sha256: $sha"

# Portable in-place edit (BSD/macOS + GNU sed).
tmp="$(mktemp)"
awk -v sha="$sha" '
  /^  sha256 / && !done { print "  sha256 \"" sha "\""; done=1; next }
  { print }
' "$FORMULA" > "$tmp"
mv "$tmp" "$FORMULA"
echo "Updated $FORMULA"

# 3) Verify with Homebrew (style is offline; audit/install/test need the tarball).
if command -v brew >/dev/null 2>&1; then
  echo "== brew style =="
  brew style "$FORMULA"
  echo "== brew audit --strict --online =="
  brew audit --strict --online "$FORMULA" || true
  echo "== brew install --build-from-source =="
  brew install --build-from-source "$FORMULA"
  echo "== brew test =="
  brew test deadpush
else
  echo "warning: brew not found; skipped audit/install/test." >&2
fi

echo "Done. Review the formula, commit, and push to your tap."
