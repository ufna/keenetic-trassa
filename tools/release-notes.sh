#!/usr/bin/env bash
# The notes of a release: what changed, from the body of the annotated tag v<version> (the lines
# after its first), then how to install it and what its files are (.github/release-notes.md).
#
#   tools/release-notes.sh 0.1.2 >notes.md
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=${1:-}
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "Usage: tools/release-notes.sh <version>, the version as 0.1.2" >&2
	exit 1
fi
changes=$(git tag -l --format='%(contents:body)' "v$VERSION" | sed '/^-----BEGIN PGP SIGNATURE-----/,$d')
if [ -n "${changes//[[:space:]]/}" ]; then
	printf '## What changed\n\n%s\n\n' "$changes"
fi
sed "s/@VERSION@/$VERSION/g" .github/release-notes.md
