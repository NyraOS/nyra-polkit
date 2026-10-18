#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Checks a downloaded release tarball (README.md, "Releases"): its tag is signed by a maintainer
# (verify-tag.sh, with the keys the logins in .github/MAINTAINERS have registered on GitHub), the
# tag's commit is on main, and the tarball's build provenance attestation was made by the release
# workflow, on a GitHub-hosted runner, from that tag and that commit. Needs git, gpg, ssh-keygen and
# the GitHub CLI 2.102 or newer, logged in. Run it from the top of a clone of this repository.
#
#   tools/release/verify-download.sh nyra-polkit-X.Y.Z-<arch>-linux-gnu.tar.gz
set -euo pipefail

repository=NyraOS/nyra-polkit
tarball=$1
version=$(basename "$tarball" | sed -n 's/^nyra-polkit-\([0-9]*\.[0-9]*\.[0-9]*\)-.*\.tar\.gz$/\1/p')
if [ -z "$version" ]; then
  echo "verify-download.sh: $tarball is not named like a release tarball" >&2
  exit 1
fi
tag=v$version

# Older gh versions lack --source-ref and --source-digest (before 2.68) or matched --signer-workflow
# and --source-ref less strictly (fixed in 2.97 and 2.102). Debian 13's gh has no attestations.
gh_found=$(gh --version 2>/dev/null | head -n 1 || true)
gh_version=$(echo "$gh_found" | sed -n 's/^gh version \([0-9]*\)\.\([0-9]*\)\..*/\1 \2/p')
read -r gh_major gh_minor <<<"${gh_version:-0 0}"
if [ "$gh_major" -lt 2 ] || { [ "$gh_major" -eq 2 ] && [ "$gh_minor" -lt 102 ]; }; then
  echo "verify-download.sh: needs the GitHub CLI 2.102 or newer (found: ${gh_found:-none});" >&2
  echo "install it from https://cli.github.com (packages for Debian, Ubuntu, Fedora and others)" >&2
  exit 1
fi

# From the repository itself, whatever this clone's remotes are.
git fetch -q "https://github.com/$repository" main
main=$(git rev-parse FETCH_HEAD)
if ! error=$(git fetch -q --no-tags "https://github.com/$repository" "+refs/tags/$tag:refs/tags/$tag" 2>&1); then
  echo "verify-download.sh: cannot fetch the tag $tag from GitHub:" >&2
  echo "$error" >&2
  exit 1
fi
commit=$(git rev-parse "refs/tags/$tag^{commit}")

tools/release/verify-tag.sh "$tag" "$commit"
if ! git merge-base --is-ancestor "$commit" "$main"; then
  echo "verify-download.sh: $tag ($commit) is not on main's history" >&2
  exit 1
fi
gh attestation verify "$tarball" -R "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" --source-digest "$commit" --deny-self-hosted-runners
echo "verify-download.sh: $tarball is $tag, signed by a maintainer and built from it by the release workflow"
