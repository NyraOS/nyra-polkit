#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Refuses a release tag unless it is an annotated tag on COMMIT, signed (SSH or GPG) with a signing
# key that a maintainer in .github/MAINTAINERS has registered in their GitHub account. The keys
# come from the GitHub API on every run and are the only ones trusted: whatever can push a tag
# cannot make a release without a maintainer's key. Run it from the top of the repository, with
# the tag object fetched and GH_TOKEN set, or the GitHub CLI logged in, for `gh api`.
#
#   tools/release/verify-tag.sh TAG COMMIT
set -euo pipefail

tag=$1
commit=$2

if [ "$(git cat-file -t "refs/tags/$tag")" != tag ]; then
  echo "verify-tag.sh: $tag is not an annotated tag" >&2
  exit 1
fi
if [ "$(git rev-parse "refs/tags/$tag^{commit}")" != "$commit" ]; then
  echo "verify-tag.sh: $tag does not point at $commit" >&2
  exit 1
fi

keys=$(mktemp -d)
trap 'rm -rf "$keys"' EXIT
# Only the maintainers' keys: an empty keyring and an allowed-signers file of our own.
export GNUPGHOME="$keys/gnupg"
mkdir -m 700 "$GNUPGHOME"
touch "$keys/allowed_signers"
key_count=0

while read -r login; do
  case $login in "" | "#"*) continue ;; esac
  # `login ssh-ed25519 AAAA...` lines: the login is the signer's name in the allowed-signers file.
  gh api "users/$login/ssh_signing_keys" --jq '.[].key' >"$keys/ssh"
  sed "s/^/$login /" "$keys/ssh" >>"$keys/allowed_signers"
  key_count=$((key_count + $(wc -l <"$keys/ssh")))
  # One armored public key (with its subkeys) per registered GPG key, revoked ones left out.
  gh api "users/$login/gpg_keys" --jq '.[] | select(.revoked | not) | .raw_key // empty' >"$keys/gpg"
  if [ -s "$keys/gpg" ]; then
    gpg --batch --quiet --import "$keys/gpg"
    key_count=$((key_count + 1))
  fi
done <.github/MAINTAINERS

if [ "$key_count" -eq 0 ]; then
  echo "verify-tag.sh: no maintainer has a signing key registered on GitHub" >&2
  exit 1
fi

# git picks SSH or GPG from the signature itself; it fails on an unsigned tag, a bad signature or
# a key that is not one of the above.
git -c gpg.ssh.allowedSignersFile="$keys/allowed_signers" verify-tag "$tag"
echo "verify-tag.sh: $tag is signed by a maintainer"
