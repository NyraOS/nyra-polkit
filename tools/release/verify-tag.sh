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

# Only OpenPGP and SSH signatures: an X.509 one would be checked by gpgsm against the machine's
# certificate authorities. git reads the signature from the last such line of the tag.
signature=$(git cat-file tag "$tag" | grep -- '^-----BEGIN ' | tail -n 1 || true)
case $signature in
  "-----BEGIN PGP SIGNATURE-----" | "-----BEGIN SSH SIGNATURE-----") ;;
  *)
    echo "verify-tag.sh: $tag has no OpenPGP or SSH signature" >&2
    exit 1
    ;;
esac

keys=$(mktemp -d)
trap 'rm -rf "$keys"' EXIT
# Only the maintainers' keys: an empty keyring and an allowed-signers file of our own. The
# machine's own GnuPG configuration still applies, so verifying must not add keys either; the
# fingerprint check below does not depend on any of it.
export GNUPGHOME="$keys/gnupg"
mkdir -m 700 "$GNUPGHOME"
printf '%s\n' no-auto-key-retrieve no-auto-key-import >"$GNUPGHOME/gpg.conf"
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

# The primary-key fingerprints of the maintainers' GPG keys, before anything else can touch the
# keyring.
gpg --batch --with-colons --list-keys |
  awk -F: '$1 == "pub" { primary = 1; next } $1 == "fpr" && primary { print $10; primary = 0 }' \
    >"$keys/fingerprints"

# git fails on an unsigned tag, a bad signature or, for SSH, a key not in the allowed-signers
# file. --raw writes gpg's status lines (or ssh-keygen's output) to standard error.
git -c gpg.ssh.allowedSignersFile="$keys/allowed_signers" -c gpg.x509.program=false \
  verify-tag --raw "$tag" 2>"$keys/status" || {
  cat "$keys/status" >&2
  echo "verify-tag.sh: the signature on $tag does not verify" >&2
  exit 1
}
# For OpenPGP, every valid signature must be made by one of the maintainers' keys (VALIDSIG's last
# field is the signing key's primary-key fingerprint), whatever gpg was configured to accept.
if [ "$signature" = "-----BEGIN PGP SIGNATURE-----" ]; then
  awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $NF }' "$keys/status" >"$keys/signers"
  if [ ! -s "$keys/signers" ] || grep -qvxFf "$keys/fingerprints" "$keys/signers"; then
    echo "verify-tag.sh: $tag is not signed by a maintainer's GPG key" >&2
    exit 1
  fi
fi
echo "verify-tag.sh: $tag is signed by a maintainer"
