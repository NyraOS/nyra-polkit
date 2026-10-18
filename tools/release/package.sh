#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Packs a release tarball from `cargo build --release --locked` in this checkout: the binaries, the
# files in dist/, LICENSE, README.md, SECURITY.md and the licence notices of every crate built into
# the binaries. Run it from the top of the repository, after the build, on the machine that built
# it (it reads the crates cargo unpacked there).
#
#   tools/release/package.sh VERSION OUTPUT_DIR   # OUTPUT_DIR/nyra-polkit-VERSION-<arch>-linux-gnu.tar.gz
set -euo pipefail

version=$1
output=$2
name="nyra-polkit-$version-$(uname -m)-linux-gnu"
stage="$output/$name"
registry="${CARGO_HOME:-$HOME/.cargo}/registry/src"

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/dist" "$stage/third-party"
cp target/release/nyra-polkitd target/release/pkcheck "$stage/bin/"
cp dist/* "$stage/dist/"
cp LICENSE README.md SECURITY.md "$stage/"

# The crates built into the binaries, with the proc-macros (and their dependencies) that write part
# of their code: normal dependencies for this machine's target, without build or dev dependencies.
# Lines look like `zbus v5.13.2|MIT`; a crate seen twice ends in " (*)", a proc-macro carries
# " (proc-macro)", this repository's own crates carry their path in parentheses, and an empty line
# separates the workspace members.
cargo tree --locked --workspace --edges normal --prefix none --format '{p}|{l}' |
  sed 's/ (\*)$//; s/ (proc-macro)//' | sort -u |
  while IFS='|' read -r package license; do
    case $package in "" | *" ("*) continue ;; esac
    crate=${package% v*}
    crate_version=${package##* v}
    crate_dir=$(find "$registry" -mindepth 2 -maxdepth 2 -name "$crate-$crate_version" -print -quit)
    notices="$stage/third-party/$crate-$crate_version"
    mkdir -p "$notices"
    if [ -n "$crate_dir" ]; then
      find "$crate_dir" -maxdepth 1 -type f \
        \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) -exec cp {} "$notices/" \;
    fi
    # A notice that cannot be shipped is a release that cannot be published: stop here.
    if [ -z "$(ls -A "$notices")" ]; then
      echo "package.sh: no licence file found for $crate $crate_version ($license)" >&2
      exit 1
    fi
    echo "$crate $crate_version: $license" >>"$stage/third-party/CRATES"
  done

# Same order, owner, modes and dates on every build of the same commit, whatever the umask.
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/bin/nyra-polkitd" "$stage/bin/pkcheck"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(git log -1 --format=%ct)" \
  -C "$output" -cf - "$name" | gzip -n >"$output/$name.tar.gz"
rm -rf "$stage"
echo "$output/$name.tar.gz"
