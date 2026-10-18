# nyra-polkit

A polkit authority daemon for [Nyra OS](https://nyraos.com), written from scratch in Rust.

It speaks the same D-Bus interface as `polkitd` (`org.freedesktop.PolicyKit1`), so the polkit client
libraries, desktop authentication agents (KDE's included) and system services such as
NetworkManager, udisks2 and Flatpak keep working unchanged. Local policy is written as simple TOML
rules instead of JavaScript, and when several rules match, the most restrictive one wins.

## Why

polkit is the gatekeeper of a Linux desktop: whenever an application asks a system service to do
something privileged (connect to a network, mount a disk, install an application, change the
time, shut down), the service asks polkit whether this user, in this session, is allowed to.
`polkitd` is a privileged system service (on Debian it runs as its own `polkitd` user, not as
root), but its answers decide actions that run as root, so a wrong answer can hand administrator
rights to anyone. polkit's own security record shows how much is at stake: PwnKit
(CVE-2021-4034), in its `pkexec` tool, gave root to any local user. nyra-polkit does not provide
`pkexec`.

We wanted that piece to be as small and as easy to check as it can be:

- **Memory safety.** Written in Rust, a whole class of bugs that C code is exposed to (buffer
  overflows, use after free) is ruled out by the language.
- **No JavaScript engine deciding who may act as root.** `polkitd` embeds a JavaScript
  interpreter to evaluate its rules. nyra-polkit reads plain TOML rules instead: who, which
  actions, and the answer.
- **Rules you can read one at a time.** With polkit, the first matching JavaScript rule wins, in
  file-name order, so a file added later can quietly change what an earlier one meant. Here the
  most restrictive matching rule always wins: within the rules in force, no file can weaken another
  file's `no` through the order the files are read in. Only root can replace a rules file, and the
  replacement is logged. A rules file with any error makes every request fail closed instead of
  matching too much.
- **Nothing else has to change.** The D-Bus interface is small, documented and stable for years, so
  applications, authentication agents and the polkit client libraries keep working as they are.

nyra-polkit is written for Nyra OS, but nothing in it is specific to Nyra; any distribution can use
it.

## Status

Early work. What exists today: the design ([`docs/DESIGN.md`](docs/DESIGN.md)) and `nyra-polkitd`,
which owns `org.freedesktop.PolicyKit1` on the system bus, reads the standard action files
(`/usr/share/polkit-1/actions`) and the TOML rules, and answers `CheckAuthorization` and
`EnumerateActions`. It serves authentication agents (the dialog that asks for a password) and
keeps temporary authorizations (`auth_self_keep`, `auth_admin_keep`) for five minutes. The files
that install it (systemd unit, bus policy and activation, system user) are in [`dist/`](dist).

**It is not a drop-in replacement for polkit:** JavaScript `.rules` files are not read, and
`pkexec` is not provided. Password checks stay with polkit's own `polkit-agent-helper-1`.

## pkcheck

`nyra-pkcheck` builds a `pkcheck` with the options and exit codes of pkcheck(1): `--action-id`,
`--process PID[,START_TIME[,UID]]` or `--system-bus-name`, `--detail KEY VALUE`,
`--allow-user-interaction`, `--list-temp`, `--revoke-temp`, `--version` and `--help`. It exits
with 0 (authorized), 1 (not authorized), 2 (an authentication is needed), 3 (the authentication was
dismissed), 126 (malformed options) or 127 (an error), prints the answer's details on standard
output and its diagnostics on standard error, as Debian's pkcheck does; the integration tests run
both side by side. It pins the process it asks about with a pidfd. `--enable-internal-agent` is not
supported: run an authentication agent instead. Where it deliberately differs from polkit's
pkcheck (it refuses ambiguous or malformed values that polkit's guesses at) is listed in
[`docs/DESIGN.md`](docs/DESIGN.md#pkcheck).

```sh
cargo build --release -p nyra-pkcheck   # target/release/pkcheck
```

Nothing installs it yet; it replaces polkit's `pkcheck` (`/usr/bin/pkcheck`) once nyra-polkitd
replaces polkitd. It reads `DBUS_SYSTEM_BUS_ADDRESS`, so it must never be setuid, and a
privileged process must not run it with an environment inherited from an unprivileged one.

## Building

```sh
cargo build --release
cargo test
```

The D-Bus integration tests run nyra-polkitd on a private bus and need root, a writable
`/sys/fs/cgroup`, `dbus-daemon`, `pkcheck`, `busctl` and the `polkitd`, `nobody` and `daemon`
users (Debian 13: the `dbus-daemon`, `polkitd` and `systemd` packages); CI runs them in a
privileged Debian 13 container:

```sh
cargo test --test dbus --test compat -- --ignored
```

Rust 1.85 or newer (the version in Debian 13).

## Releases

Releases follow [SemVer](https://semver.org) and are published on
[GitHub Releases](https://github.com/NyraOS/nyra-polkit/releases), built by the
[release workflow](.github/workflows/release.yml) from a signed `vX.Y.Z` tag on `main`. Each one
has a tarball per architecture, `nyra-polkit-X.Y.Z-x86_64-linux-gnu.tar.gz` and
`nyra-polkit-X.Y.Z-aarch64-linux-gnu.tar.gz` (Linux, glibc), with:

- `bin/nyra-polkitd` and `bin/pkcheck`;
- `dist/`: the systemd unit, the D-Bus policy and activation file and the sysusers file, each
  naming where it is installed in its first lines;
- `LICENSE`, `README.md`, `SECURITY.md`;
- `third-party/`: the licence files of every crate built into the binaries, and `CRATES`, their
  list with versions and licences.

To check a download, first compare it with `SHA256SUMS` from the same release:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

Then check where it came from. Your trust should rest on the maintainer's signature on the tag,
which no access token can make, and not only on the release workflow: anyone holding a token that
can push tags could also run a changed workflow. From a clone of this repository, with `git`,
GnuPG (`gpg`), OpenSSH (`ssh-keygen`) and the [GitHub CLI](https://cli.github.com) 2.102 or newer,
logged in (older versions lack or match more loosely the checks below, and Debian 13's gh 2.46 has
no `attestation` command; [cli.github.com](https://cli.github.com) has packages for most
distributions; on macOS `brew install gnupg gh`):

```sh
git clone https://github.com/NyraOS/nyra-polkit && cd nyra-polkit
tools/release/verify-download.sh ../nyra-polkit-X.Y.Z-x86_64-linux-gnu.tar.gz
```

It stops at the first check that fails:

1. **The tag is signed by a maintainer.** It fetches the tag `vX.Y.Z` from GitHub and runs
   `git verify-tag` with only the public signing keys that the logins in
   [`.github/MAINTAINERS`](.github/MAINTAINERS) have registered on GitHub
   ([`tools/release/verify-tag.sh`](tools/release/verify-tag.sh)). The tag must be annotated and
   signed with OpenPGP or SSH, and a GPG signature must name one of those keys' fingerprints, so
   nothing in the machine's own GnuPG configuration (keys fetched or imported while verifying,
   trusted X.509 authorities) can make another signature count. Check the signature with this
   script rather than with a bare `git verify-tag`, which trusts whatever your GnuPG setup trusts.
2. **The tag's commit is on `main`'s history** (`git merge-base --is-ancestor <commit> main`).
3. **The tarball was built by the release workflow, from that tag and that commit:**
   ```sh
   gh attestation verify nyra-polkit-X.Y.Z-x86_64-linux-gnu.tar.gz -R NyraOS/nyra-polkit \
     --signer-workflow NyraOS/nyra-polkit/.github/workflows/release.yml \
     --source-ref refs/tags/vX.Y.Z --source-digest <commit> --deny-self-hosted-runners
   ```
   - `-R NyraOS/nyra-polkit`: the attestation was made in this repository;
   - `--signer-workflow`: by the release workflow, not by any other workflow or a pull request
     run;
   - `--source-ref`: from the release's tag, not from a branch;
   - `--source-digest`: from the commit the signed tag points to;
   - `--deny-self-hosted-runners`: on a runner hosted by GitHub.

`.github/MAINTAINERS` says whose signature you trust: a change to it is a change of trust, and
its history shows who made it.

## Contributing

Every change goes through a pull request. nyra-polkit is written only from documented interfaces
and observed behaviour, never from polkit's source code: read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before you start. Security issues: please report them privately, as described in
[`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).
