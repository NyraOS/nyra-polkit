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
`EnumerateActions`. Authentication agents are not served yet: an action that needs a password is
answered "not authorized, challenge" (pkcheck's exit code 2). The files that install it (systemd
unit, bus policy and activation, system user) are in [`dist/`](dist).

**It is not a drop-in replacement for polkit:** JavaScript `.rules` files are not read, and
`pkexec` is not provided. Password checks stay with polkit's own `polkit-agent-helper-1`.

## Building

```sh
cargo build --release
cargo test
```

The D-Bus integration tests run nyra-polkitd on a private bus and need root, a writable
`/sys/fs/cgroup`, `dbus-daemon`, `pkcheck`, `busctl` and the `polkitd` user (Debian 13: the
`dbus-daemon`, `polkitd` and `systemd` packages); CI runs them in a privileged Debian 13 container:

```sh
cargo test --test dbus -- --ignored
```

Rust 1.85 or newer (the version in Debian 13).

## Contributing

Every change goes through a pull request. nyra-polkit is written only from documented interfaces
and observed behaviour, never from polkit's source code: read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before you start. Security issues: please report them privately, as described in
[`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).
