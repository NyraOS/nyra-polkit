# nyra-polkit

A polkit authority daemon for [Nyra OS](https://nyraos.com), written from scratch in Rust.

It speaks the same D-Bus interface as `polkitd` (`org.freedesktop.PolicyKit1`), so the polkit client
libraries, desktop authentication agents (KDE's included) and system services such as
NetworkManager, udisks2 and Flatpak keep working unchanged. Local policy is written as simple TOML
rules instead of JavaScript, and when several rules match, the most restrictive one wins.

## Status

Early work. What exists today: the design ([`docs/DESIGN.md`](docs/DESIGN.md)) and `nyra-polkitd`,
which reads the standard action files (`/usr/share/polkit-1/actions`) and the TOML rules and
decides, in unit tests. It does not serve D-Bus yet.

**It is not a drop-in replacement for polkit:** JavaScript `.rules` files are not read, and
`pkexec` is not provided. Password checks stay with polkit's own `polkit-agent-helper-1`.

## Building

```sh
cargo build --release
cargo test
```

Rust 1.85 or newer (the version in Debian 13).

## Contributing

Every change goes through a pull request. nyra-polkit is written only from documented interfaces
and observed behaviour, never from polkit's source code: read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before you start. Security issues: please report them privately, as described in
[`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).
