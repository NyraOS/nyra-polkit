# nyra-polkit

A polkit authority daemon for [Nyra OS](https://nyraos.com), written from scratch in Rust.

It speaks the same D-Bus interface as `polkitd` (`org.freedesktop.PolicyKit1`), so the polkit client
libraries, desktop authentication agents and system services keep working unchanged. Local policy
is written as simple TOML rules instead of JavaScript.

## Status

Early work: nothing here is usable yet.

## License

MIT. See [`LICENSE`](LICENSE).
