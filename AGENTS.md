# AGENTS.md

Guide for coding agents and people working in this repository. The rules in full: [CONTRIBUTING.md](CONTRIBUTING.md); what the project is: [README.md](README.md).

## What this is

A polkit authority daemon (`nyra-polkitd`) and a `pkcheck` replacement (`nyra-pkcheck`) for Nyra OS, written from scratch in Rust. It speaks the D-Bus interface of `polkitd`, reads the standard action files and plain TOML rules, and the most restrictive matching rule wins. Its answers decide actions that run as root.

## Clean room (read before anything else)

nyra-polkit is MIT licensed and written only from documented interfaces and observed behaviour. Do not read, copy or translate polkit's source code (C, JavaScript, tests or rule files), and do not work on a part for which you have it in mind. Add any new source you rely on to the "Sources" list in `docs/DESIGN.md`.

## Map (read in this order)

1. `README.md`, then `docs/DESIGN.md` (scope, D-Bus interface, rules, sources) and `docs/INSTALL.md`.
2. `nyra-polkitd/src/`: `lib.rs` lists the modules: `actions` (action files), `rules` (TOML rules), `decision`, `process`/`logind`/`subject` (who asks), `agents`/`temporary` (authentication), `authority` and `bus` (the D-Bus service). `main.rs` is the daemon.
3. `nyra-pkcheck/src/`: the `pkcheck` command.
4. `nyra-polkitd/tests/`, `nyra-pkcheck/tests/`, `tests/common/`: unit and integration tests and their harness.
5. `dist/`: files that install it (systemd unit, bus policy, system user). `tools/`: `hooks/` (pre-push guard) and `release/`.

## Build, test, lint

Rust 1.85 or newer. Run what CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo +1.85 test --locked --workspace   # the oldest supported Rust
cargo deny --locked check               # needs cargo-deny
```

- Root and a Debian 13 container (CI only, or your own privileged container): the D-Bus integration tests, `cargo test --locked --test dbus --test compat -- --ignored`. They need `dbus-daemon`, `polkitd`, `systemd`, a writable `/sys/fs/cgroup` and the `polkitd`, `nobody` and `daemon` users, and they start the daemon on a private bus.
- Enable the local guard once: `git config core.hooksPath tools/hooks` (it refuses a push to `main`).
- Releases (signed tags) are made by maintainers only; do not create tags or releases.

## Working rules

- Work on a branch, never on `main`. One small, focused change per pull request, with a clear reason.
- Before you start, read the recent changes (`git log`) and the docs of the area.
- Commit messages: a short imperative subject in plain English. The only trailer is `Co-Authored-By: <model name> <noreply@anthropic.com>`. No "Generated with ..." line and no session link in commits or pull request text.
- A test that fails sometimes is a bug: find the cause, do not rerun until green. Never weaken or skip a test to make it pass.
- Fail closed: anything the daemon cannot determine (a subject, a session, a rule file) ends in a denial, never a grant.
- Pin what CI runs: actions by commit SHA, container images by digest.
- English for code, comments, commits and docs. New files start with an SPDX header (`MIT`).

## Code rules (KISS: code a person can read)

- Read top to bottom. Functions about 50 lines at most, files short. Each file starts with a short header saying what it does and why it exists.
- Plain `match` and loops instead of long iterator chains. No macros.
- No generics, explicit lifetimes or `dyn` unless needed, with the reason written next to them. (`src/bus.rs` uses `dyn` and `async_trait` because zbus requires them there.)
- No `unsafe`: the code has none today (system calls go through `rustix`). Keep it so.
- Comments explain why, not what.
- Few dependencies; each one is justified next to it in `Cargo.toml`. Do not write your own replacement without a reason.
- No options or layers "for later".

## Security-sensitive areas

All of this repository: it decides who may act as root. Changes need a security review before merge, in particular the decision and rule code (`decision`, `rules`, `actions`), how the caller is identified (`process`, `subject`, `logind`), temporary authorizations, the limits on what is read from the bus, the files in `dist/` (bus policy, unit) and the release tooling in `tools/release/` and `.github/workflows/release.yml`. Never put secrets, keys or tokens in the repository, tests or logs; test secrets are throwaway. Report vulnerabilities privately: [SECURITY.md](SECURITY.md).

## Docs

`docs/DESIGN.md` (design, D-Bus interface, sources), `docs/INSTALL.md`, `README.md`.
