# Contributing to nyra-polkit

nyra-polkit decides who may do what on a Nyra OS machine, so the rules are strict but short.

- **Clean room.** nyra-polkit is MIT licensed and written only from documented interfaces and
  observed behaviour (the polkit reference manual and man pages, the D-Bus and logind
  documentation, what clients send on the bus). **Do not read, copy or translate polkit's source
  code** (C, JavaScript, its tests or its rule files), and do not contribute if you have it in mind
  for the part you change. Add any new source you rely on to the "Sources" list in
  [`docs/DESIGN.md`](docs/DESIGN.md).
- **Branch and pull request, never a push to `main`.** Enable the local guard once:
  `git config core.hooksPath tools/hooks` (`tools/hooks/pre-push` refuses a push to `main`).
  Every change is reviewed before it is merged (`.github/CODEOWNERS`).
- **One change per pull request**, small and with a clear reason. Prefer the simplest solution that
  works; no options or abstractions "for later".
- **Code rules** (for everyone, people and agents alike; reviews check them):
  - **Rust:** the code must be easy to read, without needless complication. A reader who knows
    Rust understands a function without jumping through five files; names say what a thing is;
    generics, traits, macros or `unsafe` only when really needed, with the reason written next to
    them; plain code instead of an abstraction used once; comments say why, not what.
- **Fail closed.** Anything the daemon cannot determine (a subject, a session, a rule file) ends in
  a denial, never in a grant.
- **Few dependencies.** Each one is justified next to it in `Cargo.toml`; `cargo deny` checks
  licences and advisories.
- **Never weaken or skip a test to make it pass.** A flaky test is a bug: fix it or report it.
- **No secrets.** No keys, tokens or passwords in the repository, its history or CI logs; gitleaks
  scans every push.
- **Pin what CI runs:** actions by commit SHA, container images by digest.
- **English** for code, comments, commit messages and documentation. New files carry an SPDX header
  (`MIT`, the licence of this repository); contributions are accepted under it.
- Before you push, run what CI runs: `cargo fmt --check`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked`.

## Releases

Versions follow [SemVer](https://semver.org), starting at 0.1.0. A release is a signed tag
`vX.Y.Z` on `main`, pushed by a maintainer; the [release workflow](.github/workflows/release.yml)
builds, attests and publishes it. Nothing else creates tags or releases.

1. In a pull request, set the new version in `nyra-polkitd/Cargo.toml` and
   `nyra-pkcheck/Cargo.toml`, run `cargo update --workspace` so `Cargo.lock` follows, and merge it.
2. Tag the merged commit with a signed, annotated tag and push the tag:
   ```sh
   git fetch origin
   git tag -s v0.1.0 -m "nyra-polkit 0.1.0" origin/main
   git tag -v v0.1.0
   git push origin v0.1.0
   ```
   `-s` signs with your GPG key (or your SSH key, with `gpg.format=ssh`), which must be added to
   your GitHub account as a signing key so GitHub shows the tag as verified.

The workflow cannot check the signature itself (it holds no maintainer keys), but it refuses a tag
whose commit is not on `main`'s history or whose version differs from the crates' version. The
release notes list the pull requests merged since the previous release. A tag is never moved or
reused: a broken release is fixed by the next version.
