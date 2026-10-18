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

Versions follow [SemVer](https://semver.org), starting at 0.1.0. A release is a tag `vX.Y.Z` on
`main`, signed by a maintainer; the [release workflow](.github/workflows/release.yml) builds,
attests and publishes it. Nothing else creates tags or releases.

The maintainers are listed in [`.github/MAINTAINERS`](.github/MAINTAINERS), one GitHub login per
line. Each registers a signing key (SSH or GPG) in their GitHub account, under "SSH and GPG
keys" as a signing key. That key stays with the maintainer: it never goes on a build machine or in
CI. The copy on GitHub is the one that counts, and it must not be expired: after extending a GPG
key, upload its public key to GitHub again (or register an SSH signing key).

1. In a pull request, set the new version in `nyra-polkitd/Cargo.toml` and
   `nyra-pkcheck/Cargo.toml`, run `cargo update --workspace` so `Cargo.lock` follows, and merge it.
   Skip this step when the crates already have the version to release (0.1.0 does).
2. Tag the merged commit with a signed, annotated tag, check it as the workflow will and push it:
   ```sh
   git fetch origin
   git tag -s v0.1.0 -m "nyra-polkit 0.1.0" origin/main
   tools/release/verify-tag.sh v0.1.0 "$(git rev-parse origin/main)"
   git push origin v0.1.0
   ```
   `-s` signs with your GPG key, or with your SSH key when `gpg.format=ssh` and
   `user.signingkey` point at it. Check with `verify-tag.sh` (it needs the GitHub CLI, logged
   in), not with `git tag -v`: that one uses your local keys, while the workflow uses the keys
   GitHub holds, which may differ (a key extended locally but still expired on GitHub passes
   `git tag -v` and fails the workflow). A pushed tag is never reused, so a tag the workflow
   refuses costs that version.

Before it builds anything, the workflow ([`tools/release/verify-tag.sh`](tools/release/verify-tag.sh))
refuses the tag unless it is annotated, points at the commit being built and is signed by one of
the keys the maintainers have registered on GitHub, read from the GitHub API on every run; with no
key registered, nothing is released. The signature is also what users check
([`tools/release/verify-download.sh`](tools/release/verify-download.sh), README "Releases"): the
workflow runs as written in the tagged commit, so anyone holding a token that can push tags could
run a changed one, but no token can make a maintainer's signature. That is why a tag is signed only
with a key that never leaves the maintainer. The workflow also refuses a tag whose commit is not on
`main`'s history or whose version differs from the crates' version. The release notes list the
pull requests merged since the previous release. A tag is never moved or reused: a broken release is fixed by
the next version.
