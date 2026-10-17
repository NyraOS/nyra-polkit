# nyra-polkit design

nyra-polkit is a polkit authority: the system service that answers "may this process do this
action?" for system services such as NetworkManager, udisks2, systemd and Flatpak. It replaces
`polkitd` and keeps its D-Bus interface, so the polkit client libraries (`libpolkit-gobject-1`,
`libpolkit-agent-1`), the desktop authentication agents (KDE's included) and the services that ask
keep working unchanged. Local policy is a set of TOML rules instead of JavaScript.

## Scope

The first version has:

- `nyra-polkitd`: the authority on the system bus, `org.freedesktop.PolicyKit1`;
- `pkcheck`: the same options and exit codes as pkcheck(1).

Not in the first version:

- **JavaScript rules.** Existing `.rules` files are ignored; this is not a drop-in for systems that
  rely on them.
- **`pkexec`.** Not provided.
- **Password checks.** The `polkit-agent-helper-1` of the distribution's polkit stays in charge of
  checking passwords (PAM); see "Authentication".
- `AuthenticationAgentResponse` (the old one, without `uid`): answers `NotSupported`. Helpers since
  polkit 0.114 use `AuthenticationAgentResponse2`.
- The `org.freedesktop.policykit.imply` annotation: an action is never granted because another one
  was. Without it some dialogs may ask once more, never less.
- Translations through `gettext-domain` (used by systemd's action files): these texts are shown
  untranslated for now. `xml:lang` translations work.
- `unix-netgroup` identities; watching the directories for changes (the image's `/usr` only changes
  at reboot; `systemctl reload` rereads `/etc`).

## Clean room

nyra-polkit is MIT licensed and written only from documented interfaces and observed behaviour:
the polkit reference manual and man pages, the D-Bus and logind documentation, action files as
installed by other projects, and what clients send on the bus. **Nobody working on it reads,
copies or translates polkit's source code** (C, JavaScript, its tests or its rule files). The
sources used are listed at the end; anything new that a change relies on is added there.

## D-Bus interface

Object `/org/freedesktop/PolicyKit1/Authority`, interface `org.freedesktop.PolicyKit1.Authority`,
name `org.freedesktop.PolicyKit1` on the system bus. Types are D-Bus signatures; a subject or an
identity is `(sa{sv})`: a kind and its details.

| Method | Arguments → result | Who may call |
|---|---|---|
| `CheckAuthorization` | subject, `s` action, `a{ss}` details, `u` flags, `s` cancellation id → `(bba{ss})` | anyone, for a subject of its own user; for another user's subject only root or a user named in the action's `org.freedesktop.policykit.owner` annotation |
| `CancelCheckAuthorization` | `s` cancellation id | the connection that started the check |
| `EnumerateActions` | `s` locale → `a(ssssssuuua{ss})` | anyone |
| `RegisterAuthenticationAgent` | subject, `s` locale, `o` path | the user the subject belongs to |
| `RegisterAuthenticationAgentWithOptions` | the same, `a{sv}` options (`fallback`: `b`) | the same |
| `UnregisterAuthenticationAgent` | subject, `o` path | the connection that registered it |
| `AuthenticationAgentResponse2` | `u` uid, `s` cookie, identity | root only (the helper) |
| `EnumerateTemporaryAuthorizations` | subject → `a(ss(sa{sv})tt)` | the subject's user, or root |
| `RevokeTemporaryAuthorizations` | subject | the subject's user, or root |
| `RevokeTemporaryAuthorizationById` | `s` id | the authorization's user, or root |

The caller is always identified by the bus (`GetConnectionCredentials` on its unique name), never by
what it says. Properties: `BackendName` = `nyra-polkit`, `BackendVersion`, `BackendFeatures` = 1
(temporary authorizations). The `Changed` signal is sent after the rules are reread and when a
temporary authorization appears, expires or is revoked. Errors use the documented names
(`org.freedesktop.PolicyKit1.Error.Failed`, `Cancelled`, `NotSupported`, `NotAuthorized`,
`CancellationIdNotUnique`).

`CheckAuthorization` flags: only `AllowUserInteraction` (1). Details whose names start with `polkit.`
are refused unless documented (`polkit.message`, `polkit.gettext_domain`, `polkit.icon_name`), and
those only from root. Result details: `polkit.temporary_authorization_id`,
`polkit.retains_authorization_after_challenge`, `polkit.dismissed`.

`ImplicitAuthorization` on the wire: 0 `no`, 1 `auth_self`, 2 `auth_admin`, 3 `auth_self_keep`,
4 `auth_admin_keep`, 5 `yes`.

## Subjects

A decision is only as good as knowing who asks. Every subject is turned into a user, that user's
groups (from the user database, NSS) and a session state, or the check fails with
`NotAuthorized`.

- **`system-bus-name`** (`name`: `s`), what most services send: only unique names (`:1.42`) are
  accepted, since a well-known name can change owner and unique names are never reused. The user
  comes from the bus (`GetConnectionCredentials`: `UnixUserID`, fixed when the connection was made)
  and the process from its `ProcessFD`. A bus that gives no `ProcessFD` fails the check: Debian 13's
  dbus 1.16 gives one.
- **`unix-process`** (`pid`: `u`, `start-time`: `t`; recent client libraries may also send `uid` and
  a `pidfd`, `h`): with a pidfd, the process is the pidfd's, and `pid` must match it. Without one,
  the daemon opens a pidfd for `pid`, then reads the start time from `/proc/<pid>/stat`: a different
  start time (or 0) means the PID was reused or never pinned, and the check fails. The user is the
  real uid from `/proc/<pid>/status`. When the subject carries a `uid` that differs from it, the
  process changed users since the caller looked, and the check fails.
- **`unix-session`** (`session-id`: `s`): the session and its user come from logind (`GetSession`).

**No PID race.** Everything read about a process (uid, session) is read while holding its pidfd,
and the pidfd is checked after the reads: if the process is still alive, the PID could not have
been given to another process in between, so what was read is about the right process.

**Session state**, from logind: a process's session is `GetSessionByPID`. A process outside any
session (an app started by the desktop through `systemd --user`) gets its user's display session
(`User.Display`), so desktop apps count as being in the user's session. Then:

| logind | State | Action default used |
|---|---|---|
| `Remote` false, `Active` true | local, active | `allow_active` |
| `Remote` false, `Active` false | local, inactive | `allow_inactive` |
| remote, or no session at all, or logind unreachable | not local | `allow_any` |

## Decision

```
decide(action, subject, details):
    no definition for action          -> no
    rules matching (action, subject)  -> the most restrictive of their results
    no rule matches                   -> the action's default for the subject's session
```

Results from the least to the most restrictive: `yes`, `auth_self_keep`, `auth_self`,
`auth_admin_keep`, `auth_admin`, `no`. An administrator's password counts as more than the user's
own (polkit(8) recommends `auth_admin` on multi-user systems), and a "keep" as less than asking
every time.

**The most restrictive matching rule wins** (deny wins, generalised to all six results). Why not
polkit's first match in file order:

- the answer does not depend on file names: a new file, from the image or the administrator, can
  never silently shadow a rule that denies;
- a `no` anywhere is final; to lift it, the file that holds it is replaced (see "Rules"), which is
  explicit and visible;
- each rule can be read on its own: what it says is the least that applies when it matches.

The price: no exceptions to a broader rule ("deny everything to `kiosk` except one action" is
written by listing what is denied). Rules have no negation in the first version.

Rules replace the default; they do not add to it. A rule that says `auth_admin` for an action whose
default is `no` makes that action possible with a password. Rules that match many actions (`*`)
therefore usually say `no`.

Unknown actions are denied before any rule is looked at, so no rule, not even `actions = ["*"]`
with `result = "yes"`, can grant an action that no installed program defines.

## Rules

Rule files are TOML: the image's in `/usr/share/nyra-polkit/rules.d/*.toml`, the administrator's
in `/etc/nyra-polkit/rules.d/*.toml`. A file in `/etc` replaces the image file with the same name;
an empty file there switches the image's file off. All other files apply together; their order does
not matter.

A file may have an `[administrators]` table (`users`, `groups`) and any number of `[[rule]]`
tables. The administrators of all files add up; without any, root is the administrator.
Administrators are who `auth_admin` asks for a password, and who `administrator = true` matches.

A rule holds when every condition it sets holds:

| Key | Meaning |
|---|---|
| `actions` | required: action ids; `org.example.*` matches ids starting with `org.example.`, `*` every id |
| `users`, `groups` | the subject's user is listed, or is in a listed group (both absent: anyone) |
| `administrator` | `true`: only administrators |
| `session` | `"local"`: a local session, active or not; `"active"`: the local session in the foreground |
| `details` | for each name, the service passed that detail with one of the listed values |
| `result` | required: `yes`, `auth_self_keep`, `auth_self`, `auth_admin_keep`, `auth_admin` or `no` |

Unknown keys, wrong types and malformed action ids are errors. **Any error in any rule file makes
the daemon deny every request** until it is fixed (logged on every check): skipping the broken
file could drop a rule that denies something, and a typo such as `sesion = "active"` must never
turn into a rule that matches every session.

Examples (each is a whole file; the unit tests parse every example in this document):

```toml
# /usr/share/nyra-polkit/rules.d/50-administrators.toml
# The sudo group are the administrators: auth_admin asks one of them for their own password.
[administrators]
groups = ["sudo"]
```

```toml
# /usr/share/nyra-polkit/rules.d/60-flatpak.toml
# An administrator at the machine installs and updates apps from the configured remotes without a
# password. Other remotes, other users and remote sessions keep Flatpak's defaults.
[[rule]]
actions = [
    "org.freedesktop.Flatpak.app-install",
    "org.freedesktop.Flatpak.runtime-install",
    "org.freedesktop.Flatpak.app-update",
    "org.freedesktop.Flatpak.runtime-update",
]
administrator = true
session = "active"
details = { remote = ["flathub", "nyra"] }
result = "yes"
```

The name of the detail that carries the remote has to be confirmed by observing what Flatpak's
system helper sends (integration tests, below) before this rule goes into an image.

```toml
# /etc/nyra-polkit/rules.d/70-network.toml
# Changing system-wide network connections needs an administrator's password, for everyone,
# administrators included; it is remembered for a few minutes.
[[rule]]
actions = ["org.freedesktop.NetworkManager.settings.modify.system"]
result = "auth_admin_keep"
```

```toml
# /etc/nyra-polkit/rules.d/90-kiosk.toml
# The kiosk account may do nothing that goes through polkit.
[[rule]]
actions = ["*"]
users = ["kiosk"]
result = "no"
```

## Authentication

When the decision is `auth_*` and the caller passed `AllowUserInteraction`:

1. **Agent.** The agent registered for the subject's process, else for its session, else a
   `fallback` agent. An agent is registered by the user of the session it serves, one per session
   (plus fallbacks), and is dropped when its connection leaves the bus. No agent, or no
   `AllowUserInteraction`: the result is "not authorized, challenge" (`is_challenge`), which
   pkcheck reports as exit code 2.
2. **Identities offered.** `auth_self`: the subject's user. `auth_admin`: the subject's user if
   they are an administrator, else every administrator user (the listed users and the members of
   the listed groups).
3. **Cookie.** 128 random bits, used once, tied to the request, the agent and the agent's user.
4. **`BeginAuthentication(action_id, message, icon_name, details, cookie, identities)`** goes to the
   agent, in the locale it registered with. The agent runs `polkit-agent-helper-1` (setuid, or the
   socket-activated service of recent polkit versions), which checks the password with PAM and, as
   root, calls **`AuthenticationAgentResponse2(uid, cookie, identity)`**.
5. **The daemon accepts that answer only when** the caller is root (from the bus), the cookie is
   pending, `uid` is the user of the agent that got the cookie, and the identity is one of those
   offered. Only then is the request authenticated; the agent returning from `BeginAuthentication`
   without it counts as a failure, so an agent can never authorize anything on its own.
6. **The agent returns.** Authenticated: `is_authorized`. `Cancelled` (the user dismissed the
   dialog): not authorized, with `polkit.dismissed`. Anything else: not authorized.

`CancelCheckAuthorization`, or the caller leaving the bus, sends `CancelAuthentication(cookie)` to
the agent and ends the check with `Cancelled`. An agent handles one authentication at a time;
later requests wait in order.

## Temporary authorizations

After a successful authentication for `auth_self_keep` or `auth_admin_keep`, the daemon remembers
(action id, subject, session) for **5 minutes**, counted on the boot clock (`CLOCK_BOOTTIME`), so a
suspended laptop does not keep it. The subject is the exact one that authenticated: the unique bus
name, or the process (pidfd); a restarted application asks again. It is used only while the decision
for that action and subject is still a `_keep` result: a new rule that says `no` wins at once.

It ends early when the subject leaves (bus name gone, process exited), when the session ends, on
`RevokeTemporaryAuthorizations` / `RevokeTemporaryAuthorizationById` (`pkcheck --revoke-temp`), or
when the daemon restarts (they are kept in memory only). Details are not compared: the same action
and subject succeed even with other details, as polkit(8) says; rules that depend on details should
not use the `_keep` results.

## Security

What must hold:

1. A subject never gets more than the decision for its own user, groups and session.
2. A request is authenticated only by `AuthenticationAgentResponse2` from root, for the right
   cookie, agent user and identity.
3. Anything that cannot be determined (subject, session, rules) ends in a denial, never in a grant.

Threat model:

| Who | Tries to | Stopped by |
|---|---|---|
| a local process | ask for another user's subject | subjects of other users only for root and `policykit.owner` users |
| a local process | race a PID (exit, reuse) | pidfds, start time, checking the pidfd after the reads |
| a local process | get a well-known name's credentials | only unique bus names are accepted as subjects |
| a local process | answer an authentication | `AuthenticationAgentResponse2` only from root; random single-use cookies tied to the agent's user |
| another user's agent | see or answer requests of a session | agents are registered by the session's user and only get its requests |
| a remote user (SSH) | use the desktop's `allow_active` | logind `Remote`: `allow_any` |
| a sandboxed app | act as more than its user | it is identified like any other client of the system bus, by the bus |
| anyone | exhaust the daemon | at most 32 checks in flight per connection; size limits on files; no recursion on input |
| a broken or hostile action file | crash or bloat the daemon | parse errors skip the file (its actions stay unknown, so denied); no external DTD or entity loading; node and size limits |
| an administrator's typo | open more than meant | unknown keys are errors, and any error denies everything |

Out of scope: root, the kernel, the services that enforce the answer, and the password check
itself (the helper and PAM).

The service runs as the unprivileged system user `polkitd` (the user that may own the bus name),
with no capabilities, only `AF_UNIX` sockets, a read-only view of the system and the usual systemd
sandboxing. It can still read other users' `/proc/<pid>/stat` and `status` and open their pidfds,
which is all it needs. It never runs code from rules and never calls out to the network.

## Tests

- **Unit tests** (`cargo test`, every pull request): the action XML parser, the rule parser (every
  example above), loading and replacing rule files, and the decision: defaults per session,
  unknown actions, each condition, the most restrictive result winning in any file order.
- **Integration tests** (CI, a Debian 13 container): a private `dbus-daemon` stands in for the
  system bus (`DBUS_SYSTEM_BUS_ADDRESS`), `python-dbusmock`'s logind template provides sessions,
  and `nyra-polkitd` runs with test action and rule directories. Clients: Debian's `pkcheck` and
  our `pkcheck` (same exit codes: 0, 1, 2, 3, 126, 127), `libpolkit-gobject-1` through GObject
  introspection (`CheckAuthorization`, `EnumerateActions`, temporary authorizations, cancellation),
  and a test agent on `libpolkit-agent-1` with the real `polkit-agent-helper-1` and a test user in
  the container. The bus traffic of these clients is recorded, which is how the subject details
  they send are confirmed. The same `pkcheck` matrix also runs against Debian's polkitd (default
  rules only), and the answers must match.
- **In the Nyra OS image** (later, before it replaces polkitd there): the image's own test battery
  in a VM, with a KDE session, NetworkManager, udisks2 and Flatpak.

## Dependencies

Few, and each justified in `Cargo.toml`: `roxmltree` (action XML), `serde` and `toml` (rules), and,
with the D-Bus service, `zbus` (the bus). `cargo deny` checks their licences and advisories on every
pull request.

## Sources

Read for this design; nothing from polkit's source code.

- polkit Reference Manual, `org.freedesktop.PolicyKit1.Authority`:
  <https://www.freedesktop.org/software/polkit/docs/latest/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html>
- polkit Reference Manual, `org.freedesktop.PolicyKit1.AuthenticationAgent`:
  <https://www.freedesktop.org/software/polkit/docs/latest/eggdbus-interface-org.freedesktop.PolicyKit1.AuthenticationAgent.html>
- polkit(8) (actions, defaults, annotations, administrators, `_keep`):
  <https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html>
- pkcheck(1) (options, process forms, exit codes):
  <https://www.freedesktop.org/software/polkit/docs/latest/pkcheck.1.html>
- polkit Reference Manual, `PolkitUnixProcess` and `PolkitSystemBusName` (subject fields):
  <https://www.freedesktop.org/software/polkit/docs/latest/PolkitUnixProcess.html>,
  <https://www.freedesktop.org/software/polkit/docs/latest/PolkitSystemBusName.html>
- D-Bus Specification (`GetConnectionCredentials`, `ProcessFD`, unique names):
  <https://dbus.freedesktop.org/doc/dbus-specification.html>
- org.freedesktop.login1(5) (`GetSession`, `GetSessionByPID`, `Session.Active`, `Session.Remote`,
  `User.Display`): <https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html>
- Linux man pages: pidfd_open(2), proc(5) (`/proc/<pid>/stat` start time, `status` `Uid:`,
  `fdinfo` `Pid:`).
- Observed: action files installed on Debian 13 by systemd and others (`<annotate>` values are the
  element text; `gettext-domain`); `GetConnectionCredentials` on Debian 13's dbus 1.16.2 returns
  `ProcessFD`.
