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
| `RegisterAuthenticationAgent` | subject, `s` locale, `s` object path | the user the subject (a session, a process or a bus name of that user) belongs to |
| `RegisterAuthenticationAgentWithOptions` | the same, `a{sv}` options (`fallback`: `b`) | the same |
| `UnregisterAuthenticationAgent` | subject, `s` object path | the connection that registered it |
| `AuthenticationAgentResponse` | `s` cookie, identity | nobody: `NotSupported` |
| `AuthenticationAgentResponse2` | `u` uid, `s` cookie, identity | root only (the helper) |
| `EnumerateTemporaryAuthorizations` | subject → `a(ss(sa{sv})tt)` | the subject's user, or root |
| `RevokeTemporaryAuthorizations` | subject | the subject's user, or root |
| `RevokeTemporaryAuthorizationById` | `s` id | the authorization's user, or root |

The caller is always identified by the bus (`GetConnectionCredentials` on its unique name), never by
what it says. A subject that cannot be identified is refused with a generic `NotAuthorized`
("cannot identify the subject"); the reason goes only to the journal, since it may name other
users' processes and uids, which `/proc` mounted with `hidepid` would hide.

The object path of an agent is an `s`, not an `o`: the reference manual gives it as a string, and
Debian's polkitd introspects it as `s`.

Properties: `BackendName` = `nyra-polkit`, `BackendVersion`, `BackendFeatures` = 1 (temporary
authorizations). `CheckAuthorization` returns one struct, `(bba{ss})`, not three values: polkit's
client library expects the struct. The `Changed` signal is sent after the rules are reread and when
a temporary authorization appears or is revoked (see "Temporary authorizations" for expiry). Errors
use the documented names
(`org.freedesktop.PolicyKit1.Error.Failed`, `Cancelled`, `NotSupported`, `NotAuthorized`,
`CancellationIdNotUnique`).

`CheckAuthorization` flags: only `AllowUserInteraction` (1). Details whose names start with `polkit.`
are refused unless documented (`polkit.message`, `polkit.gettext_domain`, `polkit.icon_name`), and
those only from root; `polkit.message` and `polkit.icon_name` replace the action's text and icon in
the dialog. Result details: `polkit.temporary_authorization_id` (authorized by a temporary
authorization, or one was just created), `polkit.retains_authorization_after_challenge` (a `_keep`
result, a challenge or just authenticated), `polkit.dismissed`; their values are `true`, as Debian's
polkitd sends (the manual only asks for a non-empty string).

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
- **`unix-process`** (`pid`: `u`, `start-time`: `t`; client libraries may also send `uid`, an `i`
  that is -1 when unknown, and recent ones a `pidfd`, `h`): with a pidfd, the process is the pidfd's, and `pid` must match it. Without one,
  the daemon opens a pidfd for `pid`, then reads the start time from `/proc/<pid>/stat`: a different
  start time (or 0) means the PID was reused or never pinned, and the check fails. The user is the
  real uid from `/proc/<pid>/status`. When the subject carries a `uid` that differs from it, the
  process changed users since the caller looked, and the check fails.
- **`unix-session`** (`session-id`: `s`): the session and its user come from logind (`GetSession`);
  an unknown session fails the check.

**No PID race.** Everything read about a process (uid, session) is read while holding its pidfd,
and the pidfd is checked after the reads: if the process is still alive, the PID could not have
been given to another process in between, so what was read is about the right process.

**Session state**, from logind. A process's session is `GetSessionByPID`. Only the error
`org.freedesktop.login1.NoSessionForPID` means "no session"; any other failure (logind unreachable,
no answer within 10 s, an unexpected reply) ends the check with `NotAuthorized`, never with
`allow_any`. The 10 s are well under the 25 s that D-Bus clients usually wait, so a stuck logind
gives them a refusal, not their own timeout.

**A session of another user is not the subject's.** When the session `GetSessionByPID` returns
belongs to another user (its `User`), the subject has no local session (`allow_any`). Only root
keeps the session's state. `GetSessionByPID` gives the session a process was started in, not one of
its user: whoever sits at the seat and runs `su B` or `sudo -u B` in a terminal leaves B's
processes in their own local, active session. B may be logged in only over SSH, and can reach
those processes from there (ptrace, where the ptrace scope allows it, or their files), so they must
not get `allow_active`. Root is the exception because root in a user's session (`sudo udisksctl`)
was started by the person at the seat, and root can do anything anyway.

A process without a session gets its user's display session (`User.Display`) only when its cgroup
(`/proc/<pid>/cgroup`, read under the pidfd) is inside that same user's
`user.slice/user-<uid>.slice/user@<uid>.service`: apps that the desktop starts through
`systemd --user` then count as being in the user's session. The user's processes in system units
(cron, at, services with `User=`) stay without a session.

**Local needs a seat.** logind reports some sessions as active and not remote although nobody sits
at them: every logged-in or lingering user has a `manager` session (the user manager's own,
`Class=manager`) with no seat, `Remote=no` and `Active=yes`, and `GetSessionByPID` returns it for
the user manager. So a session, whether found by PID, through `User.Display` or named by a
`unix-session` subject, is:

| logind | State | Action default used |
|---|---|---|
| `Remote` false, `Seat` set, `Active` true | local, active | `allow_active` |
| `Remote` false, `Seat` set, `Active` false | local, inactive | `allow_inactive` |
| remote, or no seat, or no session at all | not local | `allow_any` |

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
- within the rules in force, a `no` is final, whatever the other files say; to lift it, root
  replaces the file that holds it (see "Rules"), and the replacement is logged;
- each rule can be read on its own: what it says is the least that applies when it matches.

The price: no exceptions to a broader rule ("deny everything to `kiosk` except one action" is
written by listing what is denied). Rules have no negation in the first version.

Rules replace the default; they do not add to it. A rule that says `auth_admin` for an action whose
default is `no` makes that action possible with a password. That is why `actions = ["*"]` is only
allowed with `result = "no"`: a wildcard that grants anything would loosen every action whose
default is `no`, including the ones installed later. A short prefix such as `org.*` or `io.*`
(fewer than two parts before the `*`) with any result other than `no` weakens almost as much; it
is allowed, but a warning is logged each time the rules are loaded.

Unknown actions are denied before any rule is looked at, so no rule can grant an action that no
installed program defines. An action id defined in two action files is unknown too: which
definition is right cannot be known. An action file that declares an XML entity (`<!ENTITY`) is
refused as a whole, logged, and its actions are unknown: real files declare none, and expanding
entities could blow a small file up to hundreds of megabytes. The usual `<!DOCTYPE>` line is fine.

## Rules

Rule files are TOML: the image's in `/usr/share/nyra-polkit/rules.d/*.toml`, the administrator's
in `/etc/nyra-polkit/rules.d/*.toml`. A file in `/etc` replaces the image file with the same name;
a file there without rules (empty, or only comments) switches the image's file off. Both are logged.
All other files apply together; their order does not matter.

**Only root can write rules.** Both `rules.d` directories, the directories that contain them
(`/usr/share/nyra-polkit`, `/etc/nyra-polkit`; otherwise `rules.d` could be swapped for another
directory of root's) and every rule file must be owned by root and not writable by group or others,
and every rule file must be a regular file. Files are opened with `O_NONBLOCK`, so a FIFO is
refused instead of blocking the daemon, and checked on the opened file (fstat), so a symbolic link
is judged by its target. Anything else is a rule error, as sudo does for sudoers. So is a file
name that is not UTF-8; names starting with `.` (editor leftovers such as `.#50-local.toml`) are
ignored.

**A link to `/dev/null` does not disable a file.** It is the way systemd disables a unit, but here
its target is not a regular file, so it is a rule error and every request fails closed. That is
safe, only surprising. To switch off a file of the image, put an empty file (or one with only
comments) with the same name in `/etc/nyra-polkit/rules.d`; the error message says so.

A file may have an `[administrators]` table (`users`, `groups`) and any number of `[[rule]]`
tables. The administrators of all files add up; without any, root is the administrator.
Administrators are who `auth_admin` asks for a password, and who `administrator = true` matches.

A rule holds when every condition it sets holds:

| Key | Meaning |
|---|---|
| `actions` | required: action ids; `org.example.*` matches ids starting with `org.example.`; `*` every id, only with `result = "no"` |
| `users`, `groups` | the subject's user is listed, or is in a listed group (both absent: anyone) |
| `administrator` | `true`: only administrators |
| `session` | `"local"`: a local session, active or not; `"active"`: the local session in the foreground |
| `details` | for each name, the service passed that detail with one of the listed values |
| `result` | required: `yes`, `auth_self_keep`, `auth_self`, `auth_admin_keep`, `auth_admin` or `no` |

Unknown keys, wrong types and malformed action ids are errors. **Any error in any rule file, or a
rule file or directory that is not trusted, makes the daemon deny every request** until it is fixed
(see "Logging"). The daemon keeps running and keeps its bus name, so clients get an answer, not a
missing service; `systemctl reload` once the files are fixed restores normal answers. Skipping the broken
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

1. **Agent.** An agent is registered for a subject of the registering user: a session (desktop
   agents), a process or a bus name (`pkttyagent --process`, `--system-bus-name`); not even root
   registers one for another user. Each subject has at most one agent besides `fallback` ones, and
   a user at most 16 agents. An agent is removed by `UnregisterAuthenticationAgent` from the
   connection that registered it (same subject and path), or when that connection leaves the bus.
   A request goes to the agent registered for the subject itself (its bus name, or its process),
   else for its session; fallback agents only when no other agent serves the subject (as the
   manual describes `fallback`); among equals, the first registered. **Every agent, fallback agents
   included, only gets requests whose subject belongs to the agent's user.** No agent, or no
   `AllowUserInteraction`: the result is "not authorized, challenge" (`is_challenge`), which
   pkcheck reports as exit code 2.
2. **Identities offered.** `auth_self`: the subject's user. `auth_admin`: the subject's user if
   they are an administrator, else every administrator user (the listed users and the members of
   the listed groups, from the group's member list in the user database: users whose primary group
   it is are not listed there, as with `usermod -aG sudo`). No identity at all: not authorized.
3. **Cookie.** 128 random bits from getrandom(2), used once, tied to the request, the agent and the
   agent's user.
4. **`BeginAuthentication(action_id, message, icon_name, details, cookie, identities)`** goes to the
   agent, the message in the locale it registered with, the caller's details as they came, the
   identities as `unix-user` with a `u` `uid`. The call has no timeout: typing a password takes
   as long as it takes. The agent runs `polkit-agent-helper-1` (setuid, or the
   socket-activated service of recent polkit versions), which checks the password with PAM and, as
   root, calls **`AuthenticationAgentResponse2(uid, cookie, identity)`**.
5. **The daemon accepts that answer only when** the caller is root (from the bus), the cookie is
   pending, `uid` is the user of the agent that got the cookie, and the identity is one of those
   offered. Only then is the request authenticated; the agent returning from `BeginAuthentication`
   without it counts as a failure, so an agent can never authorize anything on its own.
6. **The agent returns.** Authenticated: `is_authorized`. `Cancelled` (the user dismissed the
   dialog): not authorized, with `polkit.dismissed`. Anything else: not authorized.

`CancelCheckAuthorization`, or the caller leaving the bus, sends `CancelAuthentication(cookie)` to
the agent and ends the check with `Cancelled`; the cookie is forgotten with the check. The caller
leaving ends all its checks, interactive or not. An agent handles one authentication at a time;
later requests wait their turn, and the agent is chosen again when the turn comes (the one chosen
first may have been unregistered meanwhile). The daemon's bus policy lets its user call agents
(`org.freedesktop.PolicyKit1.AuthenticationAgent`), which are ordinary connections of the users.

**The rules decide before the dialog.** The decision and the identities offered come from the
rules in force when the check started. If the rules are reread while the authentication runs (an
administrator removed, a result changed), the check ends not authorized and keeps nothing, even
when the helper answers for an identity offered before. The rules carry a generation number; the
authentication compares it, and keeps its temporary authorization, while it reads the rules, and a
reload clears the temporary authorizations while it writes them, so nothing granted under the old
rules survives.

**Waiting does not take a service's slots.** A check that waits for an agent can wait as long as
the user takes, and system services ask for every user on one connection. So once a check goes to
an agent it no longer counts in its caller's 32; it counts in its subject user's authentications
instead, at most 16 waiting or in a dialog. Beyond that the answer is the challenge, without a
dialog. A user whose agent never closes its dialogs only holds their own requests.

## Temporary authorizations

After a successful authentication for `auth_self_keep` or `auth_admin_keep`, the daemon remembers
(action id, subject, session, level) for **5 minutes**, counted on the boot clock
(`CLOCK_BOOTTIME`), so a suspended laptop does not keep it. The subject is the exact one that
authenticated: the unique bus name, or the process (pidfd); a restarted application asks again. The
level is what was asked: the user's own password (`auth_self_keep`) or an administrator's
(`auth_admin_keep`).

It is used only while the current decision for that action and subject is a `_keep` result that
asks for no more than its level: an `auth_admin_keep` authorization answers `auth_self_keep` and
`auth_admin_keep`; an `auth_self_keep` one answers only `auth_self_keep`, never `auth_admin_keep`
(the decision can change when the session goes inactive). Any other decision (`no`, `auth_admin`)
wins at once.

It ends early when its bus name leaves the bus, on `RevokeTemporaryAuthorizations` /
`RevokeTemporaryAuthorizationById` (`pkcheck --revoke-temp`), when the rules are reread (all of
them; and an authentication still running then keeps none), or when the daemon restarts (they are
kept in memory only). One for a process that exited, or for a session that ended, can no longer be
used, since a new process or session never has the same start time or id; it stays in the list until
it expires. Expiry is checked whenever the list is used, on the boot clock, so an expired
authorization is never used or listed; no timer runs for it, so no `Changed` is sent at that moment.
Details are not compared: the same action and subject succeed even with other details, as polkit(8)
says; rules that depend on details should not use the `_keep` results.

`EnumerateTemporaryAuthorizations` and `RevokeTemporaryAuthorizations` take any subject: a session
stands for every authorization of the subject's user in that session (`pkcheck --list-temp` and
`--revoke-temp` name the caller's session), a process or a bus name for its own. A user other than
root only names their own subjects and revokes their own authorizations by id; an id that does not
exist and one of another user get the same error.

## pkcheck

`pkcheck` (the `nyra-pkcheck` crate) is a client of the interface above with the options, output
and exit codes of pkcheck(1). The integration tests run it next to Debian 13's `pkcheck` (polkit
126) against `nyra-polkitd`, and both must answer the same.

| Option | Meaning |
|---|---|
| `--action-id`, `-a` ACTION | the action to check |
| `--process`, `-p` PID[,START_TIME[,UID]] | the subject: a process |
| `--system-bus-name`, `-s` NAME | the subject: the owner of a unique bus name |
| `--detail`, `-d` KEY VALUE | a detail for the check; repeatable |
| `--allow-user-interaction`, `-u` | the `AllowUserInteraction` flag |
| `--enable-internal-agent` | not supported (below) |
| `--list-temp`, `--revoke-temp` | the temporary authorizations of the current session |
| `--version`, `--help`, `-h` | |

As with Debian's pkcheck, each value is its own argument (no `--option=value`, no `--`, no grouped
one-letter options) and anything else is "Unexpected argument". Of `--help`, `--version`,
`--list-temp` and `--revoke-temp`, the first in that order wins; next to an option of a check they
are malformed (below).

**The process is pinned.** `--process` opens a pidfd for the PID and reads, under it, the start
time and the real uid; a start time or uid given by the caller must be the process's, or pkcheck
fails (127) without asking: the PID then names another process than the one meant. The subject
carries `pid` (`u`), `start-time` (`t`), `uid` (`i`) and the `pidfd` (`h`), so an authority that
takes a pidfd (nyra-polkitd) uses it, and one that does not (Debian's polkitd, observed) has the
start time. `--system-bus-name` takes only unique names.

**Output.** The details of the answer go to standard output as `KEY=VALUE` lines, keys sorted, with
every byte outside `[a-zA-Z0-9_]` written as `\` and its octal value, as pkcheck(1) shows. The
octal value is not padded (`,` is `\54`), as in pkcheck(1)'s example and Debian's output: a digit
after a short escape is ambiguous to a reader, but no byte can add a line or an `=`. Diagnostics go
to standard error, worded as Debian's pkcheck words them.

| Exit code | When |
|---|---|
| 0 | authorized |
| 1 | not authorized; for `--list-temp` and `--revoke-temp`, no session or a refusal (as Debian's) |
| 2 | not authorized, an authentication is needed: without `-u`, or with `-u` and no agent |
| 3 | the authentication was dismissed (`polkit.dismissed` in the answer) |
| 126 | malformed options; `--enable-internal-agent` when an agent would be needed |
| 127 | any other error: the bus, the process, or an error from the authority |

A check without `-u` waits at most 25 s, the usual D-Bus timeout; with `-u` it waits for the user.

**The session** of `--list-temp` and `--revoke-temp` is the one pkcheck runs in: logind puts each
session's processes in `session-<id>.scope` directly under their user's slice
(`/user.slice/user-<uid>.slice/`, cgroup v2), and Debian's pkcheck was observed to find it there
too. Outside one, both print `Error getting session: No session for pid <pid>` and exit with 1.
The subject sent is that `unix-session`. pkcheck(1) does not define the listing; ours is one line
per authorization: `<id>: <action> for <subject kind> <key>=<value>..., obtained <n> s ago,
expires in <m> s`, with the authority's strings escaped as details are.

**`--enable-internal-agent`** would need a text authentication agent inside pkcheck, which would
need the protocol of `polkit-agent-helper-1`; it is not documented, so pkcheck does not have one.
The option is accepted and only matters when a check with `-u` needs an authentication that no
agent answered: pkcheck then exits with 126 and says to run an agent (for example `pkttyagent`).
Debian's pkcheck exits with 126 there too when it cannot make its agent (no terminal), which is
the case for services and scripts.

**Where it differs from Debian's pkcheck**, on purpose:

- A `--process` field that is not all digits, more than three fields, a PID or start time of 0, or
  a PID or uid above 2^31 - 1 are malformed (126). Debian's pkcheck reads `1,x`, `1x` and `1,` as
  PID 1, uses the first three of `1,2,3,4`, and sends `-5` or `0` to the authority.
- A second `--action-id`, or a second subject (`--process` or `--system-bus-name`), is malformed:
  which one was meant cannot be known. Debian's pkcheck uses the last one.
- A `--detail` key given twice is malformed: rules match on details, and which value was meant
  cannot be known. Debian's pkcheck accepts it.
- `--help`, `--version`, `--list-temp` or `--revoke-temp` next to an option of a check (`-a`, `-p`,
  `-s`, `-d`, `-u`, `--enable-internal-agent`) is malformed (126). Debian's pkcheck does the other
  thing and exits with 0 without asking the authority, observed even for an action that is denied:
  a script that runs `if pkcheck ...` would take that for "authorized".
- No `--action-id` is malformed (126); Debian's pkcheck fails a GLib assertion and exits with 127.
- A bus name that is not unique is "Invalid --system-bus-name value" (126); Debian's pkcheck says
  "Subject not specified" (126).
- A system bus that cannot be reached is an error (127, as pkcheck(1) says); Debian's pkcheck
  exits with 126.
- A process that is gone, or whose start time or uid is not the one given, fails before the call
  (127, as with Debian's, whose authority refuses it), with a message of our own.
- `--help` has its own text; a malformed option never shows the manual page, even on a terminal.
  `--version` prints `pkcheck version <version> (nyra-polkit)`.

**Never setuid.** pkcheck connects to the bus named by `DBUS_SYSTEM_BUS_ADDRESS` when it is set (so
the tests can use a private bus), and the authority answers whoever answers there. It must never be
installed setuid or setgid, and a privileged process must not run it with an environment it took
from an unprivileged one: a caller could then point it at a bus of its own, with an "authority"
that says yes to everything.

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
| another user's agent | see or answer requests of a session | every agent, fallback agents included, only gets requests for subjects of its own user |
| a remote user (SSH) | use the desktop's `allow_active` from the SSH session | the SSH session is remote, and the user manager's session has no seat: both `allow_any` |
| a remote user (SSH) | use their processes left in another user's local session (`su`, `sudo -u` at the seat) | a session of another user is not local, except for root |
| a local user | write rules | rule files and directories must be root's and not writable by others |
| a sandboxed app | act as more than its user | it is identified like any other client of the system bus, by the bus |
| anyone | exhaust the daemon | at most 32 checks in flight per connection and 64 per user other than root, and 16 agents per user; calls to logind time out (10 s); `TasksMax=` in the unit; size limits on files; no recursion on input |
| a local user | fill a system service's connection with dialogs that never close, so its checks for everyone else fail | checks waiting for an agent leave the connection's 32 and count per subject user (at most 16); beyond that, the challenge without a dialog |
| an administrator's change | be undone by a dialog opened before it | an authentication that started under rules since reread is not authorized and keeps nothing |
| a broken or hostile action file | crash or bloat the daemon | parse errors skip the file (its actions stay unknown, so denied); no external DTD or entity loading; node and size limits |
| an administrator's typo | open more than meant | unknown keys are errors, and any error denies everything |

Out of scope: root, the kernel, the services that enforce the answer, and the password check
itself (the helper and PAM).

**Accepted limit: the same user is not a boundary.** The user manager (`user@<uid>.service`) is
shared by all of a user's sessions. A user logged in at the machine and, at the same time, over
SSH can start a process through `systemd --user` from the SSH session; it then counts as being in
the display session and gets `allow_active`. The same holds for anything else running as that
user. polkit's sessions separate users, not the sessions of one user.

The service runs as the unprivileged system user `polkitd` (the user that may own the bus name),
with no capabilities, only `AF_UNIX` sockets, a read-only view of the system and the usual systemd
sandboxing. It can still read other users' `/proc/<pid>/stat` and `status` and open their pidfds,
which is all it needs. It never runs code from rules and never calls out to the network.

**Limits.** A user can open many connections to the bus (dbus-daemon allows 256 per user), and every
check may wait on logind, while the bus limits the replies the daemon itself may be waiting for (128
by default). So besides the 32 checks per connection, one user (the callers' uid) has at most 64
checks in flight over all their connections, and no user alone can fill the daemon's replies. Checks
waiting for an agent are counted apart, per subject user (see "Authentication"), so the dialogs of
one user cannot fill a service's connection either. Root is not counted: root's callers are the
system services (logind, NetworkManager, udisks2...), and a user can make them ask on the user's
behalf, so one pool shared by all of them would let one user use it up and make every service's
checks fail for everyone. Each service connection keeps its limit of 32, and users cannot open
connections as root. Reads of `/proc` and of the user database (NSS, which may be LDAP or SSSD) run
as blocking tasks, off the bus executor, so a slow lookup holds only its own check.

**No memory limit in the unit.** The bus accepts messages up to 32 MiB, and zbus turns a call's
arguments into Rust values before the daemon sees the call or its size, so one `CheckAuthorization`
from any user with 32 MiB of small details takes the daemon to about 250 MB for a moment. A
`MemoryMax=` below that lets any user have the daemon killed (OOM) with one call; repeated, the
kills hit systemd's start limit and every check then fails for everyone. `MemoryHigh=` only slows
the daemon until it stops answering. So the unit sets no memory limit: memory is bounded by the
bus's limits (message size, connections per user) and the checks in flight. An integration test
sends such a call to the daemon in a cgroup with the unit's memory settings and no swap, and checks
that the same daemon still answers.

The files that install it are in `dist/`: the systemd unit (`nyra-polkit.service`, with this
sandboxing), the bus policy (only `polkitd` may own the name; anyone may call it), the bus
activation file and the sysusers.d line for `polkitd` (`u!`, a locked account, as on Debian). A
static user rather than `DynamicUser=`: the bus policy names the user, and the bus reads it before a
dynamic user would exist.

## Logging

To the journal, with sd-daemon priority prefixes:

- **Rule loads:** every file read, every image file that a file in `/etc` replaces or switches off,
  the administrators in force, and any error (with the file and the reason).
- **While the rules are broken:** every check is denied, and the message saying so is logged at
  most once a minute, with the number of checks denied since the last one, so the journal cannot
  be flooded.
- **Agents:** each registration and removal (user, session or process, bus name, fallback or not).
- **Authentications:** each attempt (when it starts waiting for an agent, and when it reaches one)
  and its result (action, subject user and PID, the agent, the
  identities offered and the one authenticated, authorized, dismissed or failed), and each
  `AuthenticationAgentResponse2` refused, with the reason.
- **Temporary authorizations:** created, used, and revoked or expired.
- **Action files:** files skipped and action ids dropped as defined twice.
- **Refused subjects:** why a subject could not be identified (the caller only gets a generic
  error), and a caller whose credentials the bus does not give.

Cookies are never logged.

## Tests

- **Unit tests** (`cargo test`, every pull request): the action XML parser (action ids defined
  twice included), the rule parser (every example above), loading and replacing rule files, the
  ownership and mode checks, the session state from logind's properties, and the decision:
  defaults per session, unknown actions, each condition, the most restrictive result winning in any
  file order.
- **Integration tests** (CI, a Debian 13 container, as root; `cargo test --test dbus -- --ignored`):
  a private `dbus-daemon` with the system bus's default policy and the bus policy from `dist/`
  stands in for the system bus (`DBUS_SYSTEM_BUS_ADDRESS`), and `nyra-polkitd` runs as the
  `polkitd` user with test action and rule directories. logind is a fake served by the test on the
  same bus, so each test process can be given any session, no session, a logind failure, no answer
  at all, or an answer held back until the test has acted (a generic mock cannot answer
  `GetSessionByPID` per PID). The container is privileged, so that a test can put a process under
  a user's service manager (a cgroup). Every wait of the tests has a timeout, so a regression fails
  instead of hanging. Clients: Debian's `pkcheck`, `busctl` (for the subjects `pkcheck` cannot send,
  `unix-session`) and our `pkcheck`, run next to Debian's with the same options (same exit codes,
  0, 1, 2, 126, 127, the same details and the same or comparable diagnostics; `tests/compat.rs` of
  `nyra-pkcheck`), and the real agent stack: Debian's `pkttyagent` (on `libpolkit-agent-1`) in a
  pseudo-terminal from `script`, with Debian 13's setuid `polkit-agent-helper-1`, PAM and test users
  that the test makes with random passwords, no login shell, and removes when it ends. It covers
  the right and a wrong password, `auth_self`, `auth_admin` (an administrator chosen among the
  identities offered), `auth_self_keep` and its authorization used again without a dialog, a
  cancellation by the caller, the end of input, Ctrl-C and a killed
  agent. The helper does not follow `DBUS_SYSTEM_BUS_ADDRESS` and connects to the system bus's own
  socket, so that test's bus listens there too, in a container where no system bus runs. For the
  protocol's corner cases the tests also have their own agent: the test binary, run again as
  another user, registers as an agent and passes each dialog on to the test, which answers
  `AuthenticationAgentResponse2` as root, like the helper. Planned, not written yet:
  `libpolkit-gobject-1` through GObject introspection (`CheckAuthorization`,
  `EnumerateActions`, temporary authorizations, cancellation); recorded bus traffic of the
  clients, to confirm the subject details they send; and the same `pkcheck` matrix against
  Debian's polkitd (default rules only), whose answers must match.
- **In the Nyra OS image** (later, before it replaces polkitd there): the image's own test battery
  in a VM, with a KDE session, NetworkManager, udisks2 and Flatpak.

## Dependencies

Few, and each justified in `Cargo.toml`: `roxmltree` (action XML), `serde` and `toml` (rules),
`zbus` (the bus, with its own small async runtime, no tokio) and `nix` (user names and groups from
NSS). `rustix` (pidfds, getrandom(2), `CLOCK_BOOTTIME`), `async-signal` (SIGHUP), `async-channel`
(cancellation), `async-lock` (one authentication at a time per agent), `blocking` (NSS and `/proc`
reads off the executor) and `futures-lite` are used directly but come with zbus anyway;
so does `async-io`, used by the tests for timeouts. `pkcheck` adds none: it parses its options by
hand and uses `zbus`, `futures-lite` and the daemon's own `Process`. `cargo deny` checks their
licences and advisories on every pull request.

## Sources

Read for this design; nothing from polkit's source code.

- polkit Reference Manual, `org.freedesktop.PolicyKit1.Authority`:
  <https://www.freedesktop.org/software/polkit/docs/latest/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html>
- polkit Reference Manual, `org.freedesktop.PolicyKit1.AuthenticationAgent`:
  <https://www.freedesktop.org/software/polkit/docs/latest/eggdbus-interface-org.freedesktop.PolicyKit1.AuthenticationAgent.html>
- pkttyagent(1) (`--process`, `--system-bus-name`, `--fallback`):
  <https://www.freedesktop.org/software/polkit/docs/latest/pkttyagent.1.html>
- polkit(8) (actions, defaults, annotations, administrators, `_keep`):
  <https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html>
- pkcheck(1) (options, process forms, output of details, exit codes):
  <https://www.freedesktop.org/software/polkit/docs/latest/pkcheck.1.html>
- polkit Reference Manual, `PolkitTemporaryAuthorization` (times in seconds since the epoch):
  <https://www.freedesktop.org/software/polkit/docs/latest/PolkitTemporaryAuthorization.html>
- polkit Reference Manual, `PolkitUnixProcess` and `PolkitSystemBusName` (subject fields):
  <https://www.freedesktop.org/software/polkit/docs/latest/PolkitUnixProcess.html>,
  <https://www.freedesktop.org/software/polkit/docs/latest/PolkitSystemBusName.html>
- D-Bus Specification (`GetConnectionCredentials`, `ProcessFD`, unique names):
  <https://dbus.freedesktop.org/doc/dbus-specification.html>
- dbus-daemon(1) and the default limits listed in the system bus configuration
  (`/usr/share/dbus-1/system.conf`: `max_connections_per_user` 256, `max_replies_per_connection`
  128): <https://dbus.freedesktop.org/doc/dbus-daemon.1.html>
- org.freedesktop.login1(5) (`GetSession`, `GetSessionByPID`, `Session.Active`, `Session.Remote`,
  `Session.User`, `User.Display`):
  <https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html>
- Linux man pages: pidfd_open(2), proc(5) (`/proc/<pid>/stat` start time, `status` `Uid:`,
  `fdinfo` `Pid:`).
- Observed: action files installed on Debian 13 by systemd and others (`<annotate>` values are the
  element text; `gettext-domain`); `GetConnectionCredentials` on Debian 13's dbus 1.16.2 returns
  `ProcessFD`; on Debian 13's systemd 257, each user's `manager` session has no seat, `Remote=no`
  and `Active=yes`; Debian 13's `pkcheck` (polkit 126) sends a `unix-process` subject with `pid`
  (`u`), `start-time` (`t`) and `uid` (`i`), no pidfd, and reads the result of `CheckAuthorization`
  as one `(bba{ss})` struct.
- Observed on Debian 13 with its polkitd, `pkttyagent` and `polkit-agent-helper-1` (bus traffic,
  introspection): the agent's object path is an `s`; `pkttyagent --process` registers a
  `unix-process` subject; `BeginAuthentication` carries identities as `unix-user` with a `u` `uid`;
  the helper calls `AuthenticationAgentResponse2` as root with the agent user's uid and waits for
  its reply before the agent returns; a `_keep` success answers `polkit.temporary_authorization_id`
  and `polkit.retains_authorization_after_challenge` = `true`, a later check without user
  interaction is authorized by it, and `Changed` is sent when it is created;
  `EnumerateTemporaryAuthorizations` there accepts only `unix-session` subjects.
- Observed on Debian 13 (polkit 126), with nyra-polkitd: `polkit-agent-helper-1` is installed
  setuid root in `/usr/lib/polkit-1/`, with no socket-activated service for it, and connects to
  `/run/dbus/system_bus_socket` whatever the agent's `DBUS_SYSTEM_BUS_ADDRESS`, and checks the
  password with PAM (the package installs `/usr/lib/pam.d/polkit-1`). `pkttyagent` lists several identities by name and asks
  which one; after a wrong password or an end of input it returns from `BeginAuthentication`
  without an error and without an answer from the helper; Ctrl-C ends it. After
  `CancelAuthentication` it shows "Cancelled" only once its read of the terminal ends, and then
  answers neither call and shows no other dialog (the same with Debian's polkitd); after an end of
  input it ends every later dialog at once.
- Observed, Debian 13's `pkcheck` (polkit 126) run as a black box against its polkitd and against
  nyra-polkitd: its options and one-letter forms, what it refuses and with which message, its exit
  codes (126 for malformed options, also for a missing bus and when it cannot make its internal
  agent; 127 for errors), its diagnostics, the details it prints, the session it takes from its
  cgroup for `--list-temp` and `--revoke-temp` (a `unix-session` subject), and that Debian's
  polkitd accepts a subject with a `pidfd` next to `start-time` and `uid`.
