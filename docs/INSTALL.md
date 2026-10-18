# Installing nyra-polkit on Debian

For the administrator of a Debian-based system with systemd (written for Debian 13 and sid):
install nyra-polkit in place of Debian's `polkitd`, as the Nyra OS image does, adapted to a
running system. Read section 3 first: JavaScript rules are not read.

## 1. What it replaces, what stays, requirements

- **Replaced:** `polkitd` (the daemon owning `org.freedesktop.PolicyKit1`) and `pkcheck`.
- **Stay:** `polkit-agent-helper-1` (password checks), `pkttyagent`, `pkaction`, `libpolkit` and
  every package's action files in `/usr/share/polkit-1/actions`.
- **Not provided:** `pkexec`. **Not read:** JavaScript rules (`*.rules`).
Keep Debian's `polkitd` package installed: the files that stay come from it. Applications,
agents and services such as NetworkManager, udisks2 and Flatpak need no change.

Requirements:

- Linux with systemd (`u!` in the sysusers line needs systemd 257 or newer, where it was added; Debian 13 and sid have it),
  logind (`systemd-logind`) and a system bus that gives each caller's process file descriptor
  (`ProcessFD`; Debian 13's dbus 1.16 does, an older one makes every check fail).
- x86_64 or aarch64 with glibc, a kernel with pidfds (`pidfd_open(2)`), and root.

Read [DESIGN.md](DESIGN.md) ("Decision", "Rules") first: the most restrictive matching rule wins,
and **any error in a rules file makes every request fail closed** (root is still authorized).

## 2. Install from a release

Download a tarball and `SHA256SUMS` from
[GitHub Releases](https://github.com/NyraOS/nyra-polkit/releases) and verify them as the README
describes ([Releases](../README.md#releases)): checksum, signed tag and build attestation. Do not
install one that fails a check. `X.Y.Z` is the version, `ARCH` is `x86_64` or `aarch64`; run
everything as root. Unpack it:

```sh
mkdir /tmp/nyra-polkit && tar -C /tmp/nyra-polkit --strip-components=1 --no-same-owner \
  --no-same-permissions -xzf nyra-polkit-X.Y.Z-ARCH-linux-gnu.tar.gz
cd /tmp/nyra-polkit
```

Three of the files collide with ones of Debian's `polkitd` package. Copying over them would be
undone by the next upgrade of that package without dpkg knowing, so divert them: dpkg then moves
Debian's files aside and keeps them out of the way. Check the owner first (`dpkg -S /usr/bin/pkcheck`
names `polkitd`; if your release ships it elsewhere, divert the same path regardless):

```sh
for f in /usr/bin/pkcheck \
  /usr/share/dbus-1/system.d/org.freedesktop.PolicyKit1.conf \
  /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service; do
  dpkg-divert --local --rename --add "$f"
done
```

The other files have names Debian's packages do not use (`nyra-polkit.service` is not
`polkit.service`, which is only masked below), so they need no diversion. Install the two binaries
and the four `dist/` files, each where its first lines say:

```sh
install -D -m 0755 bin/nyra-polkitd /usr/libexec/nyra-polkitd
install -D -m 0755 bin/pkcheck /usr/bin/pkcheck
install -D -m 0644 dist/nyra-polkit.service /usr/lib/systemd/system/nyra-polkit.service
install -D -m 0644 dist/org.freedesktop.PolicyKit1.conf \
  /usr/share/dbus-1/system.d/org.freedesktop.PolicyKit1.conf
install -D -m 0644 dist/org.freedesktop.PolicyKit1.service \
  /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service
install -D -m 0644 dist/nyra-polkit.sysusers /usr/lib/sysusers.d/nyra-polkit.conf
```

Upgrades of `polkitd` now leave these three files alone (section 5 restores Debian's).

**Write your rules before you start** (section 3). Without an `[administrators]` table only root
is one, so `auth_admin` asks for root's password. At least:

```sh
install -d -m 0755 /etc/nyra-polkit/rules.d
cat >/etc/nyra-polkit/rules.d/50-administrators.toml <<'EOF'
# The sudo group are the administrators: auth_admin asks for their own password.
[administrators]
groups = ["sudo"]
EOF
/usr/libexec/nyra-polkitd --check
```

Create the system user (`polkitd`, as Debian's, so it normally exists already), stop and mask
Debian's daemon, let systemd and the bus read the new files, and start:

```sh
systemd-sysusers nyra-polkit.conf
systemctl stop polkit.service
systemctl mask polkit.service
systemctl daemon-reload
systemctl reload dbus
systemctl start nyra-polkit.service
```

The unit has no `[Install]` section: the bus starts it on the first call. A desktop's
authentication agent connected to the old daemon may need a new login to reconnect.

## 3. Rules

Rules are TOML files, read together and in no particular order:

- `/usr/share/nyra-polkit/rules.d/*.toml`: the distribution's or image's;
- `/etc/nyra-polkit/rules.d/*.toml`: the administrator's. A file here with the name of one in
  `/usr/share` replaces it; an empty one (or only comments) switches it off. A link to
  `/dev/null` does not: it is a rule error.

Both directories, the directories containing them and every file must be owned by root, not
writable by group or others, and the files regular, or all requests are refused. After a change:
`nyra-polkitd --check`, then `systemctl reload nyra-polkit.service`.

The keys are in [DESIGN.md](DESIGN.md#rules). Results, from least to most restrictive: `yes`,
`auth_self_keep`, `auth_self`, `auth_admin_keep`, `auth_admin`, `no`.

### Translating JavaScript rules

Your `.rules` files in `/etc/polkit-1/rules.d` and `/usr/share/polkit-1/rules.d` (packages such as
Flatpak and systemd ship some) are not read: each one you depend on needs a TOML file. These are
the translations the Nyra OS image uses.

**The administrators** (Debian's `50-default.rules` returns `["unix-group:sudo"]` from
`polkit.addAdminRule`): the `[administrators]` file of section 2.

**One answer for some actions, for everyone** (udisks2: a `polkit.addRule` function that returns
`polkit.Result.AUTH_ADMIN` when `action.id` is one of the two ids):

```toml
[[rule]]
actions = ["org.freedesktop.udisks2.loop-setup", "org.freedesktop.udisks2.modify-device"]
result = "auth_admin"
```

**A group, in the active local session** (Flatpak's rule tests `subject.isInGroup("sudo")` and
`subject.local && subject.active` and returns `polkit.Result.YES`):

```toml
[[rule]]
actions = ["org.freedesktop.Flatpak.app-install", "org.freedesktop.Flatpak.runtime-install",
    "org.freedesktop.Flatpak.app-uninstall", "org.freedesktop.Flatpak.runtime-uninstall",
    "org.freedesktop.Flatpak.modify-repo"]
groups = ["sudo"]
session = "active"
result = "yes"
```

**A user** (systemd-networkd: `subject.user == "systemd-network"`):

```toml
[[rule]]
actions = ["org.freedesktop.hostname1.set-hostname", "org.freedesktop.timedate1.set-timezone"]
users = ["systemd-network"]
result = "yes"
```

An action that no installed package defines is refused whatever the rules say. The other
conditions (`session = "local"`, `details`, `administrator`, `prefix.*`) are in DESIGN.md.

### What cannot be translated

- **Anything computed**: loops, regular expressions, `polkit.spawn`. A rule has only the
  conditions of the table in DESIGN.md; write out the list the code produced.
- **Exceptions to a broader rule.** There is no negation ("all of `wheel` except X"): list what is
  allowed, or denied.
- **A catch-all for a group.** `actions = ["*"]` is accepted only with `result = "no"`, and a
  prefix such as `org.*` with any other result only logs a warning at each load. A wildcard that
  granted would also loosen every action whose default is `no`, including those of packages
  installed later. Name the actions.
- **First match wins.** Here order does not matter: if an old `50-` file allowed what an old
  `10-` file denied, the translation denies it.

## 4. Check that it works

```sh
nyra-polkitd --check; echo $?    # as /usr/libexec/nyra-polkitd; 0 valid, 1 not
busctl --system status org.freedesktop.PolicyKit1
pkcheck --version
```

`--check` reads the action files and rules as the service does, without the bus. `busctl` must
show `nyra-polkitd` as the owner, `pkcheck --version` must end with `(nyra-polkit)`. Ask for an
action (`$$` is your shell's process). The exit code is 0 (authorized), 1 (not authorized),
2 (authentication needed), 3 (dismissed), 126 (bad options) or 127 (error):

```sh
pkcheck --action-id org.freedesktop.login1.reboot --process $$; echo $?
pkcheck --action-id org.freedesktop.login1.reboot --process $$ --allow-user-interaction; echo $?
```

The journal has each rule file read, replaced or switched off, any error (which denies every
request but root's until fixed and reloaded), denied checks and authentications:

```sh
journalctl -u nyra-polkit.service -b
```

## 5. Going back to polkitd

Stop the daemon, remove what you installed, remove the diversions (dpkg moves Debian's files
back), unmask and start:

```sh
systemctl stop nyra-polkit.service
rm /usr/libexec/nyra-polkitd /usr/lib/systemd/system/nyra-polkit.service \
  /usr/lib/sysusers.d/nyra-polkit.conf /usr/bin/pkcheck \
  /usr/share/dbus-1/system.d/org.freedesktop.PolicyKit1.conf \
  /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service
for f in /usr/bin/pkcheck \
  /usr/share/dbus-1/system.d/org.freedesktop.PolicyKit1.conf \
  /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service; do
  dpkg-divert --rename --remove "$f"
done
systemctl unmask polkit.service
systemctl daemon-reload
systemctl reload dbus
systemctl start polkit.service
```

Debian's `pkcheck`, bus policy and activation file are back. The `polkitd` user
stays (Debian's own). Your TOML files are no longer read and may be removed. Check with
`busctl --system status org.freedesktop.PolicyKit1`: the owner is `polkitd` again.
