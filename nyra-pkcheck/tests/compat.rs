// SPDX-License-Identifier: MIT
//! Our pkcheck next to Debian's, against nyra-polkitd on a private, system-like bus
//! (docs/DESIGN.md, "Tests"): for the same options, both must exit with the same code, print the
//! same details and comparable diagnostics. The bus and the daemon are the shared harness's
//! (`tests/common/harness.rs`, as in nyra-polkitd's `tests/dbus.rs`); the fake logind is this
//! file's own and knows no session.
//!
//! Needs root, a writable `/sys/fs/cgroup` (to put pkcheck in a session's scope), `dbus-daemon`,
//! Debian's `pkcheck`, `setpriv`, `setsid`, `timeout`, the users `polkitd` and `nobody`, and nyra-polkitd
//! built next to our pkcheck: the integration job of CI runs them in a privileged Debian 13
//! container with `cargo test --test dbus --test compat -- --ignored`.
//!
//! Every wait has a timeout, so a regression fails the test instead of hanging the job.

// The harness shared with nyra-polkitd's tests/dbus.rs: one file, included with `#[path]` from
// both crates' tests (why not a crate of its own: see the top of the file).
#[path = "../../tests/common/harness.rs"]
mod harness;

use harness::Harness;
use nyra_polkitd::process::Process;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

const ACTIONS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<policyconfig>
  <action id="org.nyra.test.default">
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
  <action id="org.nyra.test.ruled">
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>no</allow_active>
    </defaults>
  </action>
  <action id="org.nyra.test.denied">
    <defaults>
      <allow_any>yes</allow_any>
      <allow_inactive>yes</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
  <action id="org.nyra.test.challenge">
    <defaults>
      <allow_any>auth_admin_keep</allow_any>
      <allow_inactive>auth_admin_keep</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
"#;

const RULES: &str = r#"
[[rule]]
actions = ["org.nyra.test.ruled"]
users = ["root"]
result = "yes"

[[rule]]
actions = ["org.nyra.test.denied"]
result = "no"
"#;

const DEFAULT: &str = "org.nyra.test.default";
const RULED: &str = "org.nyra.test.ruled";
const DENIED: &str = "org.nyra.test.denied";
const CHALLENGE: &str = "org.nyra.test.challenge";
const UNKNOWN: &str = "org.nyra.test.unknown";

/// logind knowing no session: every process gets `allow_any`, and a `unix-session` subject is
/// unknown.
struct FakeManager;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.login1")]
enum LogindError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoSessionForPID(String),
    NoSuchSession(String),
    NoSuchUser(String),
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl FakeManager {
    #[zbus(name = "GetSessionByPID")]
    fn get_session_by_pid(&self, pid: u32) -> Result<OwnedObjectPath, LogindError> {
        Err(LogindError::NoSessionForPID(format!("{pid}")))
    }

    fn get_session(&self, id: String) -> Result<OwnedObjectPath, LogindError> {
        Err(LogindError::NoSuchSession(id))
    }

    fn get_user(&self, uid: u32) -> Result<OwnedObjectPath, LogindError> {
        Err(LogindError::NoSuchUser(format!("{uid}")))
    }
}

/// Our pkcheck, built by cargo for this test.
const OURS: &str = env!("CARGO_BIN_EXE_pkcheck");

/// nyra-polkitd, built in the same target directory by the same `cargo test` (its own tests are
/// built with it).
fn daemon_binary() -> PathBuf {
    let path = Path::new(OURS).with_file_name("nyra-polkitd");
    assert!(
        path.exists(),
        "{} is not built: run `cargo test --test dbus --test compat`",
        path.display()
    );
    path
}

/// The shared harness with this file's own fake logind on the bus: the harness, and the
/// connection serving the logind (kept alive for the length of the test).
fn start(test: &str) -> (Harness, Connection) {
    futures_lite::future::block_on(Harness::start(
        test,
        &[
            ("actions/test.policy", ACTIONS),
            ("image/50-test.toml", RULES),
        ],
        "",
        false,
        FakeManager,
        &daemon_binary(),
    ))
}

/// What the diagnostics of both must have in common.
#[derive(Debug, Clone, Copy)]
enum Stderr {
    /// The same text.
    Same,
    /// The same text once numbers (PIDs) are left out.
    SameButNumbers,
    /// Both start with this; the rest differs.
    Prefix(&'static str),
    /// Both non-empty; the texts differ.
    Differs,
}

struct Answer {
    code: i32,
    stdout: String,
    stderr: String,
}

fn answer(output: Output) -> Answer {
    Answer {
        code: output.status.code().expect("pkcheck killed by a signal"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn without_numbers(text: &str) -> String {
    text.chars().filter(|c| !c.is_ascii_digit()).collect()
}

/// Debian's lines of GLib's own complaints (`** (pkcheck:42): CRITICAL **`) and the blank lines
/// around them, which are not pkcheck's diagnostics.
fn without_glib_noise(text: &str) -> String {
    let mut kept = String::new();
    for line in text.lines() {
        if !line.is_empty() && !line.starts_with("** (") && !line.starts_with('(') {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

/// Runs Debian's pkcheck and ours with the same options; both must exit with `code`, print the
/// same details on standard output and diagnostics that compare as `stderr` says.
fn same(
    bus: &Harness,
    user: Option<&str>,
    cgroup: Option<&Path>,
    args: &[&str],
    code: i32,
    stderr: Stderr,
) {
    let debian = answer(bus.run(user, cgroup, "pkcheck", args));
    let ours = answer(bus.run(user, cgroup, OURS, args));
    let debian_stderr = without_glib_noise(&debian.stderr);
    let context = format!(
        "{args:?} as {user:?}\nDebian: {} {:?} {:?}\nours:   {} {:?} {:?}",
        debian.code, debian.stdout, debian.stderr, ours.code, ours.stdout, ours.stderr
    );
    assert_eq!(debian.code, code, "Debian's exit code, {context}");
    assert_eq!(ours.code, code, "our exit code, {context}");
    if ![0, 1, 2, 3, 126, 127].contains(&code) {
        panic!("not an exit code of pkcheck(1): {context}");
    }
    assert_eq!(ours.stdout, debian.stdout, "standard output, {context}");
    if code == 0 {
        assert_eq!(ours.stderr, "", "{context}");
        assert_eq!(debian_stderr, "", "{context}");
        return;
    }
    assert!(ours.stderr.ends_with('\n'), "{context}");
    match stderr {
        Stderr::Same => assert_eq!(ours.stderr, debian_stderr, "{context}"),
        Stderr::SameButNumbers => assert_eq!(
            without_numbers(&ours.stderr),
            without_numbers(&debian_stderr),
            "{context}"
        ),
        Stderr::Prefix(prefix) => {
            assert!(debian_stderr.starts_with(prefix), "{context}");
            assert!(ours.stderr.starts_with(prefix), "{context}");
        }
        Stderr::Differs => {
            assert!(!debian_stderr.is_empty(), "{context}");
            assert!(!ours.stderr.is_empty(), "{context}");
        }
    }
}

/// A process to be a subject, killed at the end of the test.
struct Sleeper(Child);

impl Sleeper {
    fn start(user: Option<&str>) -> Self {
        let mut command = Command::new("setpriv");
        if let Some(user) = user {
            command.args([
                &format!("--reuid={user}"),
                "--regid=nogroup",
                "--clear-groups",
            ]);
        }
        Self(command.args(["--", "sleep", "600"]).spawn().unwrap())
    }

    fn pid(&self) -> String {
        self.0.id().to_string()
    }

    fn start_time(&self) -> u64 {
        Process::open(self.0.id()).unwrap().start_time().unwrap()
    }

    /// `pid,start-time,uid`, as pkcheck(1) recommends.
    fn full(&self, uid: u32) -> String {
        format!("{},{},{uid}", self.pid(), self.start_time())
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const NOBODY: u32 = 65534;

#[test]
#[ignore = "needs root, dbus-daemon and Debian's pkcheck: run by the integration job"]
fn the_same_answers_as_debians_pkcheck() {
    use Stderr::*;
    let (bus, _logind) = start("answers");
    let root = Sleeper::start(None);
    let nobody = Sleeper::start(Some("nobody"));
    let pid = root.pid();
    let full = root.full(0);
    let own_name = bus.client.unique_name().unwrap().to_string();
    let check = |action: &'static str, process: &str| -> Vec<String> {
        ["--action-id", action, "--process", process]
            .map(String::from)
            .to_vec()
    };
    let same_as_root = |args: &[String], code: i32, stderr: Stderr| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        same(&bus, None, None, &args, code, stderr);
    };

    // Authorized (a rule for root), in every form of subject.
    same_as_root(&check(RULED, &pid), 0, Same);
    same_as_root(&check(RULED, &full), 0, Same);
    let start_time = root.start_time();
    same_as_root(&check(RULED, &format!("{pid},{start_time}")), 0, Same);
    same_as_root(&["-a", RULED, "-s", &own_name].map(String::from), 0, Same);
    let mut with_details = check(RULED, &pid);
    with_details.extend(["--detail", "k", "v", "-d", "føl,你好", "x"].map(String::from));
    same_as_root(&with_details, 0, Same);

    // Root is authorized for every known action, whatever a rule or the default says; an unknown
    // action is not authorized, for root too.
    same_as_root(&check(DENIED, &pid), 0, Same);
    same_as_root(&check(DEFAULT, &full), 0, Same);
    same_as_root(&check(CHALLENGE, &pid), 0, Same);
    same_as_root(&check(UNKNOWN, &pid), 1, Same);

    // Not authorized, for nobody's own process (no session): a rule says no, the default says no,
    // or the action is unknown.
    let nobody_full = nobody.full(NOBODY);
    let as_nobody = |args: &[&str], code: i32, stderr: Stderr| {
        same(&bus, Some("nobody"), None, args, code, stderr);
    };
    as_nobody(&["-a", DENIED, "-p", &nobody_full], 1, Same);
    as_nobody(&["-a", DEFAULT, "-p", &nobody_full], 1, Same);
    as_nobody(&["-a", UNKNOWN, "-p", &nobody_full], 1, Same);

    // A password is needed: without -u, with -u and no agent; an internal agent cannot be made.
    as_nobody(&["-a", CHALLENGE, "-p", &nobody_full], 2, Same);
    let mut interactive = vec![
        "-a",
        CHALLENGE,
        "-p",
        &nobody_full,
        "--allow-user-interaction",
    ];
    as_nobody(&interactive, 2, Same);
    interactive.push("--enable-internal-agent");
    as_nobody(&interactive, 126, Differs);
    // An internal agent is only made when one is needed.
    let mut internal = check(RULED, &pid);
    internal.extend(["-u", "--enable-internal-agent"].map(String::from));
    same_as_root(&internal, 0, Same);

    // Errors from the authority: a bus name with no owner, a detail only root may pass.
    same_as_root(
        &["-a", RULED, "-s", ":1.999999"].map(String::from),
        127,
        Same,
    );
    let error = "Error checking for authorization org.nyra.test.default: ";
    let message = [
        "-a",
        DEFAULT,
        "-p",
        &nobody.pid(),
        "-d",
        "polkit.message",
        "x",
    ];
    same(&bus, Some("nobody"), None, &message, 127, Same);
    // Another user's process, asked about by a user who is not root.
    same(
        &bus,
        Some("nobody"),
        None,
        &["-a", DEFAULT, "-p", &pid],
        127,
        Same,
    );
    // Its own process: not authorized (no session, allow_any is "no").
    let own = ["-a", DEFAULT, "-p", &nobody.full(NOBODY)];
    same(&bus, Some("nobody"), None, &own, 1, Same);

    // The process is not the one meant: another start time, another uid, or it is gone.
    let other_start = format!("{pid},{},0", start_time + 1);
    same_as_root(&check(DEFAULT, &other_start), 127, Prefix(error));
    let other_uid = format!("{pid},{start_time},{NOBODY}");
    same_as_root(&check(DEFAULT, &other_uid), 127, Prefix(error));
    let mut gone = Command::new("true").spawn().unwrap();
    let gone_pid = gone.id().to_string();
    gone.wait().unwrap();
    same_as_root(&check(DEFAULT, &gone_pid), 127, Prefix(error));
}

#[test]
#[ignore = "needs root, dbus-daemon and Debian's pkcheck: run by the integration job"]
fn the_same_refusals_of_malformed_options() {
    use Stderr::*;
    let (bus, _logind) = start("malformed");
    let root = |args: &[&str], stderr: Stderr| same(&bus, None, None, args, 126, stderr);
    root(&[], Same);
    root(&["--action-id"], Same);
    root(&["-a", RULED], Same);
    root(&["-a", RULED, "--process"], Same);
    root(&["-a", RULED, "--system-bus-name"], Same);
    root(&["-a", RULED, "--process", "abc"], Same);
    root(&["-a", RULED, "--process", ",1"], Same);
    root(&["-a", RULED, "-p", "1", "--detail"], Same);
    root(&["-a", RULED, "-p", "1", "--detail", "k"], Same);
    root(&["-a", RULED, "-p", "1", "--bogus"], Same);
    root(&["-a", RULED, "-p", "1", "extra"], Same);
    root(&["-a", RULED, "-p", "1", "--"], Same);
    root(&["--action-id=x", "--process=1"], Same);
    root(&["-ua", RULED, "-p", "1"], Same);
    root(&["--help", "extra"], Same);
    root(&["--version", "--bogus"], Same);
    // Debian's pkcheck takes the bus's own name for a subject and then says it has none.
    root(&["-a", RULED, "-s", "org.freedesktop.DBus"], Differs);

    for program in ["pkcheck", OURS] {
        for args in [
            &["--help"][..],
            &["-h"],
            &["--version"],
            &["--version", "--list-temp"],
        ] {
            let output = answer(bus.run(None, None, program, args));
            assert_eq!(output.code, 0, "{program} {args:?}");
            assert!(output.stdout.contains("pkcheck"), "{program} {args:?}");
        }
    }
}

#[test]
#[ignore = "needs root, dbus-daemon and Debian's pkcheck: run by the integration job"]
fn where_ours_refuses_and_debians_guesses() {
    let (bus, _logind) = start("refuses");
    let root = Sleeper::start(None);
    let pid = root.pid();
    // Debian's pkcheck reads these as best it can (and fails later, or asks about pid 1); ours
    // refuses them as malformed (126).
    for args in [
        vec!["-a", RULED, "-p", "1,x"],
        vec!["-a", RULED, "-p", "1x"],
        vec!["-a", RULED, "-p", "1,"],
        vec!["-a", RULED, "-p", "1,2,3,4"],
        vec!["-a", RULED, "-p", "-5"],
        vec!["-a", RULED, "-p", "0"],
        vec!["-a", RULED, "-p", "1,0"],
        vec!["-p", &pid],
        vec!["-a", RULED, "-a", RULED, "-p", &pid],
        vec!["-a", RULED, "-p", &pid, "-p", &pid],
        vec!["-a", RULED, "-p", &pid, "-s", ":1.0"],
        // Two values for one detail: rules match on details.
        vec!["-a", RULED, "-p", &pid, "-d", "k", "a", "-d", "k", "b"],
        // A check next to an option that does something else: no exit code the authority did
        // not give.
        vec!["-a", DENIED, "-p", &pid, "--help"],
        vec!["-a", DENIED, "-p", &pid, "--version"],
        vec!["-a", DENIED, "-p", &pid, "--list-temp"],
        vec!["-a", DENIED, "-p", &pid, "--revoke-temp"],
        vec!["--version", "-u"],
        vec!["--list-temp", "-d", "k", "v"],
        vec!["--revoke-temp", "--enable-internal-agent"],
        vec!["--help", "-s", ":1.0"],
    ] {
        let output = answer(bus.run(None, None, OURS, &args));
        assert_eq!(output.code, 126, "{args:?}: {}", output.stderr);
        assert!(
            output.stderr.starts_with("pkcheck: "),
            "{args:?}: {}",
            output.stderr
        );
        assert_eq!(output.stdout, "", "{args:?}");
    }
    // What Debian's pkcheck answers there: 0, for an action that is denied or a detail it
    // dropped, without asking the authority (docs/DESIGN.md, "pkcheck").
    let denied_with = |option| ["-a", DENIED, "-p", &pid, option].map(String::from);
    for args in [denied_with("--help"), denied_with("--version")] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(
            answer(bus.run(None, None, "pkcheck", &args)).code,
            0,
            "{args:?}"
        );
    }
    let repeated = ["-a", RULED, "-p", &pid, "-d", "k", "a", "-d", "k", "b"];
    assert_eq!(answer(bus.run(None, None, "pkcheck", &repeated)).code, 0);
}

#[test]
#[ignore = "needs root, dbus-daemon, Debian's pkcheck and a writable /sys/fs/cgroup: run by the integration job"]
fn temporary_authorizations_of_the_session() {
    use Stderr::*;
    let (bus, _logind) = start("temporary");
    // Outside any session: both refuse before calling the authority.
    for option in ["--list-temp", "--revoke-temp"] {
        same(&bus, None, None, &[option], 1, SameButNumbers);
        same(&bus, Some("nobody"), None, &[option], 1, SameButNumbers);
    }

    // In a session's scope, as logind places a login's processes: both ask the authority about
    // that session, which (with this logind) does not exist, or (before temporary authorizations
    // are served) for a method it does not have.
    let user_slice = Path::new("/sys/fs/cgroup/user.slice");
    let scope = user_slice.join("user-0.slice/session-t1.scope");
    std::fs::create_dir_all(&scope).expect("a writable /sys/fs/cgroup (see the top)");
    for option in ["--list-temp", "--revoke-temp"] {
        same(&bus, None, Some(&scope), &[option], 1, Stderr::Same);
    }
    let _ = std::fs::remove_dir(&scope);
    let _ = std::fs::remove_dir(scope.parent().unwrap());
    let _ = std::fs::remove_dir(user_slice);
}
