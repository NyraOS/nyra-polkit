// SPDX-License-Identifier: MIT
//! nyra-polkitd on a private, system-like bus (docs/DESIGN.md, "Tests"), with the bus policy from
//! `dist/`. The daemon runs as the `polkitd` user, as the service does; logind is a fake served by
//! the test on the same bus, so each process can be put in any session. Clients: zbus, Debian's
//! `pkcheck` and `busctl`.
//!
//! Authentication agents are this test binary run again as another user ([`fake_agent_program`]):
//! each registers with the daemon and passes every dialog on to the test (the "relay"), which plays
//! the user and, as root, the helper that answers `AuthenticationAgentResponse2`. One test runs the
//! real stack instead ([`debians_agent_and_helper_check_real_passwords`]): Debian's `pkttyagent` in
//! a pseudo-terminal, its setuid `polkit-agent-helper-1` and PAM, with test users it makes and
//! gives random passwords.
//!
//! Needs root (to create rule files owned by root and to run processes as other users), a writable
//! `/sys/fs/cgroup` (to put a process under a user's service manager), `dbus-daemon`, `pkcheck`,
//! `pkttyagent`, `busctl`, `setpriv`, `timeout`, `script`, `useradd`, `groupadd`, `chpasswd`, the
//! users `polkitd`, `nobody` and `daemon`, and no system bus running (the helper only connects to
//! the system bus's own address, so the test bus takes it): the integration job of CI runs them in a
//! privileged Debian 13 container with `cargo test --test dbus -- --ignored`.
//!
//! Every wait has a timeout, so a regression fails the test instead of hanging the job.

// The harness shared with nyra-pkcheck's tests/compat.rs: one file, included with `#[path]`
// from both crates' tests (why not a crate of its own: see the top of the file).
#[path = "../../tests/common/harness.rs"]
mod harness;

use futures_lite::StreamExt;
use harness::{TIMEOUT, connect, wait_until, write_trusted};
use nyra_polkitd::bus::MAX_CALL_SIZE;
use nyra_polkitd::process::Process;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::message::Type as MessageType;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MatchRule, MessageStream, interface};

const NAME: &str = "org.freedesktop.PolicyKit1";
const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

const ACTIONS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>nyra-polkit tests</vendor>
  <action id="org.nyra.test.default">
    <description>Do the default thing</description>
    <description xml:lang="ro">Fă lucrul implicit</description>
    <message>Authentication is required</message>
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
  <action id="org.nyra.test.owned">
    <annotate key="org.freedesktop.policykit.owner">unix-user:42</annotate>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
  <action id="org.nyra.test.owned-by-name">
    <annotate key="org.freedesktop.policykit.owner">unix-user:nobody</annotate>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
  <!-- Without "unix-user:", 42 names nobody. -->
  <action id="org.nyra.test.owned-bare">
    <annotate key="org.freedesktop.policykit.owner">42</annotate>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
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
  <action id="org.nyra.test.self">
    <message>Authenticate yourself</message>
    <message xml:lang="en_US">Authenticate yourself, in English</message>
    <icon_name>test-icon</icon_name>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
  <action id="org.nyra.test.self-keep">
    <defaults>
      <allow_any>auth_self_keep</allow_any>
      <allow_inactive>auth_self_keep</allow_inactive>
      <allow_active>auth_self_keep</allow_active>
    </defaults>
  </action>
  <action id="org.nyra.test.admin">
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
  </action>
  <!-- The user's own password in the foreground, an administrator's otherwise. -->
  <action id="org.nyra.test.levels">
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>auth_admin_keep</allow_inactive>
      <allow_active>auth_self_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
"#;

const RULES: &str = r#"
[administrators]
users = ["nobody", "bin"]

[[rule]]
actions = ["org.nyra.test.ruled"]
users = ["nobody"]
result = "yes"

[[rule]]
actions = ["org.nyra.test.denied"]
result = "no"
"#;

/// A misspelt condition: a rule error, so every check is denied.
const BROKEN_RULES: &str = r#"
[[rule]]
actions = ["org.nyra.test.default"]
sesion = "active"
result = "no"
"#;

const DEFAULT: &str = "org.nyra.test.default";
const RULED: &str = "org.nyra.test.ruled";
const DENIED: &str = "org.nyra.test.denied";
const CHALLENGE: &str = "org.nyra.test.challenge";
const UNKNOWN: &str = "org.nyra.test.unknown";
const OWNED: &str = "org.nyra.test.owned";
const OWNED_BARE: &str = "org.nyra.test.owned-bare";
const OWNED_BY_NAME: &str = "org.nyra.test.owned-by-name";
const SELF: &str = "org.nyra.test.self";
const SELF_KEEP: &str = "org.nyra.test.self-keep";
const ADMIN: &str = "org.nyra.test.admin";
const LEVELS: &str = "org.nyra.test.levels";

/// `AllowUserInteraction`.
const ALLOW: u32 = 1;
const NOBODY: u32 = 65534;
const DAEMON: u32 = 1;
const BIN: u32 = 2;

type Answer = (bool, bool, HashMap<String, String>);
/// id, action id, subject, obtained, expires.
type TemporaryAuthorization = (
    String,
    String,
    (String, HashMap<String, OwnedValue>),
    u64,
    u64,
);
const YES: (bool, bool) = (true, false);
const NO: (bool, bool) = (false, false);
const CHALLENGED: (bool, bool) = (false, true);

// pkcheck(1) exit codes; an error (127) is checked through the D-Bus error it prints.
const PKCHECK_AUTHORIZED: i32 = 0;
const PKCHECK_NOT_AUTHORIZED: i32 = 1;
const PKCHECK_CHALLENGE: i32 = 2;

// --- The fake logind ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct FakeSession {
    uid: u32,
    remote: bool,
    seat: &'static str,
    active: bool,
}

const LOCAL_ACTIVE: FakeSession = FakeSession {
    uid: 0,
    remote: false,
    seat: "seat0",
    active: true,
};

/// What `GetSessionByPID` answers for a PID; PIDs not listed have no session.
enum ByPid {
    Session(&'static str),
    /// An error other than `NoSessionForPID`.
    Fail,
    /// Never answers; tells the test when the call arrives.
    Hang(async_channel::Sender<()>),
    /// Tells the test when the call arrives, then answers this session once the test releases it.
    Delayed {
        arrived: async_channel::Sender<()>,
        release: async_channel::Receiver<()>,
        session: &'static str,
    },
}

#[derive(Default)]
struct LogindState {
    by_pid: HashMap<u32, ByPid>,
    sessions: HashMap<String, FakeSession>,
    users: Vec<u32>,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.login1")]
enum LogindError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoSessionForPID(String),
    NoSuchSession(String),
    NoSuchUser(String),
    Broken(String),
}

fn session_path(id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("/org/freedesktop/login1/session/{id}")).unwrap()
}

fn user_path(uid: u32) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("/org/freedesktop/login1/user/_{uid}")).unwrap()
}

struct FakeManager(Arc<Mutex<LogindState>>);

#[interface(name = "org.freedesktop.login1.Manager")]
impl FakeManager {
    #[zbus(name = "GetSessionByPID")]
    async fn get_session_by_pid(&self, pid: u32) -> Result<OwnedObjectPath, LogindError> {
        let (arrived, release) = match self.0.lock().unwrap().by_pid.get(&pid) {
            None => return Err(LogindError::NoSessionForPID(format!("{pid}"))),
            Some(ByPid::Session(id)) => return Ok(session_path(id)),
            Some(ByPid::Fail) => return Err(LogindError::Broken("logind failed".into())),
            Some(ByPid::Hang(arrived)) => (arrived.clone(), None),
            Some(ByPid::Delayed {
                arrived,
                release,
                session,
            }) => (arrived.clone(), Some((release.clone(), *session))),
        };
        arrived.send(()).await.unwrap();
        let Some((release, session)) = release else {
            return futures_lite::future::pending().await;
        };
        release.recv().await.unwrap();
        Ok(session_path(session))
    }

    async fn get_session(&self, id: String) -> Result<OwnedObjectPath, LogindError> {
        match self.0.lock().unwrap().sessions.contains_key(&id) {
            true => Ok(session_path(&id)),
            false => Err(LogindError::NoSuchSession(id)),
        }
    }

    async fn get_user(&self, uid: u32) -> Result<OwnedObjectPath, LogindError> {
        match self.0.lock().unwrap().users.contains(&uid) {
            true => Ok(user_path(uid)),
            false => Err(LogindError::NoSuchUser(format!("{uid}"))),
        }
    }
}

struct FakeSessionObject(String, FakeSession);

#[interface(name = "org.freedesktop.login1.Session")]
impl FakeSessionObject {
    #[zbus(property)]
    fn id(&self) -> String {
        self.0.clone()
    }
    #[zbus(property)]
    fn remote(&self) -> bool {
        self.1.remote
    }
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        let path = match self.1.seat {
            "" => "/",
            _ => "/org/freedesktop/login1/seat/seat0",
        };
        (
            self.1.seat.to_string(),
            OwnedObjectPath::try_from(path).unwrap(),
        )
    }
    #[zbus(property)]
    fn active(&self) -> bool {
        self.1.active
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        (self.1.uid, user_path(self.1.uid))
    }
}

struct FakeUserObject {
    display: &'static str,
}

#[interface(name = "org.freedesktop.login1.User")]
impl FakeUserObject {
    #[zbus(property)]
    fn display(&self) -> (String, OwnedObjectPath) {
        // A user without a display session: logind answers ("", "/").
        let path = match self.display {
            "" => OwnedObjectPath::try_from("/").unwrap(),
            id => session_path(id),
        };
        (self.display.to_string(), path)
    }
}

// --- The harness -------------------------------------------------------------------------------

/// The shared harness (tests/common/harness.rs), with these tests' own fake logind on the bus:
/// the connection serving it and its state, so a test can place any process in any session.
struct Harness {
    shared: harness::Harness,
    logind: Connection,
    logind_state: Arc<Mutex<LogindState>>,
}

/// The bus policy these tests need beyond the shared one: the relay the fake agents pass their
/// dialogs to, and monitoring of the bus.
const BUS_POLICY: &str = r#"  <policy user="root">
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Monitoring"/>
    <allow own="org.nyra.test.Relay"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.nyra.test.Relay"/>
  </policy>
"#;

/// `future`, or a failed test once [`TIMEOUT`] has passed.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    let timeout = async {
        async_io::Timer::after(TIMEOUT).await;
        panic!("timed out waiting for {what}");
    };
    futures_lite::future::or(future, timeout).await
}

impl Harness {
    async fn start(test: &str, local_rules: &str) -> Self {
        Self::start_with(test, local_rules, false).await
    }

    /// The same, with the bus also at the system bus's own address, for the setuid helper. Only
    /// one test may do that, and only where no system bus runs.
    async fn start_on_system_socket(test: &str, local_rules: &str) -> Self {
        Self::start_with(test, local_rules, true).await
    }

    async fn start_with(test: &str, local_rules: &str, system_socket: bool) -> Self {
        let logind_state = Arc::new(Mutex::new(LogindState::default()));
        let (shared, logind) = harness::Harness::start(
            test,
            &[
                ("actions/test.policy", ACTIONS),
                ("image/50-test.toml", RULES),
                ("local/90-local.toml", local_rules),
            ],
            BUS_POLICY,
            system_socket,
            FakeManager(logind_state.clone()),
            Path::new(env!("CARGO_BIN_EXE_nyra-polkitd")),
        )
        .await;
        Self {
            shared,
            logind,
            logind_state,
        }
    }

    async fn add_session(&self, id: &str, session: FakeSession) {
        self.logind
            .object_server()
            .at(session_path(id), FakeSessionObject(id.to_string(), session))
            .await
            .unwrap();
        let mut state = self.logind_state.lock().unwrap();
        state.sessions.insert(id.to_string(), session);
    }

    async fn add_user_with_display(&self, uid: u32, display: &'static str) {
        self.logind
            .object_server()
            .at(user_path(uid), FakeUserObject { display })
            .await
            .unwrap();
        self.logind_state.lock().unwrap().users.push(uid);
    }

    fn place(&self, pid: u32, answer: ByPid) {
        self.logind_state.lock().unwrap().by_pid.insert(pid, answer);
    }

    async fn call_check(
        &self,
        subject: &Subject,
        action: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<zbus::Message> {
        self.shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "CheckAuthorization",
                &(subject, action, details, flags, cancellation_id),
            )
            .await
    }

    async fn check_with(
        &self,
        subject: &Subject,
        action: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> Result<Answer, String> {
        let reply = self
            .call_check(subject, action, details, flags, cancellation_id)
            .await
            .map_err(error_name)?;
        // One struct, as polkit's client library expects.
        assert_eq!(reply.body().signature().to_string(), "(bba{ss})");
        Ok(reply.body().deserialize::<Answer>().unwrap())
    }

    /// The error a check is refused with: its name and its message.
    async fn refusal(&self, subject: &Subject, action: &str) -> (String, String) {
        match self
            .call_check(subject, action, HashMap::new(), 0, "")
            .await
        {
            Err(zbus::Error::MethodError(name, message, _)) => {
                (name.to_string(), message.unwrap_or_default())
            }
            other => panic!("not refused: {other:?}"),
        }
    }

    /// The answer, without its details, or the error's name.
    async fn check(&self, subject: &Subject, action: &str) -> Result<(bool, bool), String> {
        self.check_with(subject, action, HashMap::new(), 0, "")
            .await
            .map(|(authorized, challenge, _)| (authorized, challenge))
    }

    /// The same session, in another state (the user switched away, or back).
    async fn change_session(&self, id: &str, session: FakeSession) {
        self.logind
            .object_server()
            .remove::<FakeSessionObject, _>(session_path(id))
            .await
            .unwrap();
        self.add_session(id, session).await;
    }

    /// Runs pkcheck as `user` or as root: see [`pkcheck_answer`].
    fn pkcheck_as(&self, user: Option<&str>, arguments: &[&str]) -> Result<i32, String> {
        pkcheck_answer(self.shared.run(user, None, "pkcheck", arguments))
    }

    fn pkcheck(&self, action: &str, process: &str) -> Result<i32, String> {
        self.pkcheck_as(None, &["--action-id", action, "--process", process])
    }

    async fn cancel(&self, cancellation_id: &str) -> Result<(), String> {
        self.shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "CancelCheckAuthorization",
                &(cancellation_id),
            )
            .await
            .map(|_| ())
            .map_err(error_name)
    }

    fn reload(&self) {
        let pid = rustix::process::Pid::from_raw(self.shared.daemon.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
    }
}

/// pkcheck's exit code (0, 1 or 2), or for an error (127) the D-Bus error it printed. A 127
/// without one (a shell's "command not found" is 127 too) or any other exit fails the test.
fn pkcheck_answer(output: Output) -> Result<i32, String> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    match output.status.code() {
        Some(code @ (PKCHECK_AUTHORIZED | PKCHECK_NOT_AUTHORIZED | PKCHECK_CHALLENGE)) => Ok(code),
        Some(127) => {
            let error = stderr
                .split_once("GDBus.Error:")
                .and_then(|(_, rest)| rest.split_once(':'))
                .map(|(name, _)| name.to_string());
            Err(error.unwrap_or_else(|| panic!("pkcheck failed without a D-Bus error: {stderr}")))
        }
        _ => panic!("pkcheck: {}, {stderr}", output.status),
    }
}

fn error_name(error: zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => panic!("not a D-Bus error: {other}"),
    }
}

const NOT_AUTHORIZED: &str = "org.freedesktop.PolicyKit1.Error.NotAuthorized";
const FAILED: &str = "org.freedesktop.PolicyKit1.Error.Failed";
const CANCELLED: &str = "org.freedesktop.PolicyKit1.Error.Cancelled";

type Subject = (&'static str, HashMap<&'static str, Value<'static>>);

fn unix_process(pid: u32) -> Subject {
    let start_time = Process::open(pid).unwrap().start_time().unwrap();
    unix_process_with(pid, start_time, None)
}

fn unix_process_with(pid: u32, start_time: u64, uid: Option<i32>) -> Subject {
    let mut details = HashMap::from([
        ("pid", Value::U32(pid)),
        ("start-time", Value::U64(start_time)),
    ]);
    if let Some(uid) = uid {
        details.insert("uid", Value::I32(uid));
    }
    ("unix-process", details)
}

/// A process subject with the uid the client saw.
fn unix_process_with_uid(pid: u32, uid: u32) -> Subject {
    let start_time = Process::open(pid).unwrap().start_time().unwrap();
    unix_process_with(pid, start_time, Some(uid as i32))
}

fn bus_name(name: &str) -> Subject {
    (
        "system-bus-name",
        HashMap::from([("name", Value::from(name.to_string()))]),
    )
}

fn unix_session(id: &str) -> Subject {
    (
        "unix-session",
        HashMap::from([("session-id", Value::from(id.to_string()))]),
    )
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
        let child = command.args(["--", "sleep", "600"]).spawn().unwrap();
        // Until setpriv has changed users and run sleep, the process is still root's setpriv: a
        // check of it then would be about root.
        let comm = format!("/proc/{}/comm", child.id());
        wait_until("the sleeper", || {
            std::fs::read_to_string(&comm).is_ok_and(|name| name == "sleep\n")
        });
        Self(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn me() -> u32 {
    std::process::id()
}

/// A pidfd for a process, as a client opens it.
fn pidfd(pid: u32) -> std::os::fd::OwnedFd {
    let pid = rustix::process::Pid::from_raw(pid as i32).unwrap();
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap()
}

/// A `unix-process` subject pinned by the client's pidfd, as recent client libraries send it.
fn unix_process_with_pidfd(pid: u32, pidfd: std::os::fd::OwnedFd) -> Subject {
    (
        "unix-process",
        HashMap::from([("pid", Value::U32(pid)), ("pidfd", Value::Fd(pidfd.into()))]),
    )
}

/// Sends a check of `subject` for DEFAULT without waiting for its answer.
async fn send_check(connection: &Connection, subject: &Subject) {
    let message = zbus::Message::method_call(PATH, "CheckAuthorization")
        .unwrap()
        .destination(NAME)
        .unwrap()
        .interface(INTERFACE)
        .unwrap()
        .build(&(subject, DEFAULT, HashMap::<&str, &str>::new(), 0u32, ""))
        .unwrap();
    connection.send(&message).await.unwrap();
}

/// Waits until `count` calls have arrived at the fake logind.
async fn arrivals(at_logind: &async_channel::Receiver<()>, count: usize) {
    within("calls to logind", async {
        for _ in 0..count {
            at_logind.recv().await.unwrap();
        }
    })
    .await;
}

/// The daemon's timeout on logind (`CALL_TIMEOUT` in main.rs): a check held at the fake logind
/// ends by itself after it.
const LOGIND_TIMEOUT: Duration = Duration::from_secs(10);

/// Fails, saying why, when more than half of [`LOGIND_TIMEOUT`] has passed since `sent` the first
/// of the checks a limit test holds at logind: the limit would then be checked against checks
/// that may already have timed out. The other half is the margin for the last assertions.
fn assert_still_held(sent: Instant) {
    assert!(
        sent.elapsed() < LOGIND_TIMEOUT / 2,
        "too slow: the held checks were sent {:?} ago and time out after {LOGIND_TIMEOUT:?}",
        sent.elapsed()
    );
}

// --- The tests ---------------------------------------------------------------------------------

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn answers_from_rules_and_defaults_for_every_subject_kind() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("answers", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let nobody = Sleeper::start(Some("nobody"));
        bus.place(nobody.pid(), ByPid::Session("c2"));
        // A connection of nobody's: a fake agent, whose own name is the subject.
        let (connection, connection_name) = bus.agent("nobody", "x|session|c2|0").unwrap();
        bus.place(connection.child.id(), ByPid::Session("c2"));

        for subject in [
            unix_process(nobody.pid()),
            bus_name(&connection_name),
            unix_session("c2"),
        ] {
            assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES), "{subject:?}");
            assert_eq!(bus.check(&subject, RULED).await, Ok(YES), "{subject:?}");
            assert_eq!(bus.check(&subject, DENIED).await, Ok(NO), "{subject:?}");
            assert_eq!(
                bus.check(&subject, CHALLENGE).await,
                Ok(CHALLENGED),
                "{subject:?}"
            );
            assert_eq!(bus.check(&subject, UNKNOWN).await, Ok(NO), "{subject:?}");
        }

        let pid = nobody.pid().to_string();
        assert_eq!(bus.pkcheck(DEFAULT, &pid), Ok(PKCHECK_AUTHORIZED));
        assert_eq!(bus.pkcheck(RULED, &pid), Ok(PKCHECK_AUTHORIZED));
        assert_eq!(bus.pkcheck(DENIED, &pid), Ok(PKCHECK_NOT_AUTHORIZED));
        assert_eq!(bus.pkcheck(CHALLENGE, &pid), Ok(PKCHECK_CHALLENGE));
        assert_eq!(bus.pkcheck(UNKNOWN, &pid), Ok(PKCHECK_NOT_AUTHORIZED));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn root_is_authorized_for_every_known_action() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("root-authorized", "").await;
        // No session for root's processes: the default is allow_any, "no" for DEFAULT.
        let root = Sleeper::start(None);
        let own_name = bus.shared.client.unique_name().unwrap().to_string();
        bus.add_session("c1", LOCAL_ACTIVE).await;

        // Subjects whose uid is known race-free: a process whose client sent the uid it saw, a bus
        // name and a session.
        let subjects = [
            unix_process_with_uid(root.pid(), 0),
            bus_name(&own_name),
            unix_session("c1"),
        ];
        for subject in &subjects {
            // A default of "no", a rule that says "no" and a challenge: yes, for root.
            for action in [DEFAULT, DENIED, CHALLENGE] {
                assert_eq!(bus.check(subject, action).await, Ok(YES), "{subject:?}");
            }
            // An unknown action is refused before root is looked at.
            assert_eq!(bus.check(subject, UNKNOWN).await, Ok(NO), "{subject:?}");
        }
        let pid = root.pid().to_string();
        for action in [DEFAULT, DENIED, CHALLENGE] {
            assert_eq!(bus.pkcheck(action, &pid), Ok(PKCHECK_AUTHORIZED));
        }
        assert_eq!(bus.pkcheck(UNKNOWN, &pid), Ok(PKCHECK_NOT_AUTHORIZED));

        // A process without the uid the client saw has no shortcut: the rules and the defaults
        // decide, as for anyone.
        let unconfirmed = unix_process(root.pid());
        assert_eq!(bus.check(&unconfirmed, DEFAULT).await, Ok(NO));
        assert_eq!(bus.check(&unconfirmed, DENIED).await, Ok(NO));
        assert_eq!(bus.check(&unconfirmed, CHALLENGE).await, Ok(CHALLENGED));
        // A uid that is not the process's is an error, not a shortcut.
        let wrong = unix_process_with_uid(root.pid(), NOBODY);
        assert_eq!(
            bus.check(&wrong, DEFAULT).await,
            Err(NOT_AUTHORIZED.to_string())
        );

        // Even with rules that cannot be read.
        let mut changes = changed_signals(&bus).await;
        write_trusted(
            &bus.shared.directory.join("local/90-local.toml"),
            BROKEN_RULES,
        );
        bus.reload();
        within("Changed", changes.next()).await.unwrap().unwrap();
        assert_eq!(bus.check(&subjects[0], DEFAULT).await, Ok(YES));
        assert_eq!(bus.check(&unconfirmed, DEFAULT).await, Ok(NO));

        // Only uid 0: nobody's process is still denied.
        let nobody = Sleeper::start(Some("nobody"));
        assert_eq!(
            bus.check(&unix_process_with_uid(nobody.pid(), NOBODY), DEFAULT)
                .await,
            Ok(NO)
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn the_session_from_logind_picks_the_default() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("sessions", "").await;
        let session = |remote, seat, active| FakeSession {
            uid: NOBODY,
            remote,
            seat,
            active,
        };
        bus.add_session("c1", NOBODY_ACTIVE).await;
        bus.add_session("remote", session(true, "seat0", true))
            .await;
        // Like each user's manager session: no seat, not remote, active.
        bus.add_session("manager", session(false, "", true)).await;
        bus.add_session("inactive", session(false, "seat0", false))
            .await;
        // nobody's display session is c1, but a process outside nobody's user manager does not
        // get it.
        bus.add_user_with_display(NOBODY, "c1").await;

        let no_session = Sleeper::start(Some("nobody"));
        let remote = Sleeper::start(Some("nobody"));
        let manager = Sleeper::start(Some("nobody"));
        let inactive = Sleeper::start(Some("nobody"));
        let failing = Sleeper::start(Some("nobody"));
        bus.place(remote.pid(), ByPid::Session("remote"));
        bus.place(manager.pid(), ByPid::Session("manager"));
        bus.place(inactive.pid(), ByPid::Session("inactive"));
        bus.place(failing.pid(), ByPid::Fail);

        // allow_any is "no", allow_inactive "auth_admin", allow_active "yes".
        let bus = &bus;
        let default_for = |sleeper: &Sleeper| {
            let subject = unix_process(sleeper.pid());
            async move { bus.check(&subject, DEFAULT).await }
        };
        assert_eq!(default_for(&no_session).await, Ok(NO));
        assert_eq!(default_for(&remote).await, Ok(NO));
        assert_eq!(default_for(&manager).await, Ok(NO));
        assert_eq!(default_for(&inactive).await, Ok(CHALLENGED));
        // A logind failure denies the check; it never falls back to allow_any.
        assert_eq!(default_for(&failing).await, Err(NOT_AUTHORIZED.to_string()));

        assert_eq!(
            bus.check(&unix_session("inactive"), DEFAULT).await,
            Ok(CHALLENGED)
        );
        assert_eq!(
            bus.check(&unix_session("no-such-session"), DEFAULT).await,
            Err(NOT_AUTHORIZED.to_string())
        );

        assert_eq!(
            bus.pkcheck(DEFAULT, &no_session.pid().to_string()),
            Ok(PKCHECK_NOT_AUTHORIZED)
        );
        assert_eq!(
            bus.pkcheck(DEFAULT, &inactive.pid().to_string()),
            Ok(PKCHECK_CHALLENGE)
        );
        assert_eq!(
            bus.pkcheck(DEFAULT, &failing.pid().to_string()),
            Err(NOT_AUTHORIZED.to_string())
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn another_users_session_is_not_local() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("foreign-session", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        let nobody_session = FakeSession {
            uid: 65534,
            ..LOCAL_ACTIVE
        };
        bus.add_session("c2", nobody_session).await;

        // `su nobody` in a terminal of root's session at the seat: not local, allow_any ("no").
        let nobody_in_roots = Sleeper::start(Some("nobody"));
        bus.place(nobody_in_roots.pid(), ByPid::Session("c1"));
        assert_eq!(
            bus.check(&unix_process(nobody_in_roots.pid()), DEFAULT)
                .await,
            Ok(NO)
        );
        // In nobody's own session, it is.
        let nobody_in_own = Sleeper::start(Some("nobody"));
        bus.place(nobody_in_own.pid(), ByPid::Session("c2"));
        assert_eq!(
            bus.check(&unix_process(nobody_in_own.pid()), DEFAULT).await,
            Ok(YES)
        );
        // root keeps the session it is in: `sudo` at the seat. This subject carries no uid from the
        // client, so the session's default decides, as for anyone.
        let root_in_nobodys = Sleeper::start(None);
        bus.place(root_in_nobodys.pid(), ByPid::Session("c2"));
        assert_eq!(
            bus.check(&unix_process(root_in_nobodys.pid()), DEFAULT)
                .await,
            Ok(YES)
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn a_logind_that_never_answers_is_a_refusal() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("logind-timeout", "").await;
        let stuck = Sleeper::start(None);
        let (arrived, _at_logind) = async_channel::bounded(1);
        bus.place(stuck.pid(), ByPid::Hang(arrived));
        // The daemon's timeout (10 s) answers, before the client's own (TIMEOUT) would.
        assert_eq!(
            bus.check(&unix_process(stuck.pid()), DEFAULT).await,
            Err(NOT_AUTHORIZED.to_string())
        );
    });
}

#[test]
#[ignore = "needs root, dbus-daemon and a writable /sys/fs/cgroup: run by the integration job"]
fn the_display_session_counts_under_the_users_own_manager() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("display", "").await;
        let nobody_session = FakeSession {
            uid: 65534,
            ..LOCAL_ACTIVE
        };
        bus.add_session("c2", nobody_session).await;
        bus.add_user_with_display(65534, "c2").await;

        // An app that nobody's `systemd --user` started: in no session, but in nobody's
        // user@65534.service, so it gets nobody's display session.
        let user_slice = Path::new("/sys/fs/cgroup/user.slice");
        let manager = user_slice.join("user-65534.slice/user@65534.service");
        std::fs::create_dir_all(&manager).expect("a writable /sys/fs/cgroup (see the top)");
        let app = Sleeper::start(Some("nobody"));
        std::fs::write(manager.join("cgroup.procs"), app.pid().to_string()).unwrap();
        assert_eq!(bus.check(&unix_process(app.pid()), DEFAULT).await, Ok(YES));
        // The same user elsewhere (cron, a system service) has no session.
        let elsewhere = Sleeper::start(Some("nobody"));
        assert_eq!(
            bus.check(&unix_process(elsewhere.pid()), DEFAULT).await,
            Ok(NO)
        );

        // A user under their own manager but with no display session (a server's lingering
        // user): the answer for no session, not a refusal as for a logind that fails.
        bus.add_user_with_display(DAEMON, "").await;
        let daemon_manager = user_slice.join("user-1.slice/user@1.service");
        std::fs::create_dir_all(&daemon_manager).unwrap();
        let lingering = Sleeper::start(Some("daemon"));
        std::fs::write(
            daemon_manager.join("cgroup.procs"),
            lingering.pid().to_string(),
        )
        .unwrap();
        assert_eq!(
            bus.check(&unix_process(lingering.pid()), DEFAULT).await,
            Ok(NO)
        );

        drop(app);
        drop(lingering);
        for cgroup in [
            &manager,
            &manager.parent().unwrap().to_path_buf(),
            &daemon_manager,
            &daemon_manager.parent().unwrap().to_path_buf(),
            &user_slice.to_path_buf(),
        ] {
            let _ = std::fs::remove_dir(cgroup);
        }
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn a_subject_that_exits_while_logind_answers_is_refused() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("exits", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        let bus = &bus;
        // logind answers c1 (allow_active, "yes") only after the test has killed the subject, or
        // not.
        let check_while_logind_waits = |kill: bool| async move {
            let mut subject_process = Some(Sleeper::start(None));
            let pid = subject_process.as_ref().unwrap().pid();
            let (arrived, at_logind) = async_channel::bounded(1);
            let (released, release) = async_channel::bounded(1);
            bus.place(
                pid,
                ByPid::Delayed {
                    arrived,
                    release,
                    session: "c1",
                },
            );
            let subject = unix_process(pid);
            let checking = bus.check(&subject, DEFAULT);
            let meanwhile = async {
                arrivals(&at_logind, 1).await;
                if kill {
                    subject_process.take();
                }
                released.send(()).await.unwrap();
            };
            futures_lite::future::zip(checking, meanwhile).await.0
        };
        // Still alive: the answer stands.
        assert_eq!(check_while_logind_waits(false).await, Ok(YES));
        // Gone before logind answered: its PID may already be another process's.
        assert_eq!(
            check_while_logind_waits(true).await,
            Err(NOT_AUTHORIZED.to_string())
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn subjects_that_cannot_be_pinned_are_refused() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("subjects", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let start_time = Process::open(me()).unwrap().start_time().unwrap();
        let refused = Err(NOT_AUTHORIZED.to_string());

        assert_eq!(
            bus.check(&unix_process_with(me(), start_time, Some(0)), DEFAULT)
                .await,
            Ok(YES)
        );
        // Another start time: the PID could have been reused. 0: never pinned.
        assert_eq!(
            bus.check(&unix_process_with(me(), start_time + 1, None), DEFAULT)
                .await,
            refused
        );
        assert_eq!(
            bus.check(&unix_process_with(me(), 0, None), DEFAULT).await,
            refused
        );
        // The client saw another user. The caller only learns that the subject was not
        // identified; the journal has the reason.
        assert_eq!(
            bus.refusal(&unix_process_with(me(), start_time, Some(4242)), DEFAULT)
                .await,
            (
                NOT_AUTHORIZED.to_string(),
                "cannot identify the subject".to_string()
            )
        );
        let log = bus.shared.log();
        assert!(log.contains("its user changed from 4242 to 0"), "{log}");
        // A process that is gone.
        let gone = Sleeper::start(None);
        let subject = unix_process(gone.pid());
        drop(gone);
        assert_eq!(bus.check(&subject, DEFAULT).await, refused);
        // A well-known name can change owner.
        assert_eq!(
            bus.check(&bus_name("org.freedesktop.login1"), DEFAULT)
                .await,
            refused
        );
        assert_eq!(
            bus.check(&("unix-thing", HashMap::new()), DEFAULT).await,
            refused
        );
        assert_eq!(
            bus.pkcheck(DEFAULT, &format!("{},{}", me(), start_time + 1)),
            Err(NOT_AUTHORIZED.to_string())
        );

        // A pidfd from the client pins the process: no start time needed. Its PID must be the
        // subject's.
        assert_eq!(
            bus.check(&unix_process_with_pidfd(me(), pidfd(me())), DEFAULT)
                .await,
            Ok(YES)
        );
        let other = Sleeper::start(None);
        assert_eq!(
            bus.check(&unix_process_with_pidfd(me(), pidfd(other.pid())), DEFAULT)
                .await,
            refused
        );

        // Only AllowUserInteraction (1) is a flag.
        let subject = unix_process(me());
        let flags = |flags| bus.check_with(&subject, DEFAULT, HashMap::new(), flags, "");
        assert!(flags(1).await.is_ok());
        assert_eq!(flags(2).await, Err(FAILED.to_string()));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn other_users_subjects_and_polkit_details() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("others", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        let nobody_session = FakeSession {
            uid: 65534,
            ..LOCAL_ACTIVE
        };
        bus.add_session("c2", nobody_session).await;
        bus.place(me(), ByPid::Session("c1"));
        let nobody = Sleeper::start(Some("nobody"));
        bus.place(nobody.pid(), ByPid::Session("c2"));

        // root may check anyone; the answer is the subject's own: the rule for nobody applies.
        let subject = unix_process(nobody.pid());
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert_eq!(bus.check(&subject, RULED).await, Ok(YES));

        // Another user may not check root's subjects: a process, a bus name or a session.
        let refused = Err(NOT_AUTHORIZED.to_string());
        let root_pid = me().to_string();
        let root_name = bus.shared.client.unique_name().unwrap().to_string();
        let as_nobody = |arguments: &[&str]| bus.pkcheck_as(Some("nobody"), arguments);
        assert_eq!(
            as_nobody(&["--action-id", DEFAULT, "--process", &root_pid]),
            refused
        );
        assert_eq!(
            as_nobody(&["--action-id", DEFAULT, "--system-bus-name", &root_name]),
            refused
        );
        // pkcheck has no unix-session subjects: busctl sends one.
        let session_as_nobody = |id: &str| {
            let output = bus.shared.run(
                Some("nobody"),
                None,
                "busctl",
                &[
                    "call",
                    NAME,
                    PATH,
                    INTERFACE,
                    "CheckAuthorization",
                    "(sa{sv})sa{ss}us",
                    "unix-session",
                    "1",
                    "session-id",
                    "s",
                    id,
                    DEFAULT,
                    "0",
                    "0",
                    "",
                ],
            );
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        };
        let (code, answer, _) = session_as_nobody("c2");
        assert_eq!((code, answer.trim()), (Some(0), "(bba{ss}) true false 0"));
        let (code, _, error) = session_as_nobody("c1");
        assert_eq!(code, Some(1));
        assert!(
            error.contains("only root may check the authorization of another user's subject"),
            "{error}"
        );

        // But it may check itself (no session: allow_any, "no").
        let itself = format!("exec pkcheck --action-id {DEFAULT} --process $$");
        let run_as_nobody = |script: &str| {
            pkcheck_answer(bus.shared.run(Some("nobody"), None, "sh", &["-c", script]))
        };
        assert_eq!(run_as_nobody(&itself), Ok(PKCHECK_NOT_AUTHORIZED));
        // polkit.* details: only the documented ones, and only from root.
        let with_detail = format!("{itself} --detail polkit.message hello");
        assert_eq!(run_as_nobody(&with_detail), Err(FAILED.to_string()));
        let me_subject = unix_process(me());
        let detail = |key| bus.check_with(&me_subject, DEFAULT, HashMap::from([(key, "x")]), 0, "");
        assert!(detail("polkit.message").await.is_ok());
        assert!(detail("remote").await.is_ok());
        assert_eq!(
            detail("polkit.retains_authorization_after_challenge").await,
            Err(FAILED.to_string())
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn the_owner_annotation_lets_a_user_check_others() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("owner", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let root_pid = me().to_string();
        let as_42 =
            |action| bus.pkcheck_as(Some("42"), &["--action-id", action, "--process", &root_pid]);

        // "unix-user:42": uid 42 gets root's answer (allow_active, "yes").
        assert_eq!(as_42(OWNED), Ok(PKCHECK_AUTHORIZED));
        // "unix-user:nobody": the user's name counts, over the bus, as its uid does; 42 is not it.
        assert_eq!(
            bus.pkcheck_as(
                Some("nobody"),
                &["--action-id", OWNED_BY_NAME, "--process", &root_pid]
            ),
            Ok(PKCHECK_AUTHORIZED)
        );
        assert_eq!(as_42(OWNED_BY_NAME), Err(NOT_AUTHORIZED.to_string()));
        // A bare "42" is not an identity; nor does the annotation of one action open another.
        assert_eq!(as_42(OWNED_BARE), Err(NOT_AUTHORIZED.to_string()));
        assert_eq!(as_42(DEFAULT), Err(NOT_AUTHORIZED.to_string()));
        // Other users still may not.
        assert_eq!(
            bus.pkcheck_as(
                Some("nobody"),
                &["--action-id", OWNED, "--process", &root_pid]
            ),
            Err(NOT_AUTHORIZED.to_string())
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn broken_rules_deny_everything_until_a_reload_fixes_them() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("broken", BROKEN_RULES).await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let nobody = Sleeper::start(Some("nobody"));
        bus.place(nobody.pid(), ByPid::Session("c2"));
        let subject = unix_process(nobody.pid());

        // The daemon keeps the name and denies everything, even what the defaults allow.
        for _ in 0..3 {
            assert_eq!(bus.check(&subject, DEFAULT).await, Ok(NO));
        }
        assert_eq!(
            bus.pkcheck(DEFAULT, &nobody.pid().to_string()),
            Ok(PKCHECK_NOT_AUTHORIZED)
        );
        assert!(bus.shared.name_is_owned().await);
        let log = bus.shared.log();
        assert!(log.contains("unknown field `sesion`"), "{log}");
        // Rate-limited: one message for the four denied checks.
        assert_eq!(log.matches("the rules are broken").count(), 1, "{log}");

        let changed = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .interface(INTERFACE)
            .unwrap()
            .member("Changed")
            .unwrap()
            .build();
        let mut changes = MessageStream::for_match_rule(changed, &bus.shared.client, None)
            .await
            .unwrap();

        // Fixed, then reloaded: normal answers.
        write_trusted(
            &bus.shared.directory.join("local/90-local.toml"),
            "# fixed\n",
        );
        bus.reload();
        within("Changed", changes.next()).await.unwrap().unwrap();
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert_eq!(
            bus.pkcheck(DEFAULT, &nobody.pid().to_string()),
            Ok(PKCHECK_AUTHORIZED)
        );

        // Broken again by a reload: denied again, still owning the name.
        write_trusted(
            &bus.shared.directory.join("local/90-local.toml"),
            BROKEN_RULES,
        );
        bus.reload();
        within("Changed", changes.next()).await.unwrap().unwrap();
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(NO));
        assert!(bus.shared.name_is_owned().await);
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn actions_properties_and_cancellation() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("interface", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));

        type Description = (
            String,
            String,
            String,
            String,
            String,
            String,
            u32,
            u32,
            u32,
            HashMap<String, String>,
        );
        let reply = bus
            .shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "EnumerateActions",
                &("ro_RO.UTF-8"),
            )
            .await
            .unwrap();
        let actions: Vec<Description> = reply.body().deserialize().unwrap();
        let ids: Vec<&str> = actions.iter().map(|action| action.0.as_str()).collect();
        assert_eq!(
            ids,
            [
                ADMIN,
                CHALLENGE,
                DEFAULT,
                DENIED,
                LEVELS,
                OWNED,
                OWNED_BARE,
                OWNED_BY_NAME,
                RULED,
                SELF,
                SELF_KEEP
            ]
        );
        let default = &actions[2];
        assert_eq!(default.1, "Fă lucrul implicit");
        assert_eq!(default.2, "Authentication is required");
        assert_eq!(default.3, "nyra-polkit tests");
        // no, auth_admin, yes.
        assert_eq!((default.6, default.7, default.8), (0, 2, 5));

        let properties = zbus::fdo::PropertiesProxy::builder(&bus.shared.client)
            .destination(NAME)
            .unwrap()
            .path(PATH)
            .unwrap()
            .build()
            .await
            .unwrap();
        let all = properties
            .get_all(INTERFACE.try_into().unwrap())
            .await
            .unwrap();
        assert_eq!(&*all["BackendName"], &Value::from("nyra-polkit"));
        // Temporary authorizations.
        assert_eq!(&*all["BackendFeatures"], &Value::U32(1));
        assert_eq!(
            &*all["BackendVersion"],
            &Value::from(env!("CARGO_PKG_VERSION"))
        );

        assert_eq!(bus.cancel("nothing").await, Err(FAILED.to_string()));

        // A check that waits on logind, cancelled while it waits.
        let slow = Sleeper::start(None);
        let (arrived, at_logind) = async_channel::bounded(1);
        bus.place(slow.pid(), ByPid::Hang(arrived));
        let slow_subject = unix_process(slow.pid());
        let me_subject = unix_process(me());
        let waiting = bus.check_with(&slow_subject, DEFAULT, HashMap::new(), 0, "c");
        let meanwhile = async {
            arrivals(&at_logind, 1).await;
            let again = bus
                .check_with(&me_subject, DEFAULT, HashMap::new(), 0, "c")
                .await;
            assert_eq!(
                again.map(|_| ()),
                Err("org.freedesktop.PolicyKit1.Error.CancellationIdNotUnique".to_string())
            );
            bus.cancel("c").await
        };
        let (cancelled, cancelling) = futures_lite::future::zip(waiting, meanwhile).await;
        assert_eq!(cancelling, Ok(()));
        assert_eq!(cancelled.map(|_| ()), Err(CANCELLED.to_string()));
        // The id is free again.
        let again = bus
            .check_with(&me_subject, DEFAULT, HashMap::new(), 0, "c")
            .await;
        assert_eq!(again.map(|(authorized, _, _)| authorized), Ok(true));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn two_cancellable_checks_from_one_caller() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("two-cancellable", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let slow = Sleeper::start(None);
        let (arrived, at_logind) = async_channel::bounded(1);
        bus.place(slow.pid(), ByPid::Hang(arrived));
        let slow_subject = unix_process(slow.pid());
        let me_subject = unix_process(me());
        let check = |subject, id| bus.check_with(subject, DEFAULT, HashMap::new(), 0, id);

        let second = check(&slow_subject, "b");
        let the_rest = async {
            let first = check(&slow_subject, "a");
            let cancel_first = async {
                arrivals(&at_logind, 2).await;
                assert_eq!(bus.cancel("a").await, Ok(()));
            };
            let (first, ()) = futures_lite::future::zip(first, cancel_first).await;
            assert_eq!(first.map(|_| ()), Err(CANCELLED.to_string()));
            // "a" is free again while "b" still waits, and "b" can still be cancelled.
            let again = check(&me_subject, "a").await;
            assert_eq!(again.map(|(authorized, _, _)| authorized), Ok(true));
            assert_eq!(bus.cancel("b").await, Ok(()));
        };
        let (second, ()) = futures_lite::future::zip(second, the_rest).await;
        assert_eq!(second.map(|_| ()), Err(CANCELLED.to_string()));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn the_limit_per_connection_holds_and_root_has_no_limit_per_user() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("limits-root", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let slow = Sleeper::start(None);
        let (arrived, at_logind) = async_channel::bounded(1);
        bus.place(slow.pid(), ByPid::Hang(arrived));
        let slow_subject = unix_process(slow.pid());
        let me_subject = unix_process(me());

        // 32 checks wait on one connection: a 33rd is refused at once.
        let first = connect(&bus.shared.address).await;
        let sent = Instant::now();
        for _ in 0..32 {
            send_check(&first, &slow_subject).await;
        }
        arrivals(&at_logind, 32).await;
        let on_first = first
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "CheckAuthorization",
                &(&me_subject, DEFAULT, HashMap::<&str, &str>::new(), 0u32, ""),
            )
            .await
            .map(|_| ())
            .map_err(error_name);
        assert_eq!(on_first, Err(FAILED.to_string()));
        // Another connection has its own 32.
        let second = connect(&bus.shared.address).await;
        for _ in 0..32 {
            send_check(&second, &slow_subject).await;
        }
        arrivals(&at_logind, 32).await;
        assert_still_held(sent);
        // Root's connections are the system services': 64 checks of root in flight do not stop a
        // third one.
        assert_eq!(bus.check(&me_subject, DEFAULT).await, Ok(YES));
        assert_still_held(sent);
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn a_user_has_at_most_64_checks_in_flight() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("limits-user", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let slow = Sleeper::start(Some("nobody"));
        let (arrived, at_logind) = async_channel::bounded(1);
        bus.place(slow.pid(), ByPid::Hang(arrived));
        let slow_pid = slow.pid().to_string();
        let pkcheck_slow = ["--action-id", DEFAULT, "--process", &slow_pid];

        // 64 checks of nobody wait on logind, each from its own pkcheck (its own connection).
        let sent = Instant::now();
        let mut waiting: Vec<Child> = (0..64)
            .map(|_| {
                Command::new("setpriv")
                    .args(["--reuid=nobody", "--regid=nogroup", "--clear-groups", "--"])
                    .arg("pkcheck")
                    .args(pkcheck_slow)
                    .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.shared.address)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        arrivals(&at_logind, 64).await;
        // A 65th, from yet another connection, is refused at once.
        assert_eq!(
            bus.pkcheck_as(Some("nobody"), &pkcheck_slow),
            Err(FAILED.to_string())
        );
        // Other users are not affected.
        assert_eq!(bus.check(&unix_process(me()), DEFAULT).await, Ok(YES));
        assert_still_held(sent);
        for pkcheck in &mut waiting {
            let _ = pkcheck.kill();
            let _ = pkcheck.wait();
        }
    });
}

/// The daemon's process in a cgroup with the memory settings of the unit in `dist/`: its
/// `MemoryMax=` (none: no limit) and no swap, as on a machine without swap. The memory controller
/// is only given to the children of a cgroup without processes, so the container's processes move
/// to a child cgroup first; dropping this takes the controller back and moves them back, leaving
/// the container's cgroups as they were.
struct UnitMemoryCgroup {
    others: PathBuf,
    daemon: PathBuf,
}

/// Moves every process of the cgroup `from` to `to` until `done` (processes may start meanwhile);
/// false if it never is. Does not panic: it also runs while a failed test unwinds.
fn move_processes(from: &Path, to: &Path, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        let processes = std::fs::read_to_string(from.join("cgroup.procs")).unwrap_or_default();
        for process in processes.lines() {
            let _ = std::fs::write(to.join("cgroup.procs"), process);
        }
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

impl UnitMemoryCgroup {
    fn place(pid: u32) -> Self {
        let root = Path::new(CGROUP_ROOT);
        let others = root.join("nyra-polkit-tests");
        std::fs::create_dir_all(&others).expect("a writable /sys/fs/cgroup (see the top)");
        let emptied = move_processes(root, &others, || {
            std::fs::write(root.join("cgroup.subtree_control"), "+memory").is_ok()
        });
        assert!(emptied, "the memory controller for the daemon's cgroup");

        let unit = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../dist/nyra-polkit.service"),
        )
        .unwrap();
        let memory_max = unit
            .lines()
            .find_map(|line| line.strip_prefix("MemoryMax="))
            .unwrap_or("max");
        let daemon = root.join("nyra-polkitd");
        std::fs::create_dir_all(&daemon).unwrap();
        std::fs::write(daemon.join("memory.max"), memory_max).unwrap();
        std::fs::write(daemon.join("memory.swap.max"), "0").unwrap();
        std::fs::write(daemon.join("cgroup.procs"), pid.to_string()).unwrap();
        Self { others, daemon }
    }

    /// The most memory the daemon has used.
    fn peak(&self) -> String {
        std::fs::read_to_string(self.daemon.join("memory.peak")).unwrap_or_default()
    }
}

impl Drop for UnitMemoryCgroup {
    fn drop(&mut self) {
        let root = Path::new(CGROUP_ROOT);
        let _ = std::fs::write(root.join("cgroup.subtree_control"), "-memory");
        move_processes(&self.daemon, root, || {
            std::fs::remove_dir(&self.daemon).is_ok()
        });
        move_processes(&self.others, root, || {
            std::fs::remove_dir(&self.others).is_ok()
        });
    }
}

#[test]
#[ignore = "needs root, dbus-daemon and a writable /sys/fs/cgroup: run by the integration job"]
fn a_call_over_the_size_limit_is_dropped_and_the_daemon_keeps_serving() {
    futures_lite::future::block_on(async {
        let mut bus = Harness::start("large-call", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let nobody = Sleeper::start(Some("nobody"));
        bus.place(nobody.pid(), ByPid::Session("c2"));
        let cgroup = UnitMemoryCgroup::place(bus.shared.daemon.id());
        // Not root's: only a check that reaches the rules copies the details.
        let subject = unix_process(nobody.pid());

        // One detail whose value takes the rest of the call; the other arguments take far less
        // than the 4 KiB left under the limit.
        let under = "x".repeat(MAX_CALL_SIZE - 4096);
        let over = "x".repeat(MAX_CALL_SIZE + 1);
        let answer = bus
            .check_with(
                &subject,
                DEFAULT,
                HashMap::from([("k", under.as_str())]),
                0,
                "",
            )
            .await;
        assert_eq!(answer.map(|(authorized, _, _)| authorized), Ok(true));

        // A dropped call gets no reply: its caller gives up at its own timeout.
        bus.shared.client = zbus::connection::Builder::address(bus.shared.address.as_str())
            .unwrap()
            .method_timeout(Duration::from_secs(2))
            .build()
            .await
            .unwrap();
        // About 31 MiB of details (24 bytes each on the wire), under the bus's 32 MiB per message:
        // turned into Rust values, they would take far more.
        let names: Vec<String> = (0..1_350_000).map(|i| format!("{i:x}")).collect();
        let many: HashMap<&str, &str> = names.iter().map(|name| (name.as_str(), "")).collect();
        for details in [HashMap::from([("k", over.as_str())]), many] {
            let dropped = bus.call_check(&subject, DEFAULT, details, 0, "").await;
            assert!(
                matches!(&dropped, Err(zbus::Error::InputOutput(error))
                    if error.kind() == std::io::ErrorKind::TimedOut),
                "{dropped:?}"
            );
        }
        eprintln!("the daemon's peak memory: {} bytes", cgroup.peak().trim());

        // The same daemon, and the same connection, still answer.
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert!(
            bus.shared.daemon.try_wait().unwrap().is_none(),
            "{}",
            bus.shared.log()
        );

        drop(bus);
        drop(cgroup);
    });
}

// --- Authentication agents ---------------------------------------------------------------------

const AGENT_PATH: &str = "/org/nyra/test/Agent";
const RELAY_NAME: &str = "org.nyra.test.Relay";
const RELAY_PATH: &str = "/org/nyra/test/Relay";
const RELAY_INTERFACE: &str = "org.nyra.test.Relay";
/// Set in the environment of this test binary when it runs as a fake agent.
const FAKE_AGENT: &str = "NYRA_POLKIT_FAKE_AGENT";

/// What agents answer, and what the relay tells the fake agent to answer.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Cancelled(String),
    Failed(String),
}

/// The agent a fake agent process serves: it passes each call on to the relay in the test, and
/// answers what the relay answers.
struct FakeAgent {
    label: String,
}

#[interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl FakeAgent {
    #[allow(clippy::too_many_arguments)] // The method's D-Bus arguments, plus the connection.
    async fn begin_authentication(
        &self,
        #[zbus(connection)] connection: &Connection,
        action_id: String,
        message: String,
        icon_name: String,
        details: HashMap<String, String>,
        cookie: String,
        identities: Vec<(String, HashMap<String, OwnedValue>)>,
    ) -> Result<(), AgentError> {
        // Identities as polkit's agents read them: unix-user, with the uid a u32.
        let mut uids = Vec::new();
        for (kind, identity) in &identities {
            match (kind.as_str(), identity.get("uid").map(|uid| &**uid)) {
                ("unix-user", Some(Value::U32(uid))) => uids.push(*uid),
                _ => return Err(AgentError::Failed(format!("identity {kind} {identity:?}"))),
            }
        }
        let relayed = connection
            .call_method(
                Some(RELAY_NAME),
                RELAY_PATH,
                Some(RELAY_INTERFACE),
                "BeginAuthentication",
                &(
                    &self.label,
                    action_id,
                    message,
                    icon_name,
                    details,
                    cookie,
                    uids,
                ),
            )
            .await;
        match relayed {
            Ok(_) => Ok(()),
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == CANCELLED => {
                Err(AgentError::Cancelled("dismissed".to_string()))
            }
            Err(error) => Err(AgentError::Failed(error.to_string())),
        }
    }

    async fn cancel_authentication(
        &self,
        #[zbus(connection)] connection: &Connection,
        cookie: String,
    ) -> Result<(), AgentError> {
        connection
            .call_method(
                Some(RELAY_NAME),
                RELAY_PATH,
                Some(RELAY_INTERFACE),
                "CancelAuthentication",
                &(&self.label, cookie),
            )
            .await?;
        Ok(())
    }
}

/// Not a test: this binary, run again as another user, is the fake agent (see the top). It
/// registers, says `agent: registered <its bus name>` or `agent: failed <error>` on stdout, then
/// obeys `unregister` on stdin until stdin closes.
#[test]
#[ignore = "the fake agent: the tests run it as another user"]
fn fake_agent_program() {
    let Ok(spec) = std::env::var(FAKE_AGENT) else {
        return;
    };
    futures_lite::future::block_on(run_fake_agent(&spec));
}

/// `spec`: `<label>|session|<session id>|<fallback: 0 or 1>`, `<label>|process|<pid>|<fallback>`
/// or `<label>|bus-name|self|<fallback>` (for the agent's own connection).
async fn run_fake_agent(spec: &str) {
    let [label, kind, subject, fallback] = spec.split('|').collect::<Vec<_>>()[..] else {
        panic!("fake agent: {spec:?}");
    };
    let say = |line: &str| {
        println!("agent: {line}");
        std::io::stdout().flush().unwrap();
    };
    let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap();
    let agent = FakeAgent {
        label: label.to_string(),
    };
    let connection = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .serve_at(AGENT_PATH, agent)
        .unwrap()
        .build()
        .await
        .unwrap();
    let subject = match kind {
        "session" => unix_session(subject),
        "process" => unix_process(subject.parse().unwrap()),
        "bus-name" => bus_name(connection.unique_name().unwrap().as_str()),
        _ => panic!("fake agent: {spec:?}"),
    };
    let options = HashMap::from([("fallback", Value::Bool(fallback == "1"))]);
    let registered = connection
        .call_method(
            Some(NAME),
            PATH,
            Some(INTERFACE),
            "RegisterAuthenticationAgentWithOptions",
            &(&subject, "en_US.UTF-8", AGENT_PATH, options),
        )
        .await;
    match registered {
        Ok(_) => say(&format!("registered {}", connection.unique_name().unwrap())),
        Err(error) => return say(&format!("failed {}", error_name(error))),
    }
    let (sender, lines) = async_channel::unbounded();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            if sender.send_blocking(line.unwrap()).is_err() {
                break;
            }
        }
    });
    while let Ok(line) = lines.recv().await {
        assert_eq!(line, "unregister", "fake agent: unknown command");
        let unregistered = connection
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "UnregisterAuthenticationAgent",
                &(&subject, AGENT_PATH),
            )
            .await;
        match unregistered {
            Ok(_) => say("unregistered"),
            Err(error) => say(&format!("failed {}", error_name(error))),
        }
    }
}

/// A fake agent process; killed when dropped, which takes its connection off the bus.
struct AgentProcess {
    child: Child,
    stdin: ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
}

impl AgentProcess {
    /// The next line the agent says, without its `agent: ` prefix.
    fn says(&self) -> String {
        self.lines
            .recv_timeout(TIMEOUT)
            .expect("timed out waiting for the fake agent")
    }

    fn unregister(&mut self) -> String {
        writeln!(self.stdin, "unregister").unwrap();
        self.says()
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A dialog an agent was asked to show, passed on to the test.
struct Dialog {
    agent: String,
    action_id: String,
    message: String,
    icon_name: String,
    details: HashMap<String, String>,
    cookie: String,
    identities: Vec<u32>,
    answer: async_channel::Sender<bool>,
}

impl Dialog {
    /// The agent returns from `BeginAuthentication`, as after the helper's answer.
    async fn agent_returns(self) {
        self.answer.send(true).await.unwrap();
    }

    /// The user closed the dialog: the agent answers `Cancelled`.
    async fn dismiss(self) {
        self.answer.send(false).await.unwrap();
    }
}

struct Relay {
    dialogs: async_channel::Sender<Dialog>,
    cancels: async_channel::Sender<(String, String)>,
}

#[interface(name = "org.nyra.test.Relay")]
impl Relay {
    #[allow(clippy::too_many_arguments)] // The fake agent's arguments.
    async fn begin_authentication(
        &self,
        agent: String,
        action_id: String,
        message: String,
        icon_name: String,
        details: HashMap<String, String>,
        cookie: String,
        identities: Vec<u32>,
    ) -> Result<(), AgentError> {
        let (answer, answered) = async_channel::bounded(1);
        let dialog = Dialog {
            agent,
            action_id,
            message,
            icon_name,
            details,
            cookie,
            identities,
            answer,
        };
        let _ = self.dialogs.send(dialog).await;
        match answered.recv().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(AgentError::Cancelled("dismissed".to_string())),
            Err(_) => Err(AgentError::Failed("the test did not answer".to_string())),
        }
    }

    async fn cancel_authentication(&self, agent: String, cookie: String) {
        let _ = self.cancels.send((agent, cookie)).await;
    }
}

/// What the agents passed on to the test.
struct Dialogs {
    _relay: Connection,
    dialogs: async_channel::Receiver<Dialog>,
    cancels: async_channel::Receiver<(String, String)>,
}

impl Dialogs {
    async fn next(&self) -> Dialog {
        within("a dialog", self.dialogs.recv()).await.unwrap()
    }

    /// The next `CancelAuthentication`: the agent and the cookie.
    async fn cancelled(&self) -> (String, String) {
        within("CancelAuthentication", self.cancels.recv())
            .await
            .unwrap()
    }

    fn none_pending(&self) -> bool {
        self.dialogs.is_empty() && self.cancels.is_empty()
    }
}

impl Harness {
    async fn relay(&self) -> Dialogs {
        let (dialogs, dialogs_received) = async_channel::unbounded();
        let (cancels, cancels_received) = async_channel::unbounded();
        let relay = zbus::connection::Builder::address(self.shared.address.as_str())
            .unwrap()
            .serve_at(RELAY_PATH, Relay { dialogs, cancels })
            .unwrap()
            .name(RELAY_NAME)
            .unwrap()
            .build()
            .await
            .unwrap();
        Dialogs {
            _relay: relay,
            dialogs: dialogs_received,
            cancels: cancels_received,
        }
    }

    /// Starts a fake agent as `user` (see [`run_fake_agent`] for `spec`); its bus name, or the
    /// error its registration got.
    fn agent(&self, user: &str, spec: &str) -> Result<(AgentProcess, String), String> {
        let mut child = Command::new("setpriv")
            .args([
                &format!("--reuid={user}"),
                "--regid=nogroup",
                "--clear-groups",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "fake_agent_program", "--ignored", "--nocapture"])
            .args(["--quiet", "--test-threads=1"])
            .env(FAKE_AGENT, spec)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.shared.address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the fake agent");
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in stdout.lines().map_while(Result::ok) {
                if let Some(said) = line.strip_prefix("agent: ") {
                    let _ = sender.send(said.to_string());
                }
            }
        });
        let agent = AgentProcess {
            stdin: child.stdin.take().unwrap(),
            child,
            lines,
        };
        let first = agent.says();
        match first.strip_prefix("registered ") {
            Some(name) => Ok((agent, name.to_string())),
            None => Err(first.strip_prefix("failed ").unwrap_or(&first).to_string()),
        }
    }

    /// `AuthenticationAgentResponse2` from root, as polkit-agent-helper-1 sends it.
    async fn respond(&self, uid: u32, cookie: &str, identity: u32) -> Result<(), String> {
        let identity = ("unix-user", HashMap::from([("uid", Value::U32(identity))]));
        self.shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "AuthenticationAgentResponse2",
                &(uid, cookie, identity),
            )
            .await
            .map(|_| ())
            .map_err(error_name)
    }

    /// busctl as `user` calling a method of the authority: its exit code and what it printed.
    fn busctl_as(&self, user: &str, method: &str, arguments: &[&str]) -> (Option<i32>, String) {
        let output = self.shared.run(
            Some(user),
            None,
            "busctl",
            &[&["call", NAME, PATH, INTERFACE, method], arguments].concat(),
        );
        let printed = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        (output.status.code(), printed)
    }

    /// An interactive check whose dialog the user and the helper complete: the answer.
    async fn authenticate(
        &self,
        dialogs: &Dialogs,
        subject: &Subject,
        action: &str,
    ) -> Result<Answer, String> {
        let checking = self.check_with(subject, action, HashMap::new(), ALLOW, "");
        let helping = async {
            let dialog = dialogs.next().await;
            // Here the identity offered is the agent's own user.
            let agent_uid = dialog.identities[0];
            assert_eq!(
                self.respond(agent_uid, &dialog.cookie, dialog.identities[0])
                    .await,
                Ok(())
            );
            dialog.agent_returns().await;
        };
        futures_lite::future::zip(checking, helping).await.0
    }

    /// The agent that gets the dialog of an interactive check of `subject` (dismissed).
    async fn agent_for(&self, dialogs: &Dialogs, subject: &Subject) -> String {
        let checking = self.check_with(subject, SELF, HashMap::new(), ALLOW, "");
        let dismissing = async {
            let dialog = dialogs.next().await;
            let agent = dialog.agent.clone();
            dialog.dismiss().await;
            agent
        };
        futures_lite::future::zip(checking, dismissing).await.1
    }

    /// Waits until the daemon has logged `text`.
    fn logged(&self, text: &str) {
        wait_until(text, || self.shared.log().contains(text));
    }
}

/// Sends a check without waiting for its answer.
async fn send_interactive_check(connection: &Connection, subject: &Subject, action: &str) {
    let message = zbus::Message::method_call(PATH, "CheckAuthorization")
        .unwrap()
        .destination(NAME)
        .unwrap()
        .interface(INTERFACE)
        .unwrap()
        .build(&(subject, action, HashMap::<&str, &str>::new(), ALLOW, ""))
        .unwrap();
    connection.send(&message).await.unwrap();
}

const NOBODY_ACTIVE: FakeSession = FakeSession {
    uid: NOBODY,
    ..LOCAL_ACTIVE
};

/// The authority's `Changed` signals from now on.
async fn changed_signals(bus: &Harness) -> MessageStream {
    let changed = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .interface(INTERFACE)
        .unwrap()
        .member("Changed")
        .unwrap()
        .build();
    MessageStream::for_match_rule(changed, &bus.shared.client, None)
        .await
        .unwrap()
}

const UNKNOWN_COOKIE: &str = "0123456789abcdef0123456789abcdef";

fn no_details() -> HashMap<String, String> {
    HashMap::new()
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn an_agent_authenticates_only_with_the_helpers_answer() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("agent", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let dialogs = bus.relay().await;
        let (_agent, _) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        let app = Sleeper::start(Some("nobody"));
        bus.place(app.pid(), ByPid::Session("c2"));
        let subject = unix_process(app.pid());

        // Without AllowUserInteraction, still a challenge.
        assert_eq!(bus.check(&subject, SELF).await, Ok(CHALLENGED));
        assert!(dialogs.none_pending());

        let details = HashMap::from([("color", "blue")]);
        let checking = bus.check_with(&subject, SELF, details, ALLOW, "");
        let helping = async {
            let dialog = dialogs.next().await;
            // The action's text in the agent's locale, its icon, the caller's details, and the
            // subject's own user to authenticate as.
            assert_eq!(dialog.agent, "nobody");
            assert_eq!(dialog.action_id, SELF);
            assert_eq!(dialog.message, "Authenticate yourself, in English");
            assert_eq!(dialog.icon_name, "test-icon");
            assert_eq!(dialog.details["color"], "blue");
            assert_eq!(dialog.identities, [NOBODY]);
            // 128 random bits.
            assert_eq!(dialog.cookie.len(), 32, "{}", dialog.cookie);

            // Refused: from a user other than root, an unknown cookie, a uid that is not the
            // agent's user, an identity not offered.
            let uid = NOBODY.to_string();
            let (code, printed) = bus.busctl_as(
                "nobody",
                "AuthenticationAgentResponse2",
                &[
                    "us(sa{sv})",
                    &uid,
                    &dialog.cookie,
                    "unix-user",
                    "1",
                    "uid",
                    "u",
                    &uid,
                ],
            );
            assert_eq!(code, Some(1), "{printed}");
            assert!(printed.contains("only root may answer"), "{printed}");
            let refused = Err(FAILED.to_string());
            assert_eq!(bus.respond(NOBODY, UNKNOWN_COOKIE, NOBODY).await, refused);
            assert_eq!(bus.respond(0, &dialog.cookie, NOBODY).await, refused);
            assert_eq!(bus.respond(NOBODY, &dialog.cookie, 0).await, refused);
            // The old answer, without the uid, is not supported at all.
            let identity = ("unix-user", HashMap::from([("uid", Value::U32(NOBODY))]));
            let old = bus
                .shared
                .client
                .call_method(
                    Some(NAME),
                    PATH,
                    Some(INTERFACE),
                    "AuthenticationAgentResponse",
                    &(&dialog.cookie, identity),
                )
                .await
                .map(|_| ())
                .map_err(error_name);
            assert_eq!(
                old,
                Err("org.freedesktop.PolicyKit1.Error.NotSupported".to_string())
            );
            // Accepted once.
            assert_eq!(bus.respond(NOBODY, &dialog.cookie, NOBODY).await, Ok(()));
            assert_eq!(bus.respond(NOBODY, &dialog.cookie, NOBODY).await, refused);
            dialog.agent_returns().await;
        };
        let (answer, ()) = futures_lite::future::zip(checking, helping).await;
        assert_eq!(answer, Ok((true, false, no_details())));
        let log = bus.shared.log();
        assert!(log.contains("refused: the caller is not root"), "{log}");
        assert!(
            log.contains("refused: the identity was not offered"),
            "{log}"
        );

        // The agent returns without the helper's answer: not authorized.
        let checking = bus.check_with(&subject, SELF, HashMap::new(), ALLOW, "");
        let helping = async { dialogs.next().await.agent_returns().await };
        let (answer, ()) = futures_lite::future::zip(checking, helping).await;
        assert_eq!(answer, Ok((false, false, no_details())));

        // Dismissed, even after the helper answered: not authorized, and said so.
        let checking = bus.check_with(&subject, SELF, HashMap::new(), ALLOW, "");
        let helping = async {
            let dialog = dialogs.next().await;
            assert_eq!(bus.respond(NOBODY, &dialog.cookie, NOBODY).await, Ok(()));
            dialog.dismiss().await;
        };
        let (answer, ()) = futures_lite::future::zip(checking, helping).await;
        let dismissed = HashMap::from([("polkit.dismissed".to_string(), "true".to_string())]);
        assert_eq!(answer, Ok((false, false, dismissed)));

        // Cookies are never logged.
        let log = bus.shared.log();
        assert!(!log.contains(UNKNOWN_COOKIE), "{log}");

        // A root caller gives the dialog its own text and icon.
        let own_text = HashMap::from([
            ("polkit.message", "The service's own text"),
            ("polkit.icon_name", "service-icon"),
        ]);
        let checking = bus.check_with(&subject, SELF, own_text, ALLOW, "");
        let helping = async {
            let dialog = dialogs.next().await;
            assert_eq!(dialog.message, "The service's own text");
            assert_eq!(dialog.icon_name, "service-icon");
            dialog.dismiss().await;
        };
        let (answer, ()) = futures_lite::future::zip(checking, helping).await;
        assert_eq!(answer.map(|answer| answer.0), Ok(false));

        // pkcheck --allow-user-interaction, end to end.
        let pid = app.pid().to_string();
        let mut pkcheck = bus.shared.command(
            None,
            None,
            "pkcheck",
            &[
                "--action-id",
                SELF,
                "--process",
                &pid,
                "--allow-user-interaction",
            ],
        );
        let pkcheck = blocking::unblock(move || pkcheck.output());
        let helping = async {
            let dialog = dialogs.next().await;
            assert_eq!(bus.respond(NOBODY, &dialog.cookie, NOBODY).await, Ok(()));
            dialog.agent_returns().await;
        };
        let (output, ()) = futures_lite::future::zip(pkcheck, helping).await;
        assert_eq!(pkcheck_answer(output.unwrap()), Ok(PKCHECK_AUTHORIZED));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn cancelling_or_leaving_closes_the_dialog() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("agent-cancel", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let dialogs = bus.relay().await;
        let (_agent, _) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        let app = Sleeper::start(Some("nobody"));
        bus.place(app.pid(), ByPid::Session("c2"));
        let subject = unix_process(app.pid());

        // CancelCheckAuthorization while the dialog is up: the check is cancelled, the agent told
        // to close the dialog, and its cookie no longer answers.
        let checking = bus.check_with(&subject, SELF, HashMap::new(), ALLOW, "c");
        let cancelling = async {
            let dialog = dialogs.next().await;
            assert_eq!(bus.cancel("c").await, Ok(()));
            assert_eq!(
                dialogs.cancelled().await,
                ("nobody".to_string(), dialog.cookie.clone())
            );
            assert_eq!(
                bus.respond(NOBODY, &dialog.cookie, NOBODY).await,
                Err(FAILED.to_string())
            );
            dialog.dismiss().await;
        };
        let (cancelled, ()) = futures_lite::future::zip(checking, cancelling).await;
        assert_eq!(cancelled.map(|_| ()), Err(CANCELLED.to_string()));

        // The caller leaves the bus while the dialog is up: the same.
        let leaving = connect(&bus.shared.address).await;
        send_interactive_check(&leaving, &subject, SELF).await;
        let dialog = dialogs.next().await;
        leaving.close().await.unwrap();
        assert_eq!(
            dialogs.cancelled().await,
            ("nobody".to_string(), dialog.cookie.clone())
        );
        dialog.dismiss().await;

        // The agent is free for the next one.
        assert_eq!(
            bus.authenticate(&dialogs, &subject, SELF).await,
            Ok((true, false, no_details()))
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn agents_only_get_requests_of_their_own_user() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("agent-users", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let daemon_session = FakeSession {
            uid: DAEMON,
            ..LOCAL_ACTIVE
        };
        bus.add_session("c4", daemon_session).await;
        let dialogs = bus.relay().await;
        let nobody_app = Sleeper::start(Some("nobody"));
        bus.place(nobody_app.pid(), ByPid::Session("c2"));

        // An agent is registered by the subject's own user, root included.
        let refused = |result: Result<(AgentProcess, String), String>| result.err();
        let not_authorized = Some(NOT_AUTHORIZED.to_string());
        assert_eq!(
            refused(bus.agent("daemon", "x|session|c2|0")),
            not_authorized
        );
        let nobody_process = format!("x|process|{}|1", nobody_app.pid());
        assert_eq!(
            refused(bus.agent("daemon", &nobody_process)),
            not_authorized
        );
        assert_eq!(refused(bus.agent("root", "x|session|c2|1")), not_authorized);

        let (_daemon_agent, _) = bus.agent("daemon", "daemon|session|c4|1").unwrap();
        let (mut nobody_agent, _) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        // One agent per subject, besides fallbacks.
        assert_eq!(
            refused(bus.agent("nobody", "x|session|c2|0")),
            Some(FAILED.to_string())
        );
        let (nobody_fallback, _) = bus.agent("nobody", "nobody-fallback|session|c2|1").unwrap();
        // pkttyagent's kind: an agent for one process.
        let for_the_process = format!("x|process|{}|0", nobody_app.pid());
        let (_process_agent, _) = bus.agent("nobody", &for_the_process).unwrap();

        // daemon's process in nobody's session (su daemon at the seat): no agent of its own, so a
        // challenge, and no dialog anywhere.
        let daemon_in_c2 = Sleeper::start(Some("daemon"));
        bus.place(daemon_in_c2.pid(), ByPid::Session("c2"));
        let answer = bus
            .check_with(
                &unix_process(daemon_in_c2.pid()),
                SELF,
                HashMap::new(),
                ALLOW,
                "",
            )
            .await;
        assert_eq!(answer, Ok((false, true, no_details())));
        assert!(dialogs.none_pending());

        // root's process in nobody's session (sudo at the seat): authorized, so no dialog. Without
        // the uid the client saw, the rules decide and root has no agent: a challenge.
        let root_in_c2 = Sleeper::start(None);
        bus.place(root_in_c2.pid(), ByPid::Session("c2"));
        let answer = bus
            .check_with(
                &unix_process_with_uid(root_in_c2.pid(), 0),
                SELF,
                HashMap::new(),
                ALLOW,
                "",
            )
            .await;
        assert_eq!(answer, Ok((true, false, no_details())));
        let answer = bus
            .check_with(
                &unix_process(root_in_c2.pid()),
                SELF,
                HashMap::new(),
                ALLOW,
                "",
            )
            .await;
        assert_eq!(answer, Ok((false, true, no_details())));
        assert!(dialogs.none_pending());

        // daemon's own process in its session: its fallback agent. auth_admin: daemon is no
        // administrator, so the administrators (nobody, bin) are offered; the helper answers
        // with the agent's user and one of them.
        let daemon_app = Sleeper::start(Some("daemon"));
        bus.place(daemon_app.pid(), ByPid::Session("c4"));
        let daemon_subject = unix_process(daemon_app.pid());
        let checking = bus.check_with(&daemon_subject, ADMIN, HashMap::new(), ALLOW, "");
        let helping = async {
            let dialog = dialogs.next().await;
            assert_eq!(dialog.agent, "daemon");
            assert_eq!(dialog.identities, [BIN, NOBODY]);
            assert_eq!(bus.respond(DAEMON, &dialog.cookie, NOBODY).await, Ok(()));
            dialog.agent_returns().await;
        };
        let (answer, ()) = futures_lite::future::zip(checking, helping).await;
        assert_eq!(answer, Ok((true, false, no_details())));

        // nobody's process: the agent registered for it, then the session's, then the fallback.
        let nobody_subject = unix_process(nobody_app.pid());
        let other_nobody_app = Sleeper::start(Some("nobody"));
        bus.place(other_nobody_app.pid(), ByPid::Session("c2"));
        let other_subject = unix_process(other_nobody_app.pid());
        assert_eq!(bus.agent_for(&dialogs, &nobody_subject).await, "x");
        assert_eq!(bus.agent_for(&dialogs, &other_subject).await, "nobody");

        // Only the connection that registered an agent unregisters it.
        let unregister = bus
            .shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "UnregisterAuthenticationAgent",
                &(unix_session("c2"), AGENT_PATH),
            )
            .await
            .map(|_| ())
            .map_err(error_name);
        assert_eq!(unregister, Err(FAILED.to_string()));
        assert_eq!(nobody_agent.unregister(), "unregistered");
        assert_eq!(
            bus.agent_for(&dialogs, &other_subject).await,
            "nobody-fallback"
        );

        // An agent whose connection leaves the bus is removed.
        drop(nobody_fallback);
        bus.logged("removed (its connection left the bus)");
        let answer = bus
            .check_with(&other_subject, SELF, HashMap::new(), ALLOW, "")
            .await;
        assert_eq!(answer, Ok((false, true, no_details())));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn temporary_authorizations_keep_their_subject_and_level() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("temporary", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let dialogs = bus.relay().await;
        let (agent, agent_name) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        let app = Sleeper::start(Some("nobody"));
        bus.place(app.pid(), ByPid::Session("c2"));
        let other_app = Sleeper::start(Some("nobody"));
        bus.place(other_app.pid(), ByPid::Session("c2"));
        let subject = unix_process(app.pid());
        let changed = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .interface(INTERFACE)
            .unwrap()
            .member("Changed")
            .unwrap()
            .build();
        let mut changes = MessageStream::for_match_rule(changed, &bus.shared.client, None)
            .await
            .unwrap();

        // Before: a challenge that says it would be kept.
        let (_, _, details) = bus
            .check_with(&subject, SELF_KEEP, HashMap::new(), 0, "")
            .await
            .unwrap();
        assert_eq!(
            details["polkit.retains_authorization_after_challenge"],
            "true"
        );

        // auth_self_keep, authenticated once: kept, and Changed says so.
        let (authorized, _, details) = bus
            .authenticate(&dialogs, &subject, SELF_KEEP)
            .await
            .unwrap();
        assert!(authorized);
        let id = details["polkit.temporary_authorization_id"].clone();
        assert_eq!(
            details["polkit.retains_authorization_after_challenge"],
            "true"
        );
        within("Changed", changes.next()).await.unwrap().unwrap();

        // Used again for the same process, without a dialog or user interaction...
        let again = bus
            .check_with(&subject, SELF_KEEP, HashMap::new(), 0, "")
            .await;
        let by_id = HashMap::from([("polkit.temporary_authorization_id".to_string(), id.clone())]);
        assert_eq!(again, Ok((true, false, by_id)));
        assert_eq!(
            bus.pkcheck(SELF_KEEP, &app.pid().to_string()),
            Ok(PKCHECK_AUTHORIZED)
        );
        // ...but not for another process of the same user in the same session, nor for another
        // action.
        assert_eq!(
            bus.check(&unix_process(other_app.pid()), SELF_KEEP).await,
            Ok(CHALLENGED)
        );
        assert_eq!(bus.check(&subject, LEVELS).await, Ok(CHALLENGED));
        assert!(dialogs.none_pending());

        // Listed for its user: by process (root) and by session (nobody, as pkcheck --list-temp
        // asks). Not for another user.
        let listed: Vec<TemporaryAuthorization> = bus
            .shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "EnumerateTemporaryAuthorizations",
                &(&subject),
            )
            .await
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        assert_eq!(listed.len(), 1);
        let (listed_id, action, (kind, listed_subject), obtained, expires) = &listed[0];
        assert_eq!(
            (listed_id, action.as_str(), kind.as_str()),
            (&id, SELF_KEEP, "unix-process")
        );
        assert_eq!(&*listed_subject["pid"], &Value::U32(app.pid()));
        assert_eq!(expires - obtained, 300);
        let in_session = ["(sa{sv})", "unix-session", "1", "session-id", "s", "c2"];
        let (code, printed) =
            bus.busctl_as("nobody", "EnumerateTemporaryAuthorizations", &in_session);
        assert_eq!(code, Some(0), "{printed}");
        assert!(printed.contains(&id), "{printed}");
        let (code, printed) =
            bus.busctl_as("daemon", "EnumerateTemporaryAuthorizations", &in_session);
        assert_eq!(code, Some(1), "{printed}");

        // Revoked by id: not by another user, by its own.
        let (code, _) = bus.busctl_as("daemon", "RevokeTemporaryAuthorizationById", &["s", &id]);
        assert_eq!(code, Some(1));
        let (code, printed) =
            bus.busctl_as("nobody", "RevokeTemporaryAuthorizationById", &["s", &id]);
        assert_eq!(code, Some(0), "{printed}");
        within("Changed", changes.next()).await.unwrap().unwrap();
        assert_eq!(bus.check(&subject, SELF_KEEP).await, Ok(CHALLENGED));

        // Revoked for its subject, by root: gone, and Changed says so. A new stream, so that only
        // what comes after this point is seen.
        bus.authenticate(&dialogs, &subject, SELF_KEEP)
            .await
            .unwrap();
        let mut changes_now = changed_signals(&bus).await;
        bus.shared
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "RevokeTemporaryAuthorizations",
                &(&subject),
            )
            .await
            .unwrap();
        within("Changed", changes_now.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bus.check(&subject, SELF_KEEP).await, Ok(CHALLENGED));

        // The user's own password, kept, never answers for an administrator's: in the foreground
        // LEVELS asks auth_self_keep, in the background auth_admin_keep.
        assert_eq!(
            bus.authenticate(&dialogs, &subject, LEVELS)
                .await
                .map(|answer| answer.0),
            Ok(true)
        );
        assert_eq!(bus.check(&subject, LEVELS).await, Ok(YES));
        let inactive = FakeSession {
            active: false,
            ..NOBODY_ACTIVE
        };
        bus.change_session("c2", inactive).await;
        assert_eq!(bus.check(&subject, LEVELS).await, Ok(CHALLENGED));
        // nobody is an administrator: their own password is an administrator's.
        assert_eq!(
            bus.authenticate(&dialogs, &subject, LEVELS)
                .await
                .map(|answer| answer.0),
            Ok(true)
        );
        assert_eq!(bus.check(&subject, LEVELS).await, Ok(YES));
        // An administrator's answers for the user's own.
        bus.change_session("c2", NOBODY_ACTIVE).await;
        assert_eq!(bus.check(&subject, LEVELS).await, Ok(YES));

        // Rereading the rules drops them all.
        bus.reload();
        bus.logged("temporary authorizations revoked: the rules were reread");
        assert_eq!(bus.check(&subject, LEVELS).await, Ok(CHALLENGED));

        // One kept for a bus name (here the agent's own connection) goes when the name leaves.
        bus.place(agent.child.id(), ByPid::Session("c2"));
        let by_name = bus_name(&agent_name);
        let (authorized, _, details) = bus
            .authenticate(&dialogs, &by_name, SELF_KEEP)
            .await
            .unwrap();
        assert!(authorized);
        let id = details["polkit.temporary_authorization_id"].clone();
        let in_c2 = |bus: &Harness| {
            let (code, printed) =
                bus.busctl_as("nobody", "EnumerateTemporaryAuthorizations", &in_session);
            assert_eq!(code, Some(0), "{printed}");
            printed
        };
        assert!(in_c2(&bus).contains(&id));
        let mut changes_now = changed_signals(&bus).await;
        drop(agent);
        bus.logged("revoked: it left the bus");
        within("Changed", changes_now.next())
            .await
            .unwrap()
            .unwrap();
        assert!(!in_c2(&bus).contains(&id));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn a_reload_during_the_dialog_authorizes_nothing() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("reload-dialog", "").await;
        let daemon_session = FakeSession {
            uid: DAEMON,
            ..LOCAL_ACTIVE
        };
        bus.add_session("c4", daemon_session).await;
        let dialogs = bus.relay().await;
        let (_agent, _) = bus.agent("daemon", "daemon|session|c4|0").unwrap();
        let app = Sleeper::start(Some("daemon"));
        bus.place(app.pid(), ByPid::Session("c4"));
        let subject = unix_process(app.pid());

        // auth_admin_keep: nobody and bin are offered. While the dialog is up, the administrator
        // takes nobody out of the administrators and reloads; then nobody's password is given.
        let checking = bus.check_with(&subject, CHALLENGE, HashMap::new(), ALLOW, "");
        let helping = async {
            let dialog = dialogs.next().await;
            assert_eq!(dialog.identities, [BIN, NOBODY]);
            write_trusted(
                &bus.shared.directory.join("local/50-test.toml"),
                "[administrators]\nusers = [\"bin\"]\n",
            );
            bus.reload();
            bus.logged("administrators: users [\"bin\"]");
            assert_eq!(bus.respond(DAEMON, &dialog.cookie, NOBODY).await, Ok(()));
            dialog.agent_returns().await;
        };
        let (answer, ()) = futures_lite::future::zip(checking, helping).await;
        // Decided under the old rules: not authorized, and nothing kept.
        assert_eq!(answer, Ok((false, false, no_details())));
        bus.logged("the rules were reread during the authentication");
        let again = bus
            .check_with(&subject, CHALLENGE, HashMap::new(), 0, "")
            .await;
        assert_eq!(
            again.map(|(authorized, challenge, _)| (authorized, challenge)),
            Ok(CHALLENGED)
        );
        assert!(
            !bus.shared
                .log()
                .contains("temporary authorization nyra-tmp"),
            "{}",
            bus.shared.log()
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn waiting_authentications_do_not_fill_a_services_connection() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("authentication-limits", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let daemon_session = FakeSession {
            uid: DAEMON,
            ..LOCAL_ACTIVE
        };
        bus.add_session("c4", daemon_session).await;
        // Agents whose users never close the dialog.
        let _dialogs = bus.relay().await;
        let (_nobody_agent, _) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        let (_daemon_agent, _) = bus.agent("daemon", "daemon|session|c4|0").unwrap();
        let nobody_app = Sleeper::start(Some("nobody"));
        bus.place(nobody_app.pid(), ByPid::Session("c2"));
        let daemon_app = Sleeper::start(Some("daemon"));
        bus.place(daemon_app.pid(), ByPid::Session("c4"));

        // A system service (root) asks on behalf of nobody and of daemon, 16 times each, on one
        // connection: 32 checks wait for their agents.
        let service = connect(&bus.shared.address).await;
        for app in [&nobody_app, &daemon_app] {
            for _ in 0..16 {
                send_interactive_check(&service, &unix_process(app.pid()), SELF).await;
            }
        }
        wait_until("32 authentications", || {
            bus.shared.log().matches("waits for an agent").count() == 32
        });
        let ask = |subject: Subject, action: &'static str, flags: u32| {
            let service = &service;
            async move {
                let reply = service
                    .call_method(
                        Some(NAME),
                        PATH,
                        Some(INTERFACE),
                        "CheckAuthorization",
                        &(&subject, action, HashMap::<&str, &str>::new(), flags, ""),
                    )
                    .await
                    .map_err(error_name)?;
                Ok::<Answer, String>(reply.body().deserialize::<Answer>().unwrap())
            }
        };
        // A 17th for nobody gets the challenge at once, without a dialog.
        let answer = ask(unix_process(nobody_app.pid()), SELF, ALLOW).await;
        assert_eq!(answer, Ok((false, true, no_details())));
        bus.logged("too many authentications of this user");
        // The service's other checks are still answered: the waits are not in its 32.
        assert_eq!(
            ask(unix_process(me()), DEFAULT, 0).await,
            Ok((true, false, no_details()))
        );
        assert_eq!(
            ask(unix_process(daemon_app.pid()), DEFAULT, 0).await,
            Ok((true, false, no_details()))
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn a_queued_check_goes_to_the_agent_that_serves_it_at_its_turn() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("agent-turn", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let dialogs = bus.relay().await;
        let (mut agent, _) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        let (_fallback, _) = bus.agent("nobody", "nobody-fallback|session|c2|1").unwrap();
        let app = Sleeper::start(Some("nobody"));
        bus.place(app.pid(), ByPid::Session("c2"));
        let subject = unix_process(app.pid());

        let first = bus.check_with(&subject, SELF, HashMap::new(), ALLOW, "");
        let second = bus.check_with(&subject, SELF, HashMap::new(), ALLOW, "");
        let driving = async {
            let dialog = dialogs.next().await;
            assert_eq!(dialog.agent, "nobody");
            // The other check waits for the same agent, which then unregisters, its connection
            // staying on the bus.
            wait_until("the second check waiting", || {
                bus.shared.log().matches("waits for an agent").count() == 2
            });
            assert_eq!(agent.unregister(), "unregistered");
            dialog.dismiss().await;
            let dialog = dialogs.next().await;
            assert_eq!(dialog.agent, "nobody-fallback");
            dialog.dismiss().await;
        };
        let ((first, second), ()) =
            futures_lite::future::zip(futures_lite::future::zip(first, second), driving).await;
        let dismissed = HashMap::from([("polkit.dismissed".to_string(), "true".to_string())]);
        assert_eq!(first, Ok((false, false, dismissed.clone())));
        assert_eq!(second, Ok((false, false, dismissed)));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn bus_name_and_fallback_agents_are_chosen_as_documented() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("agent-order", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let dialogs = bus.relay().await;
        let app = Sleeper::start(Some("nobody"));
        bus.place(app.pid(), ByPid::Session("c2"));
        let (_session_agent, _) = bus.agent("nobody", "session|session|c2|0").unwrap();
        let for_the_process = format!("process-fallback|process|{}|1", app.pid());
        let (_process_fallback, _) = bus.agent("nobody", &for_the_process).unwrap();
        // pkttyagent --system-bus-name: here the agent's own connection.
        let (by_name_agent, by_name) = bus.agent("nobody", "by-name|bus-name|self|0").unwrap();
        bus.place(by_name_agent.child.id(), ByPid::Session("c2"));

        // A fallback for the process gives way to the session's agent that is not one.
        assert_eq!(
            bus.agent_for(&dialogs, &unix_process(app.pid())).await,
            "session"
        );
        // The agent registered for a bus name gets that bus name's requests.
        assert_eq!(
            bus.agent_for(&dialogs, &bus_name(&by_name)).await,
            "by-name"
        );
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn a_check_sent_just_before_leaving_counts_nowhere() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("late-check", "").await;
        bus.add_session("c2", NOBODY_ACTIVE).await;
        let dialogs = bus.relay().await;
        let (_agent, _) = bus.agent("nobody", "nobody|session|c2|0").unwrap();
        let app = Sleeper::start(Some("nobody"));
        bus.place(app.pid(), ByPid::Session("c2"));
        let subject = unix_process(app.pid());
        // A caller with a check in a dialog sends one more and leaves at once: the second may be
        // handled after the departure. Repeated, as the order is up to the scheduler.
        for _ in 0..40 {
            let leaving = connect(&bus.shared.address).await;
            send_interactive_check(&leaving, &subject, SELF).await;
            let dialog = dialogs.next().await;
            send_interactive_check(&leaving, &subject, SELF).await;
            leaving.close().await.unwrap();
            dialogs.cancelled().await;
            dialog.dismiss().await;
        }
        // The daemon is whole: no panic, and checks and dialogs work as before.
        assert_eq!(
            bus.authenticate(&dialogs, &subject, SELF).await,
            Ok((true, false, no_details()))
        );
        let log = bus.shared.log();
        assert!(!log.contains("panicked"), "{log}");
    });
}

// --- Debian's agent and helper -----------------------------------------------------------------

/// Debian 13's `polkit-agent-helper-1` (polkit 126): installed setuid root, with no socket-activated
/// service for it, and run by `libpolkit-agent-1` for each dialog (observed).
const HELPER: &str = "/usr/lib/polkit-1/polkit-agent-helper-1";
const TEST_USER: &str = "nyra-test-user";
const TEST_ADMIN: &str = "nyra-test-admin";
const TEST_ADMINS: &str = "nyra-test-admins";

/// The users and groups the test made, removed when it ends, also when it fails. Those that existed
/// before the test are not recorded, so they stay.
#[derive(Default)]
struct MadeAccounts {
    users: Vec<String>,
    groups: Vec<String>,
}

impl Drop for MadeAccounts {
    fn drop(&mut self) {
        for user in &self.users {
            let _ = Command::new("userdel").arg(user).status();
        }
        for group in &self.groups {
            let _ = Command::new("groupdel").arg(group).status();
        }
    }
}

/// Makes the user `name` if it does not exist (in `group` too, if given) with no login shell, notes
/// in `made` what it made, and gives the user a new random password, which is returned: no password
/// is written in the repository or in a log.
fn user_with_password(made: &mut MadeAccounts, name: &str, group: Option<&str>) -> String {
    let run = |program: &str, arguments: &[&str]| {
        let status = Command::new(program).args(arguments).status().unwrap();
        assert!(status.success(), "{program} {arguments:?}: {status}");
    };
    let exists = |database: &str, key: &str| {
        let status = Command::new("getent")
            .args([database, key])
            .output()
            .unwrap();
        status.status.success()
    };
    if let Some(group) = group {
        if !exists("group", group) {
            run("groupadd", &[group]);
            made.groups.push(group.to_string());
        }
    }
    if !exists("passwd", name) {
        let mut arguments = vec![
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--user-group",
            name,
        ];
        if let Some(group) = group {
            arguments.extend(["--groups", group]);
        }
        run("useradd", &arguments);
        made.users.push(name.to_string());
    }
    let mut random = [0u8; 16];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
    // io::Write is already imported, so fmt::Write is brought in only for this String.
    let mut password = String::with_capacity(random.len() * 2);
    for byte in random {
        std::fmt::Write::write_fmt(&mut password, format_args!("{byte:02x}"))
            .expect("writing to a String cannot fail");
    }
    let mut chpasswd = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(chpasswd.stdin.take().unwrap(), "{name}:{password}").unwrap();
    assert!(chpasswd.wait().unwrap().success(), "chpasswd {name}");
    password
}

fn uid_of(name: &str) -> u32 {
    nix::unistd::User::from_name(name)
        .unwrap()
        .unwrap()
        .uid
        .as_raw()
}

/// Debian's `pkttyagent --process <pid>`, run as a user, in the pseudo-terminal that `script` gives
/// it: what it shows on the terminal is read from `script`'s output, and what the user types is
/// written to `script`'s input.
struct TtyAgent {
    script: Child,
    keyboard: ChildStdin,
    screen: Arc<Mutex<String>>,
    /// How much of the screen the test has already looked at.
    seen: usize,
}

impl TtyAgent {
    /// Starts it and waits until it has registered.
    fn start(bus: &Harness, user: &str, pid: u32) -> Self {
        let registered = || {
            bus.shared
                .log()
                .matches("authentication agent registered")
                .count()
        };
        let before = registered();
        let mut script = Command::new("setpriv")
            .args([
                &format!("--reuid={user}"),
                &format!("--regid={user}"),
                "--init-groups",
                "--",
            ])
            .args(["script", "--quiet", "--flush", "--return", "--command"])
            .arg(format!("exec pkttyagent --process {pid}"))
            .arg("/dev/null")
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.shared.address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("script");
        let screen = Arc::new(Mutex::new(String::new()));
        let mut output = script.stdout.take().unwrap();
        let shown = screen.clone();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            while let Ok(read @ 1..) = output.read(&mut buffer) {
                let text = String::from_utf8_lossy(&buffer[..read]);
                shown.lock().unwrap().push_str(&text);
            }
        });
        let agent = Self {
            keyboard: script.stdin.take().unwrap(),
            script,
            screen,
            seen: 0,
        };
        wait_until("pkttyagent to register", || registered() > before);
        agent
    }

    /// Waits until the terminal shows `text` after what the test has seen; what it showed up to
    /// the end of `text`.
    fn shows(&mut self, text: &str) -> String {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let screen = self.screen.lock().unwrap().clone();
            if let Some(at) = screen[self.seen..].find(text) {
                let end = self.seen + at + text.len();
                let shown = screen[self.seen..end].to_string();
                self.seen = end;
                return shown;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for pkttyagent to show {text:?}; it showed {:?}",
                &screen[self.seen..]
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for the password prompt, and for the terminal to stop echoing: only then does
    /// pkttyagent read the password, so nothing typed earlier can be lost.
    fn asks_for_password(&mut self) {
        self.shows("Password: ");
        let terminal = File::open(format!("/proc/{}/fd/0", self.pid())).unwrap();
        wait_until("the terminal to stop echoing", || {
            let modes = rustix::termios::tcgetattr(&terminal).unwrap().local_modes;
            !modes.contains(rustix::termios::LocalModes::ECHO)
        });
    }

    fn types(&mut self, text: &str) {
        self.keyboard.write_all(text.as_bytes()).unwrap();
        self.keyboard.flush().unwrap();
    }

    /// pkttyagent's PID: `script` runs it as its only child.
    fn pid(&self) -> u32 {
        let script = self.script.id();
        let children = std::fs::read_to_string(format!("/proc/{script}/task/{script}/children"));
        let pid = children.unwrap().trim().parse().unwrap();
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
        assert_eq!(name, "pkttyagent\n");
        pid
    }
}

impl Drop for TtyAgent {
    fn drop(&mut self) {
        // Its terminal goes away with script, and pkttyagent with it (SIGHUP).
        let _ = self.script.kill();
        let _ = self.script.wait();
        if std::thread::panicking() {
            // The passwords are never on it: the terminal does not echo them.
            eprintln!("--- pkttyagent ---\n{}", self.screen.lock().unwrap());
        }
    }
}

impl Harness {
    /// Debian's `pkcheck` as root for the process `pid`, started without waiting for it.
    fn start_pkcheck(&self, action: &str, pid: u32, interactive: bool) -> Child {
        let pid = pid.to_string();
        let mut arguments = vec!["--action-id", action, "--process", &pid];
        if interactive {
            arguments.push("--allow-user-interaction");
        }
        self.shared
            .command(None, None, "pkcheck", &arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("setpriv")
    }
}

/// pkcheck's answer ([`pkcheck_answer`]) and the details it printed.
fn pkcheck_finished(pkcheck: Child) -> (Result<i32, String>, String) {
    let output = pkcheck.wait_with_output().unwrap();
    let details = String::from_utf8_lossy(&output.stdout).into_owned();
    (pkcheck_answer(output), details)
}

#[test]
#[ignore = "needs root, dbus-daemon, Debian's polkit and no system bus: run by the integration job"]
fn debians_agent_and_helper_check_real_passwords() {
    futures_lite::future::block_on(async {
        // Set up as Debian 13 ships it: the helper is setuid root.
        let helper = std::fs::metadata(HELPER).expect(HELPER);
        assert_eq!(
            (helper.mode() & 0o7777, helper.uid()),
            (0o4755, 0),
            "{HELPER} is not setuid root"
        );
        let rules = format!("[administrators]\ngroups = [\"{TEST_ADMINS}\"]\n");
        // Declared first, so it is dropped last: after the agents and the bus are gone.
        let mut made = MadeAccounts::default();
        let bus = Harness::start_on_system_socket("real-agent", &rules).await;
        let user_password = user_with_password(&mut made, TEST_USER, None);
        let admin_password = user_with_password(&mut made, TEST_ADMIN, Some(TEST_ADMINS));
        let (user, admin) = (uid_of(TEST_USER), uid_of(TEST_ADMIN));
        let app = Sleeper::start(Some(TEST_USER));
        let mut agent = TtyAgent::start(&bus, TEST_USER, app.pid());

        // auth_self with the user's own password: the helper checked it with PAM and answered,
        // as root, for the agent's user.
        let pkcheck = bus.start_pkcheck(SELF, app.pid(), true);
        agent.shows(&format!("==== AUTHENTICATING FOR {SELF} ===="));
        let dialog = agent.shows(&format!("Authenticating as: {TEST_USER}"));
        assert!(dialog.contains("Authenticate yourself"), "{dialog}");
        agent.asks_for_password();
        agent.types(&format!("{user_password}\n"));
        agent.shows("==== AUTHENTICATION COMPLETE ====");
        assert_eq!(pkcheck_finished(pkcheck).0, Ok(PKCHECK_AUTHORIZED));
        bus.logged(&format!("authorized, as uid {user}"));

        // A wrong password: PAM refuses it, the helper does not answer, and pkttyagent returns as
        // usual, which is not an authentication.
        let pkcheck = bus.start_pkcheck(SELF, app.pid(), true);
        agent.asks_for_password();
        agent.types("not the password\n");
        agent.shows("pam_authenticate failed");
        agent.shows("==== AUTHENTICATION FAILED ====");
        assert_eq!(pkcheck_finished(pkcheck).0, Ok(PKCHECK_NOT_AUTHORIZED));
        bus.logged("returned without an authentication");

        // auth_admin: only administrators are offered, and the administrator's password works.
        let pkcheck = bus.start_pkcheck(ADMIN, app.pid(), true);
        let choice = agent.shows("Choose identity to authenticate as");
        assert!(!choice.contains(TEST_USER), "{choice}");
        let number = choice
            .lines()
            .find(|line| line.trim_end().ends_with(TEST_ADMIN))
            .and_then(|line| line.trim().split_once('.'))
            .map(|(number, _)| number.to_string())
            .unwrap_or_else(|| panic!("{TEST_ADMIN} is not offered: {choice}"));
        agent.shows(": ");
        agent.types(&format!("{number}\n"));
        agent.asks_for_password();
        agent.types(&format!("{admin_password}\n"));
        agent.shows("==== AUTHENTICATION COMPLETE ====");
        assert_eq!(pkcheck_finished(pkcheck).0, Ok(PKCHECK_AUTHORIZED));
        bus.logged(&format!("authorized, as uid {admin}"));

        // auth_self_keep: kept, and the next check is authorized by it, without a dialog.
        let pkcheck = bus.start_pkcheck(SELF_KEEP, app.pid(), true);
        agent.asks_for_password();
        agent.types(&format!("{user_password}\n"));
        agent.shows("==== AUTHENTICATION COMPLETE ====");
        let (answer, details) = pkcheck_finished(pkcheck);
        assert_eq!(answer, Ok(PKCHECK_AUTHORIZED));
        assert!(
            details.contains("polkit\\56retains_authorization_after_challenge=true"),
            "{details}"
        );
        let kept = details
            .lines()
            .find(|line| line.starts_with("polkit\\56temporary_authorization_id="))
            .unwrap_or_else(|| panic!("not kept: {details}"))
            .to_string();
        let dialogs = bus.shared.log().matches("through the agent of").count();
        let (answer, details) = pkcheck_finished(bus.start_pkcheck(SELF_KEEP, app.pid(), false));
        assert_eq!(answer, Ok(PKCHECK_AUTHORIZED));
        assert_eq!(details.lines().collect::<Vec<_>>(), [kept.as_str()]);
        assert_eq!(
            bus.shared.log().matches("through the agent of").count(),
            dialogs
        );

        // The caller cancels while the password is asked: the caller has its answer at once, and
        // the agent gets CancelAuthentication. pkttyagent acts on it only once its read of the
        // terminal ends; even the right password typed then authorizes nothing. After that it
        // answers neither call and shows no other dialog, with Debian's polkitd too (observed), so
        // a new agent takes over.
        let subject = unix_process(app.pid());
        let checking = bus.check_with(&subject, SELF, HashMap::new(), ALLOW, "real-cancel");
        let cancelling = async {
            let agent = blocking::unblock(move || {
                agent.asks_for_password();
                agent
            })
            .await;
            assert_eq!(bus.cancel("real-cancel").await, Ok(()));
            agent
        };
        let (answer, returned) = futures_lite::future::zip(checking, cancelling).await;
        agent = returned;
        assert_eq!(answer, Err(CANCELLED.to_string()));
        agent.types(&format!("{user_password}\n"));
        agent.shows("Cancelled");
        agent.shows("==== AUTHENTICATION FAILED ====");
        assert_eq!(bus.check(&subject, SELF).await, Ok(CHALLENGED));
        drop(agent);

        // Ctrl-C at the prompt ends pkttyagent (SIGINT from its terminal): it leaves the bus
        // without answering, so not authorized.
        let mut agent = TtyAgent::start(&bus, TEST_USER, app.pid());
        let pkcheck = bus.start_pkcheck(SELF, app.pid(), true);
        agent.asks_for_password();
        agent.types("\x03");
        assert_eq!(pkcheck_finished(pkcheck).0, Ok(PKCHECK_NOT_AUTHORIZED));
        drop(agent);

        // An agent killed during the dialog: the same.
        let mut agent = TtyAgent::start(&bus, TEST_USER, app.pid());
        let pkcheck = bus.start_pkcheck(SELF, app.pid(), true);
        agent.asks_for_password();
        let pid = rustix::process::Pid::from_raw(agent.pid() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
        assert_eq!(pkcheck_finished(pkcheck).0, Ok(PKCHECK_NOT_AUTHORIZED));
        assert_eq!(bus.check(&subject, SELF).await, Ok(CHALLENGED));
        drop(agent);

        // The user ends the input (Ctrl-D) instead of typing a password: pkttyagent returns as
        // usual, so not authorized; it does not answer Cancelled, so not "dismissed" either. Last,
        // and with an agent of its own: after an end of input, this pkttyagent ends every later
        // dialog at once in the same way (observed).
        let mut agent = TtyAgent::start(&bus, TEST_USER, app.pid());
        let pkcheck = bus.start_pkcheck(SELF, app.pid(), true);
        agent.asks_for_password();
        agent.types("\x04");
        agent.shows("==== AUTHENTICATION FAILED ====");
        assert_eq!(pkcheck_finished(pkcheck).0, Ok(PKCHECK_NOT_AUTHORIZED));
    });
}
