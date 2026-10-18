// SPDX-License-Identifier: MIT
//! nyra-polkitd on a private, system-like bus (docs/DESIGN.md, "Tests"), with the bus policy from
//! `dist/`. The daemon runs as the `polkitd` user, as the service does; logind is a fake served by
//! the test on the same bus, so each process can be put in any session. Clients: zbus, Debian's
//! `pkcheck` and `busctl`.
//!
//! Authentication agents are this test binary run again as another user ([`fake_agent_program`]):
//! each registers with the daemon and passes every dialog on to the test (the "relay"), which plays
//! the user and, as root, the helper that answers `AuthenticationAgentResponse2`.
//!
//! Needs root (to create rule files owned by root and to run processes as other users), a writable
//! `/sys/fs/cgroup` (to put a process under a user's service manager), `dbus-daemon`, `pkcheck`,
//! `busctl`, `setpriv`, `timeout` and the users `polkitd`, `nobody` and `daemon`: the integration
//! job of CI runs them in a privileged Debian 13 container with
//! `cargo test --test dbus -- --ignored`.
//!
//! Every wait has a timeout, so a regression fails the test instead of hanging the job.

use futures_lite::StreamExt;
use nyra_polkitd::process::Process;
use std::collections::HashMap;
use std::fs::{File, Permissions};
use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::fdo::DBusProxy;
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
users = ["root"]
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

/// How long any wait of the tests may take. Longer than the daemon's own timeout on logind (10 s),
/// so that one is seen; short enough that a hang fails well before the job's timeout.
const TIMEOUT: Duration = Duration::from_secs(30);

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
        (self.display.to_string(), session_path(self.display))
    }
}

// --- The harness -------------------------------------------------------------------------------

/// A private bus with nyra-polkitd, the fake logind and a client on it.
struct Harness {
    directory: PathBuf,
    address: String,
    bus: Child,
    daemon: Child,
    logind: Connection,
    logind_state: Arc<Mutex<LogindState>>,
    client: Connection,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        let _ = self.bus.kill();
        let _ = self.bus.wait();
        if std::thread::panicking() {
            eprintln!("--- nyra-polkitd log ---\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn write_trusted(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(0o644)).unwrap();
}

fn make_directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `future`, or a failed test once [`TIMEOUT`] has passed.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    let timeout = async {
        async_io::Timer::after(TIMEOUT).await;
        panic!("timed out waiting for {what}");
    };
    futures_lite::future::or(future, timeout).await
}

/// A client connection to the test bus, whose calls time out.
async fn connect(address: &str) -> Connection {
    zbus::connection::Builder::address(address)
        .unwrap()
        .method_timeout(TIMEOUT)
        .build()
        .await
        .unwrap()
}

impl Harness {
    async fn start(test: &str, local_rules: &str) -> Self {
        assert!(
            nix::unistd::geteuid().is_root(),
            "the D-Bus integration tests need root (see the top of tests/dbus.rs)"
        );
        let directory = std::env::temp_dir().join(format!("nyra-polkit-{test}"));
        let _ = std::fs::remove_dir_all(&directory);
        for sub in ["", "actions", "image", "local"] {
            make_directory(&directory.join(sub));
        }
        write_trusted(&directory.join("actions/test.policy"), ACTIONS);
        write_trusted(&directory.join("image/50-test.toml"), RULES);
        write_trusted(&directory.join("local/90-local.toml"), local_rules);

        let socket = directory.join("bus");
        let policy = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../dist/org.freedesktop.PolicyKit1.conf")
            .canonicalize()
            .unwrap();
        // The defaults of Debian's system bus (deny owning names and calling methods, unless
        // allowed), the fake logind's name, and the daemon's own policy from dist/.
        let config = format!(
            r#"<busconfig>
  <type>system</type>
  <listen>unix:path={socket}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Properties"/>
  </policy>
  <policy user="root">
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Monitoring"/>
    <allow own="org.freedesktop.login1"/>
    <allow own="org.nyra.test.Relay"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.freedesktop.login1"/>
    <allow send_destination="org.nyra.test.Relay"/>
  </policy>
  <include>{policy}</include>
</busconfig>
"#,
            socket = socket.display(),
            policy = policy.display()
        );
        write_trusted(&directory.join("bus.conf"), &config);
        let bus = Command::new("dbus-daemon")
            .arg(format!(
                "--config-file={}",
                directory.join("bus.conf").display()
            ))
            .args(["--nofork", "--nopidfile", "--nosyslog"])
            .spawn()
            .expect("dbus-daemon");
        wait_until("the bus socket", || socket.exists());
        let address = format!("unix:path={}", socket.display());

        let logind_state = Arc::new(Mutex::new(LogindState::default()));
        let logind = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .serve_at("/org/freedesktop/login1", FakeManager(logind_state.clone()))
            .unwrap()
            .name("org.freedesktop.login1")
            .unwrap()
            .build()
            .await
            .unwrap();

        let log = File::create(directory.join("daemon.log")).unwrap();
        let daemon = Command::new("setpriv")
            .args(["--reuid=polkitd", "--regid=polkitd", "--init-groups", "--"])
            .arg(env!("CARGO_BIN_EXE_nyra-polkitd"))
            .arg("--actions-dir")
            .arg(directory.join("actions"))
            .arg("--image-rules-dir")
            .arg(directory.join("image"))
            .arg("--local-rules-dir")
            .arg(directory.join("local"))
            .env("DBUS_SYSTEM_BUS_ADDRESS", &address)
            .stderr(log)
            .spawn()
            .expect("setpriv");

        let client = connect(&address).await;
        let mut harness = Self {
            directory,
            address,
            bus,
            daemon,
            logind,
            logind_state,
            client,
        };
        let deadline = Instant::now() + TIMEOUT;
        while !harness.name_is_owned().await {
            assert!(
                harness.daemon.try_wait().unwrap().is_none(),
                "nyra-polkitd exited:\n{}",
                harness.log()
            );
            assert!(Instant::now() < deadline, "nyra-polkitd never took {NAME}");
            std::thread::sleep(Duration::from_millis(50));
        }
        harness
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("daemon.log")).unwrap_or_default()
    }

    async fn name_is_owned(&self) -> bool {
        DBusProxy::new(&self.client)
            .await
            .unwrap()
            .name_has_owner(NAME.try_into().unwrap())
            .await
            .unwrap()
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
        self.client
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

    /// Runs a client on the test bus, as `user` (a name or a uid) or as root.
    fn run(&self, user: Option<&str>, program: &str, arguments: &[&str]) -> Output {
        self.command(user, program, arguments)
            .output()
            .expect("setpriv")
    }

    /// A client on the test bus, as `user` or as root, given [`TIMEOUT`] by `timeout`: a client
    /// that hangs fails the test (`timeout` exits with 124).
    fn command(&self, user: Option<&str>, program: &str, arguments: &[&str]) -> Command {
        let mut command = Command::new("setpriv");
        match user {
            Some(user) => command.args([
                &format!("--reuid={user}"),
                &format!(
                    "--regid={}",
                    if user == "nobody" { "nogroup" } else { user }
                ),
                "--clear-groups",
            ]),
            None => command.arg("--reuid=0"),
        };
        command
            .args(["--", "timeout", &TIMEOUT.as_secs().to_string(), program])
            .args(arguments)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .stdin(Stdio::null());
        command
    }

    /// Runs pkcheck as `user` or as root: see [`pkcheck_answer`].
    fn pkcheck_as(&self, user: Option<&str>, arguments: &[&str]) -> Result<i32, String> {
        pkcheck_answer(self.run(user, "pkcheck", arguments))
    }

    fn pkcheck(&self, action: &str, process: &str) -> Result<i32, String> {
        self.pkcheck_as(None, &["--action-id", action, "--process", process])
    }

    async fn cancel(&self, cancellation_id: &str) -> Result<(), String> {
        self.client
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
        let pid = rustix::process::Pid::from_raw(self.daemon.id() as i32).unwrap();
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

// --- The tests ---------------------------------------------------------------------------------

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn answers_from_rules_and_defaults_for_every_subject_kind() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("answers", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let own_name = bus.client.unique_name().unwrap().to_string();

        for subject in [unix_process(me()), bus_name(&own_name), unix_session("c1")] {
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

        let pid = me().to_string();
        assert_eq!(bus.pkcheck(DEFAULT, &pid), Ok(PKCHECK_AUTHORIZED));
        assert_eq!(bus.pkcheck(RULED, &pid), Ok(PKCHECK_AUTHORIZED));
        assert_eq!(bus.pkcheck(DENIED, &pid), Ok(PKCHECK_NOT_AUTHORIZED));
        assert_eq!(bus.pkcheck(CHALLENGE, &pid), Ok(PKCHECK_CHALLENGE));
        assert_eq!(bus.pkcheck(UNKNOWN, &pid), Ok(PKCHECK_NOT_AUTHORIZED));
    });
}

#[test]
#[ignore = "needs root and dbus-daemon: run by the integration job"]
fn the_session_from_logind_picks_the_default() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("sessions", "").await;
        let session = |remote, seat, active| FakeSession {
            uid: 0,
            remote,
            seat,
            active,
        };
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.add_session("remote", session(true, "seat0", true))
            .await;
        // Like each user's manager session: no seat, not remote, active.
        bus.add_session("manager", session(false, "", true)).await;
        bus.add_session("inactive", session(false, "seat0", false))
            .await;
        // root's display session is c1, but a process outside root's user manager does not get it.
        bus.add_user_with_display(0, "c1").await;

        let no_session = Sleeper::start(None);
        let remote = Sleeper::start(None);
        let manager = Sleeper::start(None);
        let inactive = Sleeper::start(None);
        let failing = Sleeper::start(None);
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
        // root keeps the session it is in: `sudo` at the seat.
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

        drop(app);
        for cgroup in [
            &manager,
            &manager.parent().unwrap().to_path_buf(),
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
        let log = bus.log();
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

        // root may check anyone; the answer is the subject's own: the rule for root does not apply.
        let subject = unix_process(nobody.pid());
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert_eq!(bus.check(&subject, RULED).await, Ok(NO));

        // Another user may not check root's subjects: a process, a bus name or a session.
        let refused = Err(NOT_AUTHORIZED.to_string());
        let root_pid = me().to_string();
        let root_name = bus.client.unique_name().unwrap().to_string();
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
            let output = bus.run(
                Some("nobody"),
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
        let run_as_nobody =
            |script: &str| pkcheck_answer(bus.run(Some("nobody"), "sh", &["-c", script]));
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
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let subject = unix_process(me());

        // The daemon keeps the name and denies everything, even what the defaults allow.
        for _ in 0..3 {
            assert_eq!(bus.check(&subject, DEFAULT).await, Ok(NO));
        }
        assert_eq!(
            bus.pkcheck(DEFAULT, &me().to_string()),
            Ok(PKCHECK_NOT_AUTHORIZED)
        );
        assert!(bus.name_is_owned().await);
        let log = bus.log();
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
        let mut changes = MessageStream::for_match_rule(changed, &bus.client, None)
            .await
            .unwrap();

        // Fixed, then reloaded: normal answers.
        write_trusted(&bus.directory.join("local/90-local.toml"), "# fixed\n");
        bus.reload();
        within("Changed", changes.next()).await.unwrap().unwrap();
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert_eq!(
            bus.pkcheck(DEFAULT, &me().to_string()),
            Ok(PKCHECK_AUTHORIZED)
        );

        // Broken again by a reload: denied again, still owning the name.
        write_trusted(&bus.directory.join("local/90-local.toml"), BROKEN_RULES);
        bus.reload();
        within("Changed", changes.next()).await.unwrap().unwrap();
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(NO));
        assert!(bus.name_is_owned().await);
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
                ADMIN, CHALLENGE, DEFAULT, DENIED, LEVELS, OWNED, OWNED_BARE, RULED, SELF,
                SELF_KEEP
            ]
        );
        let default = &actions[2];
        assert_eq!(default.1, "Fă lucrul implicit");
        assert_eq!(default.2, "Authentication is required");
        assert_eq!(default.3, "nyra-polkit tests");
        // no, auth_admin, yes.
        assert_eq!((default.6, default.7, default.8), (0, 2, 5));

        let properties = zbus::fdo::PropertiesProxy::builder(&bus.client)
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
        let first = connect(&bus.address).await;
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
        let second = connect(&bus.address).await;
        for _ in 0..32 {
            send_check(&second, &slow_subject).await;
        }
        arrivals(&at_logind, 32).await;
        // Root's connections are the system services': 64 checks of root in flight do not stop a
        // third one.
        assert_eq!(bus.check(&me_subject, DEFAULT).await, Ok(YES));
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
        let mut waiting: Vec<Child> = (0..64)
            .map(|_| {
                Command::new("setpriv")
                    .args(["--reuid=nobody", "--regid=nogroup", "--clear-groups", "--"])
                    .arg("pkcheck")
                    .args(pkcheck_slow)
                    .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
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
fn a_call_as_large_as_the_bus_allows_does_not_stop_the_daemon() {
    futures_lite::future::block_on(async {
        let mut bus = Harness::start("large-call", "").await;
        bus.add_session("c1", LOCAL_ACTIVE).await;
        bus.place(me(), ByPid::Session("c1"));
        let cgroup = UnitMemoryCgroup::place(bus.daemon.id());
        let subject = unix_process(me());

        // About 31 MiB of details (24 bytes each on the wire), under the bus's 32 MiB per message:
        // turned into Rust values, they take far more.
        let names: Vec<String> = (0..1_350_000).map(|i| format!("{i:x}")).collect();
        let details: HashMap<&str, &str> = names.iter().map(|name| (name.as_str(), "")).collect();
        let large = bus.check_with(&subject, DEFAULT, details, 0, "").await;
        eprintln!("the daemon's peak memory: {} bytes", cgroup.peak().trim());
        assert_eq!(large.map(|(authorized, _, _)| authorized), Ok(true));
        // The same daemon still answers.
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert!(bus.daemon.try_wait().unwrap().is_none(), "{}", bus.log());

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

/// `spec`: `<label>|session|<session id>|<fallback: 0 or 1>` or `<label>|process|<pid>|<fallback>`.
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
        let relay = zbus::connection::Builder::address(self.address.as_str())
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
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
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
        self.client
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
        let output = self.run(
            Some(user),
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
        wait_until(text, || self.log().contains(text));
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
        let log = bus.log();
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
        let log = bus.log();
        assert!(!log.contains(UNKNOWN_COOKIE), "{log}");

        // pkcheck --allow-user-interaction, end to end.
        let pid = app.pid().to_string();
        let mut pkcheck = bus.command(
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
        let leaving = connect(&bus.address).await;
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

        // root's process in nobody's session (sudo at the seat) and daemon's (su daemon there):
        // no agent of theirs, so a challenge, and no dialog anywhere.
        let root_app = Sleeper::start(None);
        bus.place(root_app.pid(), ByPid::Session("c2"));
        let daemon_in_c2 = Sleeper::start(Some("daemon"));
        bus.place(daemon_in_c2.pid(), ByPid::Session("c2"));
        for app in [&root_app, &daemon_in_c2] {
            let answer = bus
                .check_with(&unix_process(app.pid()), SELF, HashMap::new(), ALLOW, "")
                .await;
            assert_eq!(answer, Ok((false, true, no_details())));
        }
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
        let mut changes = MessageStream::for_match_rule(changed, &bus.client, None)
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
        drop(agent);
        bus.logged("revoked: it left the bus");
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
                &bus.directory.join("local/50-test.toml"),
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
            !bus.log().contains("temporary authorization nyra-tmp"),
            "{}",
            bus.log()
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
        let service = connect(&bus.address).await;
        for app in [&nobody_app, &daemon_app] {
            for _ in 0..16 {
                send_interactive_check(&service, &unix_process(app.pid()), SELF).await;
            }
        }
        wait_until("32 authentications", || {
            bus.log().matches("waits for an agent").count() == 32
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
                bus.log().matches("waits for an agent").count() == 2
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
