// SPDX-License-Identifier: MIT
//! nyra-polkitd on a private, system-like bus (docs/DESIGN.md, "Tests"), with the bus policy from
//! `dist/`. The daemon runs as the `polkitd` user, as the service does; logind is a fake served by
//! the test on the same bus, so each process can be put in any session. Clients: zbus and Debian's
//! `pkcheck`.
//!
//! Needs root (to create rule files owned by root and to run processes as other users), a writable
//! `/sys/fs/cgroup` (to put a process under a user's service manager), `dbus-daemon`, `pkcheck`,
//! `busctl`, `setpriv` and the users `polkitd` and `nobody`: the integration job of CI runs them in
//! a privileged Debian 13 container with `cargo test --test dbus -- --ignored`.
//!
//! Every wait has a timeout, so a regression fails the test instead of hanging the job.

use futures_lite::StreamExt;
use nyra_polkitd::process::Process;
use std::collections::HashMap;
use std::fs::{File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::fdo::DBusProxy;
use zbus::message::Type as MessageType;
use zbus::zvariant::{OwnedObjectPath, Value};
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

type Answer = (bool, bool, HashMap<String, String>);
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

struct FakeSessionObject(FakeSession);

#[interface(name = "org.freedesktop.login1.Session")]
impl FakeSessionObject {
    #[zbus(property)]
    fn remote(&self) -> bool {
        self.0.remote
    }
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        let path = match self.0.seat {
            "" => "/",
            _ => "/org/freedesktop/login1/seat/seat0",
        };
        (
            self.0.seat.to_string(),
            OwnedObjectPath::try_from(path).unwrap(),
        )
    }
    #[zbus(property)]
    fn active(&self) -> bool {
        self.0.active
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        (self.0.uid, user_path(self.0.uid))
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
  </policy>
  <policy context="default">
    <allow send_destination="org.freedesktop.login1"/>
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
            .at(session_path(id), FakeSessionObject(session))
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

    /// Runs a client on the test bus, as `user` (a name or a uid) or as root.
    fn run(&self, user: Option<&str>, program: &str, arguments: &[&str]) -> Output {
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
        // pkcheck and busctl give up after 25 s by themselves.
        command
            .arg("--")
            .arg(program)
            .args(arguments)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .stdin(Stdio::null())
            .output()
            .expect("setpriv")
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
        Self(command.args(["--", "sleep", "600"]).spawn().unwrap())
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
        assert_eq!(ids, [CHALLENGE, DEFAULT, DENIED, OWNED, OWNED_BARE, RULED]);
        let default = &actions[1];
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
        assert_eq!(&*all["BackendFeatures"], &Value::U32(0));
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
fn checks_in_flight_are_limited_per_connection_and_per_user() {
    futures_lite::future::block_on(async {
        let bus = Harness::start("limits", "").await;
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
        // Another connection of the same user (root) has its own 32...
        let second = connect(&bus.address).await;
        for _ in 0..32 {
            send_check(&second, &slow_subject).await;
        }
        arrivals(&at_logind, 32).await;
        // ...but the user has 64 in all: a third connection is refused too.
        assert_eq!(
            bus.check(&me_subject, DEFAULT).await,
            Err(FAILED.to_string())
        );
        // Other users are not: nobody checks itself (no session: allow_any, "no").
        let itself = format!("exec pkcheck --action-id {DEFAULT} --process $$");
        assert_eq!(
            pkcheck_answer(bus.run(Some("nobody"), "sh", &["-c", &itself])),
            Ok(PKCHECK_NOT_AUTHORIZED)
        );
    });
}
