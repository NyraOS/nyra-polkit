// SPDX-License-Identifier: MIT
//! nyra-polkitd on a private, system-like bus (docs/DESIGN.md, "Tests"), with the bus policy from
//! `dist/`. The daemon runs as the `polkitd` user, as the service does; logind is a fake served by
//! the test on the same bus, so each process can be put in any session. Clients: zbus and Debian's
//! `pkcheck`.
//!
//! Needs root (to create rule files owned by root and to run processes as other users),
//! `dbus-daemon`, `pkcheck`, `setpriv` and the users `polkitd` and `nobody`: the integration job
//! of CI runs them in a Debian 13 container with `cargo test --test dbus -- --ignored`.

use futures_lite::StreamExt;
use nyra_polkitd::process::Process;
use std::collections::HashMap;
use std::fs::{File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

type Answer = (bool, bool, HashMap<String, String>);
const YES: (bool, bool) = (true, false);
const NO: (bool, bool) = (false, false);
const CHALLENGED: (bool, bool) = (false, true);

// pkcheck(1) exit codes.
const PKCHECK_AUTHORIZED: i32 = 0;
const PKCHECK_NOT_AUTHORIZED: i32 = 1;
const PKCHECK_CHALLENGE: i32 = 2;
const PKCHECK_ERROR: i32 = 127;

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
        let hang = match self.0.lock().unwrap().by_pid.get(&pid) {
            None => return Err(LogindError::NoSessionForPID(format!("{pid}"))),
            Some(ByPid::Session(id)) => return Ok(session_path(id)),
            Some(ByPid::Fail) => return Err(LogindError::Broken("logind failed".into())),
            Some(ByPid::Hang(arrived)) => arrived.clone(),
        };
        hang.send(()).await.unwrap();
        futures_lite::future::pending().await
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
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
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

        let client = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let mut harness = Self {
            directory,
            address,
            bus,
            daemon,
            logind,
            logind_state,
            client,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
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

    async fn check_with(
        &self,
        subject: &Subject,
        action: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> Result<Answer, String> {
        let reply = self
            .client
            .call_method(
                Some(NAME),
                PATH,
                Some(INTERFACE),
                "CheckAuthorization",
                &(subject, action, details, flags, cancellation_id),
            )
            .await
            .map_err(error_name)?;
        // One struct, as polkit's client library expects.
        assert_eq!(reply.body().signature().to_string(), "(bba{ss})");
        Ok(reply.body().deserialize::<Answer>().unwrap())
    }

    /// The answer, without its details, or the error's name.
    async fn check(&self, subject: &Subject, action: &str) -> Result<(bool, bool), String> {
        self.check_with(subject, action, HashMap::new(), 0, "")
            .await
            .map(|(authorized, challenge, _)| (authorized, challenge))
    }

    /// Runs a client (pkcheck) on the test bus, as `user` or as root; its exit code.
    fn run(&self, user: Option<&str>, program: &str, arguments: &[&str]) -> i32 {
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
        let output = command
            .arg("--")
            .arg(program)
            .args(arguments)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .stdin(Stdio::null())
            .output()
            .expect("setpriv");
        output.status.code().unwrap_or_else(|| {
            panic!(
                "{program} {arguments:?}: {}, {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    fn pkcheck(&self, action: &str, process: &str) -> i32 {
        self.run(
            None,
            "pkcheck",
            &["--action-id", action, "--process", process],
        )
    }

    fn reload(&self) {
        let pid = rustix::process::Pid::from_raw(self.daemon.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
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
        assert_eq!(bus.pkcheck(DEFAULT, &pid), PKCHECK_AUTHORIZED);
        assert_eq!(bus.pkcheck(RULED, &pid), PKCHECK_AUTHORIZED);
        assert_eq!(bus.pkcheck(DENIED, &pid), PKCHECK_NOT_AUTHORIZED);
        assert_eq!(bus.pkcheck(CHALLENGE, &pid), PKCHECK_CHALLENGE);
        assert_eq!(bus.pkcheck(UNKNOWN, &pid), PKCHECK_NOT_AUTHORIZED);
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
            PKCHECK_NOT_AUTHORIZED
        );
        assert_eq!(
            bus.pkcheck(DEFAULT, &inactive.pid().to_string()),
            PKCHECK_CHALLENGE
        );
        assert_eq!(
            bus.pkcheck(DEFAULT, &failing.pid().to_string()),
            PKCHECK_ERROR
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
        // The client saw another user.
        assert_eq!(
            bus.check(&unix_process_with(me(), start_time, Some(4242)), DEFAULT)
                .await,
            refused
        );
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
            PKCHECK_ERROR
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

        // Another user may not check root's process.
        let root_pid = me().to_string();
        let as_nobody = |arguments: &[&str]| bus.run(Some("nobody"), "pkcheck", arguments);
        assert_eq!(
            as_nobody(&["--action-id", DEFAULT, "--process", &root_pid]),
            PKCHECK_ERROR
        );
        // But it may check itself (no session: allow_any, "no").
        let itself = format!("exec pkcheck --action-id {DEFAULT} --process $$");
        assert_eq!(
            bus.run(Some("nobody"), "sh", &["-c", &itself]),
            PKCHECK_NOT_AUTHORIZED
        );
        // polkit.* details: only the documented ones, and only from root.
        let with_detail = format!("{itself} --detail polkit.message hello");
        assert_eq!(
            bus.run(Some("nobody"), "sh", &["-c", &with_detail]),
            PKCHECK_ERROR
        );
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
            PKCHECK_NOT_AUTHORIZED
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
        changes.next().await.unwrap().unwrap();
        assert_eq!(bus.check(&subject, DEFAULT).await, Ok(YES));
        assert_eq!(bus.pkcheck(DEFAULT, &me().to_string()), PKCHECK_AUTHORIZED);

        // Broken again by a reload: denied again, still owning the name.
        write_trusted(&bus.directory.join("local/90-local.toml"), BROKEN_RULES);
        bus.reload();
        changes.next().await.unwrap().unwrap();
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
        assert_eq!(ids, [CHALLENGE, DEFAULT, DENIED, RULED]);
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

        let bus = &bus;
        let cancel = |id: &'static str| async move {
            bus.client
                .call_method(
                    Some(NAME),
                    PATH,
                    Some(INTERFACE),
                    "CancelCheckAuthorization",
                    &(id),
                )
                .await
                .map(|_| ())
                .map_err(error_name)
        };
        assert_eq!(cancel("nothing").await, Err(FAILED.to_string()));

        // A check that waits on logind, cancelled while it waits.
        let slow = Sleeper::start(None);
        let (arrived, at_logind) = async_channel::bounded(1);
        bus.place(slow.pid(), ByPid::Hang(arrived));
        let slow_subject = unix_process(slow.pid());
        let me_subject = unix_process(me());
        let waiting = bus.check_with(&slow_subject, DEFAULT, HashMap::new(), 0, "c");
        let meanwhile = async {
            at_logind.recv().await.unwrap();
            let again = bus
                .check_with(&me_subject, DEFAULT, HashMap::new(), 0, "c")
                .await;
            assert_eq!(
                again.map(|_| ()),
                Err("org.freedesktop.PolicyKit1.Error.CancellationIdNotUnique".to_string())
            );
            cancel("c").await
        };
        let (cancelled, cancelling) = futures_lite::future::zip(waiting, meanwhile).await;
        assert_eq!(cancelling, Ok(()));
        assert_eq!(
            cancelled.map(|_| ()),
            Err("org.freedesktop.PolicyKit1.Error.Cancelled".to_string())
        );
        // The id is free again.
        let again = bus
            .check_with(&me_subject, DEFAULT, HashMap::new(), 0, "c")
            .await;
        assert_eq!(again.map(|(authorized, _, _)| authorized), Ok(true));
    });
}
