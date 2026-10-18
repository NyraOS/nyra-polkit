// SPDX-License-Identifier: MIT
//! The harness of the D-Bus integration tests, shared by `nyra-polkitd/tests/dbus.rs` and
//! `nyra-pkcheck/tests/compat.rs`: a private, system-like bus (the system bus's default policy
//! and the daemon's own policy from `dist/`), nyra-polkitd on it as the `polkitd` user, a client
//! connection, and running clients under a timeout, so a regression fails the test instead of
//! hanging the job. Each test file keeps its own fake logind, action and rule files, and checks.
//!
//! One file, included with `#[path]` from the tests of both crates: the integration tests of
//! two crates cannot share a `tests/common/` of their own, and a helper crate (a manifest, a
//! workspace member, a Cargo.lock entry) would be more than this one file. Everything here is
//! used from both crates, if only by this file itself: each test binary is a crate of its own,
//! so an item only one of them used would be dead code in the other (`-D warnings` in CI).

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use zbus::Connection;
use zbus::fdo::DBusProxy;

/// How long any wait of the tests may take. Longer than the daemon's own timeout on logind
/// (10 s), so that one is seen; short enough that a hang fails well before the job's timeout.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The daemon's well-known name, waited for once it is started.
const POLKIT_NAME: &str = "org.freedesktop.PolicyKit1";

/// The system bus's own address. Only the setuid helper's test listens here: the helper does
/// not follow `DBUS_SYSTEM_BUS_ADDRESS` and connects here (observed: without a bus at this
/// address it fails with "Error getting authority"), and only where no system bus runs.
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

/// A private bus with nyra-polkitd and a client on it; dropping it kills both, prints the
/// daemon's log when the test failed, and removes the directory.
pub struct Harness {
    /// The test's temporary directory: the action and rule files, the bus's socket, the
    /// daemon's log.
    pub directory: PathBuf,
    /// The bus's address, for the clients the test runs.
    pub address: String,
    bus: Child,
    /// The daemon, as the `polkitd` user.
    pub daemon: Child,
    /// A client connection whose calls time out.
    pub client: Connection,
    /// The bus also listens at [`SYSTEM_BUS_SOCKET`].
    system_socket: bool,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        let _ = self.bus.kill();
        let _ = self.bus.wait();
        if self.system_socket {
            let _ = std::fs::remove_file(SYSTEM_BUS_SOCKET);
        }
        if std::thread::panicking() {
            eprintln!("--- nyra-polkitd log ---\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// A file the daemon may trust: owned by the user the test runs as (root), readable by all.
pub fn write_trusted(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(0o644)).unwrap();
}

pub fn make_directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}

/// `done`, tried until it holds, or a failed test once [`TIMEOUT`] has passed.
pub fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A client connection to the test bus, whose calls time out.
pub async fn connect(address: &str) -> Connection {
    zbus::connection::Builder::address(address)
        .unwrap()
        .method_timeout(TIMEOUT)
        .build()
        .await
        .unwrap()
}

impl Harness {
    /// A private bus with nyra-polkitd and a client on it. `files` ("actions/test.policy" and
    /// the like) are written into the test's directory, which is the daemon's action and rule
    /// directories; `extra_policy` is added to the bus's policy (the test's own names); `logind`
    /// is the test file's own fake logind, served at the well-known path and name (hence the
    /// generic: each file's logind is its own type) and its connection is returned, to be kept
    /// alive for the test; `daemon` is the nyra-polkitd binary. With `system_socket`, the bus
    /// also listens at [`SYSTEM_BUS_SOCKET`]: only one test may do that, and only where no
    /// system bus runs.
    pub async fn start(
        test: &str,
        files: &[(&str, &str)],
        extra_policy: &str,
        system_socket: bool,
        logind: impl zbus::object_server::Interface,
        daemon: &Path,
    ) -> (Self, Connection) {
        assert!(
            nix::unistd::geteuid().is_root(),
            "the integration tests need root (see the top of the test file)"
        );
        // Each crate's tests get their own prefix: both files have a `temporary` test.
        let directory = std::env::temp_dir().join(format!("{}-{test}", env!("CARGO_PKG_NAME")));
        let _ = std::fs::remove_dir_all(&directory);
        for sub in ["", "actions", "image", "local"] {
            make_directory(&directory.join(sub));
        }
        for (path, text) in files {
            write_trusted(&directory.join(path), text);
        }

        if system_socket {
            assert!(
                !Path::new(SYSTEM_BUS_SOCKET).exists(),
                "{SYSTEM_BUS_SOCKET} exists: a system bus may run here, and the test needs its \
                 address"
            );
            make_directory(Path::new(SYSTEM_BUS_SOCKET).parent().unwrap());
        }
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
  {system_listen}
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
    <allow own="org.freedesktop.login1"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.freedesktop.login1"/>
  </policy>
{extra_policy}  <include>{policy}</include>
</busconfig>
"#,
            socket = socket.display(),
            system_listen = match system_socket {
                true => format!("<listen>unix:path={SYSTEM_BUS_SOCKET}</listen>"),
                false => String::new(),
            },
            policy = policy.display(),
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

        let logind = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .serve_at("/org/freedesktop/login1", logind)
            .unwrap()
            .name("org.freedesktop.login1")
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = connect(&address).await;

        let log = std::fs::File::create(directory.join("daemon.log")).unwrap();
        let daemon = Command::new("setpriv")
            .args(["--reuid=polkitd", "--regid=polkitd", "--init-groups", "--"])
            .arg(daemon)
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
        let mut harness = Self {
            directory,
            address,
            bus,
            daemon,
            client,
            system_socket,
        };
        let deadline = Instant::now() + TIMEOUT;
        while !harness.name_is_owned().await {
            assert!(
                harness.daemon.try_wait().unwrap().is_none(),
                "nyra-polkitd exited:\n{}",
                harness.log()
            );
            assert!(
                Instant::now() < deadline,
                "nyra-polkitd never took {POLKIT_NAME}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        (harness, logind)
    }

    /// The daemon's log so far.
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("daemon.log")).unwrap_or_default()
    }

    /// Whether the daemon owns its name on the bus (a reload keeps it, a crash loses it).
    pub async fn name_is_owned(&self) -> bool {
        DBusProxy::new(&self.client)
            .await
            .unwrap()
            .name_has_owner(POLKIT_NAME.try_into().unwrap())
            .await
            .unwrap()
    }

    /// A client on the test bus, as `user` (a name or a uid) or as root, in a new session of
    /// the kernel's (setsid), without a controlling terminal, as a service runs one, so Debian's
    /// pkcheck never prompts on the terminal of whoever runs the tests. With `cgroup`, the
    /// client moves itself into it first. `timeout` gives it [`TIMEOUT`]: a client that hangs
    /// fails the test (`timeout` exits with 124).
    pub fn command(
        &self,
        user: Option<&str>,
        cgroup: Option<&Path>,
        program: &str,
        args: &[&str],
    ) -> Command {
        let mut command = Command::new("sh");
        // Moves itself into the cgroup (if any), then becomes the client.
        command.args([
            "-c",
            r#"[ -z "$0" ] || echo $$ > "$0/cgroup.procs" || exit 99; exec "$@""#,
        ]);
        command.arg(cgroup.map(Path::as_os_str).unwrap_or_default());
        command.arg("setpriv");
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
            .args(["--", "setsid", "--wait", "timeout"])
            .arg(TIMEOUT.as_secs().to_string())
            .arg(program)
            .args(args)
            .env("DBUS_SYSTEM_BUS_ADDRESS", &self.address)
            .stdin(Stdio::null());
        command
    }

    /// Runs `program` as [`Harness::command`] does, and waits for its output.
    pub fn run(
        &self,
        user: Option<&str>,
        cgroup: Option<&Path>,
        program: &str,
        args: &[&str],
    ) -> Output {
        self.command(user, cgroup, program, args)
            .output()
            .expect("sh")
    }
}
