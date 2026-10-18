// SPDX-License-Identifier: MIT
//! pkcheck: asks the polkit authority (`org.freedesktop.PolicyKit1` on the system bus) whether a
//! process may do an action, with the options, output and exit codes of pkcheck(1)
//! (docs/DESIGN.md, "pkcheck").
//!
//! Exit codes: 0 authorized, 1 not authorized, 2 not authorized without an authentication, 3 the
//! authentication was dismissed, 126 malformed options, 127 an error. The result's details go to
//! standard output, the diagnostics to standard error.

mod arguments;

use arguments::{Check, Command, Subject};
use nyra_polkitd::process::Process;
use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};
use zbus::Connection;
use zbus::zvariant::{OwnedValue, Value};

const NAME: &str = "org.freedesktop.PolicyKit1";
const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// `CheckAuthorization` flag: the authority may ask the user to authenticate.
const ALLOW_USER_INTERACTION: u32 = 1;

/// How long a call may take when nobody is asked for a password: the usual D-Bus timeout. With
/// `--allow-user-interaction`, a check waits for the user, however long they take.
const CALL_TIMEOUT: Duration = Duration::from_secs(25);

const AUTHORIZED: u8 = 0;
const NOT_AUTHORIZED: u8 = 1;
const CHALLENGE: u8 = 2;
const DISMISSED: u8 = 3;
const MALFORMED: u8 = 126;
const FAILED: u8 = 127;

const HELP: &str = "\
Usage:
  pkcheck --action-id ACTION --process PID[,START_TIME[,UID]] [OPTION...]
  pkcheck --action-id ACTION --system-bus-name BUS_NAME [OPTION...]
  pkcheck --list-temp | --revoke-temp | --version | --help

Options:
  -a, --action-id ACTION             Check authorization to perform ACTION
  -p, --process PID[,START_TIME[,UID]]
                                     Check authorization of the specified process
  -s, --system-bus-name BUS_NAME     Check authorization of the owner of BUS_NAME (unique name)
  -d, --detail KEY VALUE             Add (KEY, VALUE) to information about the action
  -u, --allow-user-interaction       Interact with the user if necessary
  --enable-internal-agent            Not supported: run an authentication agent instead
  --list-temp                        List temporary authorizations for the current session
  --revoke-temp                      Revoke all temporary authorizations for the current session
  --version                          Show the version
  -h, --help                         Show this help

Exit status: 0 authorized, 1 not authorized, 2 authentication needed, 3 authentication
dismissed, 126 malformed options, 127 error.
";

fn main() -> ExitCode {
    let mut arguments = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(argument) => arguments.push(argument),
            // D-Bus strings are UTF-8: such an argument could not be sent anyway.
            Err(argument) => {
                eprintln!(
                    "pkcheck: Unexpected argument `{}'",
                    argument.to_string_lossy()
                );
                return ExitCode::from(MALFORMED);
            }
        }
    }
    let command = match arguments::parse(arguments) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("pkcheck: {error}");
            return ExitCode::from(MALFORMED);
        }
    };
    let code = match command {
        Command::Help => {
            print!("{HELP}");
            AUTHORIZED
        }
        Command::Version => {
            println!(
                "pkcheck version {} (nyra-polkit)",
                env!("CARGO_PKG_VERSION")
            );
            AUTHORIZED
        }
        Command::ListTemporary => futures_lite::future::block_on(list_temporary()),
        Command::RevokeTemporary => futures_lite::future::block_on(revoke_temporary()),
        Command::Check(check) => futures_lite::future::block_on(run_check(check)),
    };
    ExitCode::from(code)
}

async fn connect(timeout: Option<Duration>) -> Result<Connection, String> {
    let mut builder = zbus::connection::Builder::system().map_err(|error| error.to_string())?;
    if let Some(timeout) = timeout {
        builder = builder.method_timeout(timeout);
    }
    builder.build().await.map_err(|error| error.to_string())
}

/// How an error of a call is printed. D-Bus errors keep the `GDBus.Error:<name>: <message>` form
/// of Debian's pkcheck, which scripts and tests match on.
fn describe(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, message, _) => {
            format!("GDBus.Error:{name}: {}", message.as_deref().unwrap_or(""))
        }
        other => other.to_string(),
    }
}

async fn run_check(check: Check) -> u8 {
    let action = &check.action_id;
    let timeout = (!check.allow_user_interaction).then_some(CALL_TIMEOUT);
    let connection = match connect(timeout).await {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("Error getting authority: {error}");
            return FAILED;
        }
    };
    // Held until the answer: the pidfd in the subject borrows it.
    let pinned;
    let subject = match &check.subject {
        Subject::Process {
            pid,
            start_time,
            uid,
        } => {
            pinned = match pin_process(*pid, *start_time, *uid) {
                Ok(pinned) => pinned,
                Err(error) => {
                    eprintln!("Error checking for authorization {action}: {error}");
                    return FAILED;
                }
            };
            unix_process(&pinned)
        }
        Subject::SystemBusName(name) => (
            "system-bus-name",
            HashMap::from([("name", Value::from(name.as_str()))]),
        ),
    };
    let reply = connection
        .call_method(
            Some(NAME),
            PATH,
            Some(INTERFACE),
            "CheckAuthorization",
            &(subject, action, &check.details, flags(&check), ""),
        )
        .await
        .and_then(|reply| {
            reply
                .body()
                .deserialize::<(bool, bool, HashMap<String, String>)>()
        });
    let (authorized, challenge, details) = match reply {
        Ok(answer) => answer,
        Err(error) => {
            eprintln!(
                "Error checking for authorization {action}: {}",
                describe(&error)
            );
            return FAILED;
        }
    };

    let mut keys: Vec<&String> = details.keys().collect();
    keys.sort();
    for key in keys {
        println!("{}={}", escape(key), escape(&details[key]));
    }
    let (code, diagnostic) = verdict(authorized, challenge, &details, &check);
    if let Some(diagnostic) = diagnostic {
        eprintln!("{diagnostic}");
    }
    code
}

/// The `CheckAuthorization` flags for the options.
fn flags(check: &Check) -> u32 {
    match check.allow_user_interaction {
        true => ALLOW_USER_INTERACTION,
        false => 0,
    }
}

/// The exit code for an answer of the authority, and what to say on standard error.
fn verdict(
    authorized: bool,
    challenge: bool,
    details: &HashMap<String, String>,
    check: &Check,
) -> (u8, Option<&'static str>) {
    if authorized {
        (AUTHORIZED, None)
    } else if details.contains_key("polkit.dismissed") {
        (DISMISSED, Some("Authentication request was dismissed."))
    } else if challenge && !check.allow_user_interaction {
        let message = "Authorization requires authentication and -u wasn't passed.";
        (CHALLENGE, Some(message))
    } else if challenge && check.enable_internal_agent {
        // A text agent would need the password helper's protocol, which is not documented; the
        // exit code is the one of Debian's pkcheck when it cannot make its agent.
        let message = "pkcheck: --enable-internal-agent is not supported: run an authentication \
                       agent (for example pkttyagent) for this session";
        (MALFORMED, Some(message))
    } else if challenge {
        let message = "Authorization requires authentication but no agent is available.";
        (CHALLENGE, Some(message))
    } else {
        (NOT_AUTHORIZED, Some("Not authorized."))
    }
}

/// The process to check, pinned by a pidfd. The start time and the uid the caller gave, if any,
/// must be the pinned process's: otherwise the PID now names another process (or the caller got
/// the user wrong), and the check fails rather than ask about the wrong one. Everything is read
/// before the last check that the process is alive, so it is about the pinned process.
fn pin_process(pid: u32, start_time: Option<u64>, uid: Option<u32>) -> Result<Pinned, String> {
    let process = Process::open(pid)?;
    let actual_start_time = process.start_time()?;
    let actual_uid = process.real_uid()?;
    process.ensure_alive()?;
    if start_time.is_some_and(|given| given != actual_start_time) {
        return Err(format!(
            "process {pid} has been replaced (its start time is not the one given)"
        ));
    }
    if uid.is_some_and(|given| given != actual_uid) {
        return Err(format!("process {pid} does not belong to the uid given"));
    }
    Ok(Pinned {
        process,
        start_time: actual_start_time,
        uid: actual_uid,
    })
}

/// A process pinned by its pidfd, and what was read about it while pinned.
struct Pinned {
    process: Process,
    start_time: u64,
    uid: u32,
}

type SubjectValue<'a> = (&'static str, HashMap<&'static str, Value<'a>>);

/// A `unix-process` subject with everything that identifies the process: its pidfd for an
/// authority that takes one, the PID with its start time for one that does not, and its uid (an
/// `i`, as polkit's client library sends it).
fn unix_process(pinned: &Pinned) -> SubjectValue<'_> {
    (
        "unix-process",
        HashMap::from([
            ("pid", Value::U32(pinned.process.pid())),
            ("start-time", Value::U64(pinned.start_time)),
            // At most i32::MAX: the uid of a process is never -1.
            ("uid", Value::I32(pinned.uid as i32)),
            ("pidfd", Value::Fd(pinned.process.pidfd().into())),
        ]),
    )
}

/// pkcheck(1)'s output of details: bytes other than `[a-zA-Z0-9_]` as `\` and their octal value.
fn escape(text: &str) -> String {
    let mut escaped = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("\\{byte:o}"));
        }
    }
    escaped
}

/// The session pkcheck runs in: logind puts each session's processes in `session-<id>.scope`
/// under their user's slice (cgroup v2). The same session `GetSessionByPID` gives, without a call.
fn own_session() -> Result<String, String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("/proc/self/cgroup: {error}"))?;
    session_of_cgroup(&cgroup)
        .map(str::to_string)
        .ok_or_else(|| format!("No session for pid {}", std::process::id()))
}

fn session_of_cgroup(cgroup: &str) -> Option<&str> {
    let path = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let parts: Vec<&str> = path.split('/').collect();
    let ["", "user.slice", user, scope] = parts.as_slice() else {
        return None;
    };
    if !(user.starts_with("user-") && user.ends_with(".slice")) {
        return None;
    }
    scope
        .strip_prefix("session-")?
        .strip_suffix(".scope")
        .filter(|id| !id.is_empty())
}

/// The current session as a subject, or exit code 1 as Debian's pkcheck does without one.
async fn session_subject() -> Result<(Connection, SubjectValue<'static>), u8> {
    let session = own_session().map_err(|error| {
        eprintln!("Error getting session: {error}");
        NOT_AUTHORIZED
    })?;
    let connection = connect(Some(CALL_TIMEOUT)).await.map_err(|error| {
        eprintln!("Error getting authority: {error}");
        FAILED
    })?;
    let subject = (
        "unix-session",
        HashMap::from([("session-id", Value::from(session))]),
    );
    Ok((connection, subject))
}

type TemporaryAuthorization = (
    String,
    String,
    (String, HashMap<String, OwnedValue>),
    u64,
    u64,
);

async fn list_temporary() -> u8 {
    let (connection, subject) = match session_subject().await {
        Ok(found) => found,
        Err(code) => return code,
    };
    let reply = connection
        .call_method(
            Some(NAME),
            PATH,
            Some(INTERFACE),
            "EnumerateTemporaryAuthorizations",
            &(subject,),
        )
        .await
        .and_then(|reply| reply.body().deserialize::<Vec<TemporaryAuthorization>>());
    let authorizations = match reply {
        Ok(authorizations) => authorizations,
        Err(error) => {
            eprintln!(
                "Error getting temporary authorizations: {}",
                describe(&error)
            );
            return NOT_AUTHORIZED;
        }
    };
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    for (id, action, subject, obtained, expires) in authorizations {
        println!(
            "{id}: {action} for {}, obtained {} s ago, expires in {} s",
            describe_subject(&subject),
            now.saturating_sub(obtained),
            expires.saturating_sub(now)
        );
    }
    AUTHORIZED
}

/// A subject as `kind key=value ...`, keys sorted.
fn describe_subject((kind, details): &(String, HashMap<String, OwnedValue>)) -> String {
    let mut keys: Vec<&String> = details.keys().collect();
    keys.sort();
    let mut text = kind.clone();
    for key in keys {
        let value = match &*details[key] {
            Value::Str(text) => text.to_string(),
            Value::U32(number) => number.to_string(),
            Value::U64(number) => number.to_string(),
            Value::I32(number) => number.to_string(),
            _ => "?".to_string(),
        };
        text.push_str(&format!(" {key}={value}"));
    }
    text
}

async fn revoke_temporary() -> u8 {
    let (connection, subject) = match session_subject().await {
        Ok(found) => found,
        Err(code) => return code,
    };
    let reply = connection
        .call_method(
            Some(NAME),
            PATH,
            Some(INTERFACE),
            "RevokeTemporaryAuthorizations",
            &(subject,),
        )
        .await;
    match reply {
        Ok(_) => AUTHORIZED,
        Err(error) => {
            eprintln!(
                "Error revoking temporary authorizations: {}",
                describe(&error)
            );
            NOT_AUTHORIZED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_answers_map_to_the_documented_flags_and_exit_codes() {
        let check = |allow_user_interaction, enable_internal_agent| Check {
            action_id: "org.example.act".to_string(),
            subject: Subject::SystemBusName(":1.42".to_string()),
            details: HashMap::new(),
            allow_user_interaction,
            enable_internal_agent,
        };
        let none = HashMap::new();
        let dismissed = HashMap::from([("polkit.dismissed".to_string(), "true".to_string())]);
        let code = |authorized, challenge, details, check| {
            verdict(authorized, challenge, details, &check).0
        };

        assert_eq!(verdict(true, false, &none, &check(false, false)), (0, None));
        // Authorized wins over anything else in the answer.
        assert_eq!(code(true, true, &dismissed, check(true, true)), 0);
        assert_eq!(code(false, false, &none, check(true, true)), 1);
        assert_eq!(code(false, true, &none, check(false, false)), 2);
        assert_eq!(code(false, true, &none, check(true, false)), 2);
        assert_eq!(code(false, true, &none, check(false, true)), 2);
        assert_eq!(code(false, true, &none, check(true, true)), 126);
        assert_eq!(code(false, false, &dismissed, check(true, false)), 3);
        assert_eq!(code(false, true, &dismissed, check(true, true)), 3);

        assert_eq!(flags(&check(false, true)), 0);
        assert_eq!(flags(&check(true, false)), 1);

        let message = |challenge, check| verdict(false, challenge, &none, &check).1.unwrap();
        assert_eq!(message(false, check(false, false)), "Not authorized.");
        assert!(message(true, check(false, false)).contains("-u wasn't passed"));
        assert!(message(true, check(true, false)).contains("no agent is available"));
        assert!(message(true, check(true, true)).contains("--enable-internal-agent"));
    }

    #[test]
    fn details_are_escaped_as_the_manual_shows() {
        assert_eq!(escape("føl,你好"), r"f\303\270l\54\344\275\240\345\245\275");
        assert_eq!(escape("polkit.dismissed"), r"polkit\56dismissed");
        assert_eq!(escape("Az_09"), "Az_09");
        assert_eq!(escape("a=b c\n"), r"a\75b\40c\12");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn the_session_is_the_scope_under_the_users_slice() {
        assert_eq!(
            session_of_cgroup("0::/user.slice/user-1000.slice/session-c7.scope\n"),
            Some("c7")
        );
        assert_eq!(
            session_of_cgroup("1:name=systemd:/x\n0::/user.slice/user-0.slice/session-12.scope\n"),
            Some("12")
        );
        for elsewhere in [
            // The user manager and its apps, system services, other names, the root.
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n",
            "0::/user.slice/user-1000.slice/user@1000.service/session-3.scope\n",
            "0::/system.slice/cron.service\n",
            "0::/system.slice/session-3.scope\n",
            "0::/user.slice/session-3.scope\n",
            "0::/user.slice/user-1000.slice/session-.scope\n",
            "0::/user.slice/user-1000.slice/session-3.service\n",
            "0::/user.slice/other-1000.slice/session-3.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope/sub\n",
            "0::/system.slice/user-1000.slice/session-3.scope\n",
            "0::/x/user.slice/user-1000.slice/session-3.scope\n",
            "0::/\n",
            // Only the cgroup v2 line counts.
            "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n",
            "",
        ] {
            assert_eq!(session_of_cgroup(elsewhere), None, "{elsewhere:?}");
        }
    }

    #[test]
    fn subjects_are_listed_with_their_details() {
        let details = HashMap::from([
            ("pid".to_string(), OwnedValue::from(42u32)),
            ("start-time".to_string(), OwnedValue::from(4242u64)),
            ("uid".to_string(), OwnedValue::from(-1i32)),
        ]);
        assert_eq!(
            describe_subject(&("unix-process".to_string(), details)),
            "unix-process pid=42 start-time=4242 uid=-1"
        );
        let session = HashMap::from([(
            "session-id".to_string(),
            OwnedValue::try_from(Value::from("c7")).unwrap(),
        )]);
        assert_eq!(
            describe_subject(&("unix-session".to_string(), session)),
            "unix-session session-id=c7"
        );
    }

    #[test]
    fn a_process_is_pinned_only_with_its_own_start_time_and_uid() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id();
        let process = Process::open(pid).unwrap();
        let start_time = process.start_time().unwrap();
        let uid = process.real_uid().unwrap();

        assert!(pin_process(pid, None, None).is_ok());
        assert!(pin_process(pid, Some(start_time), None).is_ok());
        assert!(pin_process(pid, Some(start_time), Some(uid)).is_ok());
        let Err(replaced) = pin_process(pid, Some(start_time + 1), Some(uid)) else {
            panic!("pinned with another start time");
        };
        assert!(replaced.contains("replaced"), "{replaced}");
        let Err(other_user) = pin_process(pid, Some(start_time), Some(uid + 1)) else {
            panic!("pinned with another uid");
        };
        assert!(other_user.contains("uid"), "{other_user}");

        let Ok(pinned) = pin_process(pid, None, None) else {
            panic!("not pinned");
        };
        let (kind, details) = unix_process(&pinned);
        assert_eq!(kind, "unix-process");
        assert_eq!(details["pid"], Value::U32(pid));
        assert_eq!(details["start-time"], Value::U64(start_time));
        assert_eq!(details["uid"], Value::I32(uid as i32));
        assert!(matches!(details["pidfd"], Value::Fd(_)));

        // Exited but not reaped yet: its PID and /proc entry are still there, but it is gone.
        child.kill().unwrap();
        let is_zombie = || {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            stat.rsplit_once(") ").unwrap().1.starts_with('Z')
        };
        while !is_zombie() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let Err(exited) = pin_process(pid, None, None) else {
            panic!("pinned a process that has exited");
        };
        assert!(exited.contains("has exited"), "{exited}");
        child.wait().unwrap();
        assert!(pin_process(pid, None, None).is_err());
    }
}
