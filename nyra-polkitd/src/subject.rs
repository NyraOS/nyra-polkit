// SPDX-License-Identifier: MIT
//! Who a subject is (docs/DESIGN.md, "Subjects"): a `(sa{sv})` from the bus turned into a uid and
//! a session state, or an error, which denies the check.
//!
//! - `system-bus-name`: a unique name only; the uid and the process (`ProcessFD`) come from the bus.
//! - `unix-process`: the process is pinned by a pidfd (the client's, or one opened here and checked
//!   against `start-time`); the uid is its real uid.
//! - `unix-session`: the session and its user, from logind.
//!
//! Errors may name other users' processes and uids: the caller logs them and answers a generic
//! refusal. Reads of `/proc` and of the user database (NSS) run as blocking tasks, off the bus
//! executor.

use crate::decision::Session;
use crate::logind;
use crate::process::Process;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};
use zbus::Connection;
use zbus::fdo::{ConnectionCredentials, DBusProxy};
use zbus::names::BusName;
use zbus::zvariant::{OwnedValue, Value};

/// A subject once identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identified {
    pub uid: u32,
    pub session: Session,
    /// The logind session the state comes from; `None` when the subject has no session of its own
    /// (none at all, or another user's).
    pub session_id: Option<String>,
    /// The exact subject: what agents are registered for and temporary authorizations are kept for.
    pub key: SubjectKey,
    /// The subject's process (for a bus name, the connection's); `None` for a session.
    pub process: Option<ProcessId>,
}

/// One exact subject. A process is its PID and start time: the PID alone may be reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKey {
    BusName(String),
    Process(ProcessId),
    Session(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessId {
    pub pid: u32,
    pub start_time: u64,
}

impl SubjectKey {
    /// The subject as the interface sends it, `(sa{sv})`.
    pub fn to_wire(&self) -> (String, HashMap<String, OwnedValue>) {
        let (kind, details): (&str, Vec<(&str, Value)>) = match self {
            Self::BusName(name) => (
                "system-bus-name",
                vec![("name", Value::from(name.as_str()))],
            ),
            Self::Process(process) => (
                "unix-process",
                vec![
                    ("pid", Value::U32(process.pid)),
                    ("start-time", Value::U64(process.start_time)),
                ],
            ),
            Self::Session(id) => (
                "unix-session",
                vec![("session-id", Value::from(id.as_str()))],
            ),
        };
        let details = details
            .into_iter()
            .map(|(key, value)| {
                // Plain numbers and strings: never a file descriptor, so this cannot fail.
                let value = OwnedValue::try_from(value).expect("a plain value");
                (key.to_string(), value)
            })
            .collect();
        (kind.to_string(), details)
    }
}

/// How the client pins the process of a `unix-process` subject.
enum Pin {
    /// The client's pidfd.
    Pidfd(OwnedFd),
    /// The start time the client read; the daemon opens the pidfd itself.
    StartTime(u64),
}

/// The uid and the pidfd of a bus connection, as the bus knows them (`GetConnectionCredentials`),
/// never as the peer says.
async fn bus_peer(connection: &Connection, name: &str) -> Result<(u32, OwnedFd), String> {
    let credentials = credentials(connection, name).await?;
    let uid = credentials
        .unix_user_id()
        .ok_or_else(|| format!("the bus gives no uid for {name}"))?;
    // Without a pidfd, the PID the bus gives could already belong to another process.
    let pidfd = credentials
        .process_fd()
        .ok_or_else(|| format!("the bus gives no ProcessFD for {name}"))?
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| error.to_string())?;
    Ok((uid, pidfd))
}

/// The uid of a bus connection, as the bus knows it.
pub async fn bus_uid(connection: &Connection, name: &str) -> Result<u32, String> {
    credentials(connection, name)
        .await?
        .unix_user_id()
        .ok_or_else(|| format!("the bus gives no uid for {name}"))
}

async fn credentials(connection: &Connection, name: &str) -> Result<ConnectionCredentials, String> {
    let bus_name =
        BusName::try_from(name).map_err(|error| format!("bus name {name:?}: {error}"))?;
    DBusProxy::new(connection)
        .await
        .map_err(|error| error.to_string())?
        .get_connection_credentials(bus_name)
        .await
        .map_err(|error| format!("credentials of {name}: {error}"))
}

pub async fn identify(
    connection: &Connection,
    kind: &str,
    details: &HashMap<String, OwnedValue>,
) -> Result<Identified, String> {
    match kind {
        "system-bus-name" => {
            let name: String = detail(details, "name")?;
            // A well-known name can change owner; a unique name is never given to another
            // connection.
            if !name.starts_with(':') {
                return Err(format!("{name:?} is not a unique bus name"));
            }
            let (uid, pidfd) = bus_peer(connection, &name).await?;
            let (process, start_time, cgroup) = blocking::unblock(move || {
                let process = Process::from_pidfd(pidfd)?;
                let start_time = process.start_time()?;
                let cgroup = process.cgroup()?;
                Ok::<_, String>((process, start_time, cgroup))
            })
            .await?;
            let process_id = ProcessId {
                pid: process.pid(),
                start_time,
            };
            process_subject(
                connection,
                uid,
                process,
                process_id,
                &cgroup,
                SubjectKey::BusName(name),
            )
            .await
        }
        "unix-process" => {
            let pid: u32 = detail(details, "pid")?;
            let pin = match details.get("pidfd") {
                Some(value) => Pin::Pidfd(fd_of(value)?),
                None => Pin::StartTime(detail(details, "start-time")?),
            };
            // The uid the client saw, when it sends one (-1: it did not know).
            let seen_uid = optional_uid(details)?;
            let (process, start_time, uid, cgroup) =
                blocking::unblock(move || read_unix_process(pid, pin, seen_uid)).await?;
            let process_id = ProcessId { pid, start_time };
            process_subject(
                connection,
                uid,
                process,
                process_id,
                &cgroup,
                SubjectKey::Process(process_id),
            )
            .await
        }
        "unix-session" => {
            let id: String = detail(details, "session-id")?;
            let session = logind::session_by_id(connection, &id).await?;
            Ok(Identified {
                uid: session.uid,
                session: session.state,
                session_id: Some(session.id),
                key: SubjectKey::Session(id),
                process: None,
            })
        }
        other => Err(format!("unsupported subject kind {other:?}")),
    }
}

/// Whether the uid of an identified subject is known race-free: a bus name has the bus's
/// credentials, a session has logind's, and a process whose client sent the uid it saw (that
/// `read_unix_process` checked) cannot have changed since. A process without one is only read.
pub fn uid_is_race_free(kind: &str, details: &HashMap<String, OwnedValue>) -> bool {
    kind != "unix-process" || matches!(optional_uid(details), Ok(Some(_)))
}

/// Pins the process of a `unix-process` subject and reads its start time, its real uid and its
/// cgroup. Blocking (`/proc`): call it as a blocking task.
fn read_unix_process(
    pid: u32,
    pin: Pin,
    seen_uid: Option<u32>,
) -> Result<(Process, u64, u32, String), String> {
    let (process, start_time) = match pin {
        Pin::Pidfd(pidfd) => {
            let process = Process::from_pidfd(pidfd)?;
            if process.pid() != pid {
                return Err(format!("pid {pid} is not the pidfd's process"));
            }
            let start_time = process.start_time()?;
            (process, start_time)
        }
        Pin::StartTime(start_time) => {
            let process = Process::open(pid)?;
            // 0: the client never pinned the process, so it may not be the one it meant.
            if start_time == 0 || process.start_time()? != start_time {
                return Err(format!(
                    "process {pid}: the start time does not match (PID reused or not given)"
                ));
            }
            (process, start_time)
        }
    };
    let uid = process.real_uid()?;
    if let Some(seen) = seen_uid {
        if seen != uid {
            return Err(format!(
                "process {pid}: its user changed from {seen} to {uid}"
            ));
        }
    }
    let cgroup = process.cgroup()?;
    Ok((process, start_time, uid, cgroup))
}

/// The session of a pinned process of user `uid`; everything is read before the last check that
/// the process is still alive (a poll that does not wait, so not a blocking task).
async fn process_subject(
    connection: &Connection,
    uid: u32,
    process: Process,
    process_id: ProcessId,
    cgroup: &str,
    key: SubjectKey,
) -> Result<Identified, String> {
    let (session, session_id) =
        logind::session_of_process(connection, process.pid(), uid, cgroup).await?;
    process.ensure_alive()?;
    Ok(Identified {
        uid,
        session,
        session_id,
        key,
        process: Some(process_id),
    })
}

/// A required detail of a given D-Bus type.
fn detail<T>(details: &HashMap<String, OwnedValue>, key: &str) -> Result<T, String>
where
    T: TryFrom<OwnedValue>,
{
    let value = details
        .get(key)
        .ok_or_else(|| format!("the subject has no {key:?}"))?;
    let value = value.try_clone().map_err(|error| error.to_string())?;
    T::try_from(value).map_err(|_| format!("the subject's {key:?} has the wrong type"))
}

/// The optional `uid` of a `unix-process` subject: an `i` (as polkit's client library sends it,
/// -1 when unknown) or a `u`.
fn optional_uid(details: &HashMap<String, OwnedValue>) -> Result<Option<u32>, String> {
    match details.get("uid").map(|value| &**value) {
        None | Some(Value::I32(-1)) => Ok(None),
        Some(Value::I32(uid)) => u32::try_from(*uid)
            .map(Some)
            .map_err(|_| format!("invalid uid {uid}")),
        Some(Value::U32(uid)) => Ok(Some(*uid)),
        Some(_) => Err("the subject's \"uid\" has the wrong type".to_string()),
    }
}

fn fd_of(value: &OwnedValue) -> Result<OwnedFd, String> {
    match &**value {
        Value::Fd(fd) => fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| error.to_string()),
        _ => Err("the subject's \"pidfd\" is not a file descriptor".to_string()),
    }
}

/// The user's name, from the user database (NSS); `None` when it has none or cannot be read.
/// Blocking: call it as a blocking task.
pub fn user_name(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

/// The user's name and the names of all their groups, from the user database (NSS). Blocking: call
/// it as a blocking task.
pub fn user_and_groups(uid: u32) -> Result<(String, Vec<String>), String> {
    use nix::unistd::{Group, Uid, User, getgrouplist};
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|error| format!("user {uid}: {error}"))?
        .ok_or_else(|| format!("user {uid} is not in the user database"))?;
    let name = CString::new(user.name.clone()).map_err(|error| error.to_string())?;
    let gids = getgrouplist(&name, user.gid)
        .map_err(|error| format!("groups of {}: {error}", user.name))?;
    let mut groups = Vec::new();
    for gid in gids {
        // A group without a name cannot be named by a rule.
        if let Some(group) =
            Group::from_gid(gid).map_err(|error| format!("group {gid}: {error}"))?
        {
            groups.push(group.name);
        }
    }
    Ok((user.name, groups))
}

/// The uids of the administrators: the listed users and the members of the listed groups (the
/// group's member list in the user database), sorted, without repeats. Names the user database does
/// not know are skipped: nobody can authenticate as them. Blocking (NSS): call it as a blocking
/// task.
pub fn administrator_uids(users: &[String], groups: &[String]) -> Vec<u32> {
    use nix::unistd::{Group, User};
    let mut names: Vec<String> = users.to_vec();
    for group in groups {
        if let Ok(Some(group)) = Group::from_name(group) {
            names.extend(group.mem);
        }
    }
    let mut uids: Vec<u32> = names
        .iter()
        .filter_map(|name| User::from_name(name).ok().flatten())
        .map(|user| user.uid.as_raw())
        .collect();
    uids.sort_unstable();
    uids.dedup();
    uids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details(entries: Vec<(&str, Value<'static>)>) -> HashMap<String, OwnedValue> {
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), OwnedValue::try_from(value).unwrap()))
            .collect()
    }

    #[test]
    fn the_uid_a_client_saw_is_optional_and_typed() {
        assert_eq!(optional_uid(&details(vec![])), Ok(None));
        assert_eq!(
            optional_uid(&details(vec![("uid", Value::I32(-1))])),
            Ok(None)
        );
        assert_eq!(
            optional_uid(&details(vec![("uid", Value::I32(1000))])),
            Ok(Some(1000))
        );
        assert_eq!(
            optional_uid(&details(vec![("uid", Value::U32(0))])),
            Ok(Some(0))
        );
        assert!(optional_uid(&details(vec![("uid", Value::I32(-2))])).is_err());
        assert!(optional_uid(&details(vec![("uid", Value::from("0"))])).is_err());
    }

    #[test]
    fn details_must_have_the_documented_type() {
        let subject = details(vec![("pid", Value::U32(42)), ("start-time", Value::I64(1))]);
        assert_eq!(detail::<u32>(&subject, "pid"), Ok(42));
        assert!(detail::<u64>(&subject, "start-time").is_err());
        assert!(detail::<String>(&subject, "name").is_err());
    }

    #[test]
    fn subjects_go_back_on_the_wire_as_the_interface_sends_them() {
        let (kind, details) = SubjectKey::Process(ProcessId {
            pid: 42,
            start_time: 7,
        })
        .to_wire();
        assert_eq!(kind, "unix-process");
        assert_eq!(detail::<u32>(&details, "pid"), Ok(42));
        assert_eq!(detail::<u64>(&details, "start-time"), Ok(7));
        let (kind, details) = SubjectKey::BusName(":1.5".to_string()).to_wire();
        assert_eq!(kind, "system-bus-name");
        assert_eq!(detail::<String>(&details, "name"), Ok(":1.5".to_string()));
        let (kind, details) = SubjectKey::Session("c1".to_string()).to_wire();
        assert_eq!(kind, "unix-session");
        assert_eq!(
            detail::<String>(&details, "session-id"),
            Ok("c1".to_string())
        );
    }

    #[test]
    fn administrators_are_listed_users_and_group_members() {
        let names = |names: &[&str]| {
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        };
        // root twice and a user nobody has: root once.
        assert_eq!(
            administrator_uids(&names(&["root", "no-such-user", "root"]), &[]),
            vec![0]
        );
        assert!(administrator_uids(&[], &names(&["no-such-group"])).is_empty());
    }

    #[test]
    fn root_has_a_name_and_groups() {
        let (name, groups) = user_and_groups(0).unwrap();
        assert_eq!(name, "root");
        assert!(groups.contains(&"root".to_string()), "{groups:?}");
        assert!(user_and_groups(u32::MAX - 1).is_err());
    }
}
