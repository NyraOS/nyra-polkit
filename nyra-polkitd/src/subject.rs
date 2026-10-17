// SPDX-License-Identifier: MIT
//! Who a subject is (docs/DESIGN.md, "Subjects"): a `(sa{sv})` from the bus turned into a uid and
//! a session state, or an error, which denies the check.
//!
//! - `system-bus-name`: a unique name only; the uid and the process (`ProcessFD`) come from the bus.
//! - `unix-process`: the process is pinned by a pidfd (the client's, or one opened here and checked
//!   against `start-time`); the uid is its real uid.
//! - `unix-session`: the session and its user, from logind.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identified {
    pub uid: u32,
    pub session: Session,
}

/// The uid and the pinned process of a bus connection, as the bus knows them
/// (`GetConnectionCredentials`), never as the peer says.
async fn bus_peer(connection: &Connection, name: &str) -> Result<(u32, Process), String> {
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
    Ok((uid, Process::from_pidfd(pidfd)?))
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
            let (uid, process) = bus_peer(connection, &name).await?;
            process_subject(connection, uid, process).await
        }
        "unix-process" => {
            let pid: u32 = detail(details, "pid")?;
            let process = match details.get("pidfd") {
                Some(value) => {
                    let process = Process::from_pidfd(fd_of(value)?)?;
                    if process.pid() != pid {
                        return Err(format!("pid {pid} is not the pidfd's process"));
                    }
                    process
                }
                None => {
                    let start_time: u64 = detail(details, "start-time")?;
                    let process = Process::open(pid)?;
                    // 0: the client never pinned the process, so it may not be the one it meant.
                    if start_time == 0 || process.start_time()? != start_time {
                        return Err(format!(
                            "process {pid}: the start time does not match (PID reused or not given)"
                        ));
                    }
                    process
                }
            };
            let uid = process.real_uid()?;
            // The uid the client saw, when it sends one (-1: it did not know).
            if let Some(seen) = optional_uid(details)? {
                if seen != uid {
                    return Err(format!(
                        "process {pid}: its user changed from {seen} to {uid}"
                    ));
                }
            }
            process_subject(connection, uid, process).await
        }
        "unix-session" => {
            let id: String = detail(details, "session-id")?;
            let session = logind::session_by_id(connection, &id).await?;
            Ok(Identified {
                uid: session.uid,
                session: session.state,
            })
        }
        other => Err(format!("unsupported subject kind {other:?}")),
    }
}

/// The session of a pinned process of user `uid`; everything is read before the last check that
/// the process is still alive.
async fn process_subject(
    connection: &Connection,
    uid: u32,
    process: Process,
) -> Result<Identified, String> {
    let cgroup = process.cgroup()?;
    let session = logind::session_of_process(connection, process.pid(), uid, &cgroup).await?;
    process.ensure_alive()?;
    Ok(Identified { uid, session })
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

/// The user's name and the names of all their groups, from the user database (NSS).
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
    fn root_has_a_name_and_groups() {
        let (name, groups) = user_and_groups(0).unwrap();
        assert_eq!(name, "root");
        assert!(groups.contains(&"root".to_string()), "{groups:?}");
        assert!(user_and_groups(u32::MAX - 1).is_err());
    }
}
