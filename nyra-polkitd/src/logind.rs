// SPDX-License-Identifier: MIT
//! Sessions, from logind on the system bus (org.freedesktop.login1(5)).
//!
//! Only `NoSessionForPID` means "no session". Any other failure (logind unreachable, a timeout, an
//! unexpected reply) is an error, which denies the check: it must never fall back to `allow_any`
//! (docs/DESIGN.md, "Subjects").

use crate::decision::Session;
use crate::process::is_under_user_manager;
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, proxy};

const NO_SESSION_FOR_PID: &str = "org.freedesktop.login1.NoSessionForPID";

#[proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    #[zbus(name = "GetSessionByPID")]
    fn get_session_by_pid(&self, pid: u32) -> zbus::Result<OwnedObjectPath>;
    fn get_session(&self, session_id: &str) -> zbus::Result<OwnedObjectPath>;
    fn get_user(&self, uid: u32) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1"
)]
trait LoginSession {
    #[zbus(property)]
    fn remote(&self) -> zbus::Result<bool>;
    /// The seat id and its object path; an empty id without a seat.
    #[zbus(property)]
    fn seat(&self) -> zbus::Result<(String, OwnedObjectPath)>;
    #[zbus(property)]
    fn active(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn user(&self) -> zbus::Result<(u32, OwnedObjectPath)>;
}

#[proxy(
    interface = "org.freedesktop.login1.User",
    default_service = "org.freedesktop.login1"
)]
trait LoginUser {
    /// The user's display session: its id and object path; an empty id without one.
    #[zbus(property)]
    fn display(&self) -> zbus::Result<(String, OwnedObjectPath)>;
}

/// A session's user and state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    pub uid: u32,
    pub state: Session,
}

/// The session of a `unix-session` subject; an unknown session is an error.
pub async fn session_by_id(connection: &Connection, id: &str) -> Result<SessionInfo, String> {
    let path = manager(connection)
        .await?
        .get_session(id)
        .await
        .map_err(|error| format!("logind, session {id:?}: {error}"))?;
    session_at(connection, path).await
}

/// The session state of a process of user `uid`, whose cgroup is `cgroup`. A process in no session
/// gets its user's display session only when it runs under that user's service manager.
pub async fn session_of_process(
    connection: &Connection,
    pid: u32,
    uid: u32,
    cgroup: &str,
) -> Result<Session, String> {
    let manager = manager(connection).await?;
    match manager.get_session_by_pid(pid).await {
        Ok(path) => return Ok(session_at(connection, path).await?.state),
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == NO_SESSION_FOR_PID => {}
        Err(error) => return Err(format!("logind, session of process {pid}: {error}")),
    }
    if !is_under_user_manager(cgroup, uid) {
        return Ok(Session::NotLocal);
    }
    let user_path = manager
        .get_user(uid)
        .await
        .map_err(|error| format!("logind, user {uid}: {error}"))?;
    let (display, display_path) = LoginUserProxy::builder(connection)
        .path(user_path)
        .map_err(|error| error.to_string())?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|error| format!("logind, user {uid}: {error}"))?
        .display()
        .await
        .map_err(|error| format!("logind, user {uid}: {error}"))?;
    if display.is_empty() {
        return Ok(Session::NotLocal);
    }
    let display = session_at(connection, display_path).await?;
    // logind only names a session of the user as their display; checked all the same.
    if display.uid != uid {
        return Err(format!(
            "logind: the display session of user {uid} is not theirs"
        ));
    }
    Ok(display.state)
}

async fn manager(connection: &Connection) -> Result<ManagerProxy<'static>, String> {
    ManagerProxy::new(connection)
        .await
        .map_err(|error| format!("logind: {error}"))
}

async fn session_at(connection: &Connection, path: OwnedObjectPath) -> Result<SessionInfo, String> {
    let failed = |error: zbus::Error| format!("logind, {}: {error}", path.as_str());
    // Not cached: each check reads the session as it is now.
    let session = LoginSessionProxy::builder(connection)
        .path(path.clone())
        .map_err(failed)?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(failed)?;
    let remote = session.remote().await.map_err(failed)?;
    let (seat, _) = session.seat().await.map_err(failed)?;
    let active = session.active().await.map_err(failed)?;
    let (uid, _) = session.user().await.map_err(failed)?;
    Ok(SessionInfo {
        uid,
        state: Session::from_logind(remote, &seat, active),
    })
}
