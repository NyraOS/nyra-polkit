// SPDX-License-Identifier: MIT
//! Authentication agents and the authentications they run (docs/DESIGN.md, "Authentication").
//!
//! - [`Agents`]: who registered an agent, for which subject, and which agent gets a request. An
//!   agent only ever gets requests for subjects of its own user.
//! - [`Cookies`]: the authentications in flight, each named by a random cookie, and the only thing
//!   that can authenticate one: `AuthenticationAgentResponse2` from root, for the agent's user and
//!   an identity offered. Cookies are never logged.
//! - [`begin_authentication`], [`cancel_authentication`]: the calls to an agent.

use crate::subject::{Identified, SubjectKey};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedValue, Value};

pub const AGENT_INTERFACE: &str = "org.freedesktop.PolicyKit1.AuthenticationAgent";

/// Agents one user may have registered: a few per session is plenty (the desktop's, a textual
/// one), and the list must not grow without bound.
const MAX_AGENTS_PER_USER: usize = 16;

/// A registered agent.
#[derive(Clone, Debug)]
pub struct Agent {
    /// The unique bus name of the connection that registered it, which serves it.
    pub connection: String,
    pub path: String,
    /// The user it authenticates for: the registering connection's, which is the subject's.
    pub uid: u32,
    /// What it was registered for: a session, a process or a bus name.
    pub subject: SubjectKey,
    pub locale: String,
    /// Used only when no agent without this flag serves the subject.
    pub fallback: bool,
    /// Held while the agent runs an authentication: it runs one at a time, later requests wait.
    pub busy: Arc<async_lock::Mutex<()>>,
}

#[derive(Default)]
pub struct Agents {
    /// In the order of registration.
    list: Vec<Agent>,
}

impl Agents {
    /// Adds an agent. Each subject has at most one agent that is not a fallback.
    pub fn register(&mut self, agent: Agent) -> Result<(), String> {
        if !agent.fallback
            && self
                .list
                .iter()
                .any(|other| !other.fallback && other.subject == agent.subject)
        {
            return Err("an authentication agent is already registered for this subject".into());
        }
        if self
            .list
            .iter()
            .filter(|other| other.uid == agent.uid)
            .count()
            >= MAX_AGENTS_PER_USER
        {
            return Err(format!(
                "too many authentication agents (at most {MAX_AGENTS_PER_USER} per user)"
            ));
        }
        self.list.push(agent);
        Ok(())
    }

    /// Removes the agent that `connection` registered for `subject` at `path`.
    pub fn unregister(
        &mut self,
        connection: &str,
        subject: &SubjectKey,
        path: &str,
    ) -> Option<Agent> {
        let index = self.list.iter().position(|agent| {
            agent.connection == connection && agent.subject == *subject && agent.path == path
        })?;
        Some(self.list.remove(index))
    }

    /// Removes the agents of a connection that left the bus; returns them.
    pub fn connection_left(&mut self, connection: &str) -> Vec<Agent> {
        let (gone, kept) = std::mem::take(&mut self.list)
            .into_iter()
            .partition(|agent| agent.connection == connection);
        self.list = kept;
        gone
    }

    /// The agent for a request about `subject`: only agents of the subject's user; one registered
    /// for the subject itself (its bus name or process) before one for its session; fallback
    /// agents only when no other serves it; among equals, the first registered.
    pub fn for_subject(&self, subject: &Identified) -> Option<Agent> {
        let process = subject.process.map(SubjectKey::Process);
        let session = subject.session_id.clone().map(SubjectKey::Session);
        let rank = |agent: &Agent| {
            if agent.subject == subject.key || Some(&agent.subject) == process.as_ref() {
                Some(0)
            } else if Some(&agent.subject) == session.as_ref() {
                Some(1)
            } else {
                None
            }
        };
        self.list
            .iter()
            .filter(|agent| agent.uid == subject.uid)
            .filter_map(|agent| rank(agent).map(|rank| ((agent.fallback, rank), agent)))
            .min_by_key(|(order, _)| *order)
            .map(|(_, agent)| agent.clone())
    }
}

/// An authentication in flight.
struct Pending {
    /// The user of the agent that got the cookie: the helper runs as the agent's user's child and
    /// answers with that uid.
    agent_uid: u32,
    /// The uids of the identities offered.
    identities: Vec<u32>,
    /// The identity authenticated, once `AuthenticationAgentResponse2` was accepted.
    authenticated: Option<u32>,
}

#[derive(Default)]
pub struct Cookies {
    pending: HashMap<String, Pending>,
}

impl Cookies {
    /// Starts an authentication for an agent of user `agent_uid`; returns its new cookie.
    pub fn add(&mut self, agent_uid: u32, identities: Vec<u32>) -> Result<String, String> {
        let cookie = new_cookie()?;
        self.pending.insert(
            cookie.clone(),
            Pending {
                agent_uid,
                identities,
                authenticated: None,
            },
        );
        Ok(cookie)
    }

    /// `AuthenticationAgentResponse2(uid, cookie, identity)` from a caller of uid `caller_uid`;
    /// `identity_uid` is the identity's uid if it is a `unix-user`. Returns why it is refused.
    pub fn respond(
        &mut self,
        caller_uid: u32,
        uid: u32,
        cookie: &str,
        identity_uid: Option<u32>,
    ) -> Result<u32, &'static str> {
        if caller_uid != 0 {
            return Err("the caller is not root");
        }
        let pending = self
            .pending
            .get_mut(cookie)
            .ok_or("no authentication with this cookie")?;
        if pending.authenticated.is_some() {
            return Err("the cookie was already used");
        }
        if uid != pending.agent_uid {
            return Err("the uid is not the agent's user");
        }
        let identity = identity_uid
            .filter(|identity| pending.identities.contains(identity))
            .ok_or("the identity was not offered")?;
        pending.authenticated = Some(identity);
        Ok(identity)
    }

    /// Ends an authentication; returns the identity authenticated, if any.
    pub fn finish(&mut self, cookie: &str) -> Option<u32> {
        self.pending.remove(cookie)?.authenticated
    }
}

/// 128 random bits from getrandom(2), in hexadecimal.
fn new_cookie() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        filled +=
            rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(|error| format!("getrandom: {error}"))?;
    }
    let mut cookie = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(cookie, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(cookie)
}

/// The uid of a `unix-user` identity, `(sa{sv})` with `uid` a `u`; `None` for anything else.
pub fn unix_user((kind, details): &(String, HashMap<String, OwnedValue>)) -> Option<u32> {
    match (kind.as_str(), details.get("uid").map(|value| &**value)) {
        ("unix-user", Some(Value::U32(uid))) => Some(*uid),
        _ => None,
    }
}

/// What an agent is asked: `BeginAuthentication`'s arguments but the cookie.
pub struct Request<'a> {
    pub action_id: &'a str,
    pub message: &'a str,
    pub icon_name: &'a str,
    pub details: &'a HashMap<String, String>,
    pub identities: &'a [u32],
}

/// Calls `BeginAuthentication` on `agent` and waits until it returns, however long the user takes.
/// `Ok` only says the agent returned: whether anyone authenticated is in [`Cookies`].
pub async fn begin_authentication(
    connection: &Connection,
    agent: &Agent,
    request: &Request<'_>,
    cookie: &str,
) -> zbus::Result<()> {
    let proxy = zbus::proxy::Builder::<zbus::Proxy>::new(connection)
        .destination(agent.connection.as_str())?
        .path(agent.path.as_str())?
        .interface(AGENT_INTERFACE)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let identities: Vec<(&str, HashMap<&str, Value>)> = request
        .identities
        .iter()
        .map(|uid| ("unix-user", HashMap::from([("uid", Value::U32(*uid))])))
        .collect();
    // `call_with_flags`, not `call`: it does not use the connection's method timeout (10 s), and
    // typing a password can take longer. A check that waits is still cancelled by its caller, or
    // ended when the caller or the agent leaves the bus.
    proxy
        .call_with_flags::<_, _, ()>(
            "BeginAuthentication",
            Default::default(),
            &(
                request.action_id,
                request.message,
                request.icon_name,
                request.details,
                cookie,
                identities,
            ),
        )
        .await
        .map(|_| ())
}

/// Tells `agent` to close the dialog for `cookie`, without waiting: called while a check ends.
pub fn cancel_authentication(connection: &Connection, agent: &Agent, cookie: String) {
    let connection_for_call = connection.clone();
    let destination = agent.connection.clone();
    let path = agent.path.clone();
    connection
        .executor()
        .spawn(
            async move {
                let result = connection_for_call
                    .call_method(
                        Some(destination.as_str()),
                        path.as_str(),
                        Some(AGENT_INTERFACE),
                        "CancelAuthentication",
                        &(cookie.as_str()),
                    )
                    .await;
                if let Err(error) = result {
                    eprintln!("<4>CancelAuthentication to {destination}: {error}");
                }
            },
            "CancelAuthentication",
        )
        .detach();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Session;
    use crate::subject::ProcessId;

    const ALICE: u32 = 1000;
    const BOB: u32 = 1001;

    fn agent(connection: &str, uid: u32, subject: SubjectKey, fallback: bool) -> Agent {
        Agent {
            connection: connection.to_string(),
            path: "/agent".to_string(),
            uid,
            subject,
            locale: "C".to_string(),
            fallback,
            busy: Arc::default(),
        }
    }

    fn session(id: &str) -> SubjectKey {
        SubjectKey::Session(id.to_string())
    }

    fn process_key(pid: u32) -> SubjectKey {
        SubjectKey::Process(ProcessId { pid, start_time: 1 })
    }

    fn subject(uid: u32, key: SubjectKey, pid: u32, session_id: &str) -> Identified {
        Identified {
            uid,
            session: Session::LocalActive,
            session_id: Some(session_id.to_string()),
            key,
            process: Some(ProcessId { pid, start_time: 1 }),
        }
    }

    fn chosen(agents: &Agents, subject: &Identified) -> Option<String> {
        agents.for_subject(subject).map(|agent| agent.connection)
    }

    #[test]
    fn the_subjects_own_agent_then_its_sessions_then_a_fallback() {
        let mut agents = Agents::default();
        agents
            .register(agent(":1.fallback", ALICE, session("c1"), true))
            .unwrap();
        let in_c1 = subject(ALICE, process_key(10), 10, "c1");
        assert_eq!(chosen(&agents, &in_c1).as_deref(), Some(":1.fallback"));
        agents
            .register(agent(":1.session", ALICE, session("c1"), false))
            .unwrap();
        assert_eq!(chosen(&agents, &in_c1).as_deref(), Some(":1.session"));
        agents
            .register(agent(":1.process", ALICE, process_key(10), false))
            .unwrap();
        assert_eq!(chosen(&agents, &in_c1).as_deref(), Some(":1.process"));
        // A bus name's process counts as the subject's: pkttyagent --process for an app.
        let by_name = subject(ALICE, SubjectKey::BusName(":1.9".into()), 10, "c1");
        assert_eq!(chosen(&agents, &by_name).as_deref(), Some(":1.process"));
        // Another process in the session gets the session's agent; another session none.
        let other = subject(ALICE, process_key(11), 11, "c1");
        assert_eq!(chosen(&agents, &other).as_deref(), Some(":1.session"));
        assert_eq!(
            chosen(&agents, &subject(ALICE, process_key(12), 12, "c2")),
            None
        );
    }

    #[test]
    fn agents_never_get_another_users_requests() {
        let mut agents = Agents::default();
        agents
            .register(agent(":1.alice", ALICE, session("c1"), false))
            .unwrap();
        agents
            .register(agent(":1.alice-fallback", ALICE, process_key(10), true))
            .unwrap();
        // bob's process in alice's session (su bob at the seat), even the very process alice's
        // fallback agent was registered for once it became bob's: no agent.
        assert_eq!(
            chosen(&agents, &subject(BOB, process_key(10), 10, "c1")),
            None
        );
        assert_eq!(chosen(&agents, &subject(BOB, session("c1"), 0, "c1")), None);
    }

    #[test]
    fn one_agent_per_subject_besides_fallbacks_and_a_limit_per_user() {
        let mut agents = Agents::default();
        agents
            .register(agent(":1.1", ALICE, session("c1"), false))
            .unwrap();
        assert!(
            agents
                .register(agent(":1.2", ALICE, session("c1"), false))
                .is_err()
        );
        agents
            .register(agent(":1.2", ALICE, session("c1"), true))
            .unwrap();
        for _ in 2..16 {
            agents
                .register(agent(":1.3", ALICE, session("c1"), true))
                .unwrap();
        }
        assert!(
            agents
                .register(agent(":1.3", ALICE, session("c1"), true))
                .is_err()
        );
        // Each user has their own limit.
        agents
            .register(agent(":1.4", BOB, session("c9"), true))
            .unwrap();
        assert_eq!(agents.connection_left(":1.3").len(), 14);
        assert_eq!(agents.list.len(), 3);
    }

    #[test]
    fn only_the_registering_connection_unregisters_with_the_same_subject_and_path() {
        let mut agents = Agents::default();
        agents
            .register(agent(":1.1", ALICE, session("c1"), false))
            .unwrap();
        assert!(
            agents
                .unregister(":1.2", &session("c1"), "/agent")
                .is_none()
        );
        assert!(
            agents
                .unregister(":1.1", &session("c2"), "/agent")
                .is_none()
        );
        assert!(
            agents
                .unregister(":1.1", &session("c1"), "/other")
                .is_none()
        );
        assert!(
            agents
                .unregister(":1.1", &session("c1"), "/agent")
                .is_some()
        );
        assert!(agents.list.is_empty());
    }

    #[test]
    fn only_root_with_a_pending_cookie_the_agents_uid_and_an_offered_identity() {
        let mut cookies = Cookies::default();
        let cookie = cookies.add(ALICE, vec![0, 1002]).unwrap();
        assert_eq!(cookie.len(), 32);
        assert!(cookie.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(cookies.add(ALICE, vec![0]).unwrap(), cookie);

        assert_eq!(
            cookies.respond(ALICE, ALICE, &cookie, Some(0)),
            Err("the caller is not root")
        );
        assert_eq!(
            cookies.respond(0, ALICE, "0123", Some(0)),
            Err("no authentication with this cookie")
        );
        assert_eq!(
            cookies.respond(0, BOB, &cookie, Some(0)),
            Err("the uid is not the agent's user")
        );
        assert_eq!(
            cookies.respond(0, ALICE, &cookie, Some(ALICE)),
            Err("the identity was not offered")
        );
        assert_eq!(
            cookies.respond(0, ALICE, &cookie, None),
            Err("the identity was not offered")
        );
        assert_eq!(cookies.respond(0, ALICE, &cookie, Some(1002)), Ok(1002));
        // Used once.
        assert_eq!(
            cookies.respond(0, ALICE, &cookie, Some(0)),
            Err("the cookie was already used")
        );
        assert_eq!(cookies.finish(&cookie), Some(1002));
        assert_eq!(cookies.finish(&cookie), None);
        assert_eq!(
            cookies.respond(0, ALICE, &cookie, Some(0)),
            Err("no authentication with this cookie")
        );
    }

    #[test]
    fn identities_are_unix_users_with_a_u32_uid() {
        let identity = |kind: &str, value: Value<'static>| {
            (
                kind.to_string(),
                HashMap::from([("uid".to_string(), OwnedValue::try_from(value).unwrap())]),
            )
        };
        assert_eq!(unix_user(&identity("unix-user", Value::U32(7))), Some(7));
        assert_eq!(unix_user(&identity("unix-user", Value::I32(7))), None);
        assert_eq!(unix_user(&identity("unix-group", Value::U32(7))), None);
        assert_eq!(unix_user(&("unix-user".to_string(), HashMap::new())), None);
    }
}
