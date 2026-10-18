// SPDX-License-Identifier: MIT
//! The D-Bus service: `org.freedesktop.PolicyKit1.Authority` at [`AUTHORITY_PATH`]
//! (docs/DESIGN.md, "D-Bus interface"): checks, authentication agents and temporary
//! authorizations.
//!
//! A decision that needs authentication (`auth_*`) goes to the subject's agent when the caller
//! allows user interaction and one is registered; otherwise it is answered "not authorized,
//! challenge".
//!
//! Log lines carry sd-daemon priority prefixes for the journal: `<3>` error, `<4>` warning,
//! `<6>` info.

use crate::actions::{Actions, load_actions};
use crate::agents::{self, Agent, Agents, Cookies};
use crate::decision::{Subject, decide, is_administrator};
use crate::rules::{Rules, load_rules};
use crate::subject::Identified;
use crate::temporary::{TemporaryAuthorizations, boot_clock};
use crate::{Authorization, subject};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use zbus::fdo::DBusProxy;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedValue};
use zbus::{Connection, interface};

pub const BUS_NAME: &str = "org.freedesktop.PolicyKit1";
pub const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";

/// `CheckAuthorizationFlags`: the only flag.
const ALLOW_USER_INTERACTION: u32 = 1;
/// Checks one connection may have in flight (docs/DESIGN.md, "Security").
const MAX_CHECKS_PER_CONNECTION: usize = 32;
/// Checks one user other than root may have in flight over all their connections. A user may open
/// many connections, and every check may wait on logind, while the bus limits the replies the
/// daemon can wait for (128 by default): one user alone must not fill them and lock out everyone
/// else. Root is not counted: see [`ChecksInFlight::begin_for_user`].
const MAX_CHECKS_PER_USER: usize = 64;
/// Authentications one user may have waiting for an agent or in a dialog, whoever asked for them.
/// They wait as long as the user's agent wants, so they do not count in the caller's connection:
/// a system service asks for every user on one connection, and one user must not fill it. Beyond
/// the limit the answer is the challenge, without a dialog.
const MAX_AUTHENTICATIONS_PER_USER: usize = 16;
/// What a caller is told when its subject cannot be identified. The reason goes to the journal
/// only: it may name another user's process or uid.
const SUBJECT_NOT_IDENTIFIED: &str = "cannot identify the subject";
/// While the rules are broken, the message saying so is logged at most this often.
const BROKEN_RULES_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// The `polkit.` details callers may set (the documented ones), and only as root.
const DOCUMENTED_POLKIT_DETAILS: [&str; 3] = [
    "polkit.message",
    "polkit.gettext_domain",
    "polkit.icon_name",
];
/// The action annotation naming the users who may check other users' subjects (polkit(8)).
const OWNER_ANNOTATION: &str = "org.freedesktop.policykit.owner";
/// What the agent says when the user dismissed the dialog.
const AGENT_CANCELLED: &str = "org.freedesktop.PolicyKit1.Error.Cancelled";

/// The errors of the interface, `org.freedesktop.PolicyKit1.Error.*`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
pub enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    Failed(String),
    Cancelled(String),
    NotSupported(String),
    NotAuthorized(String),
    CancellationIdNotUnique(String),
}

/// `AuthorizationResult`, one struct on the wire: `(bba{ss})`.
#[derive(Debug, PartialEq, serde::Serialize, zbus::zvariant::Type)]
pub struct AuthorizationResult {
    is_authorized: bool,
    /// Not authorized, but could be by authenticating.
    is_challenge: bool,
    details: HashMap<String, String>,
}

/// A subject or an identity on the wire, `(sa{sv})`.
type Wire = (String, HashMap<String, OwnedValue>);

/// `TemporaryAuthorization`: id, action id, subject, obtained and expires (seconds since the epoch).
type TemporaryAuthorizationWire = (String, String, Wire, u64, u64);

/// `ActionDescription`: id, description, message, vendor name, vendor URL, icon name, the three
/// implicit authorizations (any, inactive, active) and the annotations.
type ActionDescription = (
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

/// Where the definitions and the rules are read from.
#[derive(Debug, Clone)]
pub struct Directories {
    pub actions: PathBuf,
    pub image_rules: PathBuf,
    pub local_rules: PathBuf,
}

/// The action definitions and the rules in force. Broken rules are kept as their error: every
/// check is then denied until a reload reads valid rules.
pub struct Policy {
    pub actions: Actions,
    pub rules: Result<Rules, String>,
    /// How many times the policy was reread before this one: an authentication that started under
    /// another generation counts for nothing (see [`Authority::replace_policy`]).
    pub generation: u64,
}

/// Loads the action definitions and the rules, logging what was read and every problem.
pub fn load_policy(directories: &Directories) -> Policy {
    let (actions, problems) = load_actions(&directories.actions);
    for problem in &problems {
        eprintln!("<4>{problem}");
    }
    let rules = load_rules(&directories.image_rules, &directories.local_rules);
    match &rules {
        Ok((rules, notes)) => {
            for note in notes {
                eprintln!("<6>{note}");
            }
            eprintln!(
                "<6>{} actions, {} rules, administrators: users {:?}, groups {:?}",
                actions.len(),
                rules.rules.len(),
                rules.administrators.users,
                rules.administrators.groups
            );
        }
        Err(error) => eprintln!("<3>{error}; every check is denied until it is fixed"),
    }
    Policy {
        actions,
        rules: rules.map(|(rules, _)| rules),
        generation: 0,
    }
}

/// The checks in flight, per caller (a unique bus name): how many, and the cancellation ids of
/// those that have one, with what cancels them; and how many per user (the callers' uid).
#[derive(Default)]
struct ChecksInFlight {
    by_caller: HashMap<String, CallerChecks>,
    by_user: HashMap<u32, usize>,
    /// Authentications per subject user (see [`MAX_AUTHENTICATIONS_PER_USER`]).
    authentications: HashMap<u32, usize>,
}

struct CallerChecks {
    /// Checks in the connection's slots.
    count: usize,
    /// Checks in an authentication: not in the slots, but the caller still has them.
    authenticating: usize,
    cancellable: HashMap<String, async_channel::Sender<()>>,
    /// Never sent on, only kept: dropped with this when the caller leaves the bus, which closes
    /// the channel and so ends every check of the caller.
    _left: async_channel::Sender<()>,
    left_receiver: async_channel::Receiver<()>,
}

impl Default for CallerChecks {
    fn default() -> Self {
        let (left, left_receiver) = async_channel::bounded(1);
        Self {
            count: 0,
            authenticating: 0,
            cancellable: HashMap::new(),
            _left: left,
            left_receiver,
        }
    }
}

/// What ends a check before its answer: `CancelCheckAuthorization` with its id, if it has one, or
/// its caller leaving the bus.
struct Cancellation {
    by_id: Option<async_channel::Receiver<()>>,
    caller_left: async_channel::Receiver<()>,
}

impl Cancellation {
    async fn wait(self) {
        let by_id = async {
            match self.by_id {
                Some(cancelled) => {
                    let _ = cancelled.recv().await;
                }
                None => futures_lite::future::pending::<()>().await,
            }
        };
        // Err once the channel is closed: the caller left.
        let caller_left = async {
            let _ = self.caller_left.recv().await;
        };
        futures_lite::future::or(by_id, caller_left).await;
    }
}

impl ChecksInFlight {
    /// Counts a new check of `caller`; returns what ends it early.
    fn begin(&mut self, caller: &str, cancellation_id: &str) -> Result<Cancellation, Error> {
        let checks = self.by_caller.entry(caller.to_string()).or_default();
        if checks.count >= MAX_CHECKS_PER_CONNECTION {
            return Err(Error::Failed(format!(
                "too many checks in flight (at most {MAX_CHECKS_PER_CONNECTION} per connection)"
            )));
        }
        let mut by_id = None;
        if !cancellation_id.is_empty() {
            if checks.cancellable.contains_key(cancellation_id) {
                return Err(Error::CancellationIdNotUnique(format!(
                    "cancellation id {cancellation_id:?} is already in use"
                )));
            }
            let (sender, receiver) = async_channel::bounded(1);
            checks
                .cancellable
                .insert(cancellation_id.to_string(), sender);
            by_id = Some(receiver);
        }
        checks.count += 1;
        Ok(Cancellation {
            by_id,
            caller_left: checks.left_receiver.clone(),
        })
    }

    /// Ends every check of a caller that left the bus.
    fn caller_left(&mut self, caller: &str) {
        self.by_caller.remove(caller);
    }

    fn end(&mut self, caller: &str, cancellation_id: &str) {
        let Some(checks) = self.by_caller.get_mut(caller) else {
            return;
        };
        checks.count -= 1;
        checks.cancellable.remove(cancellation_id);
        if checks.count == 0 && checks.authenticating == 0 {
            self.by_caller.remove(caller);
        }
    }

    /// Cancels the check of `caller` with this id; false when there is none.
    fn cancel(&mut self, caller: &str, cancellation_id: &str) -> bool {
        self.by_caller
            .get(caller)
            .and_then(|checks| checks.cancellable.get(cancellation_id))
            .is_some_and(|sender| sender.try_send(()).is_ok())
    }

    /// Counts a check of user `uid`, once the caller's uid is known (after [`Self::begin`]).
    ///
    /// Root's checks are not counted: root's callers are the system services (logind,
    /// NetworkManager, udisks2...), which a user can make ask on their behalf. One pool for all of
    /// them would let one user use it up for everyone. Each of their connections keeps its own
    /// limit, and users cannot open connections as root.
    fn begin_for_user(&mut self, uid: u32) -> Result<(), Error> {
        if uid == 0 {
            return Ok(());
        }
        let count = self.by_user.entry(uid).or_default();
        if *count >= MAX_CHECKS_PER_USER {
            return Err(Error::Failed(format!(
                "too many checks in flight (at most {MAX_CHECKS_PER_USER} per user)"
            )));
        }
        *count += 1;
        Ok(())
    }

    /// A check of `caller` starts an authentication for user `uid`: counted for that user and no
    /// longer in the caller's connection. False when the user already has too many.
    fn begin_authentication(&mut self, caller: &str, uid: u32) -> bool {
        let count = self.authentications.entry(uid).or_default();
        if *count >= MAX_AUTHENTICATIONS_PER_USER {
            return false;
        }
        *count += 1;
        if let Some(checks) = self.by_caller.get_mut(caller) {
            checks.count -= 1;
            checks.authenticating += 1;
        }
        true
    }

    /// The authentication ended: the check counts in its caller's connection again until it ends.
    fn end_authentication(&mut self, caller: &str, uid: u32) {
        if let Some(count) = self.authentications.get_mut(&uid) {
            *count -= 1;
            if *count == 0 {
                self.authentications.remove(&uid);
            }
        }
        if let Some(checks) = self.by_caller.get_mut(caller) {
            checks.authenticating -= 1;
            checks.count += 1;
        }
    }

    fn end_for_user(&mut self, uid: u32) {
        let Some(count) = self.by_user.get_mut(&uid) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            self.by_user.remove(&uid);
        }
    }
}

/// Ends a check in [`ChecksInFlight`] however the check ends.
struct InFlight<'a> {
    checks: &'a Mutex<ChecksInFlight>,
    caller: String,
    cancellation_id: String,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        lock(self.checks).end(&self.caller, &self.cancellation_id);
    }
}

/// Ends a check of a user in [`ChecksInFlight`] however the check ends.
struct UserInFlight<'a> {
    checks: &'a Mutex<ChecksInFlight>,
    uid: u32,
}

impl Drop for UserInFlight<'_> {
    fn drop(&mut self) {
        lock(self.checks).end_for_user(self.uid);
    }
}

/// Ends an authentication in [`ChecksInFlight`] however the check ends.
struct AuthenticationInFlight<'a> {
    checks: &'a Mutex<ChecksInFlight>,
    caller: &'a str,
    uid: u32,
}

impl Drop for AuthenticationInFlight<'_> {
    fn drop(&mut self) {
        lock(self.checks).end_authentication(self.caller, self.uid);
    }
}

/// Counts the checks denied because the rules are broken, and says when to log it: at once for
/// the first, then at most once per [`BROKEN_RULES_LOG_INTERVAL`], with the number denied since
/// the last message.
#[derive(Default)]
struct BrokenRulesLog {
    last: Option<Instant>,
    denied: u64,
}

impl BrokenRulesLog {
    /// Counts one denied check; returns the number to log, if it is time to log.
    fn denied(&mut self, now: Instant) -> Option<u64> {
        self.denied += 1;
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < BROKEN_RULES_LOG_INTERVAL)
        {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.denied))
    }
}

/// A mutex poisoned by a panic still holds consistent data here: every critical section is a
/// few map or counter updates.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An authentication in flight: when the check ends, however it ends, its cookie is forgotten, and
/// an agent still showing the dialog is told to close it (the check was cancelled, or its caller
/// left).
struct AgentDialog<'a> {
    cookies: &'a Mutex<Cookies>,
    cookie: String,
    connection: Connection,
    agent: Agent,
    agent_returned: bool,
}

impl Drop for AgentDialog<'_> {
    fn drop(&mut self) {
        lock(self.cookies).finish(&self.cookie);
        if !self.agent_returned {
            agents::cancel_authentication(&self.connection, &self.agent, self.cookie.clone());
        }
    }
}

/// How an authentication ended.
enum Authenticated {
    As(u32),
    Dismissed,
    Failed,
}

pub struct Authority {
    policy: RwLock<Policy>,
    checks: Mutex<ChecksInFlight>,
    broken_rules_log: Mutex<BrokenRulesLog>,
    agents: Mutex<Agents>,
    cookies: Mutex<Cookies>,
    temporary: Mutex<TemporaryAuthorizations>,
}

impl Authority {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: RwLock::new(policy),
            checks: Mutex::default(),
            broken_rules_log: Mutex::default(),
            agents: Mutex::default(),
            cookies: Mutex::default(),
            temporary: Mutex::default(),
        }
    }

    /// Replaces the policy in force (`systemctl reload`). The temporary authorizations go with
    /// the old rules: they were granted under them.
    ///
    /// An authentication running meanwhile was decided under the old rules (who may authenticate,
    /// at what level): it ends not authorized and keeps nothing. The temporary authorizations are
    /// cleared while the new policy is written, and an authentication compares the generation and
    /// keeps its authorization while it reads the policy, so none can slip in between.
    pub fn replace_policy(&self, mut policy: Policy) {
        let mut current = self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        policy.generation = current.generation + 1;
        *current = policy;
        let dropped = lock(&self.temporary).clear();
        drop(current);
        if dropped > 0 {
            eprintln!("<6>{dropped} temporary authorizations revoked: the rules were reread");
        }
    }

    /// A connection left the bus: its checks end (an agent showing a dialog for one is told to
    /// close it), its agents are removed, and so are the temporary authorizations of its bus name.
    /// Returns whether any temporary authorization was removed (then `Changed` is due).
    pub fn connection_left(&self, name: &str) -> bool {
        lock(&self.checks).caller_left(name);
        for agent in lock(&self.agents).connection_left(name) {
            log_agent("removed (its connection left the bus)", &agent);
        }
        let revoked = lock(&self.temporary).bus_name_left(name);
        if revoked > 0 {
            eprintln!("<6>{revoked} temporary authorizations of {name} revoked: it left the bus");
        }
        revoked > 0
    }

    fn read_policy(&self) -> std::sync::RwLockReadGuard<'_, Policy> {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[allow(clippy::too_many_arguments)] // CheckAuthorization's arguments, plus the call's context.
    async fn check(
        &self,
        connection: &Connection,
        emitter: &SignalEmitter<'_>,
        caller: &str,
        (kind, subject_details): Wire,
        action_id: &str,
        details: HashMap<String, String>,
        flags: u32,
    ) -> Result<AuthorizationResult, Error> {
        let caller_uid = subject::bus_uid(connection, caller)
            .await
            .map_err(|error| {
                eprintln!("<4>check from {caller}: {error}");
                Error::Failed("cannot identify the caller".to_string())
            })?;
        lock(&self.checks).begin_for_user(caller_uid)?;
        let _user_in_flight = UserInFlight {
            checks: &self.checks,
            uid: caller_uid,
        };
        check_details(&details, caller_uid)?;

        let not_identified = |error: String| {
            eprintln!("<4>check of {action_id} from {caller}: {SUBJECT_NOT_IDENTIFIED}: {error}");
            Error::NotAuthorized(SUBJECT_NOT_IDENTIFIED.to_string())
        };
        let identified = subject::identify(connection, &kind, &subject_details)
            .await
            .map_err(not_identified)?;
        let uid = identified.uid;
        let (user, groups) = blocking::unblock(move || subject::user_and_groups(uid))
            .await
            .map_err(not_identified)?;
        let subject = Subject {
            user,
            groups,
            session: identified.session,
        };

        if identified.uid != caller_uid && caller_uid != 0 {
            let caller_name = blocking::unblock(move || subject::user_name(caller_uid)).await;
            let policy = self.read_policy();
            if !may_check_for_others(&policy.actions, action_id, caller_uid, caller_name) {
                return Err(Error::NotAuthorized(
                    "only root may check the authorization of another user's subject".to_string(),
                ));
            }
        }
        // What the decision needs from the policy is taken here: the lock is not held across the
        // waits that follow.
        let (decision, message, icon_name, administrators, generation) = {
            let policy = self.read_policy();
            let rules = match &policy.rules {
                Ok(rules) => rules,
                Err(error) => {
                    if let Some(denied) = lock(&self.broken_rules_log).denied(Instant::now()) {
                        eprintln!(
                            "<3>the rules are broken, so every check is denied ({denied} since the last message): {error}"
                        );
                    }
                    return Ok(answer(Authorization::No));
                }
            };
            let sorted_details: std::collections::BTreeMap<_, _> = details
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let decision = decide(&policy.actions, rules, action_id, &subject, &sorted_details);
            let action = policy.actions.get(action_id);
            (
                decision,
                action.map(|action| action.message.clone()),
                action.map(|action| action.icon_name.clone()),
                rules.administrators.clone(),
                policy.generation,
            )
        };
        if matches!(decision, Authorization::Yes | Authorization::No) {
            return Ok(answer(decision));
        }
        let keep = matches!(
            decision,
            Authorization::AuthSelfKeep | Authorization::AuthAdminKeep
        );
        if let Some(id) = lock(&self.temporary).find(action_id, &identified, decision, boot_clock())
        {
            eprintln!(
                "<6>temporary authorization {id} used for {action_id} of user {}",
                identified.uid
            );
            return Ok(authorized_by(&id));
        }
        let challenge = || {
            let mut result = answer(decision);
            if keep {
                result.details.insert(
                    "polkit.retains_authorization_after_challenge".to_string(),
                    "true".to_string(),
                );
            }
            result
        };
        if flags & ALLOW_USER_INTERACTION == 0 {
            return Ok(challenge());
        }
        let Some(agent) = lock(&self.agents).for_subject(&identified) else {
            return Ok(challenge());
        };

        // auth_self: the subject's user. auth_admin: an administrator; the subject's user if they
        // are one.
        let identities = if matches!(
            decision,
            Authorization::AuthSelf | Authorization::AuthSelfKeep
        ) || is_administrator(&subject, &administrators)
        {
            vec![identified.uid]
        } else {
            blocking::unblock(move || {
                subject::administrator_uids(&administrators.users, &administrators.groups)
            })
            .await
        };
        if identities.is_empty() {
            eprintln!(
                "<4>{action_id} for user {}: no administrator can authenticate, so it is denied",
                identified.uid
            );
            return Ok(answer(Authorization::No));
        }
        if !lock(&self.checks).begin_authentication(caller, identified.uid) {
            eprintln!(
                "<4>{action_id} for user {}: too many authentications of this user (at most {MAX_AUTHENTICATIONS_PER_USER}), so no dialog",
                identified.uid
            );
            return Ok(challenge());
        }
        let _authentication_in_flight = AuthenticationInFlight {
            checks: &self.checks,
            caller,
            uid: identified.uid,
        };
        eprintln!(
            "<6>authentication for {action_id} of user {} (process {:?}) waits for an agent",
            identified.uid,
            identified.process.map(|process| process.pid)
        );
        // An agent runs one authentication at a time; the agent is chosen again once it is this
        // one's turn, as the one chosen first may have gone meanwhile.
        let Some((agent, _turn)) = self.agent_turn(&identified, agent).await else {
            return Ok(challenge());
        };
        // A root caller may give the dialog its own text (`polkit.message`, `polkit.icon_name`:
        // only root may pass them, see check_details).
        let message = match details.get("polkit.message") {
            Some(message) => message.clone(),
            None => message
                .map(|message| message.for_locale(&agent.locale).to_string())
                .unwrap_or_default(),
        };
        let icon_name = details
            .get("polkit.icon_name")
            .cloned()
            .or(icon_name)
            .unwrap_or_default();
        let request = agents::Request {
            action_id,
            message: &message,
            icon_name: &icon_name,
            details: &details,
            identities: &identities,
        };
        let outcome = self
            .authenticate(connection, &agent, &identified, &request)
            .await?;
        // Kept, or not, while the policy is read: a reload cannot come between the comparison and
        // the authorization being kept.
        let kept = match outcome {
            Authenticated::As(_) => {
                let policy = self.read_policy();
                if policy.generation != generation {
                    eprintln!(
                        "<4>{action_id} for user {}: the rules were reread during the authentication, so it is not authorized",
                        identified.uid
                    );
                    return Ok(answer(Authorization::No));
                }
                keep.then(|| {
                    lock(&self.temporary).add(action_id, &identified, decision, boot_clock())
                })
            }
            Authenticated::Dismissed | Authenticated::Failed => None,
        };
        match (outcome, kept) {
            (Authenticated::As(_), Some(id)) => {
                eprintln!(
                    "<6>temporary authorization {id} created for {action_id} of user {}",
                    identified.uid
                );
                if let Err(error) = Authority::changed(emitter).await {
                    eprintln!("<4>Changed signal: {error}");
                }
                let mut result = authorized_by(&id);
                result.details.insert(
                    "polkit.retains_authorization_after_challenge".to_string(),
                    "true".to_string(),
                );
                Ok(result)
            }
            (Authenticated::As(_), None) => Ok(answer(Authorization::Yes)),
            (Authenticated::Dismissed, _) => {
                let mut result = answer(Authorization::No);
                result
                    .details
                    .insert("polkit.dismissed".to_string(), "true".to_string());
                Ok(result)
            }
            (Authenticated::Failed, _) => Ok(answer(Authorization::No)),
        }
    }

    /// Waits until an agent for `subject` is free, starting with `agent`: the agent and its turn, or
    /// `None` once no agent serves the subject any more.
    async fn agent_turn(
        &self,
        subject: &Identified,
        mut agent: Agent,
    ) -> Option<(Agent, async_lock::MutexGuardArc<()>)> {
        loop {
            let turn = agent.busy.lock_arc().await;
            let current = lock(&self.agents).for_subject(subject)?;
            if Arc::ptr_eq(&current.busy, &agent.busy) {
                return Some((agent, turn));
            }
            agent = current;
        }
    }

    /// Runs one authentication through `agent`, during its turn: it is authenticated only if
    /// `AuthenticationAgentResponse2` was accepted for its cookie and the agent then returned.
    async fn authenticate(
        &self,
        connection: &Connection,
        agent: &Agent,
        subject: &Identified,
        request: &agents::Request<'_>,
    ) -> Result<Authenticated, Error> {
        let cookie = lock(&self.cookies)
            .add(agent.uid, request.identities.to_vec())
            .map_err(|error| {
                eprintln!("<3>{error}");
                Error::Failed("cannot start an authentication".to_string())
            })?;
        let mut dialog = AgentDialog {
            cookies: &self.cookies,
            cookie: cookie.clone(),
            connection: connection.clone(),
            agent: agent.clone(),
            agent_returned: false,
        };
        let pid = subject.process.map(|process| process.pid);
        eprintln!(
            "<6>authentication for {} of user {} (process {pid:?}) through the agent of {}, identities {:?}",
            request.action_id, subject.uid, agent.connection, request.identities
        );
        let returned = agents::begin_authentication(connection, agent, request, &cookie).await;
        dialog.agent_returned = true;
        let authenticated = lock(&self.cookies).finish(&cookie);
        let outcome = match (returned, authenticated) {
            (Ok(()), Some(identity)) => Authenticated::As(identity),
            (Err(zbus::Error::MethodError(name, _, _)), _) if name.as_str() == AGENT_CANCELLED => {
                Authenticated::Dismissed
            }
            (Ok(()), None) => {
                eprintln!(
                    "<4>the agent of {} returned without an authentication",
                    agent.connection
                );
                Authenticated::Failed
            }
            (Err(error), _) => {
                eprintln!("<4>the agent of {}: {error}", agent.connection);
                Authenticated::Failed
            }
        };
        let result = match outcome {
            Authenticated::As(identity) => format!("authorized, as uid {identity}"),
            Authenticated::Dismissed => "dismissed".to_string(),
            Authenticated::Failed => "failed".to_string(),
        };
        eprintln!(
            "<6>authentication for {} of user {} (process {pid:?}): {result}",
            request.action_id, subject.uid
        );
        Ok(outcome)
    }

    /// The caller's uid, as the bus knows it.
    async fn caller_uid(&self, connection: &Connection, caller: &str) -> Result<u32, Error> {
        subject::bus_uid(connection, caller).await.map_err(|error| {
            eprintln!("<4>call from {caller}: {error}");
            Error::Failed("cannot identify the caller".to_string())
        })
    }

    /// Identifies `subject` for a caller that may only name its own subjects (root: anyone's).
    async fn own_subject(
        &self,
        connection: &Connection,
        caller: &str,
        (kind, details): Wire,
    ) -> Result<(Identified, u32), Error> {
        let caller_uid = self.caller_uid(connection, caller).await?;
        let identified = subject::identify(connection, &kind, &details)
            .await
            .map_err(|error| {
                eprintln!("<4>call from {caller}: {SUBJECT_NOT_IDENTIFIED}: {error}");
                Error::NotAuthorized(SUBJECT_NOT_IDENTIFIED.to_string())
            })?;
        if identified.uid != caller_uid && caller_uid != 0 {
            return Err(Error::NotAuthorized(
                "the subject belongs to another user".to_string(),
            ));
        }
        Ok((identified, caller_uid))
    }

    async fn register_agent(
        &self,
        connection: &Connection,
        caller: &str,
        subject: Wire,
        locale: String,
        path: String,
        fallback: bool,
    ) -> Result<(), Error> {
        let (identified, caller_uid) = self.own_subject(connection, caller, subject).await?;
        // Not even root registers for another user: an agent authenticates for its own user.
        if identified.uid != caller_uid {
            return Err(Error::NotAuthorized(
                "an agent may only be registered for a subject of its own user".to_string(),
            ));
        }
        if ObjectPath::try_from(path.as_str()).is_err() {
            return Err(Error::Failed(format!("{path:?} is not an object path")));
        }
        let agent = Agent {
            connection: caller.to_string(),
            path,
            uid: caller_uid,
            subject: identified.key,
            locale,
            fallback,
            busy: Default::default(),
        };
        lock(&self.agents)
            .register(agent.clone())
            .map_err(Error::Failed)?;
        // The caller may have left while it was identified, and its leaving then found no agent to
        // remove. Asked after the agent was added: if the caller is still there, its leaving comes
        // later and removes it.
        let still_there = match BusName::try_from(caller) {
            Ok(name) => match DBusProxy::new(connection).await {
                Ok(proxy) => proxy.name_has_owner(name).await.unwrap_or(false),
                Err(_) => false,
            },
            Err(_) => false,
        };
        if !still_there {
            lock(&self.agents).connection_left(caller);
            return Err(Error::Failed("the caller left the bus".to_string()));
        }
        log_agent("registered", &agent);
        Ok(())
    }
}

fn log_agent(what: &str, agent: &Agent) {
    eprintln!(
        "<6>authentication agent {what}: user {}, for {:?}, {} {}{}",
        agent.uid,
        agent.subject,
        agent.connection,
        agent.path,
        if agent.fallback { ", fallback" } else { "" }
    );
}

/// What a decision answers without authenticating. `auth_*` is a challenge: the subject could be
/// authorized by authenticating.
fn answer(authorization: Authorization) -> AuthorizationResult {
    AuthorizationResult {
        is_authorized: authorization == Authorization::Yes,
        is_challenge: !matches!(authorization, Authorization::Yes | Authorization::No),
        details: HashMap::new(),
    }
}

/// Authorized by the temporary authorization `id`.
fn authorized_by(id: &str) -> AuthorizationResult {
    let mut result = answer(Authorization::Yes);
    result.details.insert(
        "polkit.temporary_authorization_id".to_string(),
        id.to_string(),
    );
    result
}

/// `polkit.` details are refused unless documented, and those only from root.
fn check_details(details: &HashMap<String, String>, caller_uid: u32) -> Result<(), Error> {
    for key in details.keys().filter(|key| key.starts_with("polkit.")) {
        if !DOCUMENTED_POLKIT_DETAILS.contains(&key.as_str()) || caller_uid != 0 {
            return Err(Error::Failed(format!("the detail {key:?} is not allowed")));
        }
    }
    Ok(())
}

/// Whether the action's `org.freedesktop.policykit.owner` annotation names the caller
/// (`unix-user:<name or uid>`, separated by spaces), which then may check other users' subjects.
fn may_check_for_others(
    actions: &Actions,
    action_id: &str,
    caller_uid: u32,
    caller_name: Option<String>,
) -> bool {
    let Some(owners) = actions
        .get(action_id)
        .and_then(|action| action.annotations.get(OWNER_ANNOTATION))
    else {
        return false;
    };
    owners
        .split_whitespace()
        .filter_map(|identity| identity.strip_prefix("unix-user:"))
        .any(|user| user == caller_uid.to_string() || Some(user) == caller_name.as_deref())
}

/// `ImplicitAuthorization` on the wire.
fn implicit(authorization: Authorization) -> u32 {
    match authorization {
        Authorization::No => 0,
        Authorization::AuthSelf => 1,
        Authorization::AuthAdmin => 2,
        Authorization::AuthSelfKeep => 3,
        Authorization::AuthAdminKeep => 4,
        Authorization::Yes => 5,
    }
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    #[zbus(property)]
    fn backend_name(&self) -> &str {
        "nyra-polkit"
    }

    #[zbus(property)]
    fn backend_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// `TemporaryAuthorization` (1).
    #[zbus(property)]
    fn backend_features(&self) -> u32 {
        1
    }

    #[zbus(signal)]
    pub async fn changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    fn enumerate_actions(&self, locale: String) -> Vec<ActionDescription> {
        let policy = self.read_policy();
        policy
            .actions
            .values()
            .map(|action| {
                (
                    action.id.clone(),
                    action.description.for_locale(&locale).to_string(),
                    action.message.for_locale(&locale).to_string(),
                    action.vendor.clone(),
                    action.vendor_url.clone(),
                    action.icon_name.clone(),
                    implicit(action.allow_any),
                    implicit(action.allow_inactive),
                    implicit(action.allow_active),
                    action.annotations.clone().into_iter().collect(),
                )
            })
            .collect()
    }

    /// Returns a one-element tuple: zbus would send a bare struct as three arguments (`bba{ss}`),
    /// and the interface returns one struct, `(bba{ss})`.
    #[allow(clippy::too_many_arguments)] // The method's D-Bus arguments, plus the call's context.
    async fn check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        subject: Wire,
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> Result<(AuthorizationResult,), Error> {
        let caller = header
            .sender()
            .ok_or_else(|| Error::Failed("no sender".to_string()))?
            .to_string();
        if flags & !ALLOW_USER_INTERACTION != 0 {
            return Err(Error::Failed(format!("unknown flags {flags:#x}")));
        }
        let cancellation = lock(&self.checks).begin(&caller, &cancellation_id)?;
        let _in_flight = InFlight {
            checks: &self.checks,
            caller: caller.clone(),
            cancellation_id: cancellation_id.clone(),
        };
        let check = self.check(
            connection, &emitter, &caller, subject, &action_id, details, flags,
        );
        let cancellation = async {
            cancellation.wait().await;
            Err(Error::Cancelled("the check was cancelled".to_string()))
        };
        futures_lite::future::or(check, cancellation)
            .await
            .map(|result| (result,))
    }

    fn cancel_check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        cancellation_id: String,
    ) -> Result<(), Error> {
        let caller = header
            .sender()
            .ok_or_else(|| Error::Failed("no sender".to_string()))?;
        if lock(&self.checks).cancel(caller, &cancellation_id) {
            Ok(())
        } else {
            Err(Error::Failed(format!(
                "no check in flight with cancellation id {cancellation_id:?}"
            )))
        }
    }

    async fn register_authentication_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        subject: Wire,
        locale: String,
        object_path: String,
    ) -> Result<(), Error> {
        let caller = sender(&header)?;
        self.register_agent(connection, &caller, subject, locale, object_path, false)
            .await
    }

    /// Options: `fallback` (`b`). Others are ignored, as a later version of the interface may add
    /// some.
    async fn register_authentication_agent_with_options(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        subject: Wire,
        locale: String,
        object_path: String,
        options: HashMap<String, OwnedValue>,
    ) -> Result<(), Error> {
        let caller = sender(&header)?;
        let fallback = match options.get("fallback").map(|value| &**value) {
            None => false,
            Some(zbus::zvariant::Value::Bool(fallback)) => *fallback,
            Some(_) => return Err(Error::Failed("the option fallback is not a boolean".into())),
        };
        self.register_agent(connection, &caller, subject, locale, object_path, fallback)
            .await
    }

    async fn unregister_authentication_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        subject: Wire,
        object_path: String,
    ) -> Result<(), Error> {
        let caller = sender(&header)?;
        let (identified, _) = self.own_subject(connection, &caller, subject).await?;
        let removed = lock(&self.agents).unregister(&caller, &identified.key, &object_path);
        match removed {
            Some(agent) => {
                log_agent("unregistered", &agent);
                Ok(())
            }
            None => Err(Error::Failed(
                "no such authentication agent registered by this connection".to_string(),
            )),
        }
    }

    /// The old answer, without the uid of the agent's user: refused (docs/DESIGN.md, "Scope").
    fn authentication_agent_response(&self, _cookie: String, _identity: Wire) -> Result<(), Error> {
        Err(Error::NotSupported(
            "AuthenticationAgentResponse is not supported: use AuthenticationAgentResponse2"
                .to_string(),
        ))
    }

    /// The helper's answer, after it checked the password: accepted only from root, for a pending
    /// cookie, the agent's user and an identity offered.
    async fn authentication_agent_response2(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        uid: u32,
        cookie: String,
        identity: Wire,
    ) -> Result<(), Error> {
        let caller = sender(&header)?;
        let caller_uid = self.caller_uid(connection, &caller).await?;
        let identity_uid = agents::unix_user(&identity);
        let response = lock(&self.cookies).respond(caller_uid, uid, &cookie, identity_uid);
        match response {
            Ok(identity) => {
                eprintln!("<6>authentication answered by {caller}: uid {identity}");
                Ok(())
            }
            Err(refusal) => {
                eprintln!(
                    "<4>AuthenticationAgentResponse2 from {caller} (uid {caller_uid}) refused: {refusal}"
                );
                if caller_uid != 0 {
                    return Err(Error::NotAuthorized(
                        "only root may answer an authentication".to_string(),
                    ));
                }
                Err(Error::Failed(format!("refused: {refusal}")))
            }
        }
    }

    async fn enumerate_temporary_authorizations(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        subject: Wire,
    ) -> Result<Vec<TemporaryAuthorizationWire>, Error> {
        let caller = sender(&header)?;
        let (identified, _) = self.own_subject(connection, &caller, subject).await?;
        let now = boot_clock();
        let kept = lock(&self.temporary).of_subject(&identified, now);
        Ok(kept.iter().map(|kept| kept.to_wire(now)).collect())
    }

    async fn revoke_temporary_authorizations(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        subject: Wire,
    ) -> Result<(), Error> {
        let caller = sender(&header)?;
        let (identified, _) = self.own_subject(connection, &caller, subject).await?;
        let revoked = lock(&self.temporary).revoke_subject(&identified);
        for kept in &revoked {
            eprintln!(
                "<6>temporary authorization {} for {} of user {} revoked by {caller}",
                kept.id, kept.action_id, kept.uid
            );
        }
        if !revoked.is_empty() {
            Authority::changed(&emitter).await?;
        }
        Ok(())
    }

    async fn revoke_temporary_authorization_by_id(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        id: String,
    ) -> Result<(), Error> {
        let caller = sender(&header)?;
        let caller_uid = self.caller_uid(connection, &caller).await?;
        // The same answer whether it does not exist or is another user's.
        let revoked = lock(&self.temporary).revoke_id(&id, caller_uid);
        let Some(kept) = revoked else {
            return Err(Error::Failed(format!(
                "no temporary authorization {id:?} of this user"
            )));
        };
        eprintln!(
            "<6>temporary authorization {} for {} of user {} revoked by {caller}",
            kept.id, kept.action_id, kept.uid
        );
        Authority::changed(&emitter).await?;
        Ok(())
    }
}

/// The unique name of the caller.
fn sender(header: &Header<'_>) -> Result<String, Error> {
    header
        .sender()
        .map(|sender| sender.to_string())
        .ok_or_else(|| Error::Failed("no sender".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::parse_policy;

    #[test]
    fn decisions_map_to_the_documented_answers() {
        let result = |is_authorized, is_challenge| AuthorizationResult {
            is_authorized,
            is_challenge,
            details: HashMap::new(),
        };
        assert_eq!(answer(Authorization::Yes), result(true, false));
        assert_eq!(answer(Authorization::No), result(false, false));
        for authentication in [
            Authorization::AuthSelf,
            Authorization::AuthSelfKeep,
            Authorization::AuthAdmin,
            Authorization::AuthAdminKeep,
        ] {
            assert_eq!(answer(authentication), result(false, true));
        }
    }

    #[test]
    fn implicit_authorizations_use_the_wire_values() {
        let values = [
            (Authorization::No, 0),
            (Authorization::AuthSelf, 1),
            (Authorization::AuthAdmin, 2),
            (Authorization::AuthSelfKeep, 3),
            (Authorization::AuthAdminKeep, 4),
            (Authorization::Yes, 5),
        ];
        for (authorization, value) in values {
            assert_eq!(implicit(authorization), value, "{authorization:?}");
        }
    }

    #[test]
    fn polkit_details_only_documented_and_only_from_root() {
        let details = |key: &str| HashMap::from([(key.to_string(), "x".to_string())]);
        assert!(check_details(&details("remote"), 1000).is_ok());
        assert!(check_details(&details("polkit.message"), 0).is_ok());
        assert!(check_details(&details("polkit.message"), 1000).is_err());
        assert!(check_details(&details("polkit.dismissed"), 0).is_err());
    }

    #[test]
    fn the_owner_annotation_names_who_may_check_for_others() {
        let xml = r#"<policyconfig>
            <action id="org.example.color">
              <annotate key="org.freedesktop.policykit.owner">unix-user:42 unix-user:root</annotate>
            </action>
            <action id="org.example.plain"/>
        </policyconfig>"#;
        let actions: Actions = parse_policy(xml)
            .unwrap()
            .into_iter()
            .map(|action| (action.id.clone(), action))
            .collect();
        let may = |action_id, uid, name: Option<&str>| {
            may_check_for_others(&actions, action_id, uid, name.map(str::to_string))
        };
        assert!(may("org.example.color", 42, None));
        assert!(may("org.example.color", 0, Some("root")));
        assert!(!may("org.example.color", 43, Some("someone")));
        assert!(!may("org.example.plain", 42, None));
        assert!(!may("org.example.unknown", 42, None));
    }

    #[test]
    fn checks_in_flight_are_capped_and_ids_unique_per_caller() {
        // Fixed numbers, not the constants: the limits are part of the design.
        let mut checks = ChecksInFlight::default();
        for _ in 0..32 {
            assert!(checks.begin(":1.1", "").is_ok());
        }
        assert!(matches!(checks.begin(":1.1", ""), Err(Error::Failed(_))));
        // Another connection has its own limit.
        assert!(checks.begin(":1.2", "a").is_ok());
        assert!(matches!(
            checks.begin(":1.2", "a"),
            Err(Error::CancellationIdNotUnique(_))
        ));
        checks.end(":1.1", "");
        assert!(checks.begin(":1.1", "a").is_ok());
        checks.end(":1.2", "a");
        assert!(checks.begin(":1.2", "a").is_ok());
    }

    #[test]
    fn checks_in_flight_are_capped_per_user() {
        let mut checks = ChecksInFlight::default();
        for _ in 0..64 {
            assert!(checks.begin_for_user(1000).is_ok());
        }
        assert!(matches!(checks.begin_for_user(1000), Err(Error::Failed(_))));
        // Other users have their own limit; root has none.
        assert!(checks.begin_for_user(1001).is_ok());
        for _ in 0..100 {
            assert!(checks.begin_for_user(0).is_ok());
        }
        checks.end_for_user(1000);
        assert!(checks.begin_for_user(1000).is_ok());
        for _ in 0..64 {
            checks.end_for_user(1000);
        }
        checks.end_for_user(1001);
        assert!(checks.by_user.is_empty());
    }

    #[test]
    fn only_the_caller_cancels_its_check() {
        let mut checks = ChecksInFlight::default();
        let cancelled = checks.begin(":1.1", "a").unwrap().by_id.unwrap();
        assert!(!checks.cancel(":1.2", "a"));
        assert!(!checks.cancel(":1.1", "b"));
        assert!(cancelled.try_recv().is_err());
        assert!(checks.cancel(":1.1", "a"));
        assert!(cancelled.try_recv().is_ok());
        checks.end(":1.1", "a");
        assert!(!checks.cancel(":1.1", "a"));
        assert!(checks.by_caller.is_empty());
    }

    #[test]
    fn authentications_count_per_user_and_not_in_the_connection() {
        let mut checks = ChecksInFlight::default();
        for _ in 0..32 {
            checks.begin(":1.1", "").unwrap();
        }
        // 16 wait for nobody's agent, a 17th of nobody gets no dialog; daemon has their own 16.
        for _ in 0..16 {
            assert!(checks.begin_authentication(":1.1", 65534));
        }
        assert!(!checks.begin_authentication(":1.1", 65534));
        assert!(checks.begin_authentication(":1.1", 1));
        // Those 17 left the connection's slots: 17 more checks fit, not 18.
        for _ in 0..17 {
            assert!(checks.begin(":1.1", "").is_ok());
        }
        assert!(checks.begin(":1.1", "").is_err());
        checks.end_authentication(":1.1", 1);
        for _ in 0..16 {
            checks.end_authentication(":1.1", 65534);
        }
        assert!(checks.authentications.is_empty());
        assert_eq!(checks.by_caller[":1.1"].count, 32 + 17);

        // Two checks of one caller in authentications: when one ends, the other is still the
        // caller's, not ended as if the caller had left.
        let first = checks.begin(":1.3", "").unwrap();
        let second = checks.begin(":1.3", "").unwrap();
        assert!(checks.begin_authentication(":1.3", 65534));
        assert!(checks.begin_authentication(":1.3", 65534));
        checks.end_authentication(":1.3", 65534);
        checks.end(":1.3", "");
        drop(first);
        assert_eq!(
            second.caller_left.try_recv(),
            Err(async_channel::TryRecvError::Empty)
        );
        checks.end_authentication(":1.3", 65534);
        checks.end(":1.3", "");
        assert!(!checks.by_caller.contains_key(":1.3"));
        // A caller that left: its authentications still end.
        assert!(checks.begin_authentication(":1.2", 65534));
        checks.caller_left(":1.2");
        checks.end_authentication(":1.2", 65534);
        assert!(checks.authentications.is_empty());
    }

    #[test]
    fn a_caller_leaving_ends_all_its_checks_and_only_its() {
        let mut checks = ChecksInFlight::default();
        let with_id = checks.begin(":1.1", "a").unwrap();
        let without_id = checks.begin(":1.1", "").unwrap();
        let other_caller = checks.begin(":1.2", "").unwrap();
        checks.caller_left(":1.1");
        // Both end at once; without the departure, wait() would never return.
        futures_lite::future::block_on(with_id.wait());
        futures_lite::future::block_on(without_id.wait());
        assert_eq!(
            other_caller.caller_left.try_recv(),
            Err(async_channel::TryRecvError::Empty)
        );
        // The checks then end as usual, with nothing left to count.
        checks.end(":1.1", "a");
        checks.end(":1.1", "");
        assert_eq!(checks.by_caller.len(), 1);
    }

    #[test]
    fn broken_rules_are_logged_at_most_once_a_minute_with_a_count() {
        let mut log = BrokenRulesLog::default();
        let start = Instant::now();
        assert_eq!(log.denied(start), Some(1));
        assert_eq!(log.denied(start + Duration::from_secs(1)), None);
        assert_eq!(log.denied(start + Duration::from_secs(59)), None);
        assert_eq!(log.denied(start + Duration::from_secs(60)), Some(3));
        assert_eq!(log.denied(start + Duration::from_secs(61)), None);
        assert_eq!(log.denied(start + Duration::from_secs(200)), Some(2));
    }
}
