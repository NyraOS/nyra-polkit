// SPDX-License-Identifier: MIT
//! The D-Bus service: `org.freedesktop.PolicyKit1.Authority` at [`AUTHORITY_PATH`]
//! (docs/DESIGN.md, "D-Bus interface").
//!
//! Authentication agents are not served yet: a decision that needs authentication (`auth_*`) is
//! answered "not authorized, challenge", which is what the interface documents when no agent can
//! take the request.
//!
//! Log lines carry sd-daemon priority prefixes for the journal: `<3>` error, `<4>` warning,
//! `<6>` info.

use crate::actions::{Actions, load_actions};
use crate::decision::{Subject, decide};
use crate::rules::{Rules, load_rules};
use crate::{Authorization, subject};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedValue;
use zbus::{Connection, interface};

pub const BUS_NAME: &str = "org.freedesktop.PolicyKit1";
pub const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";

/// `CheckAuthorizationFlags`: the only flag.
const ALLOW_USER_INTERACTION: u32 = 1;
/// Checks one connection may have in flight (docs/DESIGN.md, "Security").
const MAX_CHECKS_PER_CONNECTION: usize = 32;
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
    }
}

/// The checks in flight, per caller (a unique bus name): how many, and the cancellation ids of
/// those that have one, with what cancels them.
#[derive(Default)]
struct ChecksInFlight {
    by_caller: HashMap<String, CallerChecks>,
}

#[derive(Default)]
struct CallerChecks {
    count: usize,
    cancellable: HashMap<String, async_channel::Sender<()>>,
}

impl ChecksInFlight {
    /// Counts a new check of `caller`. With a cancellation id, returns what receives the
    /// cancellation.
    fn begin(
        &mut self,
        caller: &str,
        cancellation_id: &str,
    ) -> Result<Option<async_channel::Receiver<()>>, Error> {
        let checks = self.by_caller.entry(caller.to_string()).or_default();
        if checks.count >= MAX_CHECKS_PER_CONNECTION {
            return Err(Error::Failed(format!(
                "too many checks in flight (at most {MAX_CHECKS_PER_CONNECTION} per connection)"
            )));
        }
        let mut cancelled = None;
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
            cancelled = Some(receiver);
        }
        checks.count += 1;
        Ok(cancelled)
    }

    fn end(&mut self, caller: &str, cancellation_id: &str) {
        let Some(checks) = self.by_caller.get_mut(caller) else {
            return;
        };
        checks.count -= 1;
        checks.cancellable.remove(cancellation_id);
        if checks.count == 0 {
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

pub struct Authority {
    policy: RwLock<Policy>,
    checks: Mutex<ChecksInFlight>,
    broken_rules_log: Mutex<BrokenRulesLog>,
}

impl Authority {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: RwLock::new(policy),
            checks: Mutex::default(),
            broken_rules_log: Mutex::default(),
        }
    }

    /// Replaces the policy in force (`systemctl reload`).
    pub fn replace_policy(&self, policy: Policy) {
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
    }

    async fn check(
        &self,
        connection: &Connection,
        caller: &str,
        (kind, subject_details): (String, HashMap<String, OwnedValue>),
        action_id: &str,
        details: &HashMap<String, String>,
    ) -> Result<AuthorizationResult, Error> {
        let caller_uid = subject::bus_uid(connection, caller)
            .await
            .map_err(Error::Failed)?;
        check_details(details, caller_uid)?;
        let identified = subject::identify(connection, &kind, &subject_details)
            .await
            .map_err(|error| {
                Error::NotAuthorized(format!("cannot identify the subject: {error}"))
            })?;
        let (user, groups) = subject::user_and_groups(identified.uid)
            .map_err(|error| Error::NotAuthorized(format!("subject: {error}")))?;

        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if identified.uid != caller_uid
            && caller_uid != 0
            && !may_check_for_others(&policy.actions, action_id, caller_uid)
        {
            return Err(Error::NotAuthorized(
                "only root may check the authorization of another user's subject".to_string(),
            ));
        }
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
        let details: std::collections::BTreeMap<_, _> = details.clone().into_iter().collect();
        let subject = Subject {
            user,
            groups,
            session: identified.session,
        };
        Ok(answer(decide(
            &policy.actions,
            rules,
            action_id,
            &subject,
            &details,
        )))
    }
}

/// What a decision answers before any authentication. `auth_*` is a challenge: the subject could
/// be authorized by authenticating, and no agent can take the request yet.
fn answer(authorization: Authorization) -> AuthorizationResult {
    AuthorizationResult {
        is_authorized: authorization == Authorization::Yes,
        is_challenge: !matches!(authorization, Authorization::Yes | Authorization::No),
        details: HashMap::new(),
    }
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
fn may_check_for_others(actions: &Actions, action_id: &str, caller_uid: u32) -> bool {
    let Some(owners) = actions
        .get(action_id)
        .and_then(|action| action.annotations.get(OWNER_ANNOTATION))
    else {
        return false;
    };
    let caller_name = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(caller_uid))
        .ok()
        .flatten()
        .map(|user| user.name);
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

    /// No `TemporaryAuthorization` (1) until authentication is served.
    #[zbus(property)]
    fn backend_features(&self) -> u32 {
        0
    }

    #[zbus(signal)]
    pub async fn changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    fn enumerate_actions(&self, locale: String) -> Vec<ActionDescription> {
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        subject: (String, HashMap<String, OwnedValue>),
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
        let cancelled = lock(&self.checks).begin(&caller, &cancellation_id)?;
        let _in_flight = InFlight {
            checks: &self.checks,
            caller: caller.clone(),
            cancellation_id: cancellation_id.clone(),
        };
        let check = self.check(connection, &caller, subject, &action_id, &details);
        let cancellation = async {
            match cancelled {
                Some(cancelled) => {
                    let _ = cancelled.recv().await;
                }
                None => futures_lite::future::pending::<()>().await,
            }
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
        assert!(may_check_for_others(&actions, "org.example.color", 42));
        // By name: root is uid 0 everywhere.
        assert!(may_check_for_others(&actions, "org.example.color", 0));
        assert!(!may_check_for_others(&actions, "org.example.color", 43));
        assert!(!may_check_for_others(&actions, "org.example.plain", 42));
        assert!(!may_check_for_others(&actions, "org.example.unknown", 42));
    }

    #[test]
    fn checks_in_flight_are_capped_and_ids_unique_per_caller() {
        let mut checks = ChecksInFlight::default();
        for _ in 0..MAX_CHECKS_PER_CONNECTION {
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
    fn only_the_caller_cancels_its_check() {
        let mut checks = ChecksInFlight::default();
        let cancelled = checks.begin(":1.1", "a").unwrap().unwrap();
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
