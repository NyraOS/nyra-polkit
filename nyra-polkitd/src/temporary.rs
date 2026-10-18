// SPDX-License-Identifier: MIT
//! Temporary authorizations (docs/DESIGN.md, "Temporary authorizations"): after a successful
//! authentication for `auth_self_keep` or `auth_admin_keep`, the action is remembered for the exact
//! subject, its session and the level asked, for [`LIFETIME`] on the boot clock.
//!
//! The store is plain data: the caller passes the time ([`boot_clock`]), so the tests can move it.

use crate::Authorization;
use crate::subject::{Identified, SubjectKey};
use std::time::{Duration, SystemTime};

pub const LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Time since boot, suspend included (`CLOCK_BOOTTIME`): a laptop that slept through the five
/// minutes does not keep the authorization.
pub fn boot_clock() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

#[derive(Debug, Clone, PartialEq)]
pub struct TemporaryAuthorization {
    pub id: String,
    pub action_id: String,
    /// The subject's user.
    pub uid: u32,
    pub subject: SubjectKey,
    pub session_id: Option<String>,
    /// What was asked: `AuthSelfKeep` (the user's own password) or `AuthAdminKeep`.
    pub level: Authorization,
    /// When it was obtained, on the boot clock.
    pub obtained: Duration,
}

impl TemporaryAuthorization {
    /// Whether it is one of `subject`'s. A session stands for every subject in it, so that
    /// `pkcheck --list-temp` and `--revoke-temp`, which name the caller's session, see them all.
    fn belongs_to(&self, subject: &Identified) -> bool {
        self.uid == subject.uid
            && match &subject.key {
                SubjectKey::Session(id) => self.session_id.as_ref() == Some(id),
                key => self.subject == *key && self.session_id == subject.session_id,
            }
    }

    /// `(id, action id, subject, obtained, expires)`, the times in seconds since the epoch, as the
    /// interface gives them. The boot clock is converted at the time of the call.
    pub fn to_wire(&self, boot_now: Duration) -> (String, String, SubjectWire, u64, u64) {
        let wall_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let obtained = wall_now.saturating_sub(boot_now.saturating_sub(self.obtained));
        (
            self.id.clone(),
            self.action_id.clone(),
            self.subject.to_wire(),
            obtained.as_secs(),
            (obtained + LIFETIME).as_secs(),
        )
    }
}

type SubjectWire = (
    String,
    std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
);

#[derive(Default)]
pub struct TemporaryAuthorizations {
    list: Vec<TemporaryAuthorization>,
    /// Ids are never reused while the daemon runs.
    next_id: u64,
}

impl TemporaryAuthorizations {
    /// Remembers that `subject` authenticated for `action_id` at `level`; returns its id.
    pub fn add(
        &mut self,
        action_id: &str,
        subject: &Identified,
        level: Authorization,
        now: Duration,
    ) -> String {
        self.expire(now);
        self.next_id += 1;
        let id = format!("nyra-tmp-{}", self.next_id);
        self.list.push(TemporaryAuthorization {
            id: id.clone(),
            action_id: action_id.to_string(),
            uid: subject.uid,
            subject: subject.key.clone(),
            session_id: subject.session_id.clone(),
            level,
            obtained: now,
        });
        id
    }

    /// The id of an authorization that answers `decision` for `action_id` and this exact subject in
    /// its current session. Only `_keep` decisions use one, and only one of at least their level: an
    /// administrator's password answers both, the user's own only `auth_self_keep`.
    pub fn find(
        &mut self,
        action_id: &str,
        subject: &Identified,
        decision: Authorization,
        now: Duration,
    ) -> Option<String> {
        if !matches!(
            decision,
            Authorization::AuthSelfKeep | Authorization::AuthAdminKeep
        ) {
            return None;
        }
        self.expire(now);
        self.list
            .iter()
            .find(|kept| {
                kept.action_id == action_id
                    && kept.uid == subject.uid
                    && kept.subject == subject.key
                    && kept.session_id == subject.session_id
                    && kept.level >= decision
            })
            .map(|kept| kept.id.clone())
    }

    /// The authorizations of `subject` (see [`TemporaryAuthorization::belongs_to`]).
    pub fn of_subject(
        &mut self,
        subject: &Identified,
        now: Duration,
    ) -> Vec<TemporaryAuthorization> {
        self.expire(now);
        self.list
            .iter()
            .filter(|kept| kept.belongs_to(subject))
            .cloned()
            .collect()
    }

    /// Removes the authorizations of `subject`; returns them.
    pub fn revoke_subject(&mut self, subject: &Identified) -> Vec<TemporaryAuthorization> {
        self.remove_where(|kept| kept.belongs_to(subject))
    }

    /// Removes the authorization `id` if it is user `uid`'s, or for root whoever's.
    pub fn revoke_id(&mut self, id: &str, uid: u32) -> Option<TemporaryAuthorization> {
        self.remove_where(|kept| kept.id == id && (kept.uid == uid || uid == 0))
            .pop()
    }

    /// Removes those of a bus name that left the bus; returns how many.
    pub fn bus_name_left(&mut self, name: &str) -> usize {
        self.remove_where(|kept| kept.subject == SubjectKey::BusName(name.to_string()))
            .len()
    }

    /// Removes all of them (the rules were reread); returns how many.
    pub fn clear(&mut self) -> usize {
        std::mem::take(&mut self.list).len()
    }

    /// Drops what is older than [`LIFETIME`]. Only looked at when the store is used: an expired
    /// authorization is never used or listed, and nothing else needs it gone sooner.
    fn expire(&mut self, now: Duration) {
        for expired in self.remove_where(|kept| now.saturating_sub(kept.obtained) >= LIFETIME) {
            eprintln!(
                "<6>temporary authorization {} for {} of user {} expired",
                expired.id, expired.action_id, expired.uid
            );
        }
    }

    fn remove_where(
        &mut self,
        mut condition: impl FnMut(&TemporaryAuthorization) -> bool,
    ) -> Vec<TemporaryAuthorization> {
        let (removed, kept) = std::mem::take(&mut self.list)
            .into_iter()
            .partition(|kept| condition(kept));
        self.list = kept;
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Session;
    use crate::subject::ProcessId;
    use Authorization::*;

    fn process(pid: u32, uid: u32, session: Option<&str>) -> Identified {
        let process = ProcessId {
            pid,
            start_time: 100,
        };
        Identified {
            uid,
            session: Session::LocalActive,
            session_id: session.map(str::to_string),
            key: SubjectKey::Process(process),
            process: Some(process),
        }
    }

    fn session(id: &str, uid: u32) -> Identified {
        Identified {
            uid,
            session: Session::LocalActive,
            session_id: Some(id.to_string()),
            key: SubjectKey::Session(id.to_string()),
            process: None,
        }
    }

    const START: Duration = Duration::from_secs(1000);

    #[test]
    fn used_by_the_same_subject_until_five_minutes_on_the_boot_clock() {
        let mut kept = TemporaryAuthorizations::default();
        let alice = process(10, 1000, Some("c1"));
        let id = kept.add("org.example.a", &alice, AuthAdminKeep, START);
        fn find(
            kept: &mut TemporaryAuthorizations,
            subject: &Identified,
            after: Duration,
        ) -> Option<String> {
            kept.find("org.example.a", subject, AuthAdminKeep, START + after)
        }
        assert_eq!(
            find(&mut kept, &alice, Duration::from_secs(299)),
            Some(id.clone())
        );
        // Another process of the same user in the same session, the same PID started at another
        // time, the same process seen in another session, another action: none of them.
        assert_eq!(
            find(&mut kept, &process(11, 1000, Some("c1")), Duration::ZERO),
            None
        );
        let mut restarted = alice.clone();
        restarted.key = SubjectKey::Process(ProcessId {
            pid: 10,
            start_time: 101,
        });
        assert_eq!(find(&mut kept, &restarted, Duration::ZERO), None);
        assert_eq!(
            find(&mut kept, &process(10, 1000, Some("c2")), Duration::ZERO),
            None
        );
        assert_eq!(
            kept.find("org.example.b", &alice, AuthAdminKeep, START),
            None
        );
        // Exactly five minutes later it is gone, for good.
        assert_eq!(find(&mut kept, &alice, LIFETIME), None);
        assert_eq!(find(&mut kept, &alice, Duration::ZERO), None);
    }

    #[test]
    fn the_users_own_password_never_answers_for_an_administrators() {
        let mut kept = TemporaryAuthorizations::default();
        let alice = process(10, 1000, Some("c1"));
        kept.add("org.example.self", &alice, AuthSelfKeep, START);
        kept.add("org.example.admin", &alice, AuthAdminKeep, START);
        let find = |kept: &mut TemporaryAuthorizations, action, decision| {
            kept.find(action, &alice, decision, START).is_some()
        };
        assert!(find(&mut kept, "org.example.self", AuthSelfKeep));
        assert!(!find(&mut kept, "org.example.self", AuthAdminKeep));
        assert!(find(&mut kept, "org.example.admin", AuthSelfKeep));
        assert!(find(&mut kept, "org.example.admin", AuthAdminKeep));
        // Decisions that ask every time, or never, are not answered by any.
        for decision in [Yes, AuthSelf, AuthAdmin, No] {
            assert!(
                !find(&mut kept, "org.example.admin", decision),
                "{decision:?}"
            );
        }
    }

    #[test]
    fn listed_and_revoked_by_subject_or_session_only_for_its_user() {
        let mut kept = TemporaryAuthorizations::default();
        let alice = process(10, 1000, Some("c1"));
        let alice_elsewhere = process(11, 1000, None);
        // root in alice's session (sudo at the seat) keeps the session.
        let root = process(12, 0, Some("c1"));
        let a = kept.add("org.example.a", &alice, AuthSelfKeep, START);
        let b = kept.add("org.example.b", &alice_elsewhere, AuthSelfKeep, START);
        let c = kept.add("org.example.c", &root, AuthSelfKeep, START);
        let ids = |list: Vec<TemporaryAuthorization>| {
            list.into_iter().map(|kept| kept.id).collect::<Vec<_>>()
        };
        assert_eq!(
            ids(kept.of_subject(&alice, START)),
            std::slice::from_ref(&a)
        );
        assert_eq!(
            ids(kept.of_subject(&session("c1", 1000), START)),
            std::slice::from_ref(&a)
        );
        assert_eq!(
            ids(kept.of_subject(&session("c1", 0), START)),
            std::slice::from_ref(&c)
        );

        // Only its user, or root, revokes one by id.
        assert_eq!(kept.revoke_id(&a, 1001), None);
        assert_eq!(kept.revoke_id(&a, 1000).map(|kept| kept.id), Some(a));
        assert_eq!(kept.revoke_id(&c, 0).map(|kept| kept.id), Some(c));
        assert_eq!(ids(kept.revoke_subject(&alice_elsewhere)), [b]);
        assert!(kept.list.is_empty());
    }

    #[test]
    fn bus_names_that_leave_and_reloads_drop_them() {
        let mut kept = TemporaryAuthorizations::default();
        let mut by_name = process(10, 1000, Some("c1"));
        by_name.key = SubjectKey::BusName(":1.7".to_string());
        kept.add("org.example.a", &by_name, AuthSelfKeep, START);
        kept.add(
            "org.example.a",
            &process(10, 1000, Some("c1")),
            AuthSelfKeep,
            START,
        );
        assert_eq!(kept.bus_name_left(":1.8"), 0);
        assert_eq!(kept.bus_name_left(":1.7"), 1);
        assert_eq!(kept.clear(), 1);
        // Ids are not reused.
        assert_eq!(
            kept.add("org.example.a", &by_name, AuthSelfKeep, START),
            "nyra-tmp-3"
        );
    }

    #[test]
    fn listed_with_times_since_the_epoch() {
        let mut kept = TemporaryAuthorizations::default();
        let alice = process(10, 1000, Some("c1"));
        kept.add("org.example.a", &alice, AuthSelfKeep, START);
        let (_, action, (kind, _), obtained, expires) =
            kept.of_subject(&alice, START)[0].to_wire(START + Duration::from_secs(60));
        let wall = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            (action.as_str(), kind.as_str()),
            ("org.example.a", "unix-process")
        );
        assert!(
            (wall - 61..=wall - 59).contains(&obtained),
            "{obtained} {wall}"
        );
        assert_eq!(expires - obtained, 300);
    }

    #[test]
    fn the_boot_clock_moves() {
        let first = boot_clock();
        assert!(first > Duration::ZERO);
        assert!(boot_clock() >= first);
    }
}
