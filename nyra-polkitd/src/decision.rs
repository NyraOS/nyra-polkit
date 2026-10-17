// SPDX-License-Identifier: MIT
//! The decision (docs/DESIGN.md, "Decision"): what a subject gets for an action, before any
//! authentication. Pure: the subject's user, groups and session were found by the caller.
//!
//! 1. An action without a definition is denied, whatever the rules say.
//! 2. When rules match, the most restrictive of their results wins.
//! 3. When none matches, the action's default for the subject's session applies.

use crate::Authorization;
use crate::actions::{Action, Actions};
use crate::rules::{Administrators, Rule, Rules, SessionCondition};
use std::collections::BTreeMap;

/// Where the subject is, as logind sees it (docs/DESIGN.md, "Subjects").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    /// No session, or a remote one (`allow_any`).
    NotLocal,
    /// A local session that is not in the foreground (`allow_inactive`).
    LocalInactive,
    /// The local session in the foreground (`allow_active`).
    LocalActive,
}

impl Session {
    /// The state of a logind session from its `Remote`, `Seat` (the seat id, empty without one) and
    /// `Active` properties. Local needs a seat: sessions without one, such as each user's
    /// `manager` session, are reported active and not remote, but nobody sits at them.
    pub fn from_logind(remote: bool, seat: &str, active: bool) -> Self {
        match (!remote && !seat.is_empty(), active) {
            (false, _) => Self::NotLocal,
            (true, false) => Self::LocalInactive,
            (true, true) => Self::LocalActive,
        }
    }
}

/// The subject of a check, once identified.
#[derive(Debug, Clone)]
pub struct Subject {
    pub user: String,
    /// All the user's groups, the primary one included.
    pub groups: Vec<String>,
    pub session: Session,
}

pub fn decide(
    actions: &Actions,
    rules: &Rules,
    action_id: &str,
    subject: &Subject,
    details: &BTreeMap<String, String>,
) -> Authorization {
    let Some(action) = actions.get(action_id) else {
        return Authorization::No;
    };
    rules
        .rules
        .iter()
        .filter(|rule| rule_matches(rule, action_id, subject, details, &rules.administrators))
        .map(|rule| rule.result)
        .max()
        .unwrap_or_else(|| action_default(action, subject.session))
}

fn action_default(action: &Action, session: Session) -> Authorization {
    match session {
        Session::NotLocal => action.allow_any,
        Session::LocalInactive => action.allow_inactive,
        Session::LocalActive => action.allow_active,
    }
}

pub fn is_administrator(subject: &Subject, administrators: &Administrators) -> bool {
    administrators.users.contains(&subject.user)
        || subject
            .groups
            .iter()
            .any(|group| administrators.groups.contains(group))
}

/// A rule matches when every condition it sets holds.
fn rule_matches(
    rule: &Rule,
    action_id: &str,
    subject: &Subject,
    details: &BTreeMap<String, String>,
    administrators: &Administrators,
) -> bool {
    let action = rule
        .actions
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => action_id.starts_with(prefix),
            None => pattern == action_id,
        });
    let who = (rule.users.is_empty() && rule.groups.is_empty())
        || rule.users.contains(&subject.user)
        || subject
            .groups
            .iter()
            .any(|group| rule.groups.contains(group));
    let administrator = !rule.administrator || is_administrator(subject, administrators);
    let session = match rule.session {
        None => true,
        Some(SessionCondition::Local) => subject.session != Session::NotLocal,
        Some(SessionCondition::Active) => subject.session == Session::LocalActive,
    };
    let details = rule.details.iter().all(|(key, allowed)| {
        details
            .get(key)
            .is_some_and(|value| allowed.contains(value))
    });
    action && who && administrator && session && details
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::Text;
    use Authorization::*;

    fn actions() -> Actions {
        let action = |id: &str, any, inactive, active| Action {
            id: id.to_string(),
            description: Text::default(),
            message: Text::default(),
            vendor: String::new(),
            vendor_url: String::new(),
            icon_name: String::new(),
            allow_any: any,
            allow_inactive: inactive,
            allow_active: active,
            annotations: BTreeMap::new(),
        };
        [
            action("org.example.mount", AuthAdmin, AuthAdmin, Yes),
            action("org.example.app-install", No, AuthAdmin, AuthAdminKeep),
            action("org.example.reboot", AuthAdmin, AuthAdmin, AuthSelf),
        ]
        .into_iter()
        .map(|action| (action.id.clone(), action))
        .collect()
    }

    fn rules(toml: &str) -> Rules {
        crate::rules::rules_from_text(toml)
    }

    fn subject(user: &str, groups: &[&str], session: Session) -> Subject {
        Subject {
            user: user.to_string(),
            groups: groups.iter().map(|group| group.to_string()).collect(),
            session,
        }
    }

    fn no_details() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    const FLATPAK: &str = r#"
        administrators = { groups = ["sudo"] }

        [[rule]]
        actions = ["org.example.app-install"]
        administrator = true
        session = "active"
        details = { remote = ["flathub", "nyra"] }
        result = "yes"
    "#;

    #[test]
    fn defaults_follow_the_session() {
        let rules = rules("");
        let decide_in = |session| {
            decide(
                &actions(),
                &rules,
                "org.example.mount",
                &subject("alice", &["alice"], session),
                &no_details(),
            )
        };
        assert_eq!(decide_in(Session::NotLocal), AuthAdmin);
        assert_eq!(decide_in(Session::LocalInactive), AuthAdmin);
        assert_eq!(decide_in(Session::LocalActive), Yes);
    }

    #[test]
    fn unknown_actions_are_denied_even_by_a_yes_rule() {
        let rules = rules("[[rule]]\nactions = [\"org.example.*\"]\nresult = \"yes\"\n");
        let alice = subject("alice", &[], Session::LocalActive);
        let decide_for = |action| decide(&actions(), &rules, action, &alice, &no_details());
        assert_eq!(decide_for("org.example.unknown"), No);
        assert_eq!(decide_for("org.example.reboot"), Yes);
    }

    #[test]
    fn local_sessions_need_a_seat() {
        assert_eq!(
            Session::from_logind(false, "seat0", true),
            Session::LocalActive
        );
        assert_eq!(
            Session::from_logind(false, "seat0", false),
            Session::LocalInactive
        );
        // The user manager's session: no seat, not remote, active.
        assert_eq!(Session::from_logind(false, "", true), Session::NotLocal);
        assert_eq!(Session::from_logind(true, "seat0", true), Session::NotLocal);
        assert_eq!(Session::from_logind(true, "", false), Session::NotLocal);
    }

    #[test]
    fn administrator_in_active_session_installs_from_a_configured_remote() {
        let rules = rules(FLATPAK);
        let admin = subject("alice", &["alice", "sudo"], Session::LocalActive);
        let flathub = BTreeMap::from([("remote".to_string(), "flathub".to_string())]);
        let other = BTreeMap::from([("remote".to_string(), "elsewhere".to_string())]);
        let install = |who: &Subject, details: &BTreeMap<String, String>| {
            decide(&actions(), &rules, "org.example.app-install", who, details)
        };

        assert_eq!(install(&admin, &flathub), Yes);
        // Any condition that fails leaves the action's default.
        assert_eq!(install(&admin, &other), AuthAdminKeep);
        assert_eq!(install(&admin, &no_details()), AuthAdminKeep);
        assert_eq!(
            install(
                &subject("alice", &["alice", "sudo"], Session::LocalInactive),
                &flathub
            ),
            AuthAdmin
        );
        assert_eq!(
            install(&subject("bob", &["bob"], Session::LocalActive), &flathub),
            AuthAdminKeep
        );
    }

    #[test]
    fn the_most_restrictive_matching_rule_wins_whatever_the_order() {
        let yes =
            "[[rule]]\nactions = [\"org.example.*\"]\ngroups = [\"staff\"]\nresult = \"yes\"\n";
        let deny =
            "[[rule]]\nactions = [\"org.example.mount\"]\nusers = [\"bob\"]\nresult = \"no\"\n";
        let ask = "[[rule]]\nactions = [\"org.example.mount\"]\nsession = \"local\"\nresult = \"auth_self\"\n";
        let bob = subject("bob", &["staff"], Session::LocalActive);
        let carol = subject("carol", &["staff"], Session::LocalActive);
        for text in [
            format!("{yes}{deny}{ask}"),
            format!("{deny}{ask}{yes}"),
            format!("{ask}{yes}{deny}"),
        ] {
            let rules = rules(&text);
            assert_eq!(
                decide(&actions(), &rules, "org.example.mount", &bob, &no_details()),
                No
            );
            assert_eq!(
                decide(
                    &actions(),
                    &rules,
                    "org.example.mount",
                    &carol,
                    &no_details()
                ),
                AuthSelf
            );
            assert_eq!(
                decide(
                    &actions(),
                    &rules,
                    "org.example.reboot",
                    &carol,
                    &no_details()
                ),
                Yes
            );
        }
    }

    /// Each pair of results, in both file orders: the more restrictive one wins. This pins the
    /// whole order, not just its ends.
    #[test]
    fn results_are_ordered_from_yes_to_no() {
        let order = [
            "yes",
            "auth_self_keep",
            "auth_self",
            "auth_admin_keep",
            "auth_admin",
            "no",
        ];
        let alice = subject("alice", &[], Session::LocalActive);
        let rule = |result: &str| {
            format!("[[rule]]\nactions = [\"org.example.mount\"]\nresult = \"{result}\"\n")
        };
        for (lower, weaker) in order.iter().enumerate() {
            for stronger in &order[lower + 1..] {
                let expected = Authorization::parse(stronger).unwrap();
                for text in [
                    rule(weaker) + &rule(stronger),
                    rule(stronger) + &rule(weaker),
                ] {
                    let rules = rules(&text);
                    let result = decide(
                        &actions(),
                        &rules,
                        "org.example.mount",
                        &alice,
                        &no_details(),
                    );
                    assert_eq!(result, expected, "{weaker} and {stronger}");
                }
            }
        }
    }

    #[test]
    fn session_local_means_a_local_session_active_or_not() {
        let rules = rules(
            "[[rule]]\nactions = [\"org.example.reboot\"]\nsession = \"local\"\nresult = \"yes\"\n",
        );
        let reboot = |session| {
            let alice = subject("alice", &[], session);
            decide(
                &actions(),
                &rules,
                "org.example.reboot",
                &alice,
                &no_details(),
            )
        };
        assert_eq!(reboot(Session::LocalActive), Yes);
        assert_eq!(reboot(Session::LocalInactive), Yes);
        // Not local: the rule does not match, the default (allow_any) applies.
        assert_eq!(reboot(Session::NotLocal), AuthAdmin);
    }

    #[test]
    fn a_rule_can_also_ask_for_more_than_the_default() {
        let rules = rules("[[rule]]\nactions = [\"org.example.mount\"]\nresult = \"auth_admin\"\n");
        let alice = subject("alice", &[], Session::LocalActive);
        assert_eq!(
            decide(
                &actions(),
                &rules,
                "org.example.mount",
                &alice,
                &no_details()
            ),
            AuthAdmin
        );
    }

    #[test]
    fn administrators_are_users_or_group_members() {
        let administrators = Administrators {
            users: vec!["root".to_string()],
            groups: vec!["sudo".to_string()],
        };
        assert!(is_administrator(
            &subject("root", &["root"], Session::NotLocal),
            &administrators
        ));
        assert!(is_administrator(
            &subject("alice", &["users", "sudo"], Session::NotLocal),
            &administrators
        ));
        assert!(!is_administrator(
            &subject("bob", &["users"], Session::NotLocal),
            &administrators
        ));
    }
}
