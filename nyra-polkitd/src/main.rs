// SPDX-License-Identifier: MIT
//! nyra-polkitd, for now: loads the action definitions and the rules, reports what it found and
//! exits. The D-Bus service (`org.freedesktop.PolicyKit1`) comes next (docs/DESIGN.md).
//!
//! Messages carry sd-daemon priority prefixes for the journal: `<3>` error, `<4>` warning,
//! `<6>` info.

use nyra_polkitd::actions::{ACTIONS_DIR, load_actions};
use nyra_polkitd::rules::{IMAGE_RULES_DIR, LOCAL_RULES_DIR, load_rules};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let (actions, problems) = load_actions(Path::new(ACTIONS_DIR));
    for problem in &problems {
        eprintln!("<4>{problem}");
    }
    let rules = match load_rules(Path::new(IMAGE_RULES_DIR), Path::new(LOCAL_RULES_DIR)) {
        Ok(rules) => rules,
        Err(error) => {
            // The service will deny every request in this state (docs/DESIGN.md, "Rules").
            eprintln!("<3>{error}; every request would be denied until it is fixed");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "<6>{} actions, {} rules, administrators: users {:?}, groups {:?}; the D-Bus service is not implemented yet",
        actions.len(),
        rules.rules.len(),
        rules.administrators.users,
        rules.administrators.groups
    );
    ExitCode::SUCCESS
}
