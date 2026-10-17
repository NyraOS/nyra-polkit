// SPDX-License-Identifier: MIT
//! nyra-polkitd: a polkit authority written from scratch (docs/DESIGN.md).
//!
//! - [`actions`]: the action definitions, from the standard polkit `.policy` XML files;
//! - [`rules`]: the TOML rules of the image and of the administrator;
//! - [`decision`]: what a subject gets for an action, from the two above.

pub mod actions;
pub mod decision;
pub mod rules;

use serde::Deserialize;
use std::io::Read;
use std::path::Path;

/// What an action default or a rule gives a subject (polkit(8), "defaults"; `ImplicitAuthorization`
/// on D-Bus). The variants go from the least to the most restrictive: when several rules match, the
/// most restrictive one wins (docs/DESIGN.md, "Decision"), which is the largest in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub enum Authorization {
    Yes,
    AuthSelfKeep,
    AuthSelf,
    AuthAdminKeep,
    AuthAdmin,
    No,
}

impl Authorization {
    /// The names used both in the action XML and in the TOML rules.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "yes" => Some(Self::Yes),
            "auth_self_keep" => Some(Self::AuthSelfKeep),
            "auth_self" => Some(Self::AuthSelf),
            "auth_admin_keep" => Some(Self::AuthAdminKeep),
            "auth_admin" => Some(Self::AuthAdmin),
            "no" => Some(Self::No),
            _ => None,
        }
    }
}

impl TryFrom<String> for Authorization {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).ok_or_else(|| {
            format!(
                "unknown result {text:?} (one of yes, auth_self_keep, auth_self, auth_admin_keep, auth_admin, no)"
            )
        })
    }
}

/// Real action and rule files are at most a few hundred KiB, even with all their translations; the
/// limit keeps a damaged file from filling the memory of the daemon.
const MAX_FILE_SIZE: u64 = 4 << 20;

/// Reads a whole configuration file, refusing one larger than [`MAX_FILE_SIZE`].
fn read_config_file(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut text = String::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > MAX_FILE_SIZE {
        return Err(format!(
            "{}: larger than {MAX_FILE_SIZE} bytes",
            path.display()
        ));
    }
    Ok(text)
}

/// Action ids may only hold ASCII letters, digits, `.` and `-` (polkit(8)).
pub fn is_valid_action_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}
