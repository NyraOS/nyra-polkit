// SPDX-License-Identifier: MIT
//! nyra-polkitd: a polkit authority written from scratch (docs/DESIGN.md).
//!
//! - [`actions`]: the action definitions, from the standard polkit `.policy` XML files;
//! - [`rules`]: the TOML rules of the image and of the administrator;
//! - [`decision`]: what a subject gets for an action, from the two above;
//! - [`process`], [`logind`], [`subject`]: who asks, as the kernel, logind and the bus know it;
//! - [`agents`], [`temporary`]: authentication agents, and what an authentication leaves behind;
//! - [`authority`]: the D-Bus service, `org.freedesktop.PolicyKit1`.

pub mod actions;
pub mod agents;
pub mod authority;
pub mod decision;
pub mod logind;
pub mod process;
pub mod rules;
pub mod subject;
pub mod temporary;

use rustix::fs::OFlags;
use serde::Deserialize;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
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
    let (file, _) = open_regular_file(path, "")?;
    read_opened_file(file, path)
}

/// Opens a file and checks what was opened (fstat), so a symbolic link is judged by its target and
/// the file cannot be swapped between the check and the read. `not_regular_hint` ends the error
/// for a file that is not a regular one.
fn open_regular_file(path: &Path, not_regular_hint: &str) -> Result<(File, Metadata), String> {
    // O_NONBLOCK: opening a FIFO would block until a writer comes, before the check below.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NONBLOCK | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{}: not a regular file{not_regular_hint}",
            path.display()
        ));
    }
    Ok((file, metadata))
}

/// Reads an opened file to its end, refusing more than [`MAX_FILE_SIZE`]; `path` labels errors.
fn read_opened_file(file: File, path: &Path) -> Result<String, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_files_over_the_size_limit() {
        let path = std::env::temp_dir().join(format!("nyra-polkit-size-{}", std::process::id()));
        std::fs::write(&path, vec![b' '; MAX_FILE_SIZE as usize]).unwrap();
        assert!(read_config_file(&path).is_ok());
        std::fs::write(&path, vec![b' '; MAX_FILE_SIZE as usize + 1]).unwrap();
        let error = read_config_file(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(error.contains("larger than"), "{error}");
    }
}
