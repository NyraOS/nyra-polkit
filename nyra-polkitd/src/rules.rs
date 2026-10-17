// SPDX-License-Identifier: MIT
//! The TOML rules (docs/DESIGN.md, "Rules"): the image's in [`IMAGE_RULES_DIR`], the
//! administrator's in [`LOCAL_RULES_DIR`]. A file in `/etc` replaces the image file with the same
//! name; one without rules switches it off.
//!
//! Any error in any rule file fails the whole load: the daemon then denies everything until it is
//! fixed, because skipping a broken file could drop a rule that denies something. A file or
//! directory that anyone but root could have written is such an error, as for sudoers.

use crate::{Authorization, is_valid_action_id, read_opened_file};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The rules that come with the image (read-only, verified with it).
pub const IMAGE_RULES_DIR: &str = "/usr/share/nyra-polkit/rules.d";
/// The administrator's own rules.
pub const LOCAL_RULES_DIR: &str = "/etc/nyra-polkit/rules.d";

/// One rule file. Unknown keys are errors everywhere: a misspelt condition must not silently turn
/// into a rule that matches everyone.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    administrators: Option<Administrators>,
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

/// Who authenticates for `auth_admin`, and who `administrator = true` matches.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Administrators {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Action ids; `org.example.*` matches every id that starts with `org.example.`, `*` all of them.
    pub actions: Vec<String>,
    /// The subject's user is one of these, or a member of one of `groups`; both empty: anyone.
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    /// Only for administrators.
    #[serde(default)]
    pub administrator: bool,
    /// Only for subjects in a local session (`local`), or in the local session in the foreground
    /// (`active`).
    pub session: Option<SessionCondition>,
    /// Only when the service passed each of these details with one of the listed values.
    #[serde(default)]
    pub details: BTreeMap<String, Vec<String>>,
    pub result: Authorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCondition {
    Local,
    Active,
}

/// All the rules in force.
#[derive(Debug, Clone, PartialEq)]
pub struct Rules {
    pub administrators: Administrators,
    pub rules: Vec<Rule>,
}

/// Parses one rule file; `name` only labels the errors.
fn parse_rule_file(name: &str, text: &str) -> Result<RuleFile, String> {
    let file: RuleFile = toml::from_str(text).map_err(|error| format!("{name}: {error}"))?;
    for (index, rule) in file.rules.iter().enumerate() {
        check_rule(rule).map_err(|error| format!("{name}: rule {}: {error}", index + 1))?;
    }
    if let Some(administrators) = &file.administrators {
        if administrators
            .users
            .iter()
            .chain(&administrators.groups)
            .any(String::is_empty)
        {
            return Err(format!("{name}: administrators: an empty name"));
        }
    }
    Ok(file)
}

/// What serde cannot check: every list means something and every name is well formed.
fn check_rule(rule: &Rule) -> Result<(), String> {
    if rule.actions.is_empty() {
        return Err("actions is empty".to_string());
    }
    // A rule for every action that grants anything would loosen each action whose default is
    // "no", including those installed later.
    if rule.actions.iter().any(|pattern| pattern == "*") && rule.result != Authorization::No {
        return Err("actions = [\"*\"] is only allowed with result = \"no\"".to_string());
    }
    for pattern in &rule.actions {
        let id = pattern.strip_suffix(".*").unwrap_or(pattern);
        if pattern != "*" && !is_valid_action_id(id) {
            return Err(format!(
                "invalid action {pattern:?} (an action id, a prefix ending in \".*\", or \"*\")"
            ));
        }
    }
    if rule.users.iter().chain(&rule.groups).any(String::is_empty) {
        return Err("an empty user or group name".to_string());
    }
    for (key, values) in &rule.details {
        if key.is_empty() || values.is_empty() {
            return Err(format!(
                "details: {key:?} needs a name and at least one value"
            ));
        }
    }
    Ok(())
}

/// Loads the rules: every `*.toml` of both directories, a file in `local` replacing the file with
/// the same name in `image`. A missing directory has no rules. The administrators of all files add
/// up; without any, the administrator is root. Returns the rules and what to log about the files.
pub fn load_rules(image: &Path, local: &Path) -> Result<(Rules, Vec<String>), String> {
    load_rules_owned_by(image, local, 0)
}

/// [`load_rules`], with the owner the directories and files must have: root (0), except in the
/// tests, which cannot create files owned by root.
fn load_rules_owned_by(
    image: &Path,
    local: &Path,
    owner: u32,
) -> Result<(Rules, Vec<String>), String> {
    let mut files: BTreeMap<String, PathBuf> = rule_files(image, owner)?.into_iter().collect();
    let mut replaced: BTreeMap<String, PathBuf> = BTreeMap::new();
    for (name, path) in rule_files(local, owner)? {
        if let Some(image_path) = files.insert(name.clone(), path) {
            replaced.insert(name, image_path);
        }
    }

    let mut parsed = Vec::new();
    let mut notes = Vec::new();
    for (name, path) in &files {
        let text = read_trusted_file(path, owner)?;
        let file = parse_rule_file(&path.display().to_string(), &text)?;
        let empty = file.rules.is_empty() && file.administrators.is_none();
        notes.push(match replaced.get(name) {
            Some(image_path) if empty => {
                format!("{} disables {}", path.display(), image_path.display())
            }
            Some(image_path) => format!("{} replaces {}", path.display(), image_path.display()),
            None => format!("read {}", path.display()),
        });
        parsed.push(file);
    }
    Ok((combine(parsed), notes))
}

fn combine(files: Vec<RuleFile>) -> Rules {
    let mut administrators = Administrators::default();
    let mut rules = Vec::new();
    for file in files {
        if let Some(more) = file.administrators {
            administrators.users.extend(more.users);
            administrators.groups.extend(more.groups);
        }
        rules.extend(file.rules);
    }
    if administrators.users.is_empty() && administrators.groups.is_empty() {
        administrators.users.push("root".to_string());
    }
    Rules {
        administrators,
        rules,
    }
}

/// The rules of a single file's text, for the tests of the decision.
#[cfg(test)]
pub(crate) fn rules_from_text(text: &str) -> Rules {
    combine(vec![parse_rule_file("test", text).unwrap()])
}

/// The `*.toml` files of a directory, by file name, once the directory itself is trusted.
fn rule_files(directory: &Path, owner: u32) -> Result<Vec<(String, PathBuf)>, String> {
    let metadata = match std::fs::metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", directory.display())),
    };
    if !metadata.is_dir() {
        return Err(format!("{}: not a directory", directory.display()));
    }
    check_owner_and_mode(&metadata, directory, owner)?;

    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".toml") {
            files.push((name, entry.path()));
        }
    }
    Ok(files)
}

/// Opens a rule file and checks what was opened (fstat), so a symbolic link is judged by its
/// target and the file cannot be swapped between the check and the read.
fn read_trusted_file(path: &Path, owner: u32) -> Result<String, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    check_owner_and_mode(&metadata, path, owner)?;
    read_opened_file(file, path)
}

fn check_owner_and_mode(metadata: &Metadata, path: &Path, owner: u32) -> Result<(), String> {
    if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{}: must be owned by root and not writable by group or others",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_rule_with_all_conditions() {
        let file = parse_rule_file(
            "test",
            r#"
            administrators = { groups = ["sudo"] }

            [[rule]]
            actions = ["org.example.install", "org.example.admin.*"]
            users = ["alice"]
            groups = ["staff"]
            administrator = true
            session = "active"
            details = { remote = ["flathub"] }
            result = "auth_admin_keep"
            "#,
        )
        .unwrap();
        assert_eq!(file.administrators.unwrap().groups, ["sudo"]);
        let rule = &file.rules[0];
        assert_eq!(rule.actions, ["org.example.install", "org.example.admin.*"]);
        assert_eq!(rule.users, ["alice"]);
        assert_eq!(rule.groups, ["staff"]);
        assert!(rule.administrator);
        assert_eq!(rule.session, Some(SessionCondition::Active));
        assert_eq!(rule.details["remote"], ["flathub"]);
        assert_eq!(rule.result, Authorization::AuthAdminKeep);
    }

    #[test]
    fn refuses_mistakes() {
        let cases = [
            (
                "[[rule]]\nactions = [\"a\"]\nresult = \"maybe\"",
                "unknown result",
            ),
            (
                "[[rule]]\nactions = [\"a\"]\nsesion = \"active\"\nresult = \"yes\"",
                "unknown field",
            ),
            (
                "[[rule]]\nactions = [\"a\"]\nsession = \"remote\"\nresult = \"yes\"",
                "unknown variant",
            ),
            ("[[rule]]\nactions = [\"a\"]", "missing field `result`"),
            (
                "[[rule]]\nactions = []\nresult = \"yes\"",
                "actions is empty",
            ),
            (
                "[[rule]]\nactions = [\"org.*.x\"]\nresult = \"yes\"",
                "invalid action",
            ),
            (
                "[[rule]]\nactions = [\"org.ex*\"]\nresult = \"yes\"",
                "invalid action",
            ),
            (
                "[[rule]]\nactions = [\"a\"]\nusers = [\"\"]\nresult = \"yes\"",
                "empty user",
            ),
            (
                "[[rule]]\nactions = [\"a\"]\ndetails = { remote = [] }\nresult = \"yes\"",
                "at least one value",
            ),
            (
                "[[rule]]\nactions = [\"*\"]\nresult = \"auth_admin\"",
                "only allowed with result = \"no\"",
            ),
            ("administrators = { group = [\"sudo\"] }", "unknown field"),
            ("administrators = { groups = [\"\"] }", "empty name"),
            (
                "[rule]\nactions = [\"a\"]\nresult = \"yes\"",
                "invalid type",
            ),
        ];
        for (text, expected) in cases {
            let error = parse_rule_file("test", text).unwrap_err();
            assert!(error.contains(expected), "{text}: {error}");
        }
    }

    /// Every TOML example in the design document is a valid rule file.
    #[test]
    fn design_examples_parse() {
        let design = include_str!("../../docs/DESIGN.md");
        let examples: Vec<&str> = design
            .split("```toml\n")
            .skip(1)
            .map(|block| block.split("```").next().unwrap())
            .collect();
        assert!(examples.len() >= 4);
        for example in examples {
            if let Err(error) = parse_rule_file("DESIGN.md", example) {
                panic!("{error}\n{example}");
            }
        }
    }

    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A new, empty directory, and the uid that owns it (the user running the tests), which stands
    /// for root here.
    fn temporary_directory(name: &str) -> (PathBuf, u32) {
        let directory =
            std::env::temp_dir().join(format!("nyra-polkit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let owner = std::fs::metadata(&directory).unwrap().uid();
        (directory, owner)
    }

    fn write(path: PathBuf, text: &str) {
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn local_files_replace_image_files_and_administrators_add_up() {
        let (image, owner) = temporary_directory("image");
        let (local, _) = temporary_directory("local");
        let deny = "[[rule]]\nactions = [\"a\"]\nresult = \"no\"\n";
        write(image.join("50-a.toml"), deny);
        write(
            image.join("60-b.toml"),
            "administrators = { groups = [\"sudo\"] }\n",
        );
        write(image.join("70-c.toml"), deny);
        write(image.join("README"), "not a rule file");
        write(
            local.join("50-a.toml"),
            "[[rule]]\nactions = [\"b\"]\nresult = \"yes\"\n",
        );
        write(local.join("70-c.toml"), "# switched off\n");
        write(
            local.join("80-d.toml"),
            "administrators = { users = [\"alice\"] }\n",
        );

        let (rules, notes) = load_rules_owned_by(&image, &local, owner).unwrap();
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].actions, ["b"]);
        assert_eq!(rules.administrators.groups, ["sudo"]);
        assert_eq!(rules.administrators.users, ["alice"]);
        let expected = [
            format!(
                "{} replaces {}",
                local.join("50-a.toml").display(),
                image.join("50-a.toml").display()
            ),
            format!("read {}", image.join("60-b.toml").display()),
            format!(
                "{} disables {}",
                local.join("70-c.toml").display(),
                image.join("70-c.toml").display()
            ),
            format!("read {}", local.join("80-d.toml").display()),
        ];
        assert_eq!(notes, expected);

        write(local.join("90-broken.toml"), "[[rule]]\n");
        let error = load_rules_owned_by(&image, &local, owner).unwrap_err();
        assert!(error.contains("90-broken.toml"), "{error}");

        std::fs::remove_dir_all(&image).unwrap();
        std::fs::remove_dir_all(&local).unwrap();
    }

    #[test]
    fn refuses_files_and_directories_others_could_write() {
        let (directory, owner) = temporary_directory("trust");
        let missing = directory.join("none");
        let file = directory.join("50-a.toml");
        write(
            file.clone(),
            "[[rule]]\nactions = [\"a\"]\nresult = \"no\"\n",
        );
        assert!(load_rules_owned_by(&directory, &missing, owner).is_ok());

        // Not owned by the expected owner (root, outside the tests).
        let error = load_rules_owned_by(&directory, &missing, owner + 1).unwrap_err();
        assert!(error.contains("must be owned by root"), "{error}");

        for mode in [0o664, 0o646] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = load_rules_owned_by(&directory, &missing, owner).unwrap_err();
            assert!(
                error.contains("50-a.toml") && error.contains("not writable"),
                "{error}"
            );
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o775)).unwrap();
        let error = load_rules_owned_by(&directory, &missing, owner).unwrap_err();
        assert!(
            !error.contains("50-a.toml") && error.contains("not writable"),
            "{error}"
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn links_are_judged_by_their_target() {
        let (directory, owner) = temporary_directory("links");
        let (target, _) = temporary_directory("links-target");
        let missing = directory.join("none");
        write(
            target.join("rules"),
            "[[rule]]\nactions = [\"a\"]\nresult = \"no\"\n",
        );
        symlink(target.join("rules"), directory.join("50-a.toml")).unwrap();
        let (rules, _) = load_rules_owned_by(&directory, &missing, owner).unwrap();
        assert_eq!(rules.rules.len(), 1);

        std::fs::set_permissions(target.join("rules"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(load_rules_owned_by(&directory, &missing, owner).is_err());

        // A link to something that is not a regular file, such as a directory or /dev/null.
        std::fs::remove_file(directory.join("50-a.toml")).unwrap();
        symlink(&target, directory.join("50-a.toml")).unwrap();
        let error = load_rules_owned_by(&directory, &missing, owner).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");

        std::fs::remove_dir_all(&directory).unwrap();
        std::fs::remove_dir_all(&target).unwrap();
    }

    #[test]
    fn no_files_means_root_is_the_administrator() {
        let missing = std::env::temp_dir().join("nyra-polkit-does-not-exist");
        let (rules, notes) = load_rules(&missing, &missing).unwrap();
        assert!(rules.rules.is_empty() && notes.is_empty());
        assert_eq!(rules.administrators.users, ["root"]);
        assert!(rules.administrators.groups.is_empty());
    }
}
