// SPDX-License-Identifier: MIT
//! Action definitions: the standard polkit `.policy` XML files in `/usr/share/polkit-1/actions`,
//! read as polkit(8) documents them ("DECLARING ACTIONS").
//!
//! A file that cannot be read is skipped as a whole: its actions stay unknown, and an unknown action
//! is always denied (docs/DESIGN.md, "Decision").

use crate::{Authorization, is_valid_action_id, read_config_file};
use roxmltree::Node;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The directory polkit(8) installs action files in.
pub const ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";

/// Real files have a few thousand nodes; the limit stops a file with a huge number of elements
/// (entity bombs are stopped earlier: `parse_policy` refuses any entity declaration).
const MAX_XML_NODES: u32 = 200_000;

/// All known actions, by id.
pub type Actions = BTreeMap<String, Action>;

/// A text with its translations (`xml:lang`), such as an action's message.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Text {
    pub untranslated: String,
    /// The language tag as written in the file ("ro", "pt_BR") to the translated text.
    pub translations: BTreeMap<String, String>,
}

impl Text {
    /// The text for a POSIX locale such as `ro_RO.UTF-8`: the `ro_RO` translation, else the `ro`
    /// one, else the untranslated text.
    pub fn for_locale(&self, locale: &str) -> &str {
        let without_encoding = locale.split(['.', '@']).next().unwrap_or_default();
        let language = without_encoding.split('_').next().unwrap_or_default();
        [without_encoding, language]
            .iter()
            .find_map(|tag| self.translations.get(*tag))
            .unwrap_or(&self.untranslated)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    pub id: String,
    pub description: Text,
    pub message: Text,
    pub vendor: String,
    pub vendor_url: String,
    pub icon_name: String,
    /// The default outside a local session (remote or no session at all).
    pub allow_any: Authorization,
    /// The default in a local session that is not in the foreground.
    pub allow_inactive: Authorization,
    /// The default in the local session in the foreground.
    pub allow_active: Authorization,
    pub annotations: BTreeMap<String, String>,
}

/// Parses one `.policy` file. Unknown elements are ignored, as new polkit versions may add some;
/// a malformed action, an unknown default or an invalid value fails the whole file.
pub fn parse_policy(xml: &str) -> Result<Vec<Action>, String> {
    // roxmltree's limits still allow an entity to expand to ~150 MB from 4 MiB, and it does not
    // expose declarations, so look at the text. A match inside a comment refuses a harmless file,
    // which is the safe side; XML is case-sensitive, so no other spelling declares an entity.
    if xml.contains("<!ENTITY") {
        return Err("the file declares an XML entity".to_string());
    }
    // The files start with a <!DOCTYPE policyconfig ...>; roxmltree never loads the external DTD.
    let options = roxmltree::ParsingOptions {
        allow_dtd: true,
        nodes_limit: MAX_XML_NODES,
        ..roxmltree::ParsingOptions::default()
    };
    let document =
        roxmltree::Document::parse_with_options(xml, options).map_err(|error| error.to_string())?;
    let root = document.root_element();
    if root.tag_name().name() != "policyconfig" {
        return Err("the root element is not <policyconfig>".to_string());
    }

    let mut vendor = String::new();
    let mut vendor_url = String::new();
    let mut icon_name = String::new();
    let mut actions = Vec::new();
    for element in root.children().filter(Node::is_element) {
        match element.tag_name().name() {
            "vendor" => vendor = text_of(element),
            "vendor_url" => vendor_url = text_of(element),
            "icon_name" => icon_name = text_of(element),
            "action" => actions.push(parse_action(element)?),
            _ => {}
        }
    }
    // The file-wide vendor and icon apply to the actions that do not set their own.
    for action in &mut actions {
        if action.vendor.is_empty() {
            action.vendor.clone_from(&vendor);
        }
        if action.vendor_url.is_empty() {
            action.vendor_url.clone_from(&vendor_url);
        }
        if action.icon_name.is_empty() {
            action.icon_name.clone_from(&icon_name);
        }
    }
    Ok(actions)
}

fn parse_action(element: Node) -> Result<Action, String> {
    let id = element
        .attribute("id")
        .ok_or("an <action> has no id attribute")?;
    if !is_valid_action_id(id) {
        return Err(format!("invalid action id {id:?}"));
    }
    // A default the file does not set is "no": a missing line must never grant anything.
    let mut action = Action {
        id: id.to_string(),
        description: Text::default(),
        message: Text::default(),
        vendor: String::new(),
        vendor_url: String::new(),
        icon_name: String::new(),
        allow_any: Authorization::No,
        allow_inactive: Authorization::No,
        allow_active: Authorization::No,
        annotations: BTreeMap::new(),
    };
    for child in element.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "description" => add_text(&mut action.description, child),
            "message" => add_text(&mut action.message, child),
            "vendor" => action.vendor = text_of(child),
            "vendor_url" => action.vendor_url = text_of(child),
            "icon_name" => action.icon_name = text_of(child),
            "defaults" => {
                for default in child.children().filter(Node::is_element) {
                    let text = text_of(default);
                    let value = Authorization::parse(&text)
                        .ok_or_else(|| format!("action {id}: invalid default {text:?}"))?;
                    match default.tag_name().name() {
                        "allow_any" => action.allow_any = value,
                        "allow_inactive" => action.allow_inactive = value,
                        "allow_active" => action.allow_active = value,
                        other => return Err(format!("action {id}: unknown default <{other}>")),
                    }
                }
            }
            "annotate" => {
                let key = child
                    .attribute("key")
                    .ok_or_else(|| format!("action {id}: <annotate> has no key"))?;
                action.annotations.insert(key.to_string(), text_of(child));
            }
            _ => {}
        }
    }
    Ok(action)
}

fn text_of(element: Node) -> String {
    element.text().unwrap_or_default().trim().to_string()
}

/// Adds a `<description>` or `<message>`: untranslated, or a translation when it has `xml:lang`.
fn add_text(text: &mut Text, element: Node) {
    match element.attribute((roxmltree::NS_XML_URI, "lang")) {
        Some(language) if !language.is_empty() => {
            text.translations
                .insert(language.to_string(), text_of(element));
        }
        _ => text.untranslated = text_of(element),
    }
}

/// Loads every `*.policy` file of a directory. Returns the actions and the problems to log: a file
/// that fails is skipped, and an action id defined in two files is dropped, so it is denied (which
/// definition is right cannot be known).
pub fn load_actions(directory: &Path) -> (Actions, Vec<String>) {
    let mut actions = Actions::new();
    let mut problems = Vec::new();
    let mut paths: Vec<_> = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "policy")
            })
            .collect(),
        Err(error) => {
            problems.push(format!("{}: {error}", directory.display()));
            return (actions, problems);
        }
    };
    paths.sort();
    let mut defined_twice = BTreeSet::new();
    for path in paths {
        let parsed = read_config_file(&path).and_then(|xml| {
            parse_policy(&xml).map_err(|error| format!("{}: {error}", path.display()))
        });
        match parsed {
            Ok(file_actions) => {
                for action in file_actions {
                    if actions.contains_key(&action.id) || defined_twice.contains(&action.id) {
                        problems.push(format!(
                            "{}: action {} is defined more than once; it stays unknown (denied)",
                            path.display(),
                            action.id
                        ));
                        actions.remove(&action.id);
                        defined_twice.insert(action.id);
                    } else {
                        actions.insert(action.id.clone(), action);
                    }
                }
            }
            Err(error) => problems.push(format!("{error}; its actions stay unknown (denied)")),
        }
    }
    (actions, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Example</vendor>
  <vendor_url>https://example.org</vendor_url>
  <action id="org.example.disk.mount">
    <description>Mount a disk</description>
    <description xml:lang="ro">Montează un disc</description>
    <message>Authentication is required to mount the disk</message>
    <message xml:lang="pt_BR">A autenticação é necessária</message>
    <icon_name>drive-harddisk</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin_keep</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.imply">org.example.disk.check</annotate>
  </action>
  <action id="org.example.disk.check">
    <vendor>Other vendor</vendor>
    <defaults>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
"#;

    #[test]
    fn reads_actions_texts_defaults_and_vendor() {
        let actions = parse_policy(POLICY).unwrap();
        assert_eq!(actions.len(), 2);
        let mount = &actions[0];
        assert_eq!(mount.id, "org.example.disk.mount");
        assert_eq!(mount.description.for_locale("C"), "Mount a disk");
        assert_eq!(
            mount.description.for_locale("ro_RO.UTF-8"),
            "Montează un disc"
        );
        assert_eq!(
            mount.message.for_locale("pt_BR"),
            "A autenticação é necessária"
        );
        assert_eq!(
            mount.message.for_locale("pt_PT.UTF-8"),
            "Authentication is required to mount the disk"
        );
        assert_eq!(mount.icon_name, "drive-harddisk");
        assert_eq!(mount.vendor, "Example");
        assert_eq!(mount.vendor_url, "https://example.org");
        assert_eq!(
            (mount.allow_any, mount.allow_inactive, mount.allow_active),
            (
                Authorization::AuthAdmin,
                Authorization::AuthAdminKeep,
                Authorization::Yes
            )
        );
        assert_eq!(
            mount.annotations["org.freedesktop.policykit.imply"],
            "org.example.disk.check"
        );
    }

    #[test]
    fn missing_defaults_are_no_and_own_vendor_wins() {
        let check = &parse_policy(POLICY).unwrap()[1];
        assert_eq!(check.vendor, "Other vendor");
        assert_eq!(check.allow_any, Authorization::No);
        assert_eq!(check.allow_inactive, Authorization::No);
        assert_eq!(check.allow_active, Authorization::AuthSelf);
    }

    #[test]
    fn refuses_malformed_files() {
        let cases = [
            ("<other/>", "root element"),
            ("<policyconfig><action/></policyconfig>", "no id"),
            (
                r#"<policyconfig><action id="org.ex ample"/></policyconfig>"#,
                "invalid action id",
            ),
            (
                r#"<policyconfig><action id="a"><defaults><allow_active>maybe</allow_active></defaults></action></policyconfig>"#,
                "invalid default",
            ),
            (
                r#"<policyconfig><action id="a"><defaults><allow_all>yes</allow_all></defaults></action></policyconfig>"#,
                "unknown default",
            ),
            (
                r#"<policyconfig><action id="a"><annotate>x</annotate></action></policyconfig>"#,
                "no key",
            ),
            ("<policyconfig>", "never closed"),
        ];
        for (xml, expected) in cases {
            let error = parse_policy(xml).unwrap_err();
            assert!(error.contains(expected), "{xml}: {error}");
        }
    }

    #[test]
    fn stops_huge_element_counts() {
        let xml = format!("<policyconfig>{}</policyconfig>", "<x/>".repeat(250_000));
        let error = parse_policy(&xml).unwrap_err();
        assert!(error.contains("nodes limit reached"), "{error}");
    }

    #[test]
    fn accepts_the_usual_doctype_and_refuses_entities() {
        assert!(parse_policy(POLICY).is_ok());
        let entity = r#"<!DOCTYPE policyconfig [<!ENTITY v "Example">]>
<policyconfig><vendor>&v;</vendor></policyconfig>"#;
        let error = parse_policy(entity).unwrap_err();
        assert!(error.contains("entity"), "{error}");
        let parameter_entity = r#"<!DOCTYPE policyconfig [<!ENTITY % p "x">]><policyconfig/>"#;
        assert!(parse_policy(parameter_entity).is_err());
    }

    #[test]
    fn stops_entity_bombs() {
        let mut xml = String::from("<!DOCTYPE policyconfig [<!ENTITY a0 \"x\">");
        for level in 1..12 {
            let previous = format!("&a{};", level - 1);
            xml.push_str(&format!("<!ENTITY a{level} \"{}\">", previous.repeat(10)));
        }
        xml.push_str("]><policyconfig><vendor>&a11;</vendor></policyconfig>");
        let error = parse_policy(&xml).unwrap_err();
        assert!(error.contains("entity"), "{error}");
    }

    #[test]
    fn loads_a_directory_skipping_bad_files_and_duplicates() {
        let directory = crate::unique_temp_dir("actions");
        std::fs::write(directory.join("a.policy"), POLICY).unwrap();
        let other = r#"<policyconfig><action id="org.example.other"/></policyconfig>"#;
        std::fs::write(directory.join("b.policy"), other).unwrap();
        // Defines org.example.disk.mount a second time.
        let again = r#"<policyconfig><action id="org.example.disk.mount"/></policyconfig>"#;
        std::fs::write(directory.join("c.policy"), again).unwrap();
        // And a third time: still unknown, not defined again.
        std::fs::write(directory.join("c2.policy"), again).unwrap();
        std::fs::write(directory.join("d.policy"), "<policyconfig>").unwrap();
        std::fs::write(directory.join("e.txt"), "ignored").unwrap();
        let (actions, problems) = load_actions(&directory);
        std::fs::remove_dir_all(&directory).unwrap();
        let ids: Vec<_> = actions.keys().collect();
        assert_eq!(ids, ["org.example.disk.check", "org.example.other"]);
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[0].contains("c.policy") && problems[0].contains("more than once"));
        assert!(problems[1].contains("c2.policy") && problems[1].contains("more than once"));
        assert!(problems[2].contains("d.policy") && problems[2].contains("denied"));
    }

    #[test]
    fn a_fifo_is_refused_instead_of_blocking() {
        let directory = crate::unique_temp_dir("actions-fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            directory.join("a.policy"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        // Run on another thread: a regression would block forever instead of failing.
        let (sender, receiver) = std::sync::mpsc::channel();
        let path = directory.clone();
        std::thread::spawn(move || {
            let _ = sender.send(load_actions(&path));
        });
        let result = receiver.recv_timeout(std::time::Duration::from_secs(10));
        std::fs::remove_dir_all(&directory).unwrap();
        let (actions, problems) = result.expect("opening a FIFO blocked");
        assert!(actions.is_empty());
        assert!(problems[0].contains("not a regular file"), "{problems:?}");
    }
}
