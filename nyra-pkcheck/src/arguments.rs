// SPDX-License-Identifier: MIT
//! pkcheck's options, as pkcheck(1) documents them and Debian's pkcheck accepts them: long options
//! and their one-letter forms, each value in its own argument (no `--option=value`, no `--`), and
//! two values after `--detail`. Anything malformed is an error, which pkcheck reports with exit
//! code 126.
//!
//! Where Debian's pkcheck guesses, this one refuses: a `--process` value with anything but digits
//! in its fields, a second subject or action, a bus name that is not unique.

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    ListTemporary,
    RevokeTemporary,
    Check(Check),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Check {
    pub action_id: String,
    pub subject: Subject,
    pub details: HashMap<String, String>,
    pub allow_user_interaction: bool,
    pub enable_internal_agent: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Subject {
    /// `--process pid[,start-time[,uid]]`: what the caller knows about the process.
    Process {
        pid: u32,
        start_time: Option<u64>,
        uid: Option<u32>,
    },
    /// `--system-bus-name`: a unique name (`:1.42`).
    SystemBusName(String),
}

/// The options in the order given, without the program name. `--help` and `--version` win over
/// everything else, then `--list-temp`, then `--revoke-temp`, as with Debian's pkcheck; any
/// malformed option is an error even with them.
pub fn parse(arguments: Vec<String>) -> Result<Command, String> {
    let mut help = false;
    let mut version = false;
    let mut list_temporary = false;
    let mut revoke_temporary = false;
    let mut action_id = None;
    let mut subject = None;
    let mut details = HashMap::new();
    let mut allow_user_interaction = false;
    let mut enable_internal_agent = false;

    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => help = true,
            "--version" => version = true,
            "--list-temp" => list_temporary = true,
            "--revoke-temp" => revoke_temporary = true,
            "-u" | "--allow-user-interaction" => allow_user_interaction = true,
            "--enable-internal-agent" => enable_internal_agent = true,
            "-a" | "--action-id" => {
                let action = value(arguments.next(), "--action-id, -a")?;
                set_once(&mut action_id, action, "--action-id")?;
            }
            "-p" | "--process" => {
                let process = parse_process(&value(arguments.next(), "--process, -p")?)?;
                set_once(&mut subject, process, "--process or --system-bus-name")?;
            }
            "-s" | "--system-bus-name" => {
                let name = parse_bus_name(value(arguments.next(), "--system-bus-name, -s")?)?;
                set_once(&mut subject, name, "--process or --system-bus-name")?;
            }
            "-d" | "--detail" => {
                let (Some(key), Some(detail)) = (arguments.next(), arguments.next()) else {
                    return Err("Two arguments expected after `--detail, -d'".to_string());
                };
                details.insert(key, detail);
            }
            _ => return Err(format!("Unexpected argument `{argument}'")),
        }
    }

    if help {
        return Ok(Command::Help);
    }
    if version {
        return Ok(Command::Version);
    }
    if list_temporary {
        return Ok(Command::ListTemporary);
    }
    if revoke_temporary {
        return Ok(Command::RevokeTemporary);
    }
    let subject = subject.ok_or("Subject not specified")?;
    let action_id = action_id.ok_or("Action not specified")?;
    Ok(Command::Check(Check {
        action_id,
        subject,
        details,
        allow_user_interaction,
        enable_internal_agent,
    }))
}

fn value(argument: Option<String>, option: &str) -> Result<String, String> {
    argument.ok_or_else(|| format!("Argument expected after `{option}'"))
}

/// A second action or subject is refused: which one the caller meant cannot be known.
fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("Only one {option} may be given"));
    }
    *slot = Some(value);
    Ok(())
}

/// `pid`, `pid,start-time` or `pid,start-time,uid`, decimal. The PID and the start time are never
/// 0; the uid fits the `i` that the subject carries it in.
fn parse_process(text: &str) -> Result<Subject, String> {
    let invalid = || format!("Invalid --process value `{text}'");
    let fields: Vec<&str> = text.split(',').collect();
    if fields.len() > 3 {
        return Err(invalid());
    }
    let number = |field: &str| -> Result<u64, String> {
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        field.parse().map_err(|_| invalid())
    };
    // The PID and the uid travel as D-Bus `u` and `i`: both must fit an `i`.
    let small = |field: &str| -> Result<u32, String> {
        let value = number(field)?;
        u32::try_from(value)
            .ok()
            .filter(|value| *value <= i32::MAX as u32)
            .ok_or_else(invalid)
    };
    let pid = small(fields[0])?;
    if pid == 0 {
        return Err(invalid());
    }
    let start_time = match fields.get(1) {
        None => None,
        Some(field) => match number(field)? {
            0 => return Err(invalid()),
            start_time => Some(start_time),
        },
    };
    let uid = match fields.get(2) {
        None => None,
        Some(field) => Some(small(field)?),
    };
    Ok(Subject::Process {
        pid,
        start_time,
        uid,
    })
}

/// Only unique names: a well-known name can change owner between the check and its use.
fn parse_bus_name(name: String) -> Result<Subject, String> {
    // zbus also takes the bus's own name, org.freedesktop.DBus, as unique.
    if name.starts_with(':') && zbus::names::UniqueName::try_from(name.as_str()).is_ok() {
        Ok(Subject::SystemBusName(name))
    } else {
        Err(format!("Invalid --system-bus-name value `{name}'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(arguments: &[&str]) -> Result<Command, String> {
        parse(
            arguments
                .iter()
                .map(|argument| argument.to_string())
                .collect(),
        )
    }

    fn check(arguments: &[&str]) -> Check {
        match parse_args(arguments) {
            Ok(Command::Check(check)) => check,
            other => panic!("{arguments:?}: {other:?}"),
        }
    }

    fn process(pid: u32, start_time: Option<u64>, uid: Option<u32>) -> Subject {
        Subject::Process {
            pid,
            start_time,
            uid,
        }
    }

    #[test]
    fn a_check_with_every_option() {
        let parsed = check(&[
            "--action-id",
            "org.example.act",
            "--process",
            "42,4242,1000",
            "--allow-user-interaction",
            "--enable-internal-agent",
            "--detail",
            "remote",
            "flathub",
            "--detail",
            "ref",
            "app/x",
        ]);
        assert_eq!(
            parsed,
            Check {
                action_id: "org.example.act".to_string(),
                subject: process(42, Some(4242), Some(1000)),
                details: HashMap::from([
                    ("remote".to_string(), "flathub".to_string()),
                    ("ref".to_string(), "app/x".to_string()),
                ]),
                allow_user_interaction: true,
                enable_internal_agent: true,
            }
        );
    }

    #[test]
    fn the_short_forms_and_the_defaults() {
        let parsed = check(&["-a", "org.example.act", "-s", ":1.42", "-d", "k", "v", "-u"]);
        assert_eq!(parsed.action_id, "org.example.act");
        assert_eq!(parsed.subject, Subject::SystemBusName(":1.42".to_string()));
        assert_eq!(
            parsed.details,
            HashMap::from([("k".to_string(), "v".to_string())])
        );
        assert!(parsed.allow_user_interaction);
        assert!(!parsed.enable_internal_agent);

        let plain = check(&["-p", "42", "-a", "org.example.act"]);
        assert_eq!(plain.subject, process(42, None, None));
        assert!(plain.details.is_empty());
        assert!(!plain.allow_user_interaction);
        assert!(!plain.enable_internal_agent);
    }

    #[test]
    fn the_three_process_forms() {
        let subject = |value: &str| check(&["-a", "x", "--process", value]).subject;
        assert_eq!(subject("42"), process(42, None, None));
        assert_eq!(subject("42,4242"), process(42, Some(4242), None));
        assert_eq!(subject("42,4242,0"), process(42, Some(4242), Some(0)));
        assert_eq!(
            subject("2147483647,18446744073709551615,2147483647"),
            process(i32::MAX as u32, Some(u64::MAX), Some(i32::MAX as u32))
        );
    }

    #[test]
    fn malformed_process_values_are_refused() {
        for value in [
            "",
            "abc",
            "-5",
            "0",
            "1x",
            " 1",
            "+1",
            "1,",
            ",1",
            "1,,0",
            "1,x",
            "1,0",
            "1,0,0",
            "1,2,3,4",
            "1,2,-1",
            "1,2,x",
            "2147483648",
            "4294967297",
            "1,18446744073709551616",
            "1,2,2147483648",
        ] {
            assert_eq!(
                parse_args(&["-a", "x", "--process", value]),
                Err(format!("Invalid --process value `{value}'")),
                "{value:?}"
            );
        }
    }

    #[test]
    fn only_unique_bus_names() {
        for name in ["", "org.freedesktop.DBus", ":", ":1", "1.42", ":1..2"] {
            assert_eq!(
                parse_args(&["-a", "x", "--system-bus-name", name]),
                Err(format!("Invalid --system-bus-name value `{name}'")),
                "{name:?}"
            );
        }
        assert_eq!(
            check(&["-a", "x", "-s", ":1.0"]).subject,
            Subject::SystemBusName(":1.0".to_string())
        );
    }

    #[test]
    fn values_are_required() {
        for (option, named) in [
            ("--action-id", "--action-id, -a"),
            ("-a", "--action-id, -a"),
            ("--process", "--process, -p"),
            ("-p", "--process, -p"),
            ("--system-bus-name", "--system-bus-name, -s"),
            ("-s", "--system-bus-name, -s"),
        ] {
            assert_eq!(
                parse_args(&["-p", "1", "-a", "x", option]),
                Err(format!("Argument expected after `{named}'")),
                "{option}"
            );
        }
        for incomplete in [&["--detail"][..], &["--detail", "k"], &["-d", "k"]] {
            let mut arguments = vec!["-p", "1", "-a", "x"];
            arguments.extend_from_slice(incomplete);
            assert_eq!(
                parse_args(&arguments),
                Err("Two arguments expected after `--detail, -d'".to_string())
            );
        }
        // The next argument is the value, whatever it looks like.
        assert_eq!(
            check(&["-a", "--process", "-p", "1"]).action_id,
            "--process"
        );
        let details = check(&["-a", "x", "-p", "1", "-d", "-u", "-a"]).details;
        assert_eq!(
            details,
            HashMap::from([("-u".to_string(), "-a".to_string())])
        );
    }

    #[test]
    fn unknown_or_other_syntax_is_refused() {
        for argument in [
            "--bogus",
            "extra",
            "-v",
            "-au",
            "--",
            "--action-id=x",
            "--process=1",
            "--details",
            "-",
        ] {
            assert_eq!(
                parse_args(&["-a", "x", "-p", "1", argument]),
                Err(format!("Unexpected argument `{argument}'")),
                "{argument}"
            );
        }
        // Even next to --help and --version.
        assert!(parse_args(&["--help", "extra"]).is_err());
        assert!(parse_args(&["--version", "--bogus"]).is_err());
        assert!(parse_args(&["--list-temp", "extra"]).is_err());
    }

    #[test]
    fn a_subject_and_an_action_are_needed_once() {
        assert_eq!(parse_args(&[]), Err("Subject not specified".to_string()));
        assert_eq!(
            parse_args(&["-a", "x"]),
            Err("Subject not specified".to_string())
        );
        assert_eq!(
            parse_args(&["-p", "1"]),
            Err("Action not specified".to_string())
        );
        assert_eq!(
            parse_args(&["-a", "x", "-p", "1", "-p", "1"]),
            Err("Only one --process or --system-bus-name may be given".to_string())
        );
        assert_eq!(
            parse_args(&["-a", "x", "-p", "1", "-s", ":1.0"]),
            Err("Only one --process or --system-bus-name may be given".to_string())
        );
        assert_eq!(
            parse_args(&["-a", "x", "-a", "y", "-p", "1"]),
            Err("Only one --action-id may be given".to_string())
        );
        // Flags may repeat.
        assert!(check(&["-u", "-a", "x", "-u", "-p", "1"]).allow_user_interaction);
    }

    #[test]
    fn help_version_and_temporary_authorizations_come_first() {
        assert_eq!(parse_args(&["--help"]), Ok(Command::Help));
        assert_eq!(parse_args(&["-h"]), Ok(Command::Help));
        assert_eq!(parse_args(&["--version", "--help"]), Ok(Command::Help));
        assert_eq!(parse_args(&["--version"]), Ok(Command::Version));
        assert_eq!(
            parse_args(&["--list-temp", "--version"]),
            Ok(Command::Version)
        );
        assert_eq!(parse_args(&["--list-temp"]), Ok(Command::ListTemporary));
        assert_eq!(
            parse_args(&["--revoke-temp", "--list-temp"]),
            Ok(Command::ListTemporary)
        );
        assert_eq!(parse_args(&["--revoke-temp"]), Ok(Command::RevokeTemporary));
        assert_eq!(
            parse_args(&["-a", "x", "-p", "1", "--revoke-temp"]),
            Ok(Command::RevokeTemporary)
        );
        assert_eq!(
            parse_args(&["--list-temp", "-a", "x"]),
            Ok(Command::ListTemporary)
        );
    }
}
