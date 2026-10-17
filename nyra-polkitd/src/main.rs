// SPDX-License-Identifier: MIT
//! nyra-polkitd: owns `org.freedesktop.PolicyKit1` on the system bus and answers authorization
//! checks (docs/DESIGN.md). SIGHUP (`systemctl reload`) rereads the action files and the rules.
//!
//! The options only move the directories, for tests; the service uses the standard ones.

use futures_lite::StreamExt;
use nyra_polkitd::actions::ACTIONS_DIR;
use nyra_polkitd::authority::{AUTHORITY_PATH, Authority, BUS_NAME, Directories, load_policy};
use nyra_polkitd::rules::{IMAGE_RULES_DIR, LOCAL_RULES_DIR};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str =
    "usage: nyra-polkitd [--actions-dir DIR] [--image-rules-dir DIR] [--local-rules-dir DIR]";

fn main() -> ExitCode {
    let directories = match parse_arguments(std::env::args().skip(1)) {
        Ok(directories) => directories,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match futures_lite::future::block_on(serve(directories)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("<3>{error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_arguments(mut arguments: impl Iterator<Item = String>) -> Result<Directories, String> {
    let mut directories = Directories {
        actions: PathBuf::from(ACTIONS_DIR),
        image_rules: PathBuf::from(IMAGE_RULES_DIR),
        local_rules: PathBuf::from(LOCAL_RULES_DIR),
    };
    while let Some(option) = arguments.next() {
        let directory = match option.as_str() {
            "--actions-dir" => &mut directories.actions,
            "--image-rules-dir" => &mut directories.image_rules,
            "--local-rules-dir" => &mut directories.local_rules,
            _ => return Err(format!("unknown option {option:?}")),
        };
        *directory = arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| format!("{option} needs a directory"))?;
    }
    Ok(directories)
}

async fn serve(directories: Directories) -> Result<(), String> {
    // Before taking the bus name: from then on, a reload may come at any time, and SIGHUP's
    // default action would end the daemon.
    let mut hangups = async_signal::Signals::new([async_signal::Signal::Hup])
        .map_err(|error| format!("SIGHUP: {error}"))?;

    // Broken rules do not stop the daemon: it keeps the name and denies every check until a
    // reload reads valid rules, so clients get an answer, never a missing service.
    let authority = Authority::new(load_policy(&directories));
    let connection = zbus::connection::Builder::system()
        .and_then(|builder| builder.serve_at(AUTHORITY_PATH, authority))
        .and_then(|builder| builder.name(BUS_NAME))
        .map_err(|error| error.to_string())?
        .build()
        .await
        .map_err(|error| format!("system bus, {BUS_NAME}: {error}"))?;
    eprintln!("<6>serving {BUS_NAME}");

    let authority = connection
        .object_server()
        .interface::<_, Authority>(AUTHORITY_PATH)
        .await
        .map_err(|error| error.to_string())?;
    while hangups.next().await.is_some() {
        eprintln!("<6>reloading the action files and the rules");
        authority
            .get()
            .await
            .replace_policy(load_policy(&directories));
        if let Err(error) = Authority::changed(authority.signal_emitter()).await {
            eprintln!("<4>Changed signal: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Directories, String> {
        parse_arguments(arguments.iter().map(|argument| argument.to_string()))
    }

    #[test]
    fn the_standard_directories_unless_moved() {
        let standard = parse(&[]).unwrap();
        assert_eq!(standard.actions, PathBuf::from(ACTIONS_DIR));
        assert_eq!(standard.image_rules, PathBuf::from(IMAGE_RULES_DIR));
        assert_eq!(standard.local_rules, PathBuf::from(LOCAL_RULES_DIR));

        let moved = parse(&["--local-rules-dir", "/t/l", "--actions-dir", "/t/a"]).unwrap();
        assert_eq!(moved.actions, PathBuf::from("/t/a"));
        assert_eq!(moved.image_rules, PathBuf::from(IMAGE_RULES_DIR));
        assert_eq!(moved.local_rules, PathBuf::from("/t/l"));

        assert!(parse(&["--actions-dir"]).is_err());
        assert!(parse(&["--rules", "/x"]).is_err());
    }
}
