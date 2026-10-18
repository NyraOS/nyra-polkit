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
use std::time::Duration;
use zbus::fdo::DBusProxy;

/// How long a call to logind or to the bus may take; a check whose call times out is refused. Well
/// under the 25 s that D-Bus clients usually wait, so they get the refusal rather than their own
/// timeout. zbus has no timeout of its own: without this, a stuck logind would hold every check.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

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
        .map(|builder| builder.method_timeout(CALL_TIMEOUT))
        .map_err(|error| error.to_string())?
        .build()
        .await
        .map_err(|error| format!("system bus: {error}"))?;
    // Connections that leave end their checks and remove their agents. Watched before anyone can
    // call the authority, so no departure is missed.
    let mut departures = DBusProxy::new(&connection)
        .await
        .map_err(|error| error.to_string())?
        .receive_name_owner_changed()
        .await
        .map_err(|error| format!("NameOwnerChanged: {error}"))?
        .filter_map(|signal| {
            let args = signal.args().ok()?;
            let unique = args.name().as_str().starts_with(':');
            (unique && args.new_owner().is_none()).then(|| args.name().to_string())
        });
    connection
        .object_server()
        .at(AUTHORITY_PATH, authority)
        .await
        .map_err(|error| error.to_string())?;
    let authority = connection
        .object_server()
        .interface::<_, Authority>(AUTHORITY_PATH)
        .await
        .map_err(|error| error.to_string())?;
    // Read from now on, in a task of its own: zbus holds every message of the connection, replies
    // included, while a stream is full, so a stream read only later could stall the RequestName
    // below and everything after it.
    let departed = authority.clone();
    connection
        .executor()
        .spawn(
            async move {
                while let Some(name) = departures.next().await {
                    if departed.get().await.connection_left(&name) {
                        if let Err(error) = Authority::changed(departed.signal_emitter()).await {
                            eprintln!("<4>Changed signal: {error}");
                        }
                    }
                }
            },
            "departures",
        )
        .detach();
    connection
        .request_name(BUS_NAME)
        .await
        .map_err(|error| format!("system bus, {BUS_NAME}: {error}"))?;
    eprintln!("<6>serving {BUS_NAME}");

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
