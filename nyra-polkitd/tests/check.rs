// SPDX-License-Identifier: MIT
//! `nyra-polkitd --check` and `--help` as run from a shell. They never touch the bus, so these run
//! anywhere. The ownership checks need files owned by root, so the rule sets are tested in
//! `authority.rs`; here a missing rules directory (no rules, valid) and a broken action file.

use std::process::Command;

fn daemon(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nyra-polkitd"))
        .args(arguments)
        .output()
        .unwrap()
}

/// A new, empty directory with a random suffix; `create_dir` fails if the path already exists.
fn unique_temp_dir(name: &str) -> std::path::PathBuf {
    let mut random = [0u8; 8];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
    let path = std::env::temp_dir().join(format!(
        "nyra-polkit-{name}-{:016x}",
        u64::from_le_bytes(random)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[test]
fn help_mentions_check() {
    let output = daemon(&["--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--check"));
}

#[test]
fn check_exits_0_for_valid_files_and_1_for_a_broken_one() {
    let root = unique_temp_dir("check-bin");
    let actions = root.join("actions");
    std::fs::create_dir(&actions).unwrap();
    let missing = root.join("missing");
    let arguments = |actions: &std::path::Path| {
        [
            "--check".to_string(),
            "--actions-dir".to_string(),
            actions.display().to_string(),
            "--image-rules-dir".to_string(),
            missing.display().to_string(),
            "--local-rules-dir".to_string(),
            missing.display().to_string(),
        ]
    };
    let run = |actions: &std::path::Path| {
        let arguments = arguments(actions);
        daemon(&arguments.iter().map(String::as_str).collect::<Vec<_>>())
    };

    let valid = run(&actions);
    assert_eq!(valid.status.code(), Some(0), "{valid:?}");
    assert!(String::from_utf8_lossy(&valid.stdout).contains("are valid"));

    std::fs::write(actions.join("broken.policy"), "<policyconfig>").unwrap();
    let invalid = run(&actions);
    assert_eq!(invalid.status.code(), Some(1), "{invalid:?}");
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("error: "));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("broken.policy"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_option_value_that_looks_like_an_option_is_refused() {
    for option in ["--actions-dir", "--image-rules-dir", "--local-rules-dir"] {
        let output = daemon(&[option, "--check"]);
        assert_eq!(output.status.code(), Some(2), "{option}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(option) && stderr.contains("--check"),
            "{stderr}"
        );
    }
}
