// SPDX-License-Identifier: MIT
//! pkcheck alone: needs no root, no daemon and no bus.

use std::process::Command;

#[test]
fn an_unreachable_system_bus_is_an_error_127() {
    let output = Command::new(env!("CARGO_BIN_EXE_pkcheck"))
        .args(["--action-id", "org.example.act", "--process", "1"])
        .env("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent")
        .output()
        .expect("pkcheck");
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("Error getting authority: "), "{stderr}");
    assert!(output.stdout.is_empty(), "{output:?}");
}
