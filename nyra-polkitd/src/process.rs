// SPDX-License-Identifier: MIT
//! A process pinned by a pidfd (pidfd_open(2)), and what the daemon reads about it from `/proc`
//! (proc(5)).
//!
//! While the pidfd is open and the process has not exited, its PID cannot be given to another
//! process. So everything is read first and [`Process::ensure_alive`] is checked last: if the
//! process is still alive then, what was read is about the right process (docs/DESIGN.md,
//! "Subjects", "No PID race").

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

pub struct Process {
    pidfd: OwnedFd,
    pid: u32,
}

impl Process {
    /// Pins the process with this PID.
    pub fn open(pid: u32) -> Result<Self, String> {
        let raw = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| format!("invalid PID {pid}"))?;
        let pidfd = pidfd_open(raw, PidfdFlags::empty())
            .map_err(|error| format!("process {pid}: {error}"))?;
        Ok(Self { pidfd, pid })
    }

    /// The process a pidfd from someone else (the bus, a client) refers to. Its PID comes from the
    /// pidfd's `fdinfo`; a file descriptor that is not a pidfd has no `Pid:` line there.
    pub fn from_pidfd(pidfd: OwnedFd) -> Result<Self, String> {
        let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
        let fdinfo = std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
        // -1: the process has exited; 0: it is in a PID namespace we cannot see into.
        let pid = parse_fdinfo_pid(&fdinfo)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("not a pidfd of a running process we can see")?;
        Ok(Self { pidfd, pid })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The pidfd, for a client that passes the pinned process on (pkcheck sends it in its subject).
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// When the process started, in clock ticks since boot (field 22 of `/proc/<pid>/stat`): with
    /// the PID, what identifies a process for clients that cannot send a pidfd.
    pub fn start_time(&self) -> Result<u64, String> {
        parse_start_time(&self.read("stat")?).ok_or_else(|| self.malformed("stat"))
    }

    /// The real user id, not the effective one (`Uid:` in `/proc/<pid>/status`).
    pub fn real_uid(&self) -> Result<u32, String> {
        parse_real_uid(&self.read("status")?).ok_or_else(|| self.malformed("status"))
    }

    /// The content of `/proc/<pid>/cgroup`.
    pub fn cgroup(&self) -> Result<String, String> {
        self.read("cgroup")
    }

    /// Fails when the process has exited (its pidfd is then readable): what was read about this
    /// PID may be about another process.
    pub fn ensure_alive(&self) -> Result<(), String> {
        let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
        let no_wait = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        match poll(&mut fds, Some(&no_wait)) {
            Ok(0) => Ok(()),
            Ok(_) => Err(format!("process {} has exited", self.pid)),
            Err(error) => Err(format!("process {}: {error}", self.pid)),
        }
    }

    fn read(&self, file: &str) -> Result<String, String> {
        let path = format!("/proc/{}/{file}", self.pid);
        std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))
    }

    fn malformed(&self, file: &str) -> String {
        format!("/proc/{}/{file}: unexpected content", self.pid)
    }
}

/// The `Pid:` line of a pidfd's fdinfo.
pub fn parse_fdinfo_pid(fdinfo: &str) -> Option<i32> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`. Field 2 is the command name in parentheses, which
/// may itself hold spaces and parentheses, so fields are counted from the last `)`.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let after_name = &stat[stat.rfind(')')? + 1..];
    // After the name come field 3 (state) onwards: field 22 is the 20th of them.
    after_name.split_whitespace().nth(19)?.parse().ok()
}

/// The real uid: the first of the four ids on the `Uid:` line of `/proc/<pid>/status`.
pub fn parse_real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().next())
        .and_then(|uid| uid.parse().ok())
}

/// Whether a `/proc/<pid>/cgroup` (cgroup v2, the `0::` line) puts the process under the user's
/// own service manager, `user@<uid>.service`: the apps the desktop starts through `systemd --user`.
/// The user's processes in system units (cron, services with `User=`) are elsewhere.
pub fn is_under_user_manager(cgroup: &str, uid: u32) -> bool {
    let manager = format!("/user.slice/user-{uid}.slice/user@{uid}.service");
    cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .is_some_and(|path| {
            path == manager
                || path
                    .strip_prefix(&manager)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_start_time_after_the_command_name() {
        // Field 22 is 4242; the name holds spaces and a ")", as any process can choose.
        let stat = "1234 (evil) 1 2 3) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 4242 \
                    1000 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(parse_start_time(stat), Some(4242));
        assert_eq!(parse_start_time("1234 (short) S 1 2 3"), None);
        assert_eq!(parse_start_time("no name at all"), None);
    }

    #[test]
    fn reads_the_real_uid_not_the_effective_one() {
        let status = "Name:\tsu\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_real_uid(status), Some(1000));
        assert_eq!(parse_real_uid("Name:\tx\n"), None);
        assert_eq!(parse_real_uid("Uid:\tnobody\n"), None);
    }

    #[test]
    fn reads_the_pid_of_a_pidfd() {
        let fdinfo =
            "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1057\nPid:\t4321\nNSpid:\t4321\n";
        assert_eq!(parse_fdinfo_pid(fdinfo), Some(4321));
        assert_eq!(parse_fdinfo_pid("pos:\t0\nPid:\t-1\n"), Some(-1));
        // A regular file's fdinfo.
        assert_eq!(parse_fdinfo_pid("pos:\t0\nflags:\t02100000\n"), None);
    }

    #[test]
    fn only_the_users_own_service_manager_counts() {
        let app = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope\n";
        assert!(is_under_user_manager(app, 1000));
        assert!(is_under_user_manager(
            "0::/user.slice/user-1000.slice/user@1000.service\n",
            1000
        ));
        // Another user's manager, a session scope, a system service, a look-alike name.
        assert!(!is_under_user_manager(app, 1001));
        assert!(!is_under_user_manager(
            "0::/user.slice/user-1000.slice/session-2.scope\n",
            1000
        ));
        assert!(!is_under_user_manager(
            "0::/system.slice/cron.service\n",
            1000
        ));
        assert!(!is_under_user_manager(
            "0::/user.slice/user-1000.slice/user@1000.service-evil/x\n",
            1000
        ));
        // Only the cgroup v2 line counts.
        assert!(!is_under_user_manager(
            "1:name=systemd:/user.slice/user-1000.slice/user@1000.service\n0::/system.slice/x.service\n",
            1000
        ));
    }

    #[test]
    fn pins_a_real_process_and_sees_it_exit() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let process = Process::open(child.id()).unwrap();
        let start_time = process.start_time().unwrap();
        assert!(start_time > 0);
        assert_eq!(
            process.real_uid().unwrap(),
            parse_real_uid(&std::fs::read_to_string("/proc/self/status").unwrap()).unwrap()
        );
        process.ensure_alive().unwrap();

        // The same process through a copy of the pidfd, as the bus or a client would pass it.
        let copy = Process::from_pidfd(process.pidfd.try_clone().unwrap()).unwrap();
        assert_eq!(copy.pid(), child.id());

        child.kill().unwrap();
        child.wait().unwrap();
        let error = process.ensure_alive().unwrap_err();
        assert!(error.contains("has exited"), "{error}");
        // Once reaped, its pidfd no longer names a PID.
        assert!(Process::from_pidfd(process.pidfd.try_clone().unwrap()).is_err());
    }

    #[test]
    fn a_file_is_not_a_pidfd() {
        let file = std::fs::File::open("/proc/self/status").unwrap();
        assert!(Process::from_pidfd(file.into()).is_err());
    }
}
