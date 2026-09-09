use std::path::{Path, PathBuf};

use crate::daemon::{self, DaemonOptions};

/// Parses daemon-related options from CLI arguments.
pub fn parse_daemon_args(args: &[String]) -> DaemonOptions {
    let mut opts = DaemonOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--daemon" | "-d" => {
                opts.daemonize = true;
            }
            "--foreground" | "-f" => {
                opts.foreground = true;
            }
            "--pid-file" => {
                i += 1;
                if i < args.len() {
                    opts.pid_file = Some(PathBuf::from(&args[i]));
                }
            }
            s if s.starts_with("--pid-file=") => {
                opts.pid_file = Some(PathBuf::from(s.trim_start_matches("--pid-file=")));
            }
            "--run-as-user" => {
                i += 1;
                if i < args.len() {
                    opts.user = Some(args[i].clone());
                }
            }
            s if s.starts_with("--run-as-user=") => {
                opts.user = Some(s.trim_start_matches("--run-as-user=").to_string());
            }
            "--run-as-group" => {
                i += 1;
                if i < args.len() {
                    opts.group = Some(args[i].clone());
                }
            }
            s if s.starts_with("--run-as-group=") => {
                opts.group = Some(s.trim_start_matches("--run-as-group=").to_string());
            }
            "--working-dir" => {
                i += 1;
                if i < args.len() {
                    opts.working_dir = Some(PathBuf::from(&args[i]));
                }
            }
            s if s.starts_with("--working-dir=") => {
                opts.working_dir = Some(PathBuf::from(s.trim_start_matches("--working-dir=")));
            }
            _ => {}
        }
        i += 1;
    }

    opts
}

/// Sends SIGTERM and waits briefly for graceful PID-file cleanup.
pub(super) fn stop(pid_file: &Path) -> i32 {
    use nix::sys::signal::Signal;

    println!("Stopping telemt daemon...");

    match daemon::signal_pid_file(pid_file, Signal::SIGTERM) {
        Ok(()) => {
            println!("Stop signal sent successfully");

            // Wait for process to exit for up to ten seconds.
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let daemon::DaemonStatus::NotRunning = daemon::check_status(pid_file) {
                    println!("Daemon stopped");
                    return 0;
                }
            }
            println!("Daemon may still be shutting down");
            0
        }
        Err(e) => {
            eprintln!("Failed to stop daemon: {}", e);
            1
        }
    }
}

/// Sends SIGHUP to trigger configuration reload.
pub(super) fn reload(pid_file: &Path) -> i32 {
    use nix::sys::signal::Signal;

    println!("Reloading telemt configuration...");

    match daemon::signal_pid_file(pid_file, Signal::SIGHUP) {
        Ok(()) => {
            println!("Reload signal sent successfully");
            0
        }
        Err(e) => {
            eprintln!("Failed to reload daemon: {}", e);
            1
        }
    }
}

/// Reports daemon status without mutating PID lifecycle state.
pub(super) fn status(pid_file: &Path) -> i32 {
    match daemon::check_status(pid_file) {
        daemon::DaemonStatus::Running(pid) => {
            println!("telemt is running (pid {})", pid);
            0
        }
        daemon::DaemonStatus::Stale(pid) => {
            println!("telemt is not running (stale pid file, was pid {})", pid);
            1
        }
        daemon::DaemonStatus::NotRunning => {
            println!("telemt is not running");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn status_does_not_remove_stale_pid_file() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("telemt.pid");
        fs::write(&pid_file, b"2000000000\n").unwrap();

        assert_eq!(status(&pid_file), 1);
        assert!(pid_file.exists());
    }
}
