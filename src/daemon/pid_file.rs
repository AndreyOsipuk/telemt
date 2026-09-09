use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use nix::unistd::{Pid, getpid};
use tracing::{debug, info, warn};

use super::DaemonError;

/// PID file manager backed by a persistent sibling lock file.
pub struct PidFile {
    path: PathBuf,
    lock_path: PathBuf,
    pid_file: Option<File>,
    lock_file: Option<Flock<File>>,
}

impl PidFile {
    /// Creates a new PID file manager for the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        let lock_path = sibling_lock_path(&path);
        Self {
            path,
            lock_path,
            pid_file: None,
            lock_file: None,
        }
    }

    /// Checks whether the PID file names a running process without modifying either file.
    pub fn check_running(&self) -> Result<Option<i32>, DaemonError> {
        let Some(pid) = read_pid_file_if_exists(&self.path)? else {
            return Ok(None);
        };
        Ok(is_process_running(pid).then_some(pid))
    }

    /// Acquires the persistent sibling lock and writes the current PID.
    ///
    /// Fails if another owner holds the lock or the existing PID names a running process.
    pub fn acquire(&mut self) -> Result<(), DaemonError> {
        if let Some(parent) = self.path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|error| {
                DaemonError::PidFile(format!(
                    "cannot create directory {}: {}",
                    parent.display(),
                    error
                ))
            })?;
        }

        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o644)
            .open(&self.lock_path)
            .map_err(|error| {
                DaemonError::PidFile(format!(
                    "cannot open lock file {}: {}",
                    self.lock_path.display(),
                    error
                ))
            })?;
        let lock_file =
            Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).map_err(|(_, errno)| {
                if let Some(pid) = self.check_running().ok().flatten() {
                    DaemonError::AlreadyRunning(pid)
                } else {
                    DaemonError::PidFile(format!(
                        "cannot lock {}: {}",
                        self.lock_path.display(),
                        errno
                    ))
                }
            })?;

        if let Some(pid) = self.check_running()? {
            return Err(DaemonError::AlreadyRunning(pid));
        }

        let mut pid_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&self.path)
            .map_err(|error| {
                DaemonError::PidFile(format!("cannot open {}: {}", self.path.display(), error))
            })?;
        let pid = getpid();
        writeln!(pid_file, "{}", pid).map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot write PID to {}: {}",
                self.path.display(),
                error
            ))
        })?;

        self.pid_file = Some(pid_file);
        self.lock_file = Some(lock_file);
        info!(pid = pid.as_raw(), path = %self.path.display(), "PID file created");
        Ok(())
    }

    /// Removes the PID file while retaining exclusive lock ownership until cleanup completes.
    pub fn release(&mut self) -> Result<(), DaemonError> {
        if self.lock_file.is_none() {
            self.pid_file = None;
            return Ok(());
        }

        let removal = match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DaemonError::PidFile(format!(
                "cannot remove {}: {}",
                self.path.display(),
                error
            ))),
        };
        self.pid_file = None;
        self.lock_file = None;
        removal?;
        debug!(path = %self.path.display(), "PID file removed");
        Ok(())
    }

    /// Returns the path to this PID file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns open files whose ownership must follow the target runtime identity.
    pub(super) fn ownership_file_handles(&self) -> [Option<&File>; 2] {
        [self.pid_file.as_ref(), self.lock_file.as_deref()]
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if self.lock_file.is_some()
            && let Err(error) = self.release()
        {
            warn!(error = %error, "Failed to clean up PID file on drop");
        }
    }
}

fn sibling_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    lock_path.into()
}

fn read_pid_file_if_exists(path: &Path) -> Result<Option<i32>, DaemonError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot read {}: {}",
                path.display(),
                error
            )));
        }
    };
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|error| {
        DaemonError::PidFile(format!("cannot read {}: {}", path.display(), error))
    })?;
    let pid = contents
        .trim()
        .parse()
        .map_err(|_| DaemonError::PidFile(format!("invalid PID in {}", path.display())))?;
    Ok(Some(pid))
}

/// Reads a PID from a PID file.
#[allow(dead_code)]
pub fn read_pid_file<P: AsRef<Path>>(path: P) -> Result<i32, DaemonError> {
    let path = path.as_ref();
    read_pid_file_if_exists(path)?.ok_or_else(|| {
        DaemonError::PidFile(format!(
            "cannot read {}: file does not exist",
            path.display()
        ))
    })
}

/// Sends a signal to the process specified in a PID file.
#[allow(dead_code)]
pub fn signal_pid_file<P: AsRef<Path>>(
    path: P,
    signal: nix::sys::signal::Signal,
) -> Result<(), DaemonError> {
    let pid = read_pid_file(&path)?;
    if !is_process_running(pid) {
        return Err(DaemonError::PidFile(format!(
            "process {} from {} is not running",
            pid,
            path.as_ref().display()
        )));
    }
    nix::sys::signal::kill(Pid::from_raw(pid), signal)
        .map_err(|error| DaemonError::PidFile(format!("cannot signal process {}: {}", pid, error)))
}

/// Daemon state derived from the PID file.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Daemon is running with the given PID.
    Running(i32),
    /// PID file exists but the named process is not running.
    Stale(i32),
    /// No readable PID file exists.
    NotRunning,
}

/// Checks daemon status without modifying the PID or lock file.
#[allow(dead_code)]
pub fn check_status<P: AsRef<Path>>(path: P) -> DaemonStatus {
    let path = path.as_ref();
    match read_pid_file_if_exists(path) {
        Ok(Some(pid)) if is_process_running(pid) => DaemonStatus::Running(pid),
        Ok(Some(pid)) => DaemonStatus::Stale(pid),
        Ok(None) | Err(_) => DaemonStatus::NotRunning,
    }
}

fn is_process_running(pid: i32) -> bool {
    nix::sys::signal::kill(Pid::from_raw(pid), None).is_ok()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    const HELPER_PID_PATH: &str = "TELEMT_PID_LOCK_HELPER_PATH";
    const HELPER_READY_PATH: &str = "TELEMT_PID_LOCK_HELPER_READY";
    const HELPER_STOP_PATH: &str = "TELEMT_PID_LOCK_HELPER_STOP";

    fn wait_for_path(path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if path.exists() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn wait_for_child(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    }

    #[test]
    fn pid_file_remains_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<PidFile>();
    }

    #[test]
    fn lock_holder_subprocess() {
        let Some(pid_path) = std::env::var_os(HELPER_PID_PATH) else {
            return;
        };
        let ready_path = PathBuf::from(std::env::var_os(HELPER_READY_PATH).unwrap());
        let stop_path = PathBuf::from(std::env::var_os(HELPER_STOP_PATH).unwrap());
        let mut pid_file = PidFile::new(PathBuf::from(pid_path));
        pid_file.acquire().unwrap();
        fs::write(&ready_path, b"ready").unwrap();
        assert!(wait_for_path(&stop_path, Duration::from_secs(10)));
        pid_file.release().unwrap();
    }

    #[test]
    fn persistent_sibling_lock_serializes_processes_after_pid_unlink() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("telemt.pid");
        let lock_path = sibling_lock_path(&pid_path);
        let ready_path = directory.path().join("ready");
        let stop_path = directory.path().join("stop");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon::pid_file::tests::lock_holder_subprocess",
                "--nocapture",
            ])
            .env(HELPER_PID_PATH, &pid_path)
            .env(HELPER_READY_PATH, &ready_path)
            .env(HELPER_STOP_PATH, &stop_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        if !wait_for_path(&ready_path, Duration::from_secs(5)) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("PID lock holder did not become ready");
        }
        let lock_inode = fs::metadata(&lock_path).unwrap().ino();
        fs::remove_file(&pid_path).unwrap();

        let mut contender = PidFile::new(&pid_path);
        assert!(contender.acquire().is_err());

        fs::write(&stop_path, b"stop").unwrap();
        let status = wait_for_child(&mut child, Duration::from_secs(5)).unwrap_or_else(|| {
            let _ = child.kill();
            child.wait().unwrap()
        });
        assert!(status.success());
        assert_eq!(fs::metadata(&lock_path).unwrap().ino(), lock_inode);

        contender.acquire().unwrap();
        assert_eq!(fs::metadata(&lock_path).unwrap().ino(), lock_inode);
        contender.release().unwrap();
        assert!(!pid_path.exists());
        assert!(lock_path.exists());
    }

    #[test]
    fn stale_pid_checks_are_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("telemt.pid");
        fs::write(&pid_path, b"2000000000\n").unwrap();
        let pid_file = PidFile::new(&pid_path);

        assert_eq!(pid_file.check_running().unwrap(), None);
        assert_eq!(check_status(&pid_path), DaemonStatus::Stale(2_000_000_000));
        assert!(pid_path.exists());
    }

    #[test]
    fn unowned_release_does_not_remove_pid_file() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("telemt.pid");
        fs::write(&pid_path, b"2000000000\n").unwrap();
        let mut pid_file = PidFile::new(&pid_path);

        pid_file.release().unwrap();

        assert!(pid_path.exists());
    }

    #[test]
    fn pid_file_release_keeps_lock_inode() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("telemt.pid");
        let lock_path = sibling_lock_path(&pid_path);
        let mut pid_file = PidFile::new(&pid_path);

        pid_file.acquire().unwrap();
        assert!(
            pid_file
                .ownership_file_handles()
                .into_iter()
                .all(|file| file.is_some())
        );
        assert_eq!(read_pid_file(&pid_path).unwrap(), std::process::id() as i32);
        let lock_inode = fs::metadata(&lock_path).unwrap().ino();
        pid_file.release().unwrap();

        assert!(!pid_path.exists());
        assert!(lock_path.exists());
        pid_file.acquire().unwrap();
        assert_eq!(fs::metadata(&lock_path).unwrap().ino(), lock_inode);
        pid_file.release().unwrap();
    }
}
