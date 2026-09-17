use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};
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
    pid_identity: Option<FileIdentity>,
    lock_file: Option<Flock<File>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
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
            pid_identity: None,
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
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.lock_path)
            .map_err(|error| {
                DaemonError::PidFile(format!(
                    "cannot open lock file {}: {}",
                    self.lock_path.display(),
                    error
                ))
            })?;
        validate_regular_single_link(&lock_file, &self.lock_path)?;
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
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|error| {
                DaemonError::PidFile(format!("cannot open {}: {}", self.path.display(), error))
            })?;
        let pid_metadata = validate_regular_single_link(&pid_file, &self.path)?;
        let pid_identity = FileIdentity::from_metadata(&pid_metadata);
        let pid = getpid();
        writeln!(pid_file, "{}", pid).map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot write PID to {}: {}",
                self.path.display(),
                error
            ))
        })?;
        pid_file.sync_data().map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot sync PID file {}: {}",
                self.path.display(),
                error
            ))
        })?;

        self.pid_file = Some(pid_file);
        self.pid_identity = Some(pid_identity);
        self.lock_file = Some(lock_file);
        info!(pid = pid.as_raw(), path = %self.path.display(), "PID file created");
        Ok(())
    }

    /// Removes the PID file while retaining exclusive lock ownership until cleanup completes.
    pub fn release(&mut self) -> Result<(), DaemonError> {
        if self.lock_file.is_none() {
            self.pid_file = None;
            self.pid_identity = None;
            return Ok(());
        }

        let removal = match fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if self.pid_identity == Some(FileIdentity::from_metadata(&metadata))
                    && metadata.is_file() =>
            {
                fs::remove_file(&self.path).map_err(|error| {
                    DaemonError::PidFile(format!(
                        "cannot remove {}: {}",
                        self.path.display(),
                        error
                    ))
                })
            }
            Ok(_) => Err(DaemonError::PidFile(format!(
                "refusing to remove replaced PID file {}",
                self.path.display()
            ))),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DaemonError::PidFile(format!(
                "cannot inspect {} before removal: {}",
                self.path.display(),
                error
            ))),
        };
        self.pid_file = None;
        self.pid_identity = None;
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
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
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
    let metadata = validate_regular_single_link(&file, path)?;
    if metadata.len() > 64 {
        return Err(DaemonError::PidFile(format!(
            "invalid PID in {}",
            path.display()
        )));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|error| {
        DaemonError::PidFile(format!("cannot read {}: {}", path.display(), error))
    })?;
    let pid: i32 = contents
        .trim()
        .parse()
        .map_err(|_| DaemonError::PidFile(format!("invalid PID in {}", path.display())))?;
    if pid <= 1 {
        return Err(DaemonError::PidFile(format!(
            "invalid PID in {}",
            path.display()
        )));
    }
    Ok(Some(pid))
}

fn validate_regular_single_link(
    file: &File,
    path: &Path,
) -> Result<fs::Metadata, DaemonError> {
    let metadata = file.metadata().map_err(|error| {
        DaemonError::PidFile(format!("cannot inspect {}: {}", path.display(), error))
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(DaemonError::PidFile(format!(
            "{} must be a regular file with one directory entry",
            path.display()
        )));
    }
    Ok(metadata)
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
    let path = path.as_ref();
    let pid = read_pid_file(path)?;
    #[cfg(target_os = "linux")]
    let pidfd = open_pidfd(pid)?;
    if !daemon_lock_is_held(path)? {
        return Err(DaemonError::PidFile(format!(
            "refusing to signal unlocked or stale PID file {}",
            path.display()
        )));
    }
    #[cfg(target_os = "linux")]
    return signal_pidfd(&pidfd, pid, signal);
    #[cfg(not(target_os = "linux"))]
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
        Ok(Some(pid))
            if daemon_lock_is_held(path).unwrap_or(false) && is_process_running(pid) =>
        {
            DaemonStatus::Running(pid)
        }
        Ok(Some(pid)) => DaemonStatus::Stale(pid),
        Ok(None) | Err(_) => DaemonStatus::NotRunning,
    }
}

fn daemon_lock_is_held(path: &Path) -> Result<bool, DaemonError> {
    let lock_path = sibling_lock_path(path);
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot inspect lock {}: {}",
                lock_path.display(),
                error
            )));
        }
    };
    validate_regular_single_link(&file, &lock_path)?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(_available) => Ok(false),
        Err((_file, nix::errno::Errno::EWOULDBLOCK)) => Ok(true),
        Err((_file, error)) => Err(DaemonError::PidFile(format!(
            "cannot inspect lock ownership for {}: {}",
            lock_path.display(),
            error
        ))),
    }
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: i32) -> Result<OwnedFd, DaemonError> {
    // SAFETY: `pidfd_open` receives a validated positive PID and no pointer arguments.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(DaemonError::PidFile(format!(
            "cannot open stable process handle for {}: {}",
            pid,
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: a successful `pidfd_open` returns one newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
}

#[cfg(target_os = "linux")]
fn signal_pidfd(
    pidfd: &OwnedFd,
    pid: i32,
    signal: nix::sys::signal::Signal,
) -> Result<(), DaemonError> {
    use std::os::fd::AsRawFd;

    // SAFETY: the pidfd is owned and valid, and both optional pointer arguments are null.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(DaemonError::PidFile(format!(
            "cannot signal process {} through stable handle: {}",
            pid,
            std::io::Error::last_os_error()
        )))
    }
}

fn is_process_running(pid: i32) -> bool {
    nix::sys::signal::kill(Pid::from_raw(pid), None).is_ok()
}

#[cfg(test)]
mod tests;
