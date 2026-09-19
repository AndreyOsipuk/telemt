use std::os::unix::fs::{MetadataExt, symlink};
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
fn system_var_run_alias_keeps_the_default_pid_path_usable() {
    let Ok(metadata) = fs::symlink_metadata("/var/run") else {
        return;
    };
    let Ok(target) = fs::read_link("/var/run") else {
        return;
    };
    if !metadata.file_type().is_symlink()
        || (target != Path::new("/run") && target != Path::new("../run"))
    {
        return;
    }

    let pid_file = PidFile::new("/var/run/telemt.pid");

    assert_eq!(pid_file.path(), Path::new("/run/telemt.pid"));
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
fn status_requires_live_lock_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("telemt.pid");
    fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();
    assert_eq!(
        check_status(&pid_path),
        DaemonStatus::Stale(std::process::id() as i32)
    );

    fs::remove_file(&pid_path).unwrap();
    let mut owner = PidFile::new(&pid_path);
    owner.acquire().unwrap();
    assert_eq!(
        check_status(&pid_path),
        DaemonStatus::Running(std::process::id() as i32)
    );
    owner.release().unwrap();
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
fn acquire_rejects_pid_symlink_without_truncating_target() {
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("telemt.pid");
    let target_path = directory.path().join("target");
    fs::write(&target_path, b"preserve\n").unwrap();
    symlink(&target_path, &pid_path).unwrap();
    let mut pid_file = PidFile::new(&pid_path);

    assert!(pid_file.acquire().is_err());
    assert_eq!(fs::read(&target_path).unwrap(), b"preserve\n");
}

#[test]
fn acquire_rejects_pid_hard_link_without_truncating_target() {
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("telemt.pid");
    let target_path = directory.path().join("target");
    fs::write(&target_path, b"preserve\n").unwrap();
    fs::hard_link(&target_path, &pid_path).unwrap();
    let mut pid_file = PidFile::new(&pid_path);

    assert!(pid_file.acquire().is_err());
    assert_eq!(fs::read(&target_path).unwrap(), b"preserve\n");
}

#[test]
fn acquire_rejects_symlinked_parent_without_publishing_outside() {
    let directory = tempfile::tempdir().unwrap();
    let real_parent = directory.path().join("real");
    let linked_parent = directory.path().join("linked");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    let pid_path = linked_parent.join("telemt.pid");
    let mut pid_file = PidFile::new(&pid_path);

    assert!(pid_file.acquire().is_err());
    assert!(!real_parent.join("telemt.pid").exists());
    assert!(!real_parent.join("telemt.pid.lock").exists());
}

#[test]
fn release_remains_anchored_after_parent_path_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let active_parent = directory.path().join("active");
    let moved_parent = directory.path().join("moved");
    fs::create_dir(&active_parent).unwrap();
    let pid_path = active_parent.join("telemt.pid");
    let mut pid_file = PidFile::new(&pid_path);
    pid_file.acquire().unwrap();

    fs::rename(&active_parent, &moved_parent).unwrap();
    fs::create_dir(&active_parent).unwrap();
    fs::write(active_parent.join("telemt.pid"), b"replacement\n").unwrap();

    pid_file.release().unwrap();

    assert!(!moved_parent.join("telemt.pid").exists());
    assert_eq!(
        fs::read(active_parent.join("telemt.pid")).unwrap(),
        b"replacement\n"
    );
}

#[test]
fn release_does_not_remove_replacement_path() {
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("telemt.pid");
    let owned_path = directory.path().join("owned.pid");
    let mut pid_file = PidFile::new(&pid_path);
    pid_file.acquire().unwrap();
    fs::rename(&pid_path, &owned_path).unwrap();
    fs::write(&pid_path, b"replacement\n").unwrap();

    let error = pid_file.release().unwrap_err();

    assert!(error.to_string().contains("refusing to remove replaced PID file"));
    assert_eq!(fs::read(&pid_path).unwrap(), b"replacement\n");
}

#[test]
fn pid_parser_rejects_process_group_values() {
    let directory = tempfile::tempdir().unwrap();
    let pid_path = directory.path().join("telemt.pid");

    for value in ["-1\n", "0\n", "1\n"] {
        fs::write(&pid_path, value).unwrap();
        assert!(read_pid_file(&pid_path).is_err());
    }
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
