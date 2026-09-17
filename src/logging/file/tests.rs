use std::io::Write;

use tempfile::tempdir;

use super::*;

fn fixed_now() -> DateTime<Utc> {
    DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(10))
}

fn options(path: PathBuf) -> FileLogOptions {
    FileLogOptions {
        path: path.to_string_lossy().to_string(),
        rotation: LogRotation::Never,
        max_size_bytes: 0,
        max_files: 0,
        max_age_secs: 0,
    }
}

fn matching_logs(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("telemt.log"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

#[test]
fn size_rotation_keeps_latest_write_in_active_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("telemt.log");
    let mut options = options(path.clone());
    options.max_size_bytes = 6;

    let mut appender = BoundedFileAppender::with_now(options, Box::new(fixed_now)).unwrap();
    appender.write_all(b"abc\n").unwrap();
    appender.write_all(b"def\n").unwrap();
    appender.flush().unwrap();

    assert_eq!(fs::read_to_string(path).unwrap(), "def\n");
    assert_eq!(matching_logs(dir.path()).len(), 2);
}

#[test]
fn max_files_retention_removes_oldest_archives() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("telemt.log");
    let mut options = options(path);
    options.max_size_bytes = 4;
    options.max_files = 2;

    let mut appender = BoundedFileAppender::with_now(options, Box::new(fixed_now)).unwrap();
    for line in [b"aa\n", b"bb\n", b"cc\n", b"dd\n"] {
        appender.write_all(line).unwrap();
    }
    appender.flush().unwrap();

    assert!(matching_logs(dir.path()).len() <= 2);
}

#[cfg(unix)]
#[test]
fn max_age_retention_removes_old_archives() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("telemt.log");
    let old_archive = dir.path().join("telemt.log.20000101000000.0");
    fs::write(&old_archive, "old").unwrap();

    let c_path = CString::new(old_archive.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    ];
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(rc, 0);

    let mut options = options(path);
    options.max_age_secs = 1;
    let _appender = BoundedFileAppender::with_now(options, Box::new(fixed_now)).unwrap();

    assert!(!old_archive.exists());
}

#[cfg(unix)]
#[test]
fn rotation_stays_bound_to_opened_directory_after_path_replacement() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let original = root.path().join("logs");
    let moved = root.path().join("logs-moved");
    let redirect = root.path().join("redirect");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&redirect).unwrap();
    let mut options = options(original.join("telemt.log"));
    options.max_size_bytes = 4;
    let mut appender = BoundedFileAppender::with_now(options, Box::new(fixed_now)).unwrap();
    appender.write_all(b"aa\n").unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(&redirect, &original).unwrap();

    appender.write_all(b"bb\n").unwrap();
    appender.flush().unwrap();

    assert!(!matching_logs(&moved).is_empty());
    assert!(matching_logs(&redirect).is_empty());
}
