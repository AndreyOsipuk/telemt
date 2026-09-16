use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use super::compute_source_revision;
use crate::api::model::ApiFailure;
use crate::config::ProxyConfig;

enum AtomicWriteError {
    Conflict,
    ReadGraph(String),
    Io(std::io::Error),
}

struct ExistingTarget {
    contents: String,
    metadata: std::fs::Metadata,
}

/// Replaces one config source through a durable same-directory rename.
pub(in crate::api) async fn write_atomic(
    path: PathBuf,
    contents: String,
) -> Result<(), ApiFailure> {
    tokio::task::spawn_blocking(move || write_atomic_sync(&path, None, &contents))
        .await
        .map_err(|error| ApiFailure::internal(format!("failed to join writer: {error}")))?
        .map_err(|error| ApiFailure::internal(format!("failed to write config: {error}")))
}

/// Replaces one source only if both its graph revision and owner contents are unchanged.
pub(in crate::api) async fn write_atomic_if_unchanged(
    config_path: PathBuf,
    expected_revision: String,
    path: PathBuf,
    expected_contents: String,
    contents: String,
) -> Result<(), ApiFailure> {
    tokio::task::spawn_blocking(move || {
        let graph = ProxyConfig::read_source_graph(&config_path)
            .map_err(|error| AtomicWriteError::ReadGraph(error.to_string()))?;
        if compute_source_revision(&graph) != expected_revision {
            return Err(AtomicWriteError::Conflict);
        }
        write_atomic_sync(&path, Some(&expected_contents), &contents).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AtomicWriteError::Conflict
            } else {
                AtomicWriteError::Io(error)
            }
        })
    })
    .await
    .map_err(|error| ApiFailure::internal(format!("failed to join writer: {error}")))?
    .map_err(|error| match error {
        AtomicWriteError::Conflict => revision_conflict(),
        AtomicWriteError::ReadGraph(error) => {
            ApiFailure::internal(format!("failed to verify config graph: {error}"))
        }
        AtomicWriteError::Io(error) => {
            ApiFailure::internal(format!("failed to write config: {error}"))
        }
    })
}

fn revision_conflict() -> ApiFailure {
    ApiFailure::new(
        hyper::StatusCode::CONFLICT,
        "revision_conflict",
        "Config revision changed before persistence",
    )
}

fn open_existing_target(path: &Path) -> std::io::Result<Option<ExistingTarget>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config target must be a regular file",
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(Some(ExistingTarget { contents, metadata }))
}

fn same_target(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

fn write_atomic_sync(
    path: &Path,
    expected_contents: Option<&str>,
    contents: &str,
) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let existing = open_existing_target(path)?;
    if expected_contents.is_some_and(|expected| {
        existing
            .as_ref()
            .is_none_or(|target| target.contents != expected)
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "config source changed before persistence",
        ));
    }

    let tmp_name = format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml"),
        rand::random::<u64>()
    );
    let tmp_path = parent.join(tmp_name);

    let write_result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp_path)?;
        #[cfg(unix)]
        if let Some(existing) = existing.as_ref() {
            use nix::unistd::{Gid, Uid, fchown};

            fchown(
                &file,
                Some(Uid::from_raw(existing.metadata.uid())),
                Some(Gid::from_raw(existing.metadata.gid())),
            )
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
            file.set_permissions(std::fs::Permissions::from_mode(
                existing.metadata.mode() & 0o7777,
            ))?;
        }
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        let current = open_existing_target(path)?;
        let target_unchanged = match (&existing, &current) {
            (Some(expected), Some(current)) => {
                same_target(&expected.metadata, &current.metadata)
                    && expected.contents == current.contents
            }
            (None, None) => true,
            _ => false,
        };
        if !target_unchanged {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "config target changed during persistence",
            ));
        }
        std::fs::rename(&tmp_path, path)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}
