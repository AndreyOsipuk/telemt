use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::error::{ProxyError, Result};

pub(super) fn normalize_config_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

pub(super) fn hash_rendered_snapshot(rendered: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    rendered.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn read_config_source(path: &Path) -> Result<(PathBuf, String)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|error| ProxyError::Config(error.to_string()))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ProxyError::Config(error.to_string()))?;
    if !opened_metadata.is_file() {
        return Err(ProxyError::Config(format!(
            "config source `{}` must be a regular file",
            path.display()
        )));
    }
    let normalized = normalize_config_path(path);
    let current_metadata = std::fs::metadata(&normalized)
        .map_err(|error| ProxyError::Config(error.to_string()))?;
    if !same_file_identity(&opened_metadata, &current_metadata) {
        return Err(ProxyError::Config(format!(
            "config source `{}` changed while it was opened",
            path.display()
        )));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| ProxyError::Config(error.to_string()))?;
    let completed_metadata = file
        .metadata()
        .map_err(|error| ProxyError::Config(error.to_string()))?;
    if !same_file_version(&opened_metadata, &completed_metadata) {
        return Err(ProxyError::Config(format!(
            "config source `{}` changed while it was read",
            path.display()
        )));
    }
    Ok((normalized, contents))
}

fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

fn same_file_version(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        same_file_identity(left, right)
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same_file_identity(left, right)
    }
}

pub(super) fn preprocess_includes(
    content: &str,
    base_dir: &Path,
    depth: u8,
    source_files: &mut BTreeSet<PathBuf>,
    source_contents: &mut BTreeMap<PathBuf, String>,
    source_overrides: &BTreeMap<PathBuf, String>,
) -> Result<String> {
    if depth > 10 {
        return Err(ProxyError::Config("Include depth > 10".into()));
    }
    let mut output = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("include") {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let path_str = rest.trim().trim_matches('"');
                let resolved = base_dir.join(path_str);
                let normalized = normalize_config_path(&resolved);
                let cached = source_contents.get(&normalized).cloned();
                let (normalized, included) = if let Some(included) =
                    source_overrides.get(&normalized).cloned().or(cached)
                {
                    (normalized, included)
                } else {
                    read_config_source(&resolved)?
                };
                source_files.insert(normalized.clone());
                source_contents
                    .entry(normalized)
                    .or_insert_with(|| included.clone());
                let included_dir = resolved.parent().unwrap_or(base_dir);
                output.push_str(&preprocess_includes(
                    &included,
                    included_dir,
                    depth + 1,
                    source_files,
                    source_contents,
                    source_overrides,
                )?);
                output.push('\n');
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output)
}
