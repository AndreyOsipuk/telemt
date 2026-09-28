use std::time::Duration;

#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::process::Command;

#[cfg(unix)]
use crate::util::trusted_command::{resolve_trusted_helper, trusted_helper_command};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandSpec {
    pub(super) binary: &'static str,
    pub(super) args: Vec<String>,
    pub(super) stdin: Option<String>,
}

impl CommandSpec {
    pub(super) fn new(binary: &'static str, args: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            binary,
            args: args.into_iter().map(str::to_string).collect(),
            stdin: None,
        }
    }

    pub(super) fn with_stdin(
        binary: &'static str,
        args: impl IntoIterator<Item = &'static str>,
        stdin: String,
    ) -> Self {
        Self {
            binary,
            args: args.into_iter().map(str::to_string).collect(),
            stdin: Some(stdin),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandErrorKind {
    Missing,
    NotFound,
    Cancelled,
    Timeout,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandError {
    pub(super) kind: CommandErrorKind,
    pub(super) message: String,
}

impl CommandError {
    pub(super) fn cancelled() -> Self {
        Self {
            kind: CommandErrorKind::Cancelled,
            message: "firewall transaction cancelled".to_string(),
        }
    }

    pub(super) fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: CommandErrorKind::Failed,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub(super) trait FirewallCommandRunner: Send + Sync {
    fn available(&self, binary: &str) -> bool;

    fn has_cap_net_admin(&self) -> bool;

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError>;
}

#[derive(Clone, Copy, Default)]
pub(super) struct SystemCommandRunner;

impl FirewallCommandRunner for SystemCommandRunner {
    fn available(&self, binary: &str) -> bool {
        #[cfg(unix)]
        {
            resolve_trusted_helper(binary).is_some()
        }
        #[cfg(not(unix))]
        {
            let _ = binary;
            false
        }
    }

    fn has_cap_net_admin(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
                return false;
            };
            for line in status.lines() {
                if let Some(raw) = line.strip_prefix("CapEff:") {
                    let caps = raw.trim();
                    if let Ok(bits) = u64::from_str_radix(caps, 16) {
                        const CAP_NET_ADMIN_BIT: u64 = 12;
                        return (bits & (1u64 << CAP_NET_ADMIN_BIT)) != 0;
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError> {
        #[cfg(not(unix))]
        {
            Err(CommandError {
                kind: CommandErrorKind::Missing,
                message: format!("{} is not available", spec.binary),
            })
        }
        #[cfg(unix)]
        {
            let Some(command) = trusted_helper_command(spec.binary) else {
                return Err(CommandError {
                    kind: CommandErrorKind::Missing,
                    message: format!("{} is not available", spec.binary),
                });
            };
            let mut command = Command::from(command);
            command.args(&spec.args);
            command.env("LC_ALL", "C");
            if spec.stdin.is_some() {
                command.stdin(std::process::Stdio::piped());
            }
            command.stdout(std::process::Stdio::null());
            command.stderr(std::process::Stdio::piped());
            command.kill_on_drop(true);
            let mut child = command.spawn().map_err(|error| CommandError {
                kind: CommandErrorKind::Failed,
                message: format!("spawn {} failed: {error}", spec.binary),
            })?;
            let binary = spec.binary;
            let output = tokio::time::timeout(COMMAND_TIMEOUT, async move {
                if let Some(blob) = spec.stdin
                    && let Some(mut writer) = child.stdin.take()
                {
                    writer
                        .write_all(blob.as_bytes())
                        .await
                        .map_err(|error| CommandError {
                            kind: CommandErrorKind::Failed,
                            message: format!("stdin write {binary} failed: {error}"),
                        })?;
                }
                child
                    .wait_with_output()
                    .await
                    .map_err(|error| CommandError {
                        kind: CommandErrorKind::Failed,
                        message: format!("wait {binary} failed: {error}"),
                    })
            })
            .await
            .map_err(|_| CommandError {
                kind: CommandErrorKind::Timeout,
                message: format!("{binary} timed out after {}s", COMMAND_TIMEOUT.as_secs()),
            })??;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let message = if stderr.is_empty() {
                format!("{binary} exited with status {}", output.status)
            } else {
                stderr
            };
            let kind = if is_not_found_error(&message) {
                CommandErrorKind::NotFound
            } else {
                CommandErrorKind::Failed
            };
            Err(CommandError { kind, message })
        }
    }
}

pub(super) fn is_not_found_error(message: &str) -> bool {
    message.contains("No chain/target/match by that name")
        || message.contains("Bad rule (does a matching rule exist in that chain?)")
        || message.contains("Could not process rule: No such file or directory")
}
