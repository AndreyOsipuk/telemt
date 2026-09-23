use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, warn};

use crate::config::{ConntrackBackend, ConntrackMode, ProxyConfig};
use crate::proxy::shared_state::ConntrackCloseEvent;
use crate::stats::Stats;
#[cfg(unix)]
use crate::util::trusted_command::resolve_trusted_helper;

use super::{ConntrackRuntimeSupport, NetfilterBackend};

/// Reconciles kernel NOTRACK rules with the active listener policy.
pub(super) async fn reconcile_rules(
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
    stats: &Stats,
) {
    if !cfg.server.conntrack_control.inline_conntrack_control {
        clear_notrack_rules_all_backends().await;
        stats.set_conntrack_rule_apply_ok(true);
        return;
    }

    if !effective_conntrack_enabled(cfg, runtime_support) {
        clear_notrack_rules_all_backends().await;
        stats.set_conntrack_rule_apply_ok(false);
        return;
    }

    let backend = runtime_support
        .netfilter_backend
        .expect("netfilter backend must be available for effective conntrack control");
    let apply_result = match backend {
        NetfilterBackend::Nftables => apply_nft_rules(cfg).await,
        NetfilterBackend::Iptables => apply_iptables_rules(cfg).await,
    };
    if let Err(error) = apply_result {
        warn!(error = %error, "Failed to reconcile conntrack/notrack rules");
        stats.set_conntrack_rule_apply_ok(false);
    } else {
        stats.set_conntrack_rule_apply_ok(true);
    }
}

/// Probes the effective firewall backend and conntrack deletion capability.
pub(super) fn probe_runtime_support(
    configured_backend: ConntrackBackend,
) -> ConntrackRuntimeSupport {
    ConntrackRuntimeSupport {
        netfilter_backend: pick_backend(configured_backend),
        has_cap_net_admin: has_cap_net_admin(),
        has_conntrack_binary: command_exists("conntrack"),
    }
}

/// Resolves whether conntrack close publication is usable for this runtime.
pub(super) fn effective_conntrack_enabled(
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
) -> bool {
    cfg.server.conntrack_control.inline_conntrack_control
        && runtime_support.has_cap_net_admin
        && runtime_support.netfilter_backend.is_some()
        && runtime_support.has_conntrack_binary
}

fn pick_backend(configured: ConntrackBackend) -> Option<NetfilterBackend> {
    match configured {
        ConntrackBackend::Auto => {
            if command_exists("nft") {
                Some(NetfilterBackend::Nftables)
            } else if command_exists("iptables") {
                Some(NetfilterBackend::Iptables)
            } else {
                None
            }
        }
        ConntrackBackend::Nftables => command_exists("nft").then_some(NetfilterBackend::Nftables),
        ConntrackBackend::Iptables => {
            command_exists("iptables").then_some(NetfilterBackend::Iptables)
        }
    }
}

fn command_exists(binary: &str) -> bool {
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

fn listener_port_set(cfg: &ProxyConfig) -> Vec<u16> {
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    if cfg.server.listeners.is_empty() {
        ports.insert(cfg.server.port);
    } else {
        for listener in &cfg.server.listeners {
            ports.insert(listener.port.unwrap_or(cfg.server.port));
        }
    }
    ports.into_iter().collect()
}

fn notrack_targets(cfg: &ProxyConfig) -> (Vec<(Option<IpAddr>, u16)>, Vec<(Option<IpAddr>, u16)>) {
    let mode = cfg.server.conntrack_control.mode;
    let mut v4_targets: BTreeSet<(Option<IpAddr>, u16)> = BTreeSet::new();
    let mut v6_targets: BTreeSet<(Option<IpAddr>, u16)> = BTreeSet::new();

    match mode {
        ConntrackMode::Tracked => {}
        ConntrackMode::Notrack => {
            if cfg.server.listeners.is_empty() {
                let port = cfg.server.port;
                if let Some(ipv4) = cfg
                    .server
                    .listen_addr_ipv4
                    .as_ref()
                    .and_then(|value| value.parse::<IpAddr>().ok())
                {
                    if ipv4.is_unspecified() {
                        v4_targets.insert((None, port));
                    } else {
                        v4_targets.insert((Some(ipv4), port));
                    }
                }
                if let Some(ipv6) = cfg
                    .server
                    .listen_addr_ipv6
                    .as_ref()
                    .and_then(|value| value.parse::<IpAddr>().ok())
                {
                    if ipv6.is_unspecified() {
                        v6_targets.insert((None, port));
                    } else {
                        v6_targets.insert((Some(ipv6), port));
                    }
                }
            } else {
                for listener in &cfg.server.listeners {
                    let port = listener.port.unwrap_or(cfg.server.port);
                    if listener.ip.is_ipv4() {
                        if listener.ip.is_unspecified() {
                            v4_targets.insert((None, port));
                        } else {
                            v4_targets.insert((Some(listener.ip), port));
                        }
                    } else if listener.ip.is_unspecified() {
                        v6_targets.insert((None, port));
                    } else {
                        v6_targets.insert((Some(listener.ip), port));
                    }
                }
            }
        }
        ConntrackMode::Hybrid => {
            let ports = listener_port_set(cfg);
            for ip in &cfg.server.conntrack_control.hybrid_listener_ips {
                if ip.is_ipv4() {
                    for port in &ports {
                        v4_targets.insert((Some(*ip), *port));
                    }
                } else {
                    for port in &ports {
                        v6_targets.insert((Some(*ip), *port));
                    }
                }
            }
        }
    }

    (
        v4_targets.into_iter().collect(),
        v6_targets.into_iter().collect(),
    )
}

async fn apply_nft_rules(cfg: &ProxyConfig) -> Result<(), String> {
    let _ = run_command(
        "nft",
        &["delete", "table", "inet", "telemt_conntrack"],
        None,
    )
    .await;
    if matches!(cfg.server.conntrack_control.mode, ConntrackMode::Tracked) {
        return Ok(());
    }

    let (v4_targets, v6_targets) = notrack_targets(cfg);
    let mut rules = Vec::new();
    for (ip, port) in v4_targets {
        let rule = if let Some(ip) = ip {
            format!("tcp dport {} ip daddr {} notrack", port, ip)
        } else {
            format!("tcp dport {} notrack", port)
        };
        rules.push(rule);
    }
    for (ip, port) in v6_targets {
        let rule = if let Some(ip) = ip {
            format!("tcp dport {} ip6 daddr {} notrack", port, ip)
        } else {
            format!("tcp dport {} notrack", port)
        };
        rules.push(rule);
    }

    let rule_blob = if rules.is_empty() {
        String::new()
    } else {
        format!("    {}\n", rules.join("\n    "))
    };
    let script = format!(
        "table inet telemt_conntrack {{\n  chain preraw {{\n    type filter hook prerouting priority raw; policy accept;\n{rule_blob}  }}\n}}\n"
    );
    run_command("nft", &["-f", "-"], Some(script)).await
}

async fn apply_iptables_rules(cfg: &ProxyConfig) -> Result<(), String> {
    apply_iptables_rules_for_binary("iptables", cfg, true).await?;
    apply_iptables_rules_for_binary("ip6tables", cfg, false).await?;
    Ok(())
}

async fn apply_iptables_rules_for_binary(
    binary: &str,
    cfg: &ProxyConfig,
    ipv4: bool,
) -> Result<(), String> {
    if !command_exists(binary) {
        return Ok(());
    }
    let chain = "TELEMT_NOTRACK";
    let _ = run_command(
        binary,
        &["-t", "raw", "-D", "PREROUTING", "-j", chain],
        None,
    )
    .await;
    let _ = run_command(binary, &["-t", "raw", "-F", chain], None).await;
    let _ = run_command(binary, &["-t", "raw", "-X", chain], None).await;
    if matches!(cfg.server.conntrack_control.mode, ConntrackMode::Tracked) {
        return Ok(());
    }

    run_command(binary, &["-t", "raw", "-N", chain], None).await?;
    run_command(binary, &["-t", "raw", "-F", chain], None).await?;
    if run_command(
        binary,
        &["-t", "raw", "-C", "PREROUTING", "-j", chain],
        None,
    )
    .await
    .is_err()
    {
        run_command(
            binary,
            &["-t", "raw", "-I", "PREROUTING", "1", "-j", chain],
            None,
        )
        .await?;
    }

    let (v4_targets, v6_targets) = notrack_targets(cfg);
    let selected = if ipv4 { v4_targets } else { v6_targets };
    for (ip, port) in selected {
        let mut args = vec![
            "-t".to_string(),
            "raw".to_string(),
            "-A".to_string(),
            chain.to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port.to_string(),
        ];
        if let Some(ip) = ip {
            args.push("-d".to_string());
            args.push(ip.to_string());
        }
        args.push("-j".to_string());
        args.push("CT".to_string());
        args.push("--notrack".to_string());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_command(binary, &arg_refs, None).await?;
    }
    Ok(())
}

async fn clear_notrack_rules_all_backends() {
    let _ = run_command(
        "nft",
        &["delete", "table", "inet", "telemt_conntrack"],
        None,
    )
    .await;
    let _ = run_command(
        "iptables",
        &["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NOTRACK"],
        None,
    )
    .await;
    let _ = run_command("iptables", &["-t", "raw", "-F", "TELEMT_NOTRACK"], None).await;
    let _ = run_command("iptables", &["-t", "raw", "-X", "TELEMT_NOTRACK"], None).await;
    let _ = run_command(
        "ip6tables",
        &["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NOTRACK"],
        None,
    )
    .await;
    let _ = run_command("ip6tables", &["-t", "raw", "-F", "TELEMT_NOTRACK"], None).await;
    let _ = run_command("ip6tables", &["-t", "raw", "-X", "TELEMT_NOTRACK"], None).await;
}

/// Result of one best-effort kernel conntrack deletion.
pub(super) enum DeleteOutcome {
    /// The kernel reported successful deletion.
    Deleted,
    /// No matching conntrack entry existed.
    NotFound,
    /// The helper was unavailable or returned an unexpected failure.
    Error,
}

/// Deletes the exact TCP tuple represented by one close event.
pub(super) async fn delete_conntrack_entry(event: ConntrackCloseEvent) -> DeleteOutcome {
    if !command_exists("conntrack") {
        return DeleteOutcome::Error;
    }
    let args = vec![
        "-D".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        event.src.ip().to_string(),
        "--sport".to_string(),
        event.src.port().to_string(),
        "-d".to_string(),
        event.dst.ip().to_string(),
        "--dport".to_string(),
        event.dst.port().to_string(),
    ];
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_command("conntrack", &arg_refs, None).await {
        Ok(()) => DeleteOutcome::Deleted,
        Err(error) => {
            if error.contains("0 flow entries have been deleted") {
                DeleteOutcome::NotFound
            } else {
                debug!(error = %error, "conntrack delete failed");
                DeleteOutcome::Error
            }
        }
    }
}

async fn run_command(binary: &str, args: &[&str], stdin: Option<String>) -> Result<(), String> {
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
    #[cfg(unix)]
    let Some(command_path) = resolve_trusted_helper(binary) else {
        return Err(format!("{binary} is not available"));
    };
    #[cfg(not(unix))]
    return Err(format!("{binary} is not available"));
    #[cfg(unix)]
    let mut command = Command::new(command_path);
    command.args(args);
    if stdin.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::piped());
    command.kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn {binary} failed: {error}"))?;
    let output = tokio::time::timeout(COMMAND_TIMEOUT, async move {
        if let Some(blob) = stdin
            && let Some(mut writer) = child.stdin.take()
        {
            writer
                .write_all(blob.as_bytes())
                .await
                .map_err(|error| format!("stdin write {binary} failed: {error}"))?;
        }
        child
            .wait_with_output()
            .await
            .map_err(|error| format!("wait {binary} failed: {error}"))
    })
    .await
        .map_err(|_| format!("{binary} timed out after {}s", COMMAND_TIMEOUT.as_secs()))??;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("{binary} exited with status {}", output.status)
    } else {
        stderr
    })
}

fn has_cap_net_admin() -> bool {
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
