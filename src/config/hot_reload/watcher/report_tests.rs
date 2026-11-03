use super::*;

const WEB_SOURCE: &str = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
bob = "101112131415161718191a1b1c1d1e1f"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[web]
enabled = true
[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://localhost:18081"
resolve = "startup"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#;

const PLAIN_SOURCE: &str = r#"
[censorship]
tls_domain = "example.com"

[access.users]
user = "00000000000000000000000000000000"
"#;

fn revision_of(path: &Path) -> String {
    let graph = ProxyConfig::read_source_graph(path).unwrap();
    crate::config::source_revision(&graph.source_contents)
}

async fn wait_for_report(
    reporter: &ConfigReloadReporter,
    ready: impl Fn(&ConfigReloadReport) -> bool,
) -> ConfigReloadReport {
    let mut rx = reporter.subscribe();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let report = rx.borrow_and_update().clone();
            if ready(&report) {
                break report;
            }
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

async fn web_reload_fixture(
    path: &Path,
) -> (
    Arc<ProxyConfig>,
    watch::Sender<Arc<ProxyConfig>>,
    watch::Sender<LogLevel>,
    ReloadState,
    ConfigReloadReporter,
    String,
) {
    std::fs::write(path, WEB_SOURCE).unwrap();
    let loaded = ProxyConfig::load_prepared(path.to_path_buf())
        .await
        .unwrap();
    let applied_revision = crate::config::source_revision(&loaded.source_contents);
    let initial = Arc::new(loaded.config);
    let (config_tx, _) = watch::channel(initial.clone());
    let (log_tx, _) = watch::channel(initial.general.log_level.clone());
    let reporter = ConfigReloadReporter::default();
    let state = ReloadState::new(Some(loaded.rendered_hash)).with_reporter(Some(reporter.clone()));
    state.report_applied(&loaded.source_contents, Vec::new());
    (
        initial,
        config_tx,
        log_tx,
        state,
        reporter,
        applied_revision,
    )
}

#[tokio::test]
async fn profile_for_removed_user_is_refused_with_its_revision() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let (initial, config_tx, log_tx, mut state, _reporter, _) = web_reload_fixture(&path).await;
    let config_rx = config_tx.subscribe();

    // The profile still names a user that the new source no longer defines.
    std::fs::write(
        &path,
        WEB_SOURCE.replace("alice = \"000102030405060708090a0b0c0d0e0f\"\n", ""),
    )
    .unwrap();
    let refused_revision = revision_of(&path);
    let result = preparation::reload(
        &path, &config_tx, &log_tx, None, None, &mut state, None, false, None, None,
    )
    .await;

    // The watcher loop retries once and then reports this as a `parse` rejection.
    let (reason, revision) = result.unwrap_err();
    assert!(!reason.is_empty());
    assert_eq!(revision.as_deref(), Some(refused_revision.as_str()));
    assert!(!config_rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&initial, &config_rx.borrow()));
}

#[tokio::test]
async fn failed_preparation_keeps_applied_revision_and_reports_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let (initial, config_tx, log_tx, mut state, reporter, applied_revision) =
        web_reload_fixture(&path).await;
    let config_rx = config_tx.subscribe();

    std::fs::write(
        &path,
        WEB_SOURCE.replace("localhost", "unresolvable.example.invalid"),
    )
    .unwrap();
    let refused_revision = revision_of(&path);
    preparation::reload(
        &path, &config_tx, &log_tx, None, None, &mut state, None, false, None, None,
    )
    .await
    .unwrap();

    assert!(!config_rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&initial, &config_rx.borrow()));
    let report = reporter.snapshot();
    assert_eq!(
        report.applied_revision.as_deref(),
        Some(applied_revision.as_str())
    );
    assert_ne!(applied_revision, refused_revision);
    assert_eq!(report.rejected_total, 1);
    let rejection = report.last_rejection.unwrap();
    assert_eq!(rejection.stage, "prepare");
    assert_eq!(
        rejection.revision.as_deref(),
        Some(refused_revision.as_str())
    );
    assert!(!rejection.reason.is_empty());
}

#[tokio::test]
async fn watcher_reports_parse_rejection_and_restart_required_sections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, PLAIN_SOURCE).unwrap();
    let initial_revision = revision_of(&path);
    let initial = Arc::new(ProxyConfig::load(&path).unwrap());
    let reporter = ConfigReloadReporter::default();
    let cancellation = tokio_util::sync::CancellationToken::new();
    let (_config_rx, _log_rx, watcher) = spawn_config_watcher(
        path.clone(),
        initial,
        None,
        None,
        cancellation.clone(),
        None,
        None,
        None,
        None,
        Some(reporter.clone()),
    );
    let watcher = tokio::spawn(watcher);

    let report = wait_for_report(&reporter, |report| report.applied_revision.is_some()).await;
    assert_eq!(
        report.applied_revision.as_deref(),
        Some(initial_revision.as_str())
    );
    assert!(report.restart_required_sections.is_empty());

    std::fs::write(&path, "[access.users\n").unwrap();
    let report = wait_for_report(&reporter, |report| report.rejected_total > 0).await;
    let rejection = report.last_rejection.unwrap();
    assert_eq!(rejection.stage, "parse");
    let readable_revision = ProxyConfig::read_source_graph(&path)
        .ok()
        .map(|graph| crate::config::source_revision(&graph.source_contents));
    assert_eq!(rejection.revision, readable_revision);
    assert_eq!(
        report.applied_revision.as_deref(),
        Some(initial_revision.as_str())
    );

    std::fs::write(&path, format!("{PLAIN_SOURCE}\n[server]\nport = 4443\n")).unwrap();
    let restart_revision = revision_of(&path);
    let report = wait_for_report(&reporter, |report| {
        report.applied_revision.as_deref() == Some(restart_revision.as_str())
    })
    .await;
    assert_eq!(report.restart_required_sections, vec!["server".to_string()]);
    assert_eq!(report.rejected_total, 1);

    cancellation.cancel();
    watcher.await.unwrap();
}
