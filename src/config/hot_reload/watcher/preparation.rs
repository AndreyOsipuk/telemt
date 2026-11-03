use super::*;

/// Restart-only differences must not enqueue another DNS preparation after activation.
pub(super) fn source_matches_active(
    active: &ProxyConfig,
    source: &crate::config::ParsedConfigSource,
) -> bool {
    config_equal(active, &overlay_hot_fields(active, &source.config))
}

/// Top-level sections whose restart-only differences stay pending after a hot apply.
pub(super) fn restart_required_sections(
    active: &ProxyConfig,
    source: &crate::config::ParsedConfigSource,
) -> Vec<String> {
    changed_sections(&overlay_hot_fields(active, &source.config), &source.config)
}

/// Source that could not be parsed: the error and, when the files were readable,
/// the revision of the refused bytes.
pub(super) type SourceReadError = (String, Option<String>);

/// Reads only source state; watcher initialization and unchanged events never need DNS.
pub(super) async fn read_source(
    path: &PathBuf,
) -> Result<crate::config::ParsedConfigSource, SourceReadError> {
    let path = path.clone();
    let parsed = tokio::task::spawn_blocking(move || {
        ProxyConfig::parse_source(&path).map_err(|error| {
            // Validation errors still leave readable bytes; identify them for the API.
            let revision = ProxyConfig::read_source_graph(&path)
                .ok()
                .map(|graph| crate::config::source_revision(&graph.source_contents));
            (error, revision)
        })
    })
    .await;
    match parsed {
        Ok(Ok(source)) => Ok(source),
        Ok(Err((error, revision))) => {
            error!("config reload: failed to parse: {}", error);
            Err((error.to_string(), revision))
        }
        Err(error) => {
            error!("config reload: source reader failed: {}", error);
            Err((error.to_string(), None))
        }
    }
}

/// Prepares fresh evidence only for changed sources or an explicit reload request.
///
/// Returns `Err` only when the source could not be parsed, so the caller can retry a
/// partial write first; every later refusal is reported through `reload_state`.
pub(super) async fn reload(
    path: &PathBuf,
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    reload_state: &mut ReloadState,
    dns_resolver: Option<Arc<crate::network::dns_overrides::GenerationDnsResolver>>,
    force: bool,
    quota_mutation: Option<&Arc<tokio::sync::Mutex<()>>>,
    quota_source_refresh: Option<&(dyn Fn() -> bool + Send + Sync)>,
) -> Result<WatchManifest, SourceReadError> {
    // Serialize source acquisition with API lifecycle commits, then release before DNS.
    // The source timestamp fences any later mutation during asynchronous preparation.
    let guard = match quota_mutation {
        Some(gate) => Some(gate.lock().await),
        None => None,
    };
    let source = read_source(path).await?;
    let manifest = WatchManifest::from_source_files(&source.source_files);
    // A new file edit can restore the exact pre-creation bytes. Refresh only source
    // evidence for fenced accounts, retaining prepared DNS and immutable WEB state.
    if !force
        && quota_source_refresh.is_some_and(|refresh| refresh())
        && source_matches_active(&config_tx.borrow(), &source)
    {
        let mut refreshed = (**config_tx.borrow()).clone();
        refreshed.quota_source_read_at = source.config.quota_source_read_at;
        let restart_sections = restart_required_sections(&refreshed, &source);
        config_tx.send(Arc::new(refreshed)).ok();
        reload_state.mark_applied(source.rendered_hash);
        reload_state.report_applied(&source.source_contents, restart_sections);
        return Ok(manifest);
    }
    drop(guard);
    if !force && reload_state.is_applied(source.rendered_hash) {
        return Ok(manifest);
    }
    let revision = crate::config::source_revision(&source.source_contents);
    let loaded = match source.prepare().await {
        Ok(loaded) => loaded,
        Err(error) => {
            error!(
                "config reload: preparation failed: {}; keeping old config",
                error
            );
            reload_state.report_rejected("prepare", &error.to_string(), Some(revision));
            return Ok(manifest);
        }
    };
    let old = config_tx.borrow().clone();
    // Static-site reconstruction after the listener overlay must not block Tokio workers.
    // The worker only builds data: cancellation cannot leave a detached publisher behind.
    let result = tokio::task::spawn_blocking(move || {
        prepare_effective_config(&old, &loaded.config).map(|applied| (loaded, applied))
    })
    .await;
    match result {
        Ok(Ok(prepared)) => Ok(reload_config_with_resolver(
            prepared,
            config_tx,
            log_tx,
            detected_ip_v4,
            detected_ip_v6,
            reload_state,
            dns_resolver.as_deref(),
            quota_source_refresh.is_some_and(|refresh| refresh()),
        )
        .unwrap_or(manifest)),
        Ok(Err(error)) => {
            error!(
                "config reload: effective WEB validation failed: {}; keeping old config",
                error
            );
            reload_state.report_rejected("validate", &error.to_string(), Some(revision));
            Ok(manifest)
        }
        Err(error) => {
            error!(
                "config reload: runtime builder failed: {}; keeping old config",
                error
            );
            reload_state.report_rejected("runtime_builder", &error.to_string(), Some(revision));
            Ok(manifest)
        }
    }
}
