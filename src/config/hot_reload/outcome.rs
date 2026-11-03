use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

/// Upper bound for a stored rejection reason; keeps API payloads and events bounded.
const REJECTION_REASON_MAX_BYTES: usize = 160;

/// One hot reload that was refused while the previous config stayed active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigReloadRejection {
    /// Pipeline stage that refused the candidate snapshot.
    pub(crate) stage: &'static str,
    /// Bounded error text; the full error is logged by the watcher.
    pub(crate) reason: String,
    /// Source revision of the refused snapshot when it could be read.
    pub(crate) revision: Option<String>,
    pub(crate) at_epoch_secs: u64,
}

/// Outcome of the config watcher, observed by the API and metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfigReloadReport {
    /// Source revision of the last snapshot accepted by hot reload.
    pub(crate) applied_revision: Option<String>,
    /// Top-level sections of the accepted snapshot that only apply after restart.
    pub(crate) restart_required_sections: Vec<String>,
    pub(crate) rejected_total: u64,
    pub(crate) last_rejection: Option<ConfigReloadRejection>,
}

/// Publishes watcher outcomes without blocking the reload path.
#[derive(Debug, Clone)]
pub(crate) struct ConfigReloadReporter {
    tx: Arc<watch::Sender<ConfigReloadReport>>,
}

impl Default for ConfigReloadReporter {
    fn default() -> Self {
        Self {
            tx: Arc::new(watch::Sender::new(ConfigReloadReport::default())),
        }
    }
}

impl ConfigReloadReporter {
    pub(crate) fn subscribe(&self) -> watch::Receiver<ConfigReloadReport> {
        self.tx.subscribe()
    }

    pub(crate) fn snapshot(&self) -> ConfigReloadReport {
        self.tx.borrow().clone()
    }

    pub(crate) fn record_applied(
        &self,
        source_contents: &BTreeMap<PathBuf, String>,
        restart_required_sections: Vec<String>,
    ) {
        let revision = crate::config::source_revision(source_contents);
        self.tx.send_if_modified(|report| {
            let changed = report.applied_revision.as_deref() != Some(revision.as_str())
                || report.restart_required_sections != restart_required_sections;
            report.applied_revision = Some(revision);
            report.restart_required_sections = restart_required_sections;
            changed
        });
    }

    pub(crate) fn record_rejected(
        &self,
        stage: &'static str,
        reason: &str,
        revision: Option<String>,
    ) {
        let rejection = ConfigReloadRejection {
            stage,
            reason: bounded_reason(reason),
            revision,
            at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        self.tx.send_modify(|report| {
            report.rejected_total = report.rejected_total.saturating_add(1);
            report.last_rejection = Some(rejection);
        });
    }
}

/// Keeps one line of the error and cuts it on a UTF-8 boundary.
fn bounded_reason(reason: &str) -> String {
    let line = reason.lines().next().unwrap_or_default();
    if line.len() <= REJECTION_REASON_MAX_BYTES {
        return line.to_string();
    }
    let mut end = REJECTION_REASON_MAX_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(body: &str) -> BTreeMap<PathBuf, String> {
        BTreeMap::from([(PathBuf::from("/etc/telemt/config.toml"), body.to_string())])
    }

    #[test]
    fn rejection_keeps_applied_revision_and_counts() {
        let reporter = ConfigReloadReporter::default();
        let accepted = sources("a = 1\n");
        reporter.record_applied(&accepted, Vec::new());
        let applied = reporter.snapshot().applied_revision;
        assert_eq!(applied, Some(crate::config::source_revision(&accepted)));

        let refused = sources("a = 2\n");
        reporter.record_rejected(
            "validate",
            "unknown user",
            Some(crate::config::source_revision(&refused)),
        );
        reporter.record_rejected("parse", "expected `=`", None);

        let report = reporter.snapshot();
        assert_eq!(report.applied_revision, applied);
        assert_eq!(report.rejected_total, 2);
        let last = report.last_rejection.unwrap();
        assert_eq!(last.stage, "parse");
        assert_eq!(last.revision, None);
    }

    #[test]
    fn rejection_reason_is_bounded_on_char_boundary() {
        let reason = format!("{}\nsecond line", "é".repeat(REJECTION_REASON_MAX_BYTES));
        let bounded = bounded_reason(&reason);
        assert!(bounded.len() <= REJECTION_REASON_MAX_BYTES);
        assert!(!bounded.contains('\n'));
        assert!(bounded.chars().all(|ch| ch == 'é'));
    }

    #[test]
    fn unchanged_applied_snapshot_does_not_notify() {
        let reporter = ConfigReloadReporter::default();
        let mut rx = reporter.subscribe();
        let accepted = sources("a = 1\n");
        reporter.record_applied(&accepted, Vec::new());
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();
        reporter.record_applied(&accepted, Vec::new());
        assert!(!rx.has_changed().unwrap());
    }
}
