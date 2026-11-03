use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use crate::maestro::control_plane::ProcessControlPlane;
use crate::maestro::generation::RuntimeWatchState;

use super::ApiRuntimeState;
use super::events::ApiEventStore;

pub(super) fn spawn_runtime_watchers(
    runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
    runtime_state: Arc<ApiRuntimeState>,
    runtime_events: Arc<ApiEventStore>,
    control_plane: &ProcessControlPlane,
) {
    spawn_config_watcher(
        runtime_watch_rx.clone(),
        runtime_state.clone(),
        runtime_events.clone(),
        control_plane,
    );
    spawn_admission_watcher(
        runtime_watch_rx.clone(),
        runtime_state,
        runtime_events.clone(),
        control_plane,
    );
    spawn_config_rejection_watcher(runtime_watch_rx, runtime_events, control_plane);
}

fn spawn_config_watcher(
    mut runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
    runtime_state: Arc<ApiRuntimeState>,
    runtime_events: Arc<ApiEventStore>,
    control_plane: &ProcessControlPlane,
) {
    let _ = control_plane.spawn(async move {
        let Some(mut current) = runtime_watch_rx.borrow().clone() else {
            return;
        };
        loop {
            tokio::select! {
                biased;
                changed = runtime_watch_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let Some(next) = runtime_watch_rx.borrow().clone() else {
                        continue;
                    };
                    if next.generation_id != current.generation_id {
                        current = next;
                        record_config_reload(
                            &runtime_state,
                            &runtime_events,
                            format!("runtime generation {} activated", current.generation_id),
                        );
                    }
                }
                changed = current.config_rx.changed() => {
                    if changed.is_err() {
                        let Some(next) = wait_for_new_generation(
                            &mut runtime_watch_rx,
                            current.generation_id,
                        ).await else {
                            break;
                        };
                        current = next;
                        record_config_reload(
                            &runtime_state,
                            &runtime_events,
                            format!("runtime generation {} activated", current.generation_id),
                        );
                        continue;
                    }
                    if active_generation_id(&runtime_watch_rx) != Some(current.generation_id) {
                        continue;
                    }
                    record_config_reload(
                        &runtime_state,
                        &runtime_events,
                        format!("generation {} config receiver updated", current.generation_id),
                    );
                }
            }
        }
    });
}

fn spawn_admission_watcher(
    mut runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
    runtime_state: Arc<ApiRuntimeState>,
    runtime_events: Arc<ApiEventStore>,
    control_plane: &ProcessControlPlane,
) {
    let _ = control_plane.spawn(async move {
        let Some(mut current) = runtime_watch_rx.borrow().clone() else {
            return;
        };
        record_admission_state(&runtime_state, &runtime_events, &current);
        loop {
            tokio::select! {
                biased;
                changed = runtime_watch_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let Some(next) = runtime_watch_rx.borrow().clone() else {
                        continue;
                    };
                    if next.generation_id != current.generation_id {
                        current = next;
                        record_admission_state(&runtime_state, &runtime_events, &current);
                    }
                }
                changed = current.admission_rx.changed() => {
                    if changed.is_err() {
                        let Some(next) = wait_for_new_generation(
                            &mut runtime_watch_rx,
                            current.generation_id,
                        ).await else {
                            break;
                        };
                        current = next;
                        record_admission_state(&runtime_state, &runtime_events, &current);
                        continue;
                    }
                    if active_generation_id(&runtime_watch_rx) == Some(current.generation_id) {
                        record_admission_state(&runtime_state, &runtime_events, &current);
                    }
                }
            }
        }
    });
}

/// Records refused hot reloads; the active config is unchanged, so no reload counter moves.
fn spawn_config_rejection_watcher(
    mut runtime_watch_rx: watch::Receiver<Option<RuntimeWatchState>>,
    runtime_events: Arc<ApiEventStore>,
    control_plane: &ProcessControlPlane,
) {
    let _ = control_plane.spawn(async move {
        let Some(mut current) = runtime_watch_rx.borrow().clone() else {
            return;
        };
        // Each generation owns a fresh watcher report, so its rejections start at zero.
        let mut seen_rejections = 0;
        record_config_rejection(&runtime_events, &mut current, &mut seen_rejections);
        loop {
            tokio::select! {
                biased;
                changed = runtime_watch_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let Some(next) = runtime_watch_rx.borrow().clone() else {
                        continue;
                    };
                    if next.generation_id != current.generation_id {
                        current = next;
                        seen_rejections = 0;
                        record_config_rejection(&runtime_events, &mut current, &mut seen_rejections);
                    }
                }
                changed = current.config_reload_rx.changed() => {
                    if changed.is_err() {
                        let Some(next) = wait_for_new_generation(
                            &mut runtime_watch_rx,
                            current.generation_id,
                        ).await else {
                            break;
                        };
                        current = next;
                        seen_rejections = 0;
                    }
                    record_config_rejection(&runtime_events, &mut current, &mut seen_rejections);
                }
            }
        }
    });
}

fn record_config_rejection(
    runtime_events: &ApiEventStore,
    current: &mut RuntimeWatchState,
    seen_rejections: &mut u64,
) {
    let (rejected_total, last_rejection) = {
        let report = current.config_reload_rx.borrow_and_update();
        (report.rejected_total, report.last_rejection.clone())
    };
    if rejected_total <= *seen_rejections {
        return;
    }
    *seen_rejections = rejected_total;
    // Rejections coalesced by the watch channel are still counted in rejected_total.
    if let Some(rejection) = last_rejection {
        runtime_events.record(
            "config.reload.rejected",
            format!(
                "generation={} stage={} reason={}",
                current.generation_id, rejection.stage, rejection.reason
            ),
        );
    }
}

fn active_generation_id(
    runtime_watch_rx: &watch::Receiver<Option<RuntimeWatchState>>,
) -> Option<u64> {
    runtime_watch_rx
        .borrow()
        .as_ref()
        .map(|state| state.generation_id)
}

async fn wait_for_new_generation(
    runtime_watch_rx: &mut watch::Receiver<Option<RuntimeWatchState>>,
    previous_generation_id: u64,
) -> Option<RuntimeWatchState> {
    loop {
        if let Some(state) = runtime_watch_rx.borrow().clone()
            && state.generation_id != previous_generation_id
        {
            return Some(state);
        }
        if runtime_watch_rx.changed().await.is_err() {
            return None;
        }
    }
}

fn record_config_reload(
    runtime_state: &ApiRuntimeState,
    runtime_events: &ApiEventStore,
    context: String,
) {
    runtime_state
        .config_reload_count
        .fetch_add(1, Ordering::Relaxed);
    runtime_state
        .last_config_reload_epoch_secs
        .store(now_epoch_secs(), Ordering::Relaxed);
    runtime_events.record("config.reload.applied", context);
}

fn record_admission_state(
    runtime_state: &ApiRuntimeState,
    runtime_events: &ApiEventStore,
    current: &RuntimeWatchState,
) {
    let admission_open = *current.admission_rx.borrow();
    runtime_state
        .admission_open
        .store(admission_open, Ordering::Relaxed);
    runtime_events.record(
        "admission.state",
        format!(
            "generation={} accepting_new_connections={}",
            current.generation_id, admission_open
        ),
    );
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;
    use crate::config::hot_reload::ConfigReloadReporter;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::time::Duration;

    fn state(
        generation_id: u64,
    ) -> (
        RuntimeWatchState,
        watch::Sender<Arc<ProxyConfig>>,
        watch::Sender<bool>,
    ) {
        let (config_tx, config_rx) = watch::channel(Arc::new(ProxyConfig::default()));
        let (admission_tx, admission_rx) = watch::channel(true);
        (
            RuntimeWatchState {
                generation_id,
                config_rx,
                admission_rx,
                config_reload_rx: ConfigReloadReporter::default().subscribe(),
            },
            config_tx,
            admission_tx,
        )
    }

    fn runtime_state() -> Arc<ApiRuntimeState> {
        Arc::new(ApiRuntimeState {
            process_started_at_epoch_secs: 1,
            config_reload_count: AtomicU64::new(0),
            last_config_reload_epoch_secs: AtomicU64::new(0),
            admission_open: AtomicBool::new(false),
        })
    }

    async fn wait_for_count(runtime_state: &ApiRuntimeState, expected: u64) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if runtime_state.config_reload_count.load(Ordering::Relaxed) == expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn watchers_follow_only_the_active_generation() {
        let (initial, initial_config_tx, initial_admission_tx) = state(1);
        let (runtime_watch_tx, runtime_watch_rx) = watch::channel(Some(initial));
        let runtime_state = runtime_state();
        let events = Arc::new(ApiEventStore::new(16));
        let control_plane = ProcessControlPlane::new();
        spawn_runtime_watchers(
            runtime_watch_rx,
            runtime_state.clone(),
            events.clone(),
            &control_plane,
        );
        tokio::task::yield_now().await;

        assert_eq!(runtime_state.config_reload_count.load(Ordering::Relaxed), 0);
        initial_config_tx.send_replace(Arc::new(ProxyConfig::default()));
        wait_for_count(&runtime_state, 1).await;

        let (next, next_config_tx, next_admission_tx) = state(2);
        runtime_watch_tx.send_replace(Some(next));
        wait_for_count(&runtime_state, 2).await;

        initial_config_tx.send_replace(Arc::new(ProxyConfig::default()));
        initial_admission_tx.send_replace(false);
        tokio::task::yield_now().await;
        assert_eq!(runtime_state.config_reload_count.load(Ordering::Relaxed), 2);
        assert!(runtime_state.admission_open.load(Ordering::Relaxed));

        next_config_tx.send_replace(Arc::new(ProxyConfig::default()));
        next_admission_tx.send_replace(false);
        wait_for_count(&runtime_state, 3).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while runtime_state.admission_open.load(Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let snapshot = events.snapshot(16);
        assert_eq!(
            snapshot
                .events
                .iter()
                .filter(|event| event.event_type == "config.reload.applied")
                .count(),
            3
        );
        assert!(control_plane.shutdown(Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn watcher_recovers_from_closed_generation_and_exits_with_process_channel() {
        let (initial, initial_config_tx, _initial_admission_tx) = state(1);
        let (runtime_watch_tx, runtime_watch_rx) = watch::channel(Some(initial));
        let runtime_state = runtime_state();
        let events = Arc::new(ApiEventStore::new(16));
        let control_plane = ProcessControlPlane::new();
        spawn_config_watcher(
            runtime_watch_rx,
            runtime_state.clone(),
            events.clone(),
            &control_plane,
        );
        drop(initial_config_tx);
        tokio::task::yield_now().await;

        let (next, next_config_tx, _next_admission_tx) = state(2);
        runtime_watch_tx.send_replace(Some(next));
        wait_for_count(&runtime_state, 1).await;
        next_config_tx.send_replace(Arc::new(ProxyConfig::default()));
        wait_for_count(&runtime_state, 2).await;

        drop(runtime_watch_tx);
        assert!(control_plane.shutdown(Duration::from_secs(1)).await);
        assert_eq!(
            events
                .snapshot(16)
                .events
                .iter()
                .filter(|event| event.event_type == "config.reload.applied")
                .count(),
            2
        );
    }

    async fn wait_for_rejections(events: &ApiEventStore, expected: usize) -> Vec<String> {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let contexts: Vec<String> = events
                    .snapshot(16)
                    .events
                    .into_iter()
                    .filter(|event| event.event_type == "config.reload.rejected")
                    .map(|event| event.context)
                    .collect();
                if contexts.len() >= expected {
                    break contexts;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn rejected_reloads_are_recorded_for_the_active_generation_only() {
        let (mut initial, _initial_config_tx, _initial_admission_tx) = state(1);
        let initial_reporter = ConfigReloadReporter::default();
        initial.config_reload_rx = initial_reporter.subscribe();
        let (runtime_watch_tx, runtime_watch_rx) = watch::channel(Some(initial));
        let runtime_state = runtime_state();
        let events = Arc::new(ApiEventStore::new(16));
        let control_plane = ProcessControlPlane::new();
        spawn_runtime_watchers(
            runtime_watch_rx,
            runtime_state.clone(),
            events.clone(),
            &control_plane,
        );
        tokio::task::yield_now().await;

        initial_reporter.record_rejected("validate", "unknown user in web profile", None);
        let contexts = wait_for_rejections(&events, 1).await;
        assert_eq!(
            contexts,
            vec!["generation=1 stage=validate reason=unknown user in web profile".to_string()]
        );
        // A refused snapshot never reaches the config receiver.
        assert_eq!(runtime_state.config_reload_count.load(Ordering::Relaxed), 0);

        let (mut next, _next_config_tx, _next_admission_tx) = state(2);
        let next_reporter = ConfigReloadReporter::default();
        next.config_reload_rx = next_reporter.subscribe();
        runtime_watch_tx.send_replace(Some(next));
        initial_reporter.record_rejected("parse", "retired generation", None);
        next_reporter.record_rejected("parse", "expected `=`", None);
        let contexts = wait_for_rejections(&events, 2).await;
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[1], "generation=2 stage=parse reason=expected `=`");

        drop(runtime_watch_tx);
        assert!(control_plane.shutdown(Duration::from_secs(1)).await);
    }
}
