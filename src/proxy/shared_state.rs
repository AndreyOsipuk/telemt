use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::proxy::direct_buffer_budget::{DirectBufferBudget, fallback_direct_buffer_hard_limit};
use crate::proxy::handshake::{AuthProbeSaturationState, AuthProbeState};
use crate::proxy::middle_relay::{DesyncDedupRotationState, RelayIdleCandidateRegistry};
use crate::proxy::traffic_limiter::TrafficLimiter;

const HANDSHAKE_RECENT_USER_RING_LEN: usize = 64;
const MASKING_FALLBACK_MAX_CONCURRENT: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConntrackCloseReason {
    NormalEof,
    Timeout,
    Pressure,
    Reset,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConntrackCloseEvent {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) reason: ConntrackCloseReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConntrackClosePublishResult {
    Sent,
    Disabled,
    QueueFull,
    QueueClosed,
}

/// Controls whether a relay tuple maps to a real kernel conntrack entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConntrackClosePolicy {
    /// Publish closure for a tuple backed by an accepted kernel TCP flow.
    Publish,
    /// Suppress closure for a virtual transport tuple with no kernel flow.
    Suppress,
}

pub(crate) struct HandshakeSharedState {
    pub(crate) auth_probe: DashMap<IpAddr, AuthProbeState>,
    pub(crate) auth_probe_saturation: Mutex<Option<AuthProbeSaturationState>>,
    pub(crate) auth_probe_eviction_hasher: RandomState,
    pub(crate) invalid_secret_warned: Mutex<HashSet<(String, String)>>,
    pub(crate) unknown_sni_warn_next_allowed: Mutex<Option<Instant>>,
    pub(crate) sticky_user_by_ip: DashMap<IpAddr, u32>,
    pub(crate) sticky_user_by_ip_prefix: DashMap<u64, u32>,
    pub(crate) sticky_user_by_sni_hash: DashMap<u64, u32>,
    pub(crate) recent_user_ring: Box<[AtomicU32]>,
    pub(crate) recent_user_ring_seq: AtomicU64,
    pub(crate) auth_expensive_checks_total: AtomicU64,
    pub(crate) auth_budget_exhausted_total: AtomicU64,
}

pub(crate) struct MiddleRelaySharedState {
    pub(crate) desync_dedup: DashMap<u64, Instant>,
    pub(crate) desync_dedup_previous: DashMap<u64, Instant>,
    pub(crate) desync_hasher: RandomState,
    pub(crate) desync_full_cache_last_emit_at: Mutex<Option<Instant>>,
    pub(crate) desync_dedup_rotation_state: Mutex<DesyncDedupRotationState>,
    pub(crate) relay_idle_registry: RelayIdleCandidateRegistry,
    pub(crate) relay_idle_mark_seq: AtomicU64,
}

#[derive(Default)]
struct UserAdmissionState {
    disabled_users: HashSet<String>,
    sessions_by_user: HashMap<String, HashMap<u64, CancellationToken>>,
}

pub(crate) struct ProxySharedState {
    pub(crate) handshake: HandshakeSharedState,
    pub(crate) middle_relay: MiddleRelaySharedState,
    pub(crate) traffic_limiter: Arc<TrafficLimiter>,
    pub(crate) direct_buffer_budget: Arc<DirectBufferBudget>,
    user_admission: ParkingMutex<UserAdmissionState>,
    pub(crate) conntrack_pressure_active: AtomicBool,
    pub(crate) conntrack_close_tx: Mutex<Option<mpsc::Sender<ConntrackCloseEvent>>>,
    masking_fallback_permits: Arc<Semaphore>,
}

#[must_use = "registered user sessions must be kept alive until relay completion"]
pub(crate) struct UserSessionRegistration {
    token: CancellationToken,
    _guard: UserSessionGuard,
}

impl UserSessionRegistration {
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

struct UserSessionGuard {
    shared: Arc<ProxySharedState>,
    key: (String, u64),
}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        let mut admission = self.shared.user_admission.lock();
        let remove_user = admission
            .sessions_by_user
            .get_mut(&self.key.0)
            .map(|sessions| {
                sessions.remove(&self.key.1);
                sessions.is_empty()
            })
            .unwrap_or(false);
        if remove_user {
            admission.sessions_by_user.remove(&self.key.0);
        }
    }
}

impl ProxySharedState {
    pub(crate) fn new() -> Arc<Self> {
        Self::new_with_direct_buffer_budget(DirectBufferBudget::new(
            fallback_direct_buffer_hard_limit(),
        ))
    }

    /// Creates process state with the startup-resolved Direct buffer envelope.
    pub(crate) fn new_with_direct_buffer_budget(
        direct_buffer_budget: Arc<DirectBufferBudget>,
    ) -> Arc<Self> {
        Arc::new(Self {
            handshake: HandshakeSharedState {
                auth_probe: DashMap::new(),
                auth_probe_saturation: Mutex::new(None),
                auth_probe_eviction_hasher: RandomState::new(),
                invalid_secret_warned: Mutex::new(HashSet::new()),
                unknown_sni_warn_next_allowed: Mutex::new(None),
                sticky_user_by_ip: DashMap::new(),
                sticky_user_by_ip_prefix: DashMap::new(),
                sticky_user_by_sni_hash: DashMap::new(),
                recent_user_ring: std::iter::repeat_with(|| AtomicU32::new(0))
                    .take(HANDSHAKE_RECENT_USER_RING_LEN)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                recent_user_ring_seq: AtomicU64::new(0),
                auth_expensive_checks_total: AtomicU64::new(0),
                auth_budget_exhausted_total: AtomicU64::new(0),
            },
            middle_relay: MiddleRelaySharedState {
                desync_dedup: DashMap::new(),
                desync_dedup_previous: DashMap::new(),
                desync_hasher: RandomState::new(),
                desync_full_cache_last_emit_at: Mutex::new(None),
                desync_dedup_rotation_state: Mutex::new(DesyncDedupRotationState::default()),
                relay_idle_registry: RelayIdleCandidateRegistry::default(),
                relay_idle_mark_seq: AtomicU64::new(0),
            },
            traffic_limiter: TrafficLimiter::new(),
            direct_buffer_budget,
            user_admission: ParkingMutex::new(UserAdmissionState::default()),
            conntrack_pressure_active: AtomicBool::new(false),
            conntrack_close_tx: Mutex::new(None),
            masking_fallback_permits: Arc::new(Semaphore::new(MASKING_FALLBACK_MAX_CONCURRENT)),
        })
    }

    /// Attempts to reserve one masking fallback slot for a pre-auth connection.
    pub(crate) fn try_acquire_masking_fallback_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.masking_fallback_permits
            .clone()
            .try_acquire_owned()
            .ok()
    }

    pub(crate) fn is_user_enabled(&self, user: &str) -> bool {
        !self.user_admission.lock().disabled_users.contains(user)
    }

    pub(crate) fn set_user_enabled(&self, user: &str, enabled: bool) -> (bool, usize) {
        let (newly_disabled, tokens) = {
            let mut admission = self.user_admission.lock();
            if enabled {
                admission.disabled_users.remove(user);
                (false, Vec::new())
            } else {
                let newly_disabled = admission.disabled_users.insert(user.to_string());
                let tokens = admission
                    .sessions_by_user
                    .get(user)
                    .map(|sessions| sessions.values().cloned().collect())
                    .unwrap_or_default();
                (newly_disabled, tokens)
            }
        };
        for token in &tokens {
            token.cancel();
        }
        (newly_disabled, tokens.len())
    }

    pub(crate) fn apply_user_enabled_config(
        &self,
        user_enabled: &HashMap<String, bool>,
    ) -> Vec<(String, usize)> {
        let desired_disabled = user_enabled
            .iter()
            .filter_map(|(user, enabled)| (!*enabled).then_some(user.clone()))
            .collect::<HashSet<_>>();
        let cancellations = {
            let mut admission = self.user_admission.lock();
            let newly_disabled = desired_disabled
                .difference(&admission.disabled_users)
                .cloned()
                .collect::<Vec<_>>();
            admission.disabled_users = desired_disabled;
            newly_disabled
                .into_iter()
                .map(|user| {
                    let tokens = admission
                        .sessions_by_user
                        .get(&user)
                        .map(|sessions| sessions.values().cloned().collect())
                        .unwrap_or_default();
                    (user, tokens)
                })
                .collect::<Vec<(String, Vec<CancellationToken>)>>()
        };
        cancellations
            .into_iter()
            .map(|(user, tokens)| {
                for token in &tokens {
                    token.cancel();
                }
                (user, tokens.len())
            })
            .collect()
    }

    pub(crate) fn register_user_session(
        self: &Arc<Self>,
        user: &str,
        session_id: u64,
    ) -> Option<UserSessionRegistration> {
        let token = CancellationToken::new();
        let key = (user.to_string(), session_id);
        let mut admission = self.user_admission.lock();
        if admission.disabled_users.contains(user) {
            return None;
        }
        admission
            .sessions_by_user
            .entry(key.0.clone())
            .or_default()
            .insert(session_id, token.clone());
        Some(UserSessionRegistration {
            token,
            _guard: UserSessionGuard {
                shared: Arc::clone(self),
                key,
            },
        })
    }

    pub(crate) fn cancel_user_sessions(&self, user: &str) -> usize {
        let tokens: Vec<CancellationToken> = self
            .user_admission
            .lock()
            .sessions_by_user
            .get(user)
            .map(|sessions| sessions.values().cloned().collect())
            .unwrap_or_default();
        for token in &tokens {
            token.cancel();
        }
        tokens.len()
    }

    pub(crate) fn set_conntrack_close_sender(&self, tx: mpsc::Sender<ConntrackCloseEvent>) {
        match self.conntrack_close_tx.lock() {
            Ok(mut guard) => {
                *guard = Some(tx);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = Some(tx);
                self.conntrack_close_tx.clear_poison();
            }
        }
    }

    pub(crate) fn disable_conntrack_close_sender(&self) {
        match self.conntrack_close_tx.lock() {
            Ok(mut guard) => {
                *guard = None;
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = None;
                self.conntrack_close_tx.clear_poison();
            }
        }
    }

    pub(crate) fn publish_conntrack_close_event(
        &self,
        event: ConntrackCloseEvent,
    ) -> ConntrackClosePublishResult {
        let tx = match self.conntrack_close_tx.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                let cloned = guard.clone();
                self.conntrack_close_tx.clear_poison();
                cloned
            }
        };

        let Some(tx) = tx else {
            return ConntrackClosePublishResult::Disabled;
        };

        match tx.try_send(event) {
            Ok(()) => ConntrackClosePublishResult::Sent,
            Err(mpsc::error::TrySendError::Full(_)) => ConntrackClosePublishResult::QueueFull,
            Err(mpsc::error::TrySendError::Closed(_)) => ConntrackClosePublishResult::QueueClosed,
        }
    }

    pub(crate) fn set_conntrack_pressure_active(&self, active: bool) {
        self.conntrack_pressure_active
            .store(active, Ordering::Relaxed);
    }

    pub(crate) fn conntrack_pressure_active(&self) -> bool {
        self.conntrack_pressure_active.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_enabled_config_sync_tracks_disabled_overrides() {
        let shared = ProxySharedState::new();
        assert!(shared.is_user_enabled("alice"));

        let mut user_enabled = HashMap::new();
        user_enabled.insert("alice".to_string(), false);
        user_enabled.insert("bob".to_string(), true);

        let mut newly_disabled = shared.apply_user_enabled_config(&user_enabled);
        newly_disabled.sort();
        assert_eq!(newly_disabled, vec![("alice".to_string(), 0)]);
        assert!(!shared.is_user_enabled("alice"));
        assert!(shared.is_user_enabled("bob"));

        assert!(shared.apply_user_enabled_config(&user_enabled).is_empty());

        user_enabled.clear();
        assert!(shared.apply_user_enabled_config(&user_enabled).is_empty());
        assert!(shared.is_user_enabled("alice"));
    }

    #[test]
    fn cancel_user_sessions_cancels_only_registered_matching_user() {
        let shared = ProxySharedState::new();
        let alice_1 = shared.register_user_session("alice", 1).unwrap();
        let alice_2 = shared.register_user_session("alice", 2).unwrap();
        let bob = shared.register_user_session("bob", 1).unwrap();
        let alice_1_token = alice_1.token();
        let alice_2_token = alice_2.token();
        let bob_token = bob.token();

        drop(alice_1);

        assert_eq!(shared.cancel_user_sessions("alice"), 1);
        assert!(!alice_1_token.is_cancelled());
        assert!(alice_2_token.is_cancelled());
        assert!(!bob_token.is_cancelled());
    }

    #[test]
    fn disabled_user_cannot_register_after_the_cancellation_snapshot() {
        let shared = ProxySharedState::new();

        assert_eq!(shared.set_user_enabled("alice", false), (true, 0));
        assert_eq!(shared.cancel_user_sessions("alice"), 0);

        let late = shared.register_user_session("alice", 1);
        assert!(
            late.is_none(),
            "a session registered after disable returned must be rejected"
        );
    }

    #[test]
    fn disabling_user_cancels_existing_sessions_before_return() {
        let shared = ProxySharedState::new();
        let registration = shared.register_user_session("alice", 1).unwrap();
        let token = registration.token();

        assert_eq!(shared.set_user_enabled("alice", false), (true, 1));
        assert!(token.is_cancelled());
        assert!(shared.register_user_session("alice", 2).is_none());

        assert_eq!(shared.set_user_enabled("alice", true), (false, 0));
        assert!(shared.register_user_session("alice", 3).is_some());
    }

    #[test]
    fn concurrent_disable_and_registration_never_leave_a_live_session() {
        const ITERATIONS: usize = 10_000;

        let shared = ProxySharedState::new();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let register_shared = Arc::clone(&shared);
        let register_barrier = Arc::clone(&barrier);
        let register = std::thread::spawn(move || {
            let mut registrations = Vec::with_capacity(ITERATIONS);
            for session_id in 0..ITERATIONS as u64 {
                let user = format!("user-{session_id}");
                register_barrier.wait();
                registrations.push(register_shared.register_user_session(&user, session_id));
            }
            registrations
        });

        for session_id in 0..ITERATIONS as u64 {
            let user = format!("user-{session_id}");
            barrier.wait();
            shared.set_user_enabled(&user, false);
        }

        for registration in register.join().unwrap().into_iter().flatten() {
            assert!(registration.token().is_cancelled());
        }
    }
}
