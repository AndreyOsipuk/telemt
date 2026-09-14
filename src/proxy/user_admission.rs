use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::{Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;

use crate::crypto::sha256;

/// Stable secret identity used to fence authentication across runtime generations.
pub(crate) type UserCredentialId = [u8; 16];

/// Monotonic identity of one configured username lifetime.
pub(crate) type UserIncarnation = u64;

#[derive(Clone, Copy, PartialEq, Eq)]
struct EffectiveUser {
    credential_id: UserCredentialId,
    enabled: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UserOverride {
    Present(EffectiveUser),
    Deleted,
}

struct UserRecord {
    configured: Option<EffectiveUser>,
    mutation_override: Option<UserOverride>,
    incarnation: UserIncarnation,
}

impl UserRecord {
    fn effective(&self) -> Option<EffectiveUser> {
        match self.mutation_override {
            Some(UserOverride::Present(user)) => Some(user),
            Some(UserOverride::Deleted) => None,
            None => self.configured,
        }
    }
}

struct RegisteredOwner {
    token: CancellationToken,
    incarnation: UserIncarnation,
}

#[derive(Default)]
struct UserAdmissionState {
    initialized: bool,
    epoch: u64,
    next_incarnation: UserIncarnation,
    next_registration_id: u64,
    users: HashMap<String, UserRecord>,
    owners_by_user: HashMap<String, HashMap<u64, RegisteredOwner>>,
}

impl UserAdmissionState {
    fn allocate_incarnation(&mut self) -> UserIncarnation {
        self.next_incarnation = self.next_incarnation.checked_add(1).unwrap_or(u64::MAX);
        self.next_incarnation
    }

    fn allocate_registration_id(&mut self) -> Option<u64> {
        let next = self.next_registration_id.checked_add(1)?;
        self.next_registration_id = next;
        Some(next)
    }

    fn bump_epoch(&mut self) {
        self.epoch = self.epoch.checked_add(1).unwrap_or(u64::MAX);
    }

    fn owner_tokens(&self, user: &str) -> Vec<CancellationToken> {
        self.owners_by_user
            .get(user)
            .map(|owners| owners.values().map(|owner| owner.token.clone()).collect())
            .unwrap_or_default()
    }
}

/// Result of one durable user mutation applied to the process admission authority.
pub(crate) struct UserMutationResult {
    /// Incarnation invalidated or created by the mutation.
    pub(crate) incarnation: UserIncarnation,
    /// Number of live owners cancelled by the mutation.
    pub(crate) cancelled: usize,
    /// Whether the effective enabled state changed from enabled to disabled.
    pub(crate) newly_disabled: bool,
}

/// Process-owned user authentication and live-owner authority.
pub(crate) struct UserAdmissionAuthority {
    state: Mutex<UserAdmissionState>,
}

impl UserAdmissionAuthority {
    /// Creates an uninitialized authority for isolated tests and startup wiring.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(UserAdmissionState::default()),
        })
    }

    /// Returns the mutation epoch used to reject stale candidate configuration.
    pub(crate) fn epoch(&self) -> u64 {
        self.state.lock().epoch
    }

    /// Reconciles the complete configured user set into the process authority.
    pub(crate) fn apply_config(
        &self,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Vec<(String, usize)> {
        self.apply_config_locked(None, users, user_enabled)
            .unwrap_or_default()
    }

    /// Applies a candidate configuration only if no newer authority mutation occurred.
    pub(crate) fn apply_config_if_epoch(
        &self,
        expected_epoch: u64,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        self.apply_config_locked(Some(expected_epoch), users, user_enabled)
    }

    fn apply_config_locked(
        &self,
        expected_epoch: Option<u64>,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        let configured = users
            .iter()
            .filter_map(|(user, secret)| {
                credential_id_from_hex(secret).map(|credential_id| {
                    (
                        user.clone(),
                        EffectiveUser {
                            credential_id,
                            enabled: user_enabled.get(user).copied().unwrap_or(true),
                        },
                    )
                })
            })
            .collect::<HashMap<_, _>>();
        let cancellations = {
            let mut state = self.state.lock();
            if expected_epoch.is_some_and(|epoch| state.epoch != epoch) {
                return None;
            }

            let mut changed = !state.initialized;
            state.initialized = true;
            let existing_users = state.users.keys().cloned().collect::<Vec<_>>();
            let mut cancellations = Vec::new();

            for user in existing_users {
                let desired = configured.get(&user).copied();
                let old_effective = state.users.get(&user).and_then(UserRecord::effective);
                let override_matches = state.users.get(&user).is_some_and(|record| {
                    matches!(
                        (record.mutation_override, desired),
                        (Some(UserOverride::Present(current)), Some(next)) if current == next
                    ) || matches!(
                        (record.mutation_override, desired),
                        (Some(UserOverride::Deleted), None)
                    )
                });

                if let Some(record) = state.users.get_mut(&user) {
                    if record.configured != desired || override_matches {
                        changed = true;
                    }
                    record.configured = desired;
                    if override_matches {
                        record.mutation_override = None;
                    }
                }

                let new_effective = state.users.get(&user).and_then(UserRecord::effective);
                if old_effective != new_effective {
                    let identity_changed = old_effective.map(|entry| entry.credential_id)
                        != new_effective.map(|entry| entry.credential_id);
                    if identity_changed {
                        let incarnation = state.allocate_incarnation();
                        if let Some(record) = state.users.get_mut(&user) {
                            record.incarnation = incarnation;
                        }
                    }
                    if identity_changed
                        || old_effective.is_some_and(|entry| entry.enabled)
                            && new_effective.is_none_or(|entry| !entry.enabled)
                    {
                        let tokens = state.owner_tokens(&user);
                        cancellations.push((user, tokens));
                    }
                }
            }

            for (user, desired) in configured {
                if state.users.contains_key(&user) {
                    continue;
                }
                changed = true;
                let incarnation = state.allocate_incarnation();
                state.users.insert(
                    user,
                    UserRecord {
                        configured: Some(desired),
                        mutation_override: None,
                        incarnation,
                    },
                );
            }

            if changed {
                state.bump_epoch();
            }
            cancellations
        };
        Some(cancel_owners(cancellations))
    }

    /// Applies one persisted user value ahead of asynchronous runtime reload.
    pub(crate) fn stage_user(
        &self,
        user: &str,
        secret: &str,
        enabled: bool,
    ) -> Option<UserMutationResult> {
        let credential_id = credential_id_from_hex(secret)?;
        let desired = EffectiveUser {
            credential_id,
            enabled,
        };
        let (incarnation, newly_disabled, tokens) = {
            let mut state = self.state.lock();
            let previous = state.users.get(user).and_then(UserRecord::effective);
            let identity_changed = previous.map(|entry| entry.credential_id) != Some(credential_id);
            let incarnation = if identity_changed {
                state.allocate_incarnation()
            } else {
                state
                    .users
                    .get(user)
                    .map(|record| record.incarnation)
                    .unwrap_or_else(|| state.allocate_incarnation())
            };
            let record = state.users.entry(user.to_string()).or_insert(UserRecord {
                configured: None,
                mutation_override: None,
                incarnation,
            });
            record.mutation_override = Some(UserOverride::Present(desired));
            record.incarnation = incarnation;
            state.initialized = true;
            state.bump_epoch();
            let newly_disabled = previous.is_some_and(|entry| entry.enabled) && !enabled;
            let tokens = if identity_changed || !enabled {
                state.owner_tokens(user)
            } else {
                Vec::new()
            };
            (incarnation, newly_disabled, tokens)
        };
        let cancelled = tokens.len();
        for token in tokens {
            token.cancel();
        }
        Some(UserMutationResult {
            incarnation,
            cancelled,
            newly_disabled,
        })
    }

    /// Installs a deletion tombstone and cancels every owner of the old incarnation.
    pub(crate) fn delete_user(&self, user: &str) -> UserMutationResult {
        let (incarnation, newly_disabled, tokens) = {
            let mut state = self.state.lock();
            let previous = state.users.get(user).and_then(UserRecord::effective);
            let incarnation = state.allocate_incarnation();
            let record = state.users.entry(user.to_string()).or_insert(UserRecord {
                configured: None,
                mutation_override: None,
                incarnation,
            });
            record.mutation_override = Some(UserOverride::Deleted);
            record.incarnation = incarnation;
            state.initialized = true;
            state.bump_epoch();
            (
                incarnation,
                previous.is_some_and(|entry| entry.enabled),
                state.owner_tokens(user),
            )
        };
        let cancelled = tokens.len();
        for token in tokens {
            token.cancel();
        }
        UserMutationResult {
            incarnation,
            cancelled,
            newly_disabled,
        }
    }

    /// Returns whether the effective process policy currently enables a user.
    pub(crate) fn is_user_enabled(&self, user: &str) -> bool {
        let state = self.state.lock();
        if !state.initialized {
            return true;
        }
        state
            .users
            .get(user)
            .and_then(UserRecord::effective)
            .is_some_and(|entry| entry.enabled)
    }

    /// Returns the authenticated incarnation for an exact current credential.
    pub(crate) fn authenticated_incarnation(
        &self,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserIncarnation> {
        let state = self.state.lock();
        if !state.initialized {
            return Some(0);
        }
        let record = state.users.get(user)?;
        let effective = record.effective()?;
        (effective.enabled && effective.credential_id == credential_id).then_some(record.incarnation)
    }

    /// Starts a short publication critical section for one authenticated owner.
    pub(crate) fn claim_authenticated(
        self: &Arc<Self>,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserAdmissionPublication<'_>> {
        let mut state = self.state.lock();
        let incarnation = if state.initialized {
            let record = state.users.get(user)?;
            let effective = record.effective()?;
            if !effective.enabled || effective.credential_id != credential_id {
                return None;
            }
            record.incarnation
        } else {
            0
        };
        let registration_id = state.allocate_registration_id()?;
        let token = CancellationToken::new();
        let active = Arc::new(AtomicBool::new(false));
        Some(UserAdmissionPublication {
            state,
            authority: Arc::clone(self),
            user: user.to_string(),
            registration_id,
            incarnation,
            token,
            active,
            registration_taken: false,
        })
    }

    /// Registers a legacy owner when no credential snapshot is available.
    pub(crate) fn register_legacy(
        self: &Arc<Self>,
        user: &str,
    ) -> Option<UserSessionRegistration> {
        let credential_id = {
            let state = self.state.lock();
            if !state.initialized {
                [0; 16]
            } else {
                state.users.get(user)?.effective()?.credential_id
            }
        };
        let mut publication = self.claim_authenticated(user, credential_id)?;
        let registration = publication.take_registration()?;
        publication.commit();
        Some(registration)
    }

    /// Cancels all current owners without changing admission policy.
    pub(crate) fn cancel_user_owners(&self, user: &str) -> usize {
        let tokens = self.state.lock().owner_tokens(user);
        let count = tokens.len();
        for token in tokens {
            token.cancel();
        }
        count
    }

    fn unregister(&self, user: &str, registration_id: u64, incarnation: UserIncarnation) {
        let mut state = self.state.lock();
        let remove_user = state
            .owners_by_user
            .get_mut(user)
            .map(|owners| {
                if owners
                    .get(&registration_id)
                    .is_some_and(|owner| owner.incarnation == incarnation)
                {
                    owners.remove(&registration_id);
                }
                owners.is_empty()
            })
            .unwrap_or(false);
        if remove_user {
            state.owners_by_user.remove(user);
        }
    }
}

/// Authority lock retained until the caller publishes its owned object.
pub(crate) struct UserAdmissionPublication<'a> {
    state: MutexGuard<'a, UserAdmissionState>,
    authority: Arc<UserAdmissionAuthority>,
    user: String,
    registration_id: u64,
    incarnation: UserIncarnation,
    token: CancellationToken,
    active: Arc<AtomicBool>,
    registration_taken: bool,
}

impl UserAdmissionPublication<'_> {
    /// Moves the registered owner out while retaining the authority lock.
    pub(crate) fn take_registration(&mut self) -> Option<UserSessionRegistration> {
        if self.registration_taken {
            return None;
        }
        self.registration_taken = true;
        Some(UserSessionRegistration {
            authority: Arc::clone(&self.authority),
            user: self.user.clone(),
            registration_id: self.registration_id,
            incarnation: self.incarnation,
            token: self.token.clone(),
            active: Arc::clone(&self.active),
        })
    }

    /// Commits the owner record after the caller publishes its lifecycle object.
    pub(crate) fn commit(mut self) {
        if !self.registration_taken {
            return;
        }
        self.state
            .owners_by_user
            .entry(self.user.clone())
            .or_default()
            .insert(
                self.registration_id,
                RegisteredOwner {
                    token: self.token.clone(),
                    incarnation: self.incarnation,
                },
            );
        self.active.store(true, Ordering::Release);
    }
}

/// RAII ownership registered against one user incarnation.
#[must_use = "registered user ownership must be retained until lifecycle completion"]
pub(crate) struct UserSessionRegistration {
    authority: Arc<UserAdmissionAuthority>,
    user: String,
    registration_id: u64,
    incarnation: UserIncarnation,
    token: CancellationToken,
    active: Arc<AtomicBool>,
}

impl UserSessionRegistration {
    /// Returns the cancellation signal for revocation or credential replacement.
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Returns the immutable user incarnation owned by this registration.
    pub(crate) fn incarnation(&self) -> UserIncarnation {
        self.incarnation
    }

    /// Returns whether revocation has cancelled this ownership.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl Drop for UserSessionRegistration {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::AcqRel) {
            self.authority
                .unregister(&self.user, self.registration_id, self.incarnation);
        }
    }
}

/// Derives the stable credential identity from one decoded MTProxy secret.
pub(crate) fn credential_id(secret: &[u8; 16]) -> UserCredentialId {
    let digest = sha256(secret);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Decodes one configured secret and derives its credential identity.
pub(crate) fn credential_id_from_hex(secret: &str) -> Option<UserCredentialId> {
    let decoded = hex::decode(secret).ok()?;
    let secret: [u8; 16] = decoded.try_into().ok()?;
    Some(credential_id(&secret))
}

fn cancel_owners(
    cancellations: Vec<(String, Vec<CancellationToken>)>,
) -> Vec<(String, usize)> {
    cancellations
        .into_iter()
        .map(|(user, tokens)| {
            let count = tokens.len();
            for token in tokens {
                token.cancel();
            }
            (user, count)
        })
        .collect()
}

#[cfg(test)]
#[path = "user_admission/tests.rs"]
mod tests;
