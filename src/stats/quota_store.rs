use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::{QuotaReserveError, UserQuotaSnapshot};

/// Process-scoped per-user quota accounting shared by runtime generations.
#[derive(Default)]
pub struct QuotaStore {
    users: DashMap<String, Arc<UserQuotaCounters>>,
}

/// Atomically replaceable quota state for one configured user.
pub(crate) struct UserQuotaCounters {
    generation: ArcSwap<QuotaGeneration>,
}

struct QuotaGeneration {
    used_bytes: AtomicU64,
    last_reset_epoch_secs: u64,
}

/// Owns a quota debit until the corresponding I/O outcome is known.
#[must_use = "quota reservations must be committed or settled"]
pub(crate) struct QuotaReservation {
    generation: Arc<QuotaGeneration>,
    reserved_bytes: u64,
    total_after_reserve: u64,
}

impl QuotaStore {
    pub(crate) fn user(&self, user: &str) -> Arc<UserQuotaCounters> {
        if let Some(existing) = self.users.get(user) {
            return Arc::clone(existing.value());
        }
        Arc::clone(
            self.users
                .entry(user.to_string())
                .or_insert_with(|| Arc::new(UserQuotaCounters::default()))
                .value(),
        )
    }

    pub(crate) fn used(&self, user: &str) -> u64 {
        self.users.get(user).map(|state| state.used()).unwrap_or(0)
    }

    pub(crate) fn load(&self, user: &str, used_bytes: u64, last_reset_epoch_secs: u64) {
        let state = self.user(user);
        state.replace(used_bytes, last_reset_epoch_secs);
    }

    pub(crate) fn reset(&self, user: &str, now_epoch_secs: u64) -> UserQuotaSnapshot {
        let state = self.user(user);
        state.replace(0, now_epoch_secs);
        UserQuotaSnapshot {
            used_bytes: 0,
            last_reset_epoch_secs: now_epoch_secs,
        }
    }

    pub(crate) fn remove(&self, user: &str) {
        self.users.remove(user);
    }

    pub(crate) fn snapshot(&self) -> HashMap<String, UserQuotaSnapshot> {
        let mut out = HashMap::new();
        for entry in self.users.iter() {
            let state = entry.value();
            let generation = state.generation.load_full();
            let used_bytes = generation.used_bytes.load(Ordering::Relaxed);
            let last_reset_epoch_secs = generation.last_reset_epoch_secs;
            if used_bytes == 0 && last_reset_epoch_secs == 0 {
                continue;
            }
            out.insert(
                entry.key().clone(),
                UserQuotaSnapshot {
                    used_bytes,
                    last_reset_epoch_secs,
                },
            );
        }
        out
    }
}

impl Default for UserQuotaCounters {
    fn default() -> Self {
        Self {
            generation: ArcSwap::from_pointee(QuotaGeneration {
                used_bytes: AtomicU64::new(0),
                last_reset_epoch_secs: 0,
            }),
        }
    }
}

impl UserQuotaCounters {
    fn replace(&self, used_bytes: u64, last_reset_epoch_secs: u64) {
        self.generation.store(Arc::new(QuotaGeneration {
            used_bytes: AtomicU64::new(used_bytes),
            last_reset_epoch_secs,
        }));
    }

    #[inline]
    pub(crate) fn used(&self) -> u64 {
        self.generation.load().used_bytes.load(Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn charge(&self, bytes: u64) -> u64 {
        self.generation
            .load_full()
            .used_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes)
    }

    #[inline]
    pub(crate) fn try_reserve(
        &self,
        bytes: u64,
        limit: u64,
    ) -> Result<QuotaReservation, QuotaReserveError> {
        let generation = self.generation.load_full();
        let current = generation.used_bytes.load(Ordering::Relaxed);
        if bytes > limit.saturating_sub(current) {
            return Err(QuotaReserveError::LimitExceeded);
        }

        let next = current.saturating_add(bytes);
        match generation.used_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => Ok(QuotaReservation {
                generation,
                reserved_bytes: bytes,
                total_after_reserve: next,
            }),
            Err(_) => Err(QuotaReserveError::Contended),
        }
    }
}

impl QuotaReservation {
    /// Returns the number of bytes held by this reservation.
    pub(crate) fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// Commits the complete reservation and returns the generation-local total.
    pub(crate) fn commit(mut self) -> u64 {
        self.reserved_bytes = 0;
        self.total_after_reserve
    }

    /// Commits part of the reservation and refunds the remainder.
    pub(crate) fn settle(mut self, committed_bytes: u64) {
        let committed_bytes = committed_bytes.min(self.reserved_bytes);
        refund_generation(
            self.generation.as_ref(),
            self.reserved_bytes - committed_bytes,
        );
        self.reserved_bytes = 0;
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        refund_generation(self.generation.as_ref(), self.reserved_bytes);
    }
}

fn refund_generation(generation: &QuotaGeneration, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let mut current = generation.used_bytes.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(bytes);
        match generation.used_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Stats;
    use std::sync::Barrier;

    #[test]
    fn quota_counters_are_shared_across_stats_generations() {
        let store = Arc::new(QuotaStore::default());
        let first = Stats::with_quota_store(store.clone());
        store.user("alice").charge(512);
        assert_eq!(first.get_user_quota_used("alice"), 512);

        let second = Stats::with_quota_store(store);
        assert_eq!(second.get_user_quota_used("alice"), 512);
        second.reset_user_quota("alice");
        assert_eq!(first.get_user_quota_used("alice"), 0);
    }

    #[test]
    fn quota_snapshot_never_combines_different_generations() {
        const ITERATIONS: u64 = 10_000;

        let store = Arc::new(QuotaStore::default());
        store.load("alice", 1, 1);
        let barrier = Arc::new(Barrier::new(2));
        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            for generation in 2..=ITERATIONS {
                writer_store.load("alice", generation, generation);
            }
        });

        barrier.wait();
        for _ in 0..ITERATIONS {
            let snapshot = store.snapshot().remove("alice").unwrap();
            assert_eq!(snapshot.used_bytes, snapshot.last_reset_epoch_secs);
        }
        writer.join().unwrap();
    }

    #[test]
    fn repeated_old_generation_refunds_leave_new_usage_intact() {
        const ITERATIONS: u64 = 10_000;

        let store = QuotaStore::default();
        let state = store.user("alice");
        for generation in 1..=ITERATIONS {
            let reservation = state.try_reserve(80, 100).unwrap();
            store.load("alice", 40, generation);
            drop(reservation);
            assert_eq!(store.used("alice"), 40);
            store.reset("alice", generation);
        }
    }
}
