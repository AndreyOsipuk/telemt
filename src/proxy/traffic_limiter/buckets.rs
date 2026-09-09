use super::*;

impl ScopeMetrics {
    pub(super) fn throttle(&self, direction: RateDirection) {
        match direction {
            RateDirection::Up => {
                self.throttle_up_total.fetch_add(1, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.throttle_down_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn wait_ms(&self, direction: RateDirection, wait_ms: u64) {
        match direction {
            RateDirection::Up => {
                self.wait_up_ms_total.fetch_add(wait_ms, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.wait_down_ms_total
                    .fetch_add(wait_ms, Ordering::Relaxed);
            }
        }
    }
}

impl AtomicRatePair {
    pub(super) fn new(revision: u64, limits: RateLimitBps) -> Self {
        let rates = Self::default();
        rates.set(revision, limits);
        rates
    }

    pub(super) fn set(&self, revision: u64, limits: RateLimitBps) {
        let mut current_revision = self.revision.lock();
        if revision < *current_revision {
            return;
        }
        self.up_bps.store(limits.up_bps, Ordering::Release);
        self.down_bps.store(limits.down_bps, Ordering::Release);
        *current_revision = revision;
    }

    pub(super) fn get(&self, direction: RateDirection) -> u64 {
        match direction {
            RateDirection::Up => self.up_bps.load(Ordering::Acquire),
            RateDirection::Down => self.down_bps.load(Ordering::Acquire),
        }
    }
}

impl DirectionBucket {
    fn unpack(state: u64) -> (u64, u64) {
        (state >> PACKED_USAGE_BITS, state & PACKED_USAGE_MASK)
    }

    fn pack(epoch: u64, used: u64) -> Option<u64> {
        if epoch > PACKED_EPOCH_MAX || used > PACKED_USAGE_MASK {
            return None;
        }
        Some((epoch << PACKED_USAGE_BITS) | used)
    }

    pub(super) fn used_at(&self, epoch: u64) -> Option<u64> {
        if epoch > PACKED_EPOCH_MAX {
            return None;
        }
        let (current_epoch, used) = Self::unpack(self.state.load(Ordering::Relaxed));
        (current_epoch == epoch).then_some(used)
    }

    pub(super) fn try_reserve_at(
        &self,
        epoch: u64,
        cap: u64,
        requested: u64,
    ) -> Option<DirectionDebit<'_>> {
        if requested == 0 || cap == 0 || epoch > PACKED_EPOCH_MAX {
            return None;
        }
        let cap = cap.min(PACKED_USAGE_MASK);

        let mut observed = self.state.load(Ordering::Relaxed);
        loop {
            let (observed_epoch, observed_used) = Self::unpack(observed);
            if observed_epoch > epoch {
                return None;
            }
            let used = if observed_epoch == epoch {
                observed_used
            } else {
                0
            };
            if used >= cap {
                return None;
            }
            let remaining = cap - used;
            let grant = requested.min(remaining);
            if grant == 0 {
                return None;
            }
            let next = Self::pack(epoch, used + grant)?;
            match self.state.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(DirectionDebit {
                        bucket: self,
                        epoch,
                        refundable: grant,
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn refund_at(&self, epoch: u64, bytes: u64) {
        if bytes == 0 || epoch > PACKED_EPOCH_MAX {
            return;
        }

        let mut observed = self.state.load(Ordering::Relaxed);
        loop {
            let (observed_epoch, used) = Self::unpack(observed);
            if observed_epoch != epoch || used == 0 {
                return;
            }
            let next = Self::pack(epoch, used.saturating_sub(bytes)).unwrap_or(observed);
            match self.state.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => observed = actual,
            }
        }
    }
}

impl DirectionDebit<'_> {
    fn granted(&self) -> u64 {
        self.refundable
    }

    pub(super) fn shrink_to(&mut self, retained: u64) {
        let retained = retained.min(self.refundable);
        self.bucket
            .refund_at(self.epoch, self.refundable - retained);
        self.refundable = retained;
    }

    pub(super) fn settle(&mut self, committed: u64) {
        self.shrink_to(committed);
        self.refundable = 0;
    }

    pub(super) fn commit_all(&mut self) -> u64 {
        let committed = self.refundable;
        self.refundable = 0;
        committed
    }
}

impl Drop for DirectionDebit<'_> {
    fn drop(&mut self) {
        self.bucket.refund_at(self.epoch, self.refundable);
    }
}

impl UserBucket {
    pub(super) fn new(revision: u64, limits: RateLimitBps) -> Self {
        Self {
            rates: AtomicRatePair::new(revision, limits),
            up: DirectionBucket::default(),
            down: DirectionBucket::default(),
            active_leases: AtomicU64::new(0),
        }
    }

    pub(super) fn set_rates(&self, revision: u64, limits: RateLimitBps) {
        self.rates.set(revision, limits);
    }

    pub(super) fn try_reserve(
        &self,
        direction: RateDirection,
        requested: u64,
    ) -> (u64, Option<DirectionDebit<'_>>) {
        let cap_bps = self.rates.get(direction);
        if cap_bps == 0 {
            return (requested, None);
        }
        let cap = bytes_per_epoch(cap_bps);
        let debit = match direction {
            RateDirection::Up => self.up.try_reserve_at(current_epoch(), cap, requested),
            RateDirection::Down => self.down.try_reserve_at(current_epoch(), cap, requested),
        };
        let granted = debit.as_ref().map(DirectionDebit::granted).unwrap_or(0);
        (granted, debit)
    }
}

impl CidrDirectionBucket {
    pub(super) fn try_reserve<'a>(
        &'a self,
        user_state: &'a CidrUserDirectionState,
        cap_epoch: u64,
        requested: u64,
    ) -> (u64, Option<DirectionDebit<'a>>, Option<DirectionDebit<'a>>) {
        if requested == 0 || cap_epoch == 0 {
            return (0, None, None);
        }

        let epoch = current_epoch();
        if !user_state.ensure_active(epoch, &self.active_users) {
            return (0, None, None);
        }
        let Some(active_users) = self.active_users.used_at(epoch) else {
            return (0, None, None);
        };
        let active_users = active_users.max(1);
        let fair_share = cap_epoch.saturating_div(active_users).max(1);

        loop {
            let Some(user_used) = user_state.used.used_at(epoch) else {
                return (0, None, None);
            };
            let guaranteed_remaining = fair_share.saturating_sub(user_used);
            let (user_cap, desired) = if guaranteed_remaining > 0 {
                (fair_share, requested.min(guaranteed_remaining))
            } else {
                (PACKED_USAGE_MASK, requested.min(MAX_BORROW_CHUNK_BYTES))
            };
            let Some(mut user_debit) = user_state.used.try_reserve_at(epoch, user_cap, desired)
            else {
                if guaranteed_remaining > 0 {
                    continue;
                }
                return (0, None, None);
            };
            let user_granted = user_debit.granted();
            let Some(aggregate_debit) = self.used.try_reserve_at(epoch, cap_epoch, user_granted)
            else {
                return (0, None, None);
            };
            let granted = aggregate_debit.granted();
            if granted < user_granted {
                user_debit.shrink_to(granted);
            }
            return (granted, Some(aggregate_debit), Some(user_debit));
        }
    }
}

impl CidrUserDirectionState {
    pub(super) fn ensure_active(&self, epoch: u64, active_users: &DirectionBucket) -> bool {
        if epoch > PACKED_EPOCH_MAX {
            return false;
        }
        let mut observed = self.used.state.load(Ordering::Relaxed);
        loop {
            let (observed_epoch, _) = DirectionBucket::unpack(observed);
            if observed_epoch == epoch {
                return true;
            }
            if observed_epoch > epoch {
                return false;
            }
            let Some(mut active_debit) = active_users.try_reserve_at(epoch, PACKED_USAGE_MASK, 1)
            else {
                return false;
            };
            let Some(next) = DirectionBucket::pack(epoch, 0) else {
                return false;
            };
            match self.used.state.compare_exchange(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    active_debit.commit_all();
                    return true;
                }
                Err(actual) => {
                    drop(active_debit);
                    observed = actual;
                }
            }
        }
    }
}

impl CidrUserShare {
    pub(super) fn new() -> Self {
        Self {
            active_conns: AtomicU64::new(0),
            up: CidrUserDirectionState::default(),
            down: CidrUserDirectionState::default(),
        }
    }
}

impl CidrBucket {
    pub(super) fn new(revision: u64, limits: RateLimitBps) -> Self {
        Self {
            rates: AtomicRatePair::new(revision, limits),
            up: CidrDirectionBucket::default(),
            down: CidrDirectionBucket::default(),
            users: ShardedRegistry::new(REGISTRY_SHARDS),
            active_leases: AtomicU64::new(0),
        }
    }

    pub(super) fn set_rates(&self, revision: u64, limits: RateLimitBps) {
        self.rates.set(revision, limits);
    }

    pub(super) fn acquire_user_share(&self, user: &str) -> Arc<CidrUserShare> {
        self.users
            .get_or_insert_with(user, CidrUserShare::new, |share| {
                share.active_conns.fetch_add(1, Ordering::Relaxed);
            })
    }

    pub(super) fn release_user_share(&self, user: &str, share: &Arc<CidrUserShare>) {
        decrement_atomic_saturating(&share.active_conns, 1);
        let share_for_remove = Arc::clone(share);
        let _ = self.users.remove_if(user, |candidate| {
            Arc::ptr_eq(candidate, &share_for_remove)
                && candidate.active_conns.load(Ordering::Relaxed) == 0
        });
    }

    pub(super) fn try_reserve_for_user<'a>(
        &'a self,
        direction: RateDirection,
        share: &'a CidrUserShare,
        requested: u64,
    ) -> (u64, Option<DirectionDebit<'a>>, Option<DirectionDebit<'a>>) {
        let cap_bps = self.rates.get(direction);
        if cap_bps == 0 {
            return (requested, None, None);
        }
        let cap_epoch = bytes_per_epoch(cap_bps);
        match direction {
            RateDirection::Up => self.up.try_reserve(&share.up, cap_epoch, requested),
            RateDirection::Down => self.down.try_reserve(&share.down, cap_epoch, requested),
        }
    }

    pub(super) fn cleanup_idle_users(&self) {
        self.users
            .retain(|_, share| share.active_conns.load(Ordering::Relaxed) > 0);
    }
}
