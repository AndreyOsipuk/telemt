use super::*;

impl TrafficLease {
    /// Reserves shaping budget until the associated I/O result is settled.
    pub(crate) fn try_reserve(
        &self,
        direction: RateDirection,
        requested: u64,
    ) -> TrafficReservation<'_> {
        if requested == 0 {
            return TrafficReservation {
                result: TrafficConsumeResult {
                    granted: 0,
                    blocked_user: false,
                    blocked_cidr: false,
                },
                user: None,
                cidr: None,
                cidr_user: None,
            };
        }

        let mut granted = requested;
        let mut user_debit = None;
        if let Some(user_bucket) = self.user_bucket.as_ref() {
            let (user_granted, debit) = user_bucket.try_reserve(direction, granted);
            user_debit = debit;
            if user_granted == 0 {
                self.limiter.observe_throttle(direction, true, false);
                return TrafficReservation {
                    result: TrafficConsumeResult {
                        granted: 0,
                        blocked_user: true,
                        blocked_cidr: false,
                    },
                    user: user_debit,
                    cidr: None,
                    cidr_user: None,
                };
            }
            granted = user_granted;
        }

        let mut cidr_debit = None;
        let mut cidr_user_debit = None;
        if let (Some(cidr_bucket), Some(cidr_user_share)) =
            (self.cidr_bucket.as_ref(), self.cidr_user_share.as_ref())
        {
            let (cidr_granted, aggregate_debit, share_debit) =
                cidr_bucket.try_reserve_for_user(direction, cidr_user_share, granted);
            cidr_debit = aggregate_debit;
            cidr_user_debit = share_debit;
            if cidr_granted < granted
                && let Some(debit) = user_debit.as_mut()
            {
                debit.shrink_to(cidr_granted);
            }
            if cidr_granted == 0 {
                self.limiter.observe_throttle(direction, false, true);
                return TrafficReservation {
                    result: TrafficConsumeResult {
                        granted: 0,
                        blocked_user: false,
                        blocked_cidr: true,
                    },
                    user: user_debit,
                    cidr: cidr_debit,
                    cidr_user: cidr_user_debit,
                };
            }
            granted = cidr_granted;
        }

        TrafficReservation {
            result: TrafficConsumeResult {
                granted,
                blocked_user: false,
                blocked_cidr: false,
            },
            user: user_debit,
            cidr: cidr_debit,
            cidr_user: cidr_user_debit,
        }
    }

    pub fn try_consume(&self, direction: RateDirection, requested: u64) -> TrafficConsumeResult {
        let reservation = self.try_reserve(direction, requested);
        let result = reservation.result();
        reservation.settle_written(result.granted);
        result
    }

    pub fn observe_wait_ms(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
        wait_ms: u64,
    ) {
        if wait_ms == 0 {
            return;
        }
        self.limiter
            .observe_wait(direction, blocked_user, blocked_cidr, wait_ms);
    }
}

impl TrafficReservation<'_> {
    /// Returns the shaping decision associated with this reservation.
    pub(crate) fn result(&self) -> TrafficConsumeResult {
        self.result
    }

    /// Commits written bytes and refunds the uncommitted remainder.
    pub(crate) fn settle_written(mut self, committed: u64) {
        let committed = committed.min(self.result.granted);
        if let Some(debit) = self.user.as_mut() {
            debit.settle(committed);
        }
        if let Some(debit) = self.cidr.as_mut() {
            debit.settle(committed);
        }
        if let Some(debit) = self.cidr_user.as_mut() {
            debit.settle(committed);
        }
    }
}

impl Drop for TrafficLease {
    fn drop(&mut self) {
        if let Some(bucket) = self.user_bucket.as_ref() {
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.user_scope.active_leases, 1);
        }

        if let Some(bucket) = self.cidr_bucket.as_ref() {
            if let (Some(user_key), Some(share)) =
                (self.cidr_user_key.as_ref(), self.cidr_user_share.as_ref())
            {
                bucket.release_user_share(user_key, share);
            }
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.cidr_scope.active_leases, 1);
        }
    }
}
