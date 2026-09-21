use super::*;
use crate::config::CidrRateLimitKey;

fn rate(up_bps: u64, down_bps: u64) -> RateLimitBps {
    RateLimitBps { up_bps, down_bps }
}

#[test]
fn explicit_cidr_rule_wins_over_auto_template() {
    let limiter = TrafficLimiter::new();
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(CidrRateLimitKey::AutoV4(24), rate(1_000, 0));
    cidr_limits.insert(
        CidrRateLimitKey::Network("203.0.113.7/32".parse().unwrap()),
        rate(2_000, 0),
    );

    limiter.apply_policy(HashMap::new(), cidr_limits);
    let policy = limiter.policy.load_full();
    let matched = policy.match_cidr("203.0.113.7".parse().unwrap()).unwrap();

    match matched {
        CidrPolicyMatch::Explicit(rule) => assert_eq!(rule.key.as_str(), "203.0.113.7/32"),
        CidrPolicyMatch::Auto { .. } => panic!("explicit CIDR must have priority"),
    }
}

#[test]
fn auto_template_uses_longest_prefix() {
    let limiter = TrafficLimiter::new();
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(CidrRateLimitKey::AutoV4(24), rate(1_000, 0));
    cidr_limits.insert(CidrRateLimitKey::AutoV4(32), rate(2_000, 0));

    limiter.apply_policy(HashMap::new(), cidr_limits);
    let policy = limiter.policy.load_full();
    let matched = policy.match_cidr("203.0.113.129".parse().unwrap()).unwrap();

    match matched {
        CidrPolicyMatch::Auto { key, limits } => {
            assert_eq!(key, "auto:4:203.0.113.129/32");
            assert_eq!(limits.up_bps, 2_000);
        }
        CidrPolicyMatch::Explicit(_) => panic!("auto-template match expected"),
    }
}

#[test]
fn dual_auto_template_maps_v6_prefix_by_four() {
    let limiter = TrafficLimiter::new();
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(CidrRateLimitKey::AutoDual(32), rate(1_000, 0));

    limiter.apply_policy(HashMap::new(), cidr_limits);
    let policy = limiter.policy.load_full();
    let matched = policy.match_cidr("2001:db8::1".parse().unwrap()).unwrap();

    match matched {
        CidrPolicyMatch::Auto { key, .. } => {
            assert_eq!(key, "auto:6:2001:db8::1/128");
        }
        CidrPolicyMatch::Explicit(_) => panic!("auto-template match expected"),
    }
}

#[test]
fn auto_cidr_bucket_key_canonicalizes_network_address() {
    assert_eq!(
        auto_cidr_bucket_key("203.0.113.129".parse().unwrap(), 24).unwrap(),
        "auto:4:203.0.113.0/24"
    );
    assert_eq!(
        auto_cidr_bucket_key("2001:db8::abcd".parse().unwrap(), 64).unwrap(),
        "auto:6:2001:db8::/64"
    );
}

#[test]
fn refund_from_an_old_epoch_does_not_reduce_the_current_epoch() {
    let bucket = Arc::new(DirectionBucket::default());
    let old_debit = bucket.try_reserve_at(7, 100, 80).unwrap();
    let current_debit = bucket.try_reserve_at(8, 100, 60).unwrap();

    drop(old_debit);

    assert_eq!(bucket.used_at(8), Some(60));
    drop(current_debit);
}

#[test]
fn concurrent_rollover_cannot_publish_multiple_epoch_budgets() {
    const CONTENDERS: usize = 32;

    let bucket = Arc::new(DirectionBucket::default());
    let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS));
    let mut threads = Vec::with_capacity(CONTENDERS);
    for _ in 0..CONTENDERS {
        let bucket = Arc::clone(&bucket);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            bucket
                .try_reserve_at(9, 100, 100)
                .map(|mut debit| debit.commit_all())
                .unwrap_or(0)
        }));
    }

    let granted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .sum::<u64>();
    assert_eq!(granted, 100);
    assert_eq!(bucket.used_at(9), Some(100));
}

#[test]
fn scheduler_pressure_never_exceeds_a_packed_epoch_budget() {
    const CONTENDERS: usize = 4;
    const EPOCHS: usize = 10_000;

    let bucket = Arc::new(DirectionBucket::default());
    let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS));
    let mut threads = Vec::with_capacity(CONTENDERS);
    for _ in 0..CONTENDERS {
        let bucket = Arc::clone(&bucket);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let mut grants = Vec::with_capacity(EPOCHS);
            for epoch in 1..=EPOCHS as u64 {
                barrier.wait();
                let granted = bucket
                    .try_reserve_at(epoch, 100, 100)
                    .map(|mut debit| debit.commit_all())
                    .unwrap_or(0);
                grants.push(granted);
                barrier.wait();
            }
            grants
        }));
    }

    let grants = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    for epoch_index in 0..EPOCHS {
        let granted = grants
            .iter()
            .map(|thread_grants| thread_grants[epoch_index])
            .sum::<u64>();
        assert_eq!(granted, 100);
    }
}

#[test]
fn stale_policy_revision_cannot_restore_an_old_rate() {
    let bucket = UserBucket::new(2, rate(2_000, 3_000));

    bucket.set_rates(3, rate(4_000, 5_000));
    bucket.set_rates(2, rate(6_000, 7_000));

    assert_eq!(bucket.rates.get(RateDirection::Up), 4_000);
    assert_eq!(bucket.rates.get(RateDirection::Down), 5_000);
}

#[test]
fn dropped_debit_refunds_only_its_packed_epoch() {
    let bucket = Arc::new(DirectionBucket::default());
    let debit = bucket.try_reserve_at(11, 100, 80).unwrap();

    drop(debit);

    assert_eq!(bucket.used_at(11), Some(0));
    assert!(
        bucket
            .try_reserve_at(PACKED_EPOCH_MAX + 1, 100, 1)
            .is_none()
    );
}

#[test]
fn concurrent_first_use_counts_one_active_cidr_user() {
    const CONTENDERS: usize = 32;

    let bucket = Arc::new(CidrDirectionBucket::default());
    let user = Arc::new(CidrUserDirectionState::default());
    let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS));
    let mut threads = Vec::with_capacity(CONTENDERS);
    for _ in 0..CONTENDERS {
        let bucket = Arc::clone(&bucket);
        let user = Arc::clone(&user);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            assert!(user.ensure_active(13, &bucket.active_users));
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    assert_eq!(bucket.active_users.used_at(13), Some(1));
}

#[test]
fn configured_rate_maximum_fits_the_packed_epoch_budget() {
    assert_eq!(bytes_per_epoch(100_000_000_000), 250_000_000);
    assert!(bytes_per_epoch(100_000_000_000) <= PACKED_USAGE_MASK);
}

#[test]
fn dropped_traffic_reservation_refunds_user_and_cidr_debits() {
    let limiter = TrafficLimiter::new();
    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(400_000, 400_000));
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(
        CidrRateLimitKey::Network("203.0.113.0/24".parse().unwrap()),
        rate(400_000, 400_000),
    );
    limiter.apply_policy(user_limits, cidr_limits);
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();

    let reservation = lease.try_reserve(RateDirection::Down, 800);
    assert_eq!(reservation.result().granted, 800);
    let epoch = reservation.user.as_ref().unwrap().epoch;
    drop(reservation);

    let binding = lease.binding.load_full();
    let user_bucket = binding.user_bucket.as_ref().unwrap();
    let cidr_bucket = binding.cidr_bucket.as_ref().unwrap();
    let cidr_user = binding.cidr_user_share.as_ref().unwrap();
    assert_eq!(user_bucket.down.used_at(epoch), Some(0));
    assert_eq!(cidr_bucket.down.used.used_at(epoch), Some(0));
    assert_eq!(cidr_user.down.used.used_at(epoch), Some(0));
}

#[test]
fn partial_traffic_settlement_charges_only_committed_bytes() {
    let limiter = TrafficLimiter::new();
    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(400_000, 400_000));
    limiter.apply_policy(user_limits, HashMap::new());
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();

    let reservation = lease.try_reserve(RateDirection::Down, 800);
    let epoch = reservation.user.as_ref().unwrap().epoch;
    reservation.settle_written(300);

    assert_eq!(
        lease
            .binding
            .load_full()
            .user_bucket
            .as_ref()
            .unwrap()
            .down
            .used_at(epoch),
        Some(300)
    );
}

#[test]
fn active_lease_observes_policy_removal() {
    let limiter = TrafficLimiter::new();
    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(1, 0));
    limiter.apply_policy(user_limits, HashMap::new());
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();
    assert_eq!(lease.try_consume(RateDirection::Up, 1).granted, 1);
    assert_eq!(lease.try_consume(RateDirection::Up, 1).granted, 0);

    limiter.apply_policy(HashMap::new(), HashMap::new());

    assert_eq!(lease.try_consume(RateDirection::Up, 1).granted, 1);
}

#[test]
fn active_lease_observes_policy_addition() {
    let limiter = TrafficLimiter::new();
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();
    assert_eq!(lease.try_consume(RateDirection::Up, 2).granted, 2);

    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(1, 0));
    limiter.apply_policy(user_limits, HashMap::new());

    assert_eq!(lease.try_consume(RateDirection::Up, 1).granted, 1);
    assert_eq!(lease.try_consume(RateDirection::Up, 1).granted, 0);
}

#[test]
fn reservation_refund_stays_with_retired_binding() {
    let limiter = TrafficLimiter::new();
    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(400_000, 400_000));
    limiter.apply_policy(user_limits, HashMap::new());
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();

    let reservation = lease.try_reserve(RateDirection::Down, 800);
    let old_bucket = Arc::clone(
        reservation
            ._binding
            .user_bucket
            .as_ref()
            .expect("the original policy must bind a user bucket"),
    );
    let epoch = reservation.user.as_ref().unwrap().epoch;
    limiter.apply_policy(HashMap::new(), HashMap::new());
    assert_eq!(lease.try_consume(RateDirection::Down, 1).granted, 1);
    assert!(lease.binding.load().user_bucket.is_none());

    drop(reservation);

    assert_eq!(old_bucket.down.used_at(epoch), Some(0));
}
