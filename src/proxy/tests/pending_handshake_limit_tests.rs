use crate::proxy::client::handle_client_stream_with_shared;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::{
    config::ProxyConfig,
    crypto::SecureRandom,
    ip_tracker::UserIpTracker,
    stats::{ReplayChecker, Stats, beobachten::BeobachtenStore},
    stream::BufferPool,
    transport::UpstreamManager,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
use tokio::task::JoinHandle;

struct Harness {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
}

fn harness(limit: u32, dry_run: bool) -> Harness {
    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = false;
    cfg.general.modes.classic = true;
    cfg.general.modes.secure = true;
    cfg.timeouts.client_handshake = 30;
    cfg.server.max_pending_handshakes_per_ip = limit;
    cfg.server.pending_handshakes_per_ip_dry_run = dry_run;
    Harness {
        config: Arc::new(cfg),
        stats: Arc::new(Stats::new()),
        shared: ProxySharedState::new(),
    }
}

/// Opens a connection that sends one byte and then stalls inside the
/// handshake. Returns the client side (keep it alive to keep the handshake
/// pending) and the handler task.
async fn stalled_connection(
    h: &Harness,
    peer: &str,
) -> (DuplexStream, JoinHandle<crate::error::Result<()>>) {
    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = peer.parse().unwrap();
    let stats = h.stats.clone();
    let task = tokio::spawn(handle_client_stream_with_shared(
        server_side,
        peer,
        h.config.clone(),
        stats.clone(),
        Arc::new(UpstreamManager::new(vec![], 1, 1, 1, 10, 1, false, stats)),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        h.shared.clone(),
        false,
    ));
    client_side.write_all(&[0xef]).await.unwrap();
    (client_side, task)
}

async fn wait_pending(h: &Harness, ip: &str, expected: u32) {
    let ip = ip.parse().unwrap();
    for _ in 0..200 {
        if h.shared.pending_handshakes.pending_for(ip) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "pending handshakes for {ip}: got {}, want {expected}",
        h.shared.pending_handshakes.pending_for(ip)
    );
}

#[tokio::test]
async fn over_limit_handshake_is_closed_and_slot_is_released_after_handshake_ends() {
    let h = harness(2, false);

    let (first, _t1) = stalled_connection(&h, "198.51.100.20:40001").await;
    let (_second, _t2) = stalled_connection(&h, "198.51.100.20:40002").await;
    wait_pending(&h, "198.51.100.20", 2).await;

    // The third pending handshake from the same address is closed right away.
    let (_third, t3) = stalled_connection(&h, "198.51.100.20:40003").await;
    let result = tokio::time::timeout(Duration::from_secs(2), t3)
        .await
        .expect("rejected connection must be closed promptly")
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 1);
    wait_pending(&h, "198.51.100.20", 2).await;

    // Other addresses are not affected.
    let (_other, _t4) = stalled_connection(&h, "203.0.113.7:40004").await;
    wait_pending(&h, "203.0.113.7", 1).await;

    // When a pending handshake ends (here: the client goes away), its slot is
    // released and a new connection from the same address is admitted.
    drop(first);
    wait_pending(&h, "198.51.100.20", 1).await;
    let (_fourth, _t5) = stalled_connection(&h, "198.51.100.20:40005").await;
    wait_pending(&h, "198.51.100.20", 2).await;
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 1);
}

#[tokio::test]
async fn dry_run_admits_over_limit_and_counts_it() {
    let h = harness(1, true);

    let (_first, _t1) = stalled_connection(&h, "198.51.100.30:40001").await;
    wait_pending(&h, "198.51.100.30", 1).await;
    let (_second, _t2) = stalled_connection(&h, "198.51.100.30:40002").await;
    wait_pending(&h, "198.51.100.30", 2).await;

    assert_eq!(h.stats.get_pending_handshake_per_ip_observed_total(), 1);
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);
}

#[tokio::test]
async fn disabled_by_default_tracks_nothing() {
    let h = harness(0, false);

    let mut clients = Vec::new();
    for port in 0..20 {
        clients.push(stalled_connection(&h, &format!("198.51.100.40:{}", 41000 + port)).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.shared.pending_handshakes.tracked_ips(), 0);
    assert_eq!(h.stats.get_pending_handshake_per_ip_rejected_total(), 0);
}
