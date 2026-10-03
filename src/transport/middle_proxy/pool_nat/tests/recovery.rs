use super::*;
use crate::crypto::{SecureRandom, derive_middleproxy_keys};
use crate::transport::middle_proxy::codec::{
    RpcChecksumMode, build_handshake_payload, build_nonce_payload, build_rpc_frame,
    cbc_decrypt_inplace, cbc_encrypt_padded, parse_handshake_flags, parse_nonce_payload,
    read_rpc_frame_plaintext, rpc_crc,
};
use crate::transport::middle_proxy::me_health_monitor;
use crate::transport::middle_proxy::pool::MeFamilyRuntimeState;
use tokio::net::TcpStream;

struct MiddlePeer {
    addr: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for MiddlePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MiddlePeer {
    async fn new(server_ip: Ipv4Addr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let succeeded = handshakes.clone();
        let closed = cancelled.clone();
        let task = tokio::spawn(async move {
            let mut pending = JoinSet::new();
            let mut established = Vec::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        pending.spawn(accept_handshake(stream, server_ip));
                    }
                    completed = pending.join_next(), if !pending.is_empty() => {
                        match completed.unwrap().expect("fake ME handshake task must not panic") {
                            Some(stream) => {
                                established.push(stream);
                                succeeded.fetch_add(1, Ordering::Release);
                            }
                            None => { closed.fetch_add(1, Ordering::Release); }
                        }
                    }
                }
            }
        });
        Self {
            addr,
            handshakes,
            cancelled,
            task,
        }
    }
}

async fn accept_handshake(mut stream: TcpStream, server_ip: Ipv4Addr) -> Option<TcpStream> {
    let client_port = stream.peer_addr().unwrap().port();
    let server_port = stream.local_addr().unwrap().port();
    let (seq, payload) = match read_rpc_frame_plaintext(&mut stream).await {
        Ok(frame) => frame,
        // Reconnect may time out during NAT discovery, before sending any nonce.
        Err(ProxyError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return None;
        }
        Err(error) => panic!("invalid client nonce: {error}"),
    };
    assert_eq!(seq, -2);
    let (selector, _, timestamp, client_nonce) = parse_nonce_payload(&payload).unwrap();
    let server_nonce = [0x42u8; 16];
    let nonce = build_nonce_payload(selector, timestamp, &server_nonce);
    stream
        .write_all(&build_rpc_frame(-2, &nonce, RpcChecksumMode::Crc32))
        .await
        .unwrap();
    let mut client_ip = PUBLIC_IP.octets();
    client_ip.reverse();
    let mut server_ip = server_ip.octets();
    server_ip.reverse();
    let (read_key, read_iv) = derive_middleproxy_keys(
        &server_nonce,
        &client_nonce,
        &timestamp.to_le_bytes(),
        Some(&server_ip),
        &client_port.to_le_bytes(),
        b"CLIENT",
        Some(&client_ip),
        &server_port.to_le_bytes(),
        &[1u8; 32],
        None,
        None,
    );
    let (write_key, write_iv) = derive_middleproxy_keys(
        &server_nonce,
        &client_nonce,
        &timestamp.to_le_bytes(),
        Some(&server_ip),
        &client_port.to_le_bytes(),
        b"SERVER",
        Some(&client_ip),
        &server_port.to_le_bytes(),
        &[1u8; 32],
        None,
        None,
    );
    let mut encrypted = [0u8; 48];
    stream.read_exact(&mut encrypted).await.unwrap();
    cbc_decrypt_inplace(&read_key, &read_iv, &mut encrypted).unwrap();
    assert_eq!(u32::from_le_bytes(encrypted[..4].try_into().unwrap()), 44);
    assert_eq!(i32::from_le_bytes(encrypted[4..8].try_into().unwrap()), -1);
    assert_eq!(
        u32::from_le_bytes(encrypted[40..44].try_into().unwrap()),
        rpc_crc(RpcChecksumMode::Crc32, &encrypted[..40])
    );
    parse_handshake_flags(&encrypted[8..40]).unwrap();
    assert_eq!(&encrypted[16..20], &client_ip);
    assert_eq!(
        u16::from_le_bytes(encrypted[20..22].try_into().unwrap()),
        client_port
    );
    assert_eq!(
        u16::from_le_bytes(encrypted[32..34].try_into().unwrap()),
        server_port
    );
    let reply = build_handshake_payload(server_ip, server_port, client_ip, client_port, 0);
    let (encrypted, _) = cbc_encrypt_padded(
        &write_key,
        &write_iv,
        &build_rpc_frame(-1, &reply, RpcChecksumMode::Crc32),
    )
    .unwrap();
    stream.write_all(&encrypted).await.unwrap();
    Some(stream)
}

async fn suppressed_pool_recovers_after_delayed_discovery(http_slow: bool) {
    // Every lookup exceeds me_one_timeout_ms, not just the first request of the outage.
    let delay = Duration::from_millis(1500);
    let stun = stun_server_response(
        "127.0.0.1:0".parse().unwrap(),
        Some(PUBLIC_IP.into()),
        delay,
    )
    .await;
    let http = http_server_with_delay("91.108.56.1", delay).await;
    stun.release.add_permits(64);
    http.release.add_permits(64);
    let peer = MiddlePeer::new(if http_slow {
        PUBLIC_IP
    } else {
        Ipv4Addr::LOCALHOST
    })
    .await;
    let urls = if http_slow {
        vec![format!("http://{}/", http.addr)]
    } else {
        vec![]
    };
    let pool = nat_pool(vec![stun.addr.to_string()], urls).await;
    pool.health_runtime
        .me_health_interval_ms_unhealthy
        .store(10, Ordering::Relaxed);
    pool.health_runtime
        .me_health_interval_ms_healthy
        .store(10, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_outage_backoff_min_ms
        .store(100, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_outage_backoff_max_ms
        .store(100, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_shadow_writers
        .store(0, Ordering::Relaxed);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(peer.addr.ip(), peer.addr.port())])]),
        None,
    )
    .await;
    let generation = pool.current_generation();
    let now = MePool::now_epoch_secs();
    pool.set_family_runtime_state(
        IpFamily::V4,
        MeFamilyRuntimeState::Suppressed,
        now,
        now + 3600,
        5,
        0,
    );
    pool.nat_runtime.nat_reflection_cache.lock().await.v4 = Some((
        if http_slow {
            Instant::now()
        } else {
            Instant::now() - Duration::from_secs(601)
        },
        SocketAddr::new(PUBLIC_IP.into(), 45678),
    ));
    let monitor = tokio::spawn(me_health_monitor(
        pool.clone(),
        Arc::new(SecureRandom::new()),
        0,
    ));
    if http_slow {
        http.received().await;
    } else {
        stun.received().await;
    }
    timeout(Duration::from_secs(5), async {
        while peer.cancelled.load(Ordering::Acquire) == 0 {
            assert!(!peer.task.is_finished());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the actual 1200ms reconnect must cancel at least one pre-KDF TCP connection");
    assert_eq!(peer.handshakes.load(Ordering::Acquire), 0);
    let expected = 2 * pool.required_writers_for_dc(1);
    timeout(Duration::from_secs(10), async {
        while !pool.admission_ready_full_floor().await
            || peer.handshakes.load(Ordering::Acquire) < expected
        {
            assert!(
                !peer.task.is_finished(),
                "fake ME must validate every encrypted handshake"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("suppressed pool must autonomously regain its full floor without restart");
    monitor.abort();
    let _ = monitor.await;
    assert_eq!(pool.current_generation(), generation);
    assert_eq!(pool.reinit.status.load().pending_hardswap_generation, 0);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
    assert_eq!(pool.writers.read().await.len(), expected);
    assert!(peer.handshakes.load(Ordering::Acquire) >= expected);
    assert_eq!(
        http.requests.load(Ordering::Relaxed),
        usize::from(http_slow)
    );
    assert_eq!(
        stun.requests.load(Ordering::Relaxed),
        usize::from(!http_slow)
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn suppressed_pool_recovers_full_floor_after_expired_stun_refresh() {
    suppressed_pool_recovers_after_delayed_discovery(false).await;
}

#[tokio::test]
async fn suppressed_pool_recovers_full_floor_after_slow_http_with_fresh_stun() {
    suppressed_pool_recovers_after_delayed_discovery(true).await;
}
