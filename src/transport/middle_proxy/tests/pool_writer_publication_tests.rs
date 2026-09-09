use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::pool::{MeWriter, WriterContour};
use super::pool_writer_security_tests::make_pool;
use super::registry::ConnMeta;

#[tokio::test]
async fn successful_writer_publication_is_fully_visible_and_removable() {
    let pool = make_pool().await;
    let writer_id = 76_002;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    let byte_budget = pool.new_writer_byte_budget();
    let cancel = CancellationToken::new();
    let writer = MeWriter {
        id: writer_id,
        addr,
        source_ip: addr.ip(),
        writer_dc: 2,
        generation: pool.current_generation(),
        contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
        created_at: Instant::now(),
        tx: tx.clone(),
        byte_budget: byte_budget.clone(),
        cancel: cancel.clone(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };
    let task_started = Arc::new(AtomicBool::new(false));
    let task_started_writer = Arc::clone(&task_started);
    let writer_task = async move {
        task_started_writer.store(true, Ordering::Release);
        cancel.cancelled().await;
    };
    let task_registration = pool.lifecycle.try_register().unwrap();

    pool.publish_prepared_writer(writer, tx, byte_budget, task_registration, writer_task)
        .await;

    assert_eq!(pool.writers.read().await.len(), 1);
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !task_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("published writer task must start");

    let (conn_id, _response_rx) = pool.registry.register().await;
    assert!(
        pool.registry
            .bind_writer(
                conn_id,
                writer_id,
                ConnMeta {
                    target_dc: 2,
                    client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7300),
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );
    assert_eq!(
        pool.registry.get_writer(conn_id).await.unwrap().writer_id,
        writer_id
    );

    pool.remove_writer_and_close_clients(writer_id).await;

    assert!(pool.writers.read().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    assert!(pool.registry.get_writer(conn_id).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn published_writer_removal_race_preserves_count() {
    let pool = make_pool().await;

    for writer_id in 80_000..90_000 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let (tx, _rx) = mpsc::channel::<WriterCommand>(1);
        let byte_budget = pool.new_writer_byte_budget();
        let cancel = CancellationToken::new();
        let writer = MeWriter {
            id: writer_id,
            addr,
            source_ip: addr.ip(),
            writer_dc: 2,
            generation: pool.current_generation(),
            contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
            created_at: Instant::now(),
            tx: tx.clone(),
            byte_budget: byte_budget.clone(),
            cancel: cancel.clone(),
            degraded: Arc::new(AtomicBool::new(false)),
            rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
            draining: Arc::new(AtomicBool::new(false)),
            draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
            drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
            allow_drain_fallback: Arc::new(AtomicBool::new(false)),
        };
        let writer_task = async move {
            cancel.cancelled().await;
        };
        let task_registration = pool.lifecycle.try_register().unwrap();
        let remover_pool = Arc::clone(&pool);
        let remover = tokio::spawn(async move {
            loop {
                if remover_pool
                    .writers
                    .snapshot()
                    .iter()
                    .any(|writer| writer.id == writer_id)
                {
                    remover_pool
                        .remove_writer_and_close_clients(writer_id)
                        .await;
                    return;
                }
                tokio::task::yield_now().await;
            }
        });

        pool.publish_prepared_writer(writer, tx, byte_budget, task_registration, writer_task)
            .await;
        tokio::time::timeout(Duration::from_secs(1), remover)
            .await
            .expect("published writer must become removable")
            .expect("writer remover task must not panic");

        assert!(pool.writers.read().await.is_empty());
        assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    }
}
