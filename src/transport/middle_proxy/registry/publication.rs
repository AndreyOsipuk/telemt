use std::sync::Arc;

use tokio::sync::{MutexGuard, Semaphore, mpsc};

use super::super::codec::WriterCommand;
use super::{BindingInner, ConnRegistry, WriterRoute};

/// Holds registry binding ownership until pool writer visibility is published.
pub(in crate::transport::middle_proxy) struct WriterRegistrationGuard<'a> {
    registry: &'a ConnRegistry,
    binding: MutexGuard<'a, BindingInner>,
}

impl ConnRegistry {
    /// Acquires the only cancellation point required for writer registration.
    pub(in crate::transport::middle_proxy) async fn prepare_writer_registration(
        &self,
    ) -> WriterRegistrationGuard<'_> {
        WriterRegistrationGuard {
            registry: self,
            binding: self.binding.inner.lock().await,
        }
    }
}

impl WriterRegistrationGuard<'_> {
    /// Installs registry state while retaining binding ownership for pool publication.
    pub(in crate::transport::middle_proxy) fn install(
        &mut self,
        writer_id: u64,
        tx: mpsc::Sender<WriterCommand>,
        byte_budget: Arc<Semaphore>,
    ) {
        self.binding.conns_for_writer.entry(writer_id).or_default();
        self.registry
            .binding
            .bound_clients_by_writer
            .entry(writer_id)
            .or_insert(0);
        self.registry
            .binding
            .writer_idle_since_epoch_secs
            .entry(writer_id)
            .or_insert_with(ConnRegistry::now_epoch_secs);
        self.registry
            .writers
            .map
            .insert(writer_id, WriterRoute { tx, byte_budget });
    }
}
