use super::*;

#[derive(Clone, Debug)]
/// Bounded control-plane snapshot of hardswap and replacement progress.
pub(crate) struct MeApiHardswapSnapshot {
    /// Whether a hardswap generation is pending.
    pub pending: bool,
    /// Age of the pending generation when one exists.
    pub pending_age_secs: Option<u64>,
    /// Number of authoritative warm writers in the pending generation.
    pub pending_writers_current: usize,
    /// Number of writers still required to reach the pending generation floor.
    pub pending_writer_deficit: usize,
    /// Number of desired DC groups without a pending-generation writer.
    pub pending_missing_dc_groups: usize,
    /// Whether the pending generation targets the current desired endpoint map.
    pub pending_map_current: Option<bool>,
    /// Number of warm writers not owned by the current pending generation.
    pub orphan_warm_writers_current: usize,
    /// Number of writer replacements still in the preparatory phase.
    pub replacement_preparing_current: usize,
    /// Number of replacement victims already closed to new bindings.
    pub replacement_retiring_current: usize,
}

impl MePool {
    /// Returns bounded hardswap progress without exposing generation or endpoint labels.
    pub(crate) async fn api_hardswap_snapshot(&self) -> MeApiHardswapSnapshot {
        let reinit = self.reinit.status.load_full();
        self.api_hardswap_snapshot_for_reinit(reinit.as_ref()).await
    }

    /// Builds the bounded projection from one coherent reinitialization snapshot.
    pub(super) async fn api_hardswap_snapshot_for_reinit(
        &self,
        reinit: &ReinitStatusSnapshot,
    ) -> MeApiHardswapSnapshot {
        let desired_by_dc = self.desired_dc_endpoints().await;
        let desired_hash = Self::desired_map_hash(&desired_by_dc);
        let writers = self.writers.read().await;
        let pending_generation = reinit.pending_hardswap_generation;
        let pending = pending_generation != 0;
        let mut pending_writers_current = 0usize;
        let mut pending_by_dc = HashMap::<i32, usize>::new();
        let mut orphan_warm_writers_current = 0usize;

        for writer in writers.iter() {
            if writer.draining.load(Ordering::Acquire) {
                continue;
            }
            let contour = WriterContour::from_u8(writer.contour.load(Ordering::Acquire));
            if contour == WriterContour::Warm && writer.generation != pending_generation {
                orphan_warm_writers_current = orphan_warm_writers_current.saturating_add(1);
            }
            if pending
                && writer.generation == pending_generation
                && contour == WriterContour::Warm
                && desired_by_dc
                    .get(&writer.writer_dc)
                    .is_some_and(|endpoints| endpoints.contains(&writer.addr))
            {
                pending_writers_current = pending_writers_current.saturating_add(1);
                *pending_by_dc.entry(writer.writer_dc).or_insert(0) += 1;
            }
        }

        let mut pending_writer_deficit = 0usize;
        let mut pending_missing_dc_groups = 0usize;
        if pending {
            for (dc, endpoints) in &desired_by_dc {
                if endpoints.is_empty() {
                    continue;
                }
                let alive = pending_by_dc.get(dc).copied().unwrap_or(0);
                let required = self.required_writers_for_dc(endpoints.len());
                pending_writer_deficit = pending_writer_deficit
                    .saturating_add(required.saturating_sub(alive));
                if alive == 0 {
                    pending_missing_dc_groups = pending_missing_dc_groups.saturating_add(1);
                }
            }
        }
        let (replacement_preparing_current, replacement_retiring_current) =
            self.registry.writer_replacement_counts();
        let pending_age_secs = pending.then(|| {
            Self::now_epoch_secs()
                .saturating_sub(reinit.pending_hardswap_started_at_epoch_secs)
        });

        MeApiHardswapSnapshot {
            pending,
            pending_age_secs,
            pending_writers_current,
            pending_writer_deficit,
            pending_missing_dc_groups,
            pending_map_current: pending
                .then_some(reinit.pending_hardswap_map_hash == desired_hash),
            orphan_warm_writers_current,
            replacement_preparing_current,
            replacement_retiring_current,
        }
    }
}
