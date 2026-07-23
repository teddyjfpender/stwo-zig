//! Whole-allocation reclaim through an owned, bounded pinned DMA window.

use core::mem::size_of;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedDmaWindowState {
    Ready,
    TransferPending,
    Quarantined,
}

/// Proof-owned pinned staging memory. An uncertain CUDA transfer failure
/// quarantines the allocation; Drop then leaks it rather than risking a
/// use-after-free by an in-flight DMA.
pub struct PinnedDmaWindow {
    pointer: NonNull<u32>,
    bytes: usize,
    state: PinnedDmaWindowState,
    pending_context: Option<NonNull<c_void>>,
    _same_thread: PhantomData<Rc<()>>,
}

impl PinnedDmaWindow {
    pub fn new(bytes: usize) -> Result<Self, VmmAllocationError> {
        require_staging(bytes)?;
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(CudaRuntimeError::Unavailable.into());
        }
        let words = u64::try_from(bytes / size_of::<u32>())
            .map_err(|_| VmmAllocationError::InvalidStagingSize(bytes))?;
        let pointer = NonNull::new(unsafe {
            stwo_backend_cuda_kernels::raw::cuda_alloc_pinned_host_u32(words)
        })
        .ok_or(VmmAllocationError::PinnedStagingAllocationFailed(bytes))?;
        Ok(Self {
            pointer,
            bytes,
            state: PinnedDmaWindowState::Ready,
            pending_context: None,
            _same_thread: PhantomData,
        })
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    pub const fn state(&self) -> PinnedDmaWindowState {
        self.state
    }

    /// Recover a quarantined window only after the exact submitting context
    /// proves that all of its stream work has drained.
    pub fn recover_after_context_drain(
        &mut self,
        context: &CudaExecContext,
    ) -> Result<(), VmmAllocationError> {
        if self.state == PinnedDmaWindowState::Ready {
            return Ok(());
        }
        if self.pending_context != Some(context.identity_token()) {
            return Err(VmmAllocationError::ContextMismatch);
        }
        if let Err(error) = context.sync() {
            self.state = PinnedDmaWindowState::Quarantined;
            return Err(error.into());
        }
        self.state = PinnedDmaWindowState::Ready;
        self.pending_context = None;
        Ok(())
    }

    fn pointer(&self) -> NonNull<c_void> {
        self.pointer.cast()
    }

    fn require_ready(&self) -> Result<(), VmmAllocationError> {
        if self.state == PinnedDmaWindowState::Ready {
            Ok(())
        } else {
            Err(VmmAllocationError::InvalidPinnedStagingState(self.state))
        }
    }

    fn mark_pending(&mut self, context: NonNull<c_void>) -> Result<(), VmmAllocationError> {
        self.require_ready()?;
        self.state = PinnedDmaWindowState::TransferPending;
        self.pending_context = Some(context);
        Ok(())
    }

    fn mark_drained(&mut self, context: NonNull<c_void>) -> Result<(), VmmAllocationError> {
        if self.state != PinnedDmaWindowState::TransferPending
            || self.pending_context != Some(context)
        {
            return Err(VmmAllocationError::InvalidPinnedStagingState(self.state));
        }
        self.state = PinnedDmaWindowState::Ready;
        self.pending_context = None;
        Ok(())
    }

    fn quarantine(&mut self) {
        self.state = PinnedDmaWindowState::Quarantined;
    }
}

impl Drop for PinnedDmaWindow {
    fn drop(&mut self) {
        if self.state == PinnedDmaWindowState::Ready {
            unsafe {
                stwo_backend_cuda_kernels::raw::cuda_free_pinned_host_u32(self.pointer.as_ptr())
            };
        } else if !std::thread::panicking() {
            eprintln!(
                "stwo-backend-cuda: leaking quarantined {}-byte pinned DMA window after {:?}",
                self.bytes, self.state
            );
        }
    }
}

impl VmmAllocation<'_> {
    /// Spill all bytes through an owned bounded pinned window into ordinary
    /// host storage, then release physical device backing.
    ///
    /// # Safety
    ///
    /// The caller must hold exclusive scheduling authority over the owner
    /// context; no copied launch handle may enqueue concurrent work.
    pub unsafe fn spill_through_staging(
        &mut self,
        staging: &mut PinnedDmaWindow,
        expected_generation: u32,
        destination: &mut [u8],
    ) -> Result<(), VmmAllocationError> {
        require_exact_bytes(self.bytes, destination.len())?;
        staging.require_ready()?;
        let mut operations = CudaTiledVmmOps::new(self.handle, self.owner_context, staging);
        unsafe {
            spill_tiled_transition(
                &mut self.state,
                &mut operations,
                expected_generation,
                self.stable_address,
                self.bytes,
                destination,
            )
        }
    }

    /// Remap the exact next generation and restore all bytes from ordinary
    /// host storage through an owned bounded pinned window.
    ///
    /// # Safety
    ///
    /// The caller must hold exclusive scheduling authority over the owner
    /// context; no copied launch handle may enqueue concurrent work.
    pub unsafe fn restore_through_staging(
        &mut self,
        staging: &mut PinnedDmaWindow,
        current_generation: u32,
        next_generation: u32,
        source: &[u8],
    ) -> Result<(), VmmAllocationError> {
        require_exact_bytes(self.bytes, source.len())?;
        staging.require_ready()?;
        let mut operations = CudaTiledVmmOps::new(self.handle, self.owner_context, staging);
        unsafe {
            restore_tiled_transition(
                &mut self.state,
                &mut operations,
                current_generation,
                next_generation,
                self.stable_address,
                self.bytes,
                source,
            )
        }
    }
}

fn require_staging(bytes: usize) -> Result<(), VmmAllocationError> {
    if bytes == 0 || bytes % size_of::<u32>() != 0 {
        Err(VmmAllocationError::InvalidStagingSize(bytes))
    } else {
        Ok(())
    }
}

trait TiledVmmOps: VmmOps {
    fn staging_bytes(&self) -> usize;

    unsafe fn copy_device_to_staging(
        &mut self,
        source: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError>;

    fn drain_staging_transfer(&mut self) -> Result<(), VmmAllocationError>;

    fn retire_staging(
        &mut self,
        offset: usize,
        bytes: usize,
        destination: &mut [u8],
    ) -> Result<(), VmmAllocationError>;

    fn prefetch_staging(
        &mut self,
        offset: usize,
        bytes: usize,
        source: &[u8],
    ) -> Result<(), VmmAllocationError>;

    unsafe fn copy_staging_to_device(
        &mut self,
        destination: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError>;
}

struct CudaTiledVmmOps<'context, 'staging> {
    base: CudaVmmOps<'context>,
    staging: &'staging mut PinnedDmaWindow,
}

impl<'context, 'staging> CudaTiledVmmOps<'context, 'staging> {
    fn new(
        allocation: NonNull<c_void>,
        context: &'context CudaExecContext,
        staging: &'staging mut PinnedDmaWindow,
    ) -> Self {
        Self {
            base: CudaVmmOps::new(allocation, context),
            staging,
        }
    }
}

impl VmmOps for CudaTiledVmmOps<'_, '_> {
    fn join_all_lanes(&mut self) -> Result<(), VmmAllocationError> {
        self.base.join_all_lanes()
    }

    unsafe fn copy_d2h(
        &mut self,
        _destination: NonNull<c_void>,
        _source: NonNull<c_void>,
        _bytes: usize,
    ) -> Result<(), VmmAllocationError> {
        Err(VmmAllocationError::SequenceViolation("raw_tiled_copy_d2h"))
    }

    fn sync_main(&mut self) -> Result<(), VmmAllocationError> {
        self.base.sync_main()
    }

    fn sync_transfer(&mut self) -> Result<(), VmmAllocationError> {
        Err(VmmAllocationError::SequenceViolation("raw_tiled_sync"))
    }

    fn unmap_release(&mut self, expected_generation: u32) -> Result<(), VmmAllocationError> {
        self.base.unmap_release(expected_generation)
    }

    fn remap_next(
        &mut self,
        current_generation: u32,
        next_generation: u32,
    ) -> Result<(), VmmAllocationError> {
        self.base.remap_next(current_generation, next_generation)
    }

    fn lane_count(&self) -> usize {
        self.base.lane_count()
    }

    fn fork_lane(&mut self, lane: usize) -> Result<(), VmmAllocationError> {
        self.base.fork_lane(lane)
    }

    unsafe fn copy_h2d(
        &mut self,
        _destination: NonNull<c_void>,
        _source: NonNull<c_void>,
        _bytes: usize,
    ) -> Result<(), VmmAllocationError> {
        Err(VmmAllocationError::SequenceViolation("raw_tiled_copy_h2d"))
    }
}

impl TiledVmmOps for CudaTiledVmmOps<'_, '_> {
    fn staging_bytes(&self) -> usize {
        self.staging.bytes()
    }

    unsafe fn copy_device_to_staging(
        &mut self,
        source: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError> {
        if bytes > self.staging.bytes() {
            return Err(VmmAllocationError::InvalidStagingSize(bytes));
        }
        let context = self.base.context.identity_token();
        self.staging.mark_pending(context)?;
        if let Err(error) = unsafe { self.base.copy_d2h(self.staging.pointer(), source, bytes) } {
            self.staging.quarantine();
            return Err(error);
        }
        Ok(())
    }

    fn drain_staging_transfer(&mut self) -> Result<(), VmmAllocationError> {
        let context = self.base.context.identity_token();
        if let Err(error) = self.base.sync_transfer() {
            self.staging.quarantine();
            return Err(error);
        }
        if let Err(error) = self.staging.mark_drained(context) {
            self.staging.quarantine();
            return Err(error);
        }
        Ok(())
    }

    fn retire_staging(
        &mut self,
        offset: usize,
        bytes: usize,
        destination: &mut [u8],
    ) -> Result<(), VmmAllocationError> {
        self.staging.require_ready()?;
        let source =
            unsafe { core::slice::from_raw_parts(self.staging.pointer.as_ptr().cast(), bytes) };
        destination[offset..offset + bytes].copy_from_slice(source);
        Ok(())
    }

    fn prefetch_staging(
        &mut self,
        offset: usize,
        bytes: usize,
        source: &[u8],
    ) -> Result<(), VmmAllocationError> {
        self.staging.require_ready()?;
        let destination =
            unsafe { core::slice::from_raw_parts_mut(self.staging.pointer.as_ptr().cast(), bytes) };
        destination.copy_from_slice(&source[offset..offset + bytes]);
        Ok(())
    }

    unsafe fn copy_staging_to_device(
        &mut self,
        destination: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError> {
        if bytes > self.staging.bytes() {
            return Err(VmmAllocationError::InvalidStagingSize(bytes));
        }
        let context = self.base.context.identity_token();
        self.staging.mark_pending(context)?;
        if let Err(error) = unsafe {
            self.base
                .copy_h2d(destination, self.staging.pointer(), bytes)
        } {
            self.staging.quarantine();
            return Err(error);
        }
        Ok(())
    }
}

unsafe fn spill_tiled_transition(
    state: &mut VmmAllocationState,
    operations: &mut impl TiledVmmOps,
    expected_generation: u32,
    device_source: NonNull<c_void>,
    bytes: usize,
    destination: &mut [u8],
) -> Result<(), VmmAllocationError> {
    let staging_bytes = operations.staging_bytes();
    require_staging(staging_bytes)?;
    if let Err(error) = require_mapped_generation(*state, "spill_tiled", expected_generation) {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    let result = (|| {
        operations.join_all_lanes()?;
        operations.sync_main()?;
        for offset in (0..bytes).step_by(staging_bytes) {
            let tile_bytes = staging_bytes.min(bytes - offset);
            let source = unsafe { add_bytes(device_source, offset) };
            unsafe { operations.copy_device_to_staging(source, tile_bytes)? };
            operations.drain_staging_transfer()?;
            operations.retire_staging(offset, tile_bytes, destination)?;
        }
        operations.unmap_release(expected_generation)
    })();
    match result {
        Ok(()) => {
            *state = VmmAllocationState::Unmapped {
                generation: expected_generation,
            };
            Ok(())
        }
        Err(error) => {
            *state = VmmAllocationState::Poisoned;
            Err(error)
        }
    }
}

unsafe fn restore_tiled_transition(
    state: &mut VmmAllocationState,
    operations: &mut impl TiledVmmOps,
    current_generation: u32,
    next_generation: u32,
    device_destination: NonNull<c_void>,
    bytes: usize,
    source: &[u8],
) -> Result<(), VmmAllocationError> {
    let staging_bytes = operations.staging_bytes();
    require_staging(staging_bytes)?;
    if let Err(error) = require_unmapped_generation_step(
        *state,
        "restore_tiled",
        current_generation,
        next_generation,
    ) {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    let result = (|| {
        operations.remap_next(current_generation, next_generation)?;
        for offset in (0..bytes).step_by(staging_bytes) {
            let tile_bytes = staging_bytes.min(bytes - offset);
            operations.prefetch_staging(offset, tile_bytes, source)?;
            let destination = unsafe { add_bytes(device_destination, offset) };
            unsafe { operations.copy_staging_to_device(destination, tile_bytes)? };
            operations.drain_staging_transfer()?;
        }
        for lane in 0..operations.lane_count() {
            operations.fork_lane(lane)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            *state = VmmAllocationState::Mapped {
                generation: next_generation,
            };
            Ok(())
        }
        Err(error) => {
            *state = VmmAllocationState::Poisoned;
            Err(error)
        }
    }
}

unsafe fn add_bytes(pointer: NonNull<c_void>, offset: usize) -> NonNull<c_void> {
    unsafe { NonNull::new_unchecked(pointer.as_ptr().cast::<u8>().add(offset).cast()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        JoinAll,
        Sync,
        D2h,
        TransferSync,
        Retire(usize, usize),
        Unmap(u32),
        Remap(u32, u32),
        Prefetch(usize, usize),
        H2d,
        Fork(usize),
    }

    struct MockOps {
        calls: Vec<Call>,
        fail_at: Option<Call>,
        staging: Vec<u8>,
    }

    impl MockOps {
        fn new(bytes: usize) -> Self {
            Self {
                calls: Vec::new(),
                fail_at: None,
                staging: vec![0; bytes],
            }
        }

        fn failing(bytes: usize, fail_at: Call) -> Self {
            Self {
                fail_at: Some(fail_at),
                ..Self::new(bytes)
            }
        }

        fn invoke(&mut self, call: Call) -> Result<(), VmmAllocationError> {
            self.calls.push(call);
            if self.fail_at == Some(call) {
                Err(VmmAllocationError::SequenceViolation("injected failure"))
            } else {
                Ok(())
            }
        }
    }

    impl VmmOps for MockOps {
        fn join_all_lanes(&mut self) -> Result<(), VmmAllocationError> {
            self.invoke(Call::JoinAll)
        }

        unsafe fn copy_d2h(
            &mut self,
            _destination: NonNull<c_void>,
            _source: NonNull<c_void>,
            _bytes: usize,
        ) -> Result<(), VmmAllocationError> {
            Err(VmmAllocationError::SequenceViolation("raw_mock_copy_d2h"))
        }

        fn sync_main(&mut self) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Sync)
        }

        fn sync_transfer(&mut self) -> Result<(), VmmAllocationError> {
            Err(VmmAllocationError::SequenceViolation("raw_mock_sync"))
        }

        fn unmap_release(&mut self, expected_generation: u32) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Unmap(expected_generation))
        }

        fn remap_next(
            &mut self,
            current_generation: u32,
            next_generation: u32,
        ) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Remap(current_generation, next_generation))
        }

        fn lane_count(&self) -> usize {
            3
        }

        fn fork_lane(&mut self, lane: usize) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Fork(lane))
        }

        unsafe fn copy_h2d(
            &mut self,
            _destination: NonNull<c_void>,
            _source: NonNull<c_void>,
            _bytes: usize,
        ) -> Result<(), VmmAllocationError> {
            Err(VmmAllocationError::SequenceViolation("raw_mock_copy_h2d"))
        }
    }

    impl TiledVmmOps for MockOps {
        fn staging_bytes(&self) -> usize {
            self.staging.len()
        }

        unsafe fn copy_device_to_staging(
            &mut self,
            source: NonNull<c_void>,
            bytes: usize,
        ) -> Result<(), VmmAllocationError> {
            self.invoke(Call::D2h)?;
            let source = unsafe { core::slice::from_raw_parts(source.as_ptr().cast(), bytes) };
            self.staging[..bytes].copy_from_slice(source);
            Ok(())
        }

        fn drain_staging_transfer(&mut self) -> Result<(), VmmAllocationError> {
            self.invoke(Call::TransferSync)
        }

        fn retire_staging(
            &mut self,
            offset: usize,
            bytes: usize,
            destination: &mut [u8],
        ) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Retire(offset, bytes))?;
            destination[offset..offset + bytes].copy_from_slice(&self.staging[..bytes]);
            Ok(())
        }

        fn prefetch_staging(
            &mut self,
            offset: usize,
            bytes: usize,
            source: &[u8],
        ) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Prefetch(offset, bytes))?;
            self.staging[..bytes].copy_from_slice(&source[offset..offset + bytes]);
            Ok(())
        }

        unsafe fn copy_staging_to_device(
            &mut self,
            destination: NonNull<c_void>,
            bytes: usize,
        ) -> Result<(), VmmAllocationError> {
            self.invoke(Call::H2d)?;
            let destination =
                unsafe { core::slice::from_raw_parts_mut(destination.as_ptr().cast(), bytes) };
            destination.copy_from_slice(&self.staging[..bytes]);
            Ok(())
        }
    }

    fn pointer(bytes: &mut [u8]) -> NonNull<c_void> {
        NonNull::new(bytes.as_mut_ptr().cast()).unwrap()
    }

    #[test]
    fn staging_geometry_is_exact_and_nonzero() {
        assert_eq!(require_staging(16), Ok(()));
        assert_eq!(
            require_staging(0),
            Err(VmmAllocationError::InvalidStagingSize(0))
        );
        assert_eq!(
            require_staging(15),
            Err(VmmAllocationError::InvalidStagingSize(15))
        );
    }

    #[test]
    fn bounded_window_roundtrips_every_offset_and_orders_lifecycle() {
        let mut device = (0..40_u8).collect::<Vec<_>>();
        let mut host = vec![0_u8; device.len()];
        let mut state = VmmAllocationState::Mapped { generation: 0 };
        let mut spill = MockOps::new(16);
        unsafe {
            spill_tiled_transition(
                &mut state,
                &mut spill,
                0,
                pointer(&mut device),
                host.len(),
                &mut host,
            )
            .unwrap();
        }
        assert_eq!(host, (0..40_u8).collect::<Vec<_>>());
        assert_eq!(state, VmmAllocationState::Unmapped { generation: 0 });
        assert_eq!(
            spill.calls,
            [
                Call::JoinAll,
                Call::Sync,
                Call::D2h,
                Call::TransferSync,
                Call::Retire(0, 16),
                Call::D2h,
                Call::TransferSync,
                Call::Retire(16, 16),
                Call::D2h,
                Call::TransferSync,
                Call::Retire(32, 8),
                Call::Unmap(0),
            ]
        );

        let source = (100..140_u8).rev().collect::<Vec<_>>();
        let mut restore = MockOps::new(16);
        unsafe {
            restore_tiled_transition(
                &mut state,
                &mut restore,
                0,
                1,
                pointer(&mut device),
                source.len(),
                &source,
            )
            .unwrap();
        }
        assert_eq!(device, source);
        assert_eq!(state, VmmAllocationState::Mapped { generation: 1 });
        assert_eq!(
            restore.calls,
            [
                Call::Remap(0, 1),
                Call::Prefetch(0, 16),
                Call::H2d,
                Call::TransferSync,
                Call::Prefetch(16, 16),
                Call::H2d,
                Call::TransferSync,
                Call::Prefetch(32, 8),
                Call::H2d,
                Call::TransferSync,
                Call::Fork(0),
                Call::Fork(1),
                Call::Fork(2),
            ]
        );
    }

    #[test]
    fn rust_mock_covers_one_hundred_generation_control_flow_and_data() {
        let mut device = (0..40_u8).collect::<Vec<_>>();
        let mut host = vec![0_u8; device.len()];
        let stable_address = pointer(&mut device);
        let mut state = VmmAllocationState::Mapped { generation: 0 };

        for current_generation in 0..100_u32 {
            let mut spill = MockOps::new(16);
            unsafe {
                spill_tiled_transition(
                    &mut state,
                    &mut spill,
                    current_generation,
                    stable_address,
                    device.len(),
                    &mut host,
                )
                .unwrap();
            }
            assert_eq!(host, device);
            assert_eq!(
                state,
                VmmAllocationState::Unmapped {
                    generation: current_generation,
                }
            );

            for byte in &mut host {
                *byte = byte.wrapping_add(1);
            }
            let next_generation = current_generation + 1;
            let mut restore = MockOps::new(16);
            unsafe {
                restore_tiled_transition(
                    &mut state,
                    &mut restore,
                    current_generation,
                    next_generation,
                    stable_address,
                    device.len(),
                    &host,
                )
                .unwrap();
            }
            assert_eq!(device, host);
            assert_eq!(pointer(&mut device), stable_address);
            assert_eq!(
                state,
                VmmAllocationState::Mapped {
                    generation: next_generation,
                }
            );
        }
    }

    #[test]
    fn stale_skipped_and_overflowed_generations_poison_before_cuda_work() {
        let mut device = vec![0_u8; 40];
        let mut host = vec![0_u8; 40];

        let mut state = VmmAllocationState::Mapped { generation: 3 };
        let mut operations = MockOps::new(16);
        assert_eq!(
            unsafe {
                spill_tiled_transition(
                    &mut state,
                    &mut operations,
                    2,
                    pointer(&mut device),
                    host.len(),
                    &mut host,
                )
            },
            Err(VmmAllocationError::GenerationMismatch {
                expected: 2,
                actual: 3,
            })
        );
        assert_eq!(state, VmmAllocationState::Poisoned);
        assert!(operations.calls.is_empty());

        for (actual_generation, current_generation, next_generation, expected_error) in [
            (
                3,
                2,
                3,
                VmmAllocationError::GenerationMismatch {
                    expected: 2,
                    actual: 3,
                },
            ),
            (
                3,
                3,
                5,
                VmmAllocationError::InvalidGenerationStep {
                    current: 3,
                    next: 5,
                },
            ),
            (
                u32::MAX,
                u32::MAX,
                0,
                VmmAllocationError::GenerationOverflow(u32::MAX),
            ),
        ] {
            let mut state = VmmAllocationState::Unmapped {
                generation: actual_generation,
            };
            let mut operations = MockOps::new(16);
            assert_eq!(
                unsafe {
                    restore_tiled_transition(
                        &mut state,
                        &mut operations,
                        current_generation,
                        next_generation,
                        pointer(&mut device),
                        host.len(),
                        &host,
                    )
                },
                Err(expected_error)
            );
            assert_eq!(state, VmmAllocationState::Poisoned);
            assert!(operations.calls.is_empty());
        }
    }

    #[test]
    fn every_tiled_stage_failure_poison_state_and_rejects_retry() {
        for failure in [
            Call::JoinAll,
            Call::Sync,
            Call::D2h,
            Call::TransferSync,
            Call::Retire(0, 16),
            Call::Unmap(0),
        ] {
            let mut device = vec![0_u8; 40];
            let mut host = vec![0_u8; 40];
            let mut state = VmmAllocationState::Mapped { generation: 0 };
            let mut operations = MockOps::failing(16, failure);
            assert!(unsafe {
                spill_tiled_transition(
                    &mut state,
                    &mut operations,
                    0,
                    pointer(&mut device),
                    host.len(),
                    &mut host,
                )
            }
            .is_err());
            assert_eq!(state, VmmAllocationState::Poisoned);
            let mut retry = MockOps::new(16);
            assert!(unsafe {
                spill_tiled_transition(
                    &mut state,
                    &mut retry,
                    0,
                    pointer(&mut device),
                    host.len(),
                    &mut host,
                )
            }
            .is_err());
            assert!(retry.calls.is_empty());
        }

        for failure in [
            Call::Remap(0, 1),
            Call::Prefetch(0, 16),
            Call::H2d,
            Call::TransferSync,
            Call::Fork(0),
            Call::Fork(1),
            Call::Fork(2),
        ] {
            let mut device = vec![0_u8; 40];
            let host = vec![0_u8; 40];
            let mut state = VmmAllocationState::Unmapped { generation: 0 };
            let mut operations = MockOps::failing(16, failure);
            assert!(unsafe {
                restore_tiled_transition(
                    &mut state,
                    &mut operations,
                    0,
                    1,
                    pointer(&mut device),
                    host.len(),
                    &host,
                )
            }
            .is_err());
            assert_eq!(state, VmmAllocationState::Poisoned);
        }
    }
}
