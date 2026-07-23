//! Stable-address whole-allocation VMM storage for bounded repeated reclaim.
//!
//! Each legal lifecycle step is mapped generation N, unmapped generation N
//! after a complete D2H spill, then physically remapped and restored as mapped
//! generation N+1. Unmapping consumes proof that every auxiliary lane joined
//! and the main stream completed; restore forks the new bytes into every lane.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::rc::Rc;

use super::exec_context::{
    check_cuda, CudaExecContext, CudaQuiescence, CudaRuntimeError, JoinedCudaLanes,
};

#[cfg(all(test, stwo_cuda_link))]
mod native_tests;
mod tiled;

pub use tiled::{PinnedDmaWindow, PinnedDmaWindowState};

const INITIAL_GENERATION: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmmAllocationState {
    Mapped { generation: u32 },
    Unmapped { generation: u32 },
    Poisoned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmmAllocationError {
    Cuda(CudaRuntimeError),
    InvalidSize(usize),
    InvalidStagingSize(usize),
    PinnedStagingAllocationFailed(usize),
    InvalidPinnedStagingState(PinnedDmaWindowState),
    InvalidGeometry {
        bytes: usize,
        granularity: usize,
    },
    SizeMismatch {
        expected: usize,
        actual: usize,
    },
    ContextMismatch,
    InvalidState {
        operation: &'static str,
        state: VmmAllocationState,
    },
    GenerationMismatch {
        expected: u32,
        actual: u32,
    },
    InvalidGenerationStep {
        current: u32,
        next: u32,
    },
    GenerationOverflow(u32),
    SequenceViolation(&'static str),
}

impl core::fmt::Display for VmmAllocationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cuda(error) => error.fmt(f),
            Self::InvalidSize(bytes) => write!(f, "invalid CUDA VMM allocation size {bytes}"),
            Self::InvalidStagingSize(bytes) => {
                write!(f, "invalid CUDA VMM staging-window size {bytes}")
            }
            Self::PinnedStagingAllocationFailed(bytes) => {
                write!(f, "CUDA pinned staging allocation failed for {bytes} bytes")
            }
            Self::InvalidPinnedStagingState(state) => {
                write!(f, "invalid CUDA pinned staging state {state:?}")
            }
            Self::InvalidGeometry { bytes, granularity } => write!(
                f,
                "invalid CUDA VMM geometry: {bytes} bytes at {granularity}-byte granularity"
            ),
            Self::SizeMismatch { expected, actual } => write!(
                f,
                "CUDA VMM full-allocation transfer requires {expected} bytes, got {actual}"
            ),
            Self::ContextMismatch => f.write_str("CUDA VMM owner context mismatch"),
            Self::InvalidState { operation, state } => {
                write!(
                    f,
                    "CUDA VMM operation {operation} is invalid in state {state:?}"
                )
            }
            Self::GenerationMismatch { expected, actual } => write!(
                f,
                "CUDA VMM generation mismatch: expected {expected}, actual {actual}"
            ),
            Self::InvalidGenerationStep { current, next } => write!(
                f,
                "CUDA VMM generation step must be consecutive, got {current} -> {next}"
            ),
            Self::GenerationOverflow(generation) => {
                write!(f, "CUDA VMM generation {generation} cannot be advanced")
            }
            Self::SequenceViolation(step) => {
                write!(f, "CUDA VMM quiescence sequence violated at {step}")
            }
        }
    }
}

impl std::error::Error for VmmAllocationError {}

impl From<CudaRuntimeError> for VmmAllocationError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

/// One stable virtual address with strictly consecutive reclaim generations.
///
/// This allocation is independent of [`super::exec_context::DeviceArena`]. A
/// graph may retain `stable_address`, but replay is legal only while `state` is
/// mapped. The exact owner context is borrowed for the allocation's lifetime,
/// making context-before-allocation destruction impossible. A workspace can
/// hold this value by borrowing an externally owned context or arena; it needs
/// no self-reference. Both values remain confined to one owning host thread. A
/// graph or consumer launch is forbidden unless [`Self::state`] is
/// [`VmmAllocationState::Mapped`] at the launch's exact expected generation.
pub struct VmmAllocation<'context> {
    handle: NonNull<c_void>,
    stable_address: NonNull<c_void>,
    bytes: usize,
    granularity: usize,
    owner_context: &'context CudaExecContext,
    state: VmmAllocationState,
    // VMM transitions are host-side boundaries owned by one scheduler thread.
    _same_thread: PhantomData<Rc<()>>,
}

impl<'context> VmmAllocation<'context> {
    pub fn new(
        context: &'context CudaExecContext,
        bytes: usize,
    ) -> Result<Self, VmmAllocationError> {
        if bytes == 0 {
            return Err(VmmAllocationError::InvalidSize(bytes));
        }
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(CudaRuntimeError::Unavailable.into());
        }

        let mut raw_handle = core::ptr::null_mut();
        let mut raw_address = core::ptr::null_mut();
        let mut mapped_bytes = 0usize;
        let mut granularity = 0usize;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_create(
                context.identity_token().as_ptr(),
                bytes,
                &mut raw_handle,
                &mut raw_address,
                &mut mapped_bytes,
                &mut granularity,
            )
        };
        if let Err(error) = check_cuda("vmm_allocation_create", code) {
            if !raw_handle.is_null() {
                unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_destroy(raw_handle);
                }
            }
            return Err(error.into());
        }

        let handle = NonNull::new(raw_handle).ok_or(CudaRuntimeError::NullPointer {
            operation: "vmm_allocation_create_handle",
        })?;
        let Some(stable_address) = NonNull::new(raw_address) else {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_destroy(handle.as_ptr());
            }
            return Err(CudaRuntimeError::NullPointer {
                operation: "vmm_allocation_create_address",
            }
            .into());
        };
        if mapped_bytes != bytes {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_destroy(handle.as_ptr());
            }
            return Err(VmmAllocationError::SizeMismatch {
                expected: bytes,
                actual: mapped_bytes,
            });
        }
        if !valid_geometry(mapped_bytes, granularity) {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_destroy(handle.as_ptr());
            }
            return Err(VmmAllocationError::InvalidGeometry {
                bytes: mapped_bytes,
                granularity,
            });
        }

        Ok(Self {
            handle,
            stable_address,
            bytes,
            granularity,
            owner_context: context,
            state: VmmAllocationState::Mapped {
                generation: INITIAL_GENERATION,
            },
            _same_thread: PhantomData,
        })
    }

    /// The reserved address is numerically stable across reclaim generations.
    /// It may be dereferenced or captured by a graph only while [`Self::state`]
    /// is [`VmmAllocationState::Mapped`] at the consumer's expected generation.
    pub fn stable_address(&self) -> NonNull<c_void> {
        self.stable_address
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn granularity(&self) -> usize {
        self.granularity
    }

    pub fn state(&self) -> VmmAllocationState {
        self.state
    }
}

impl Drop for VmmAllocation<'_> {
    fn drop(&mut self) {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_destroy(self.handle.as_ptr())
        };
        if code != 0 && !std::thread::panicking() {
            eprintln!("stwo-backend-cuda: vmm_allocation_destroy failed with status {code}");
        }
    }
}

fn valid_geometry(bytes: usize, granularity: usize) -> bool {
    granularity != 0 && granularity.is_power_of_two() && bytes != 0 && bytes % granularity == 0
}

fn require_exact_bytes(expected: usize, actual: usize) -> Result<(), VmmAllocationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(VmmAllocationError::SizeMismatch { expected, actual })
    }
}

fn require_mapped_generation(
    state: VmmAllocationState,
    operation: &'static str,
    expected_generation: u32,
) -> Result<(), VmmAllocationError> {
    match state {
        VmmAllocationState::Mapped { generation } if generation == expected_generation => Ok(()),
        VmmAllocationState::Mapped { generation } => Err(VmmAllocationError::GenerationMismatch {
            expected: expected_generation,
            actual: generation,
        }),
        state => Err(VmmAllocationError::InvalidState { operation, state }),
    }
}

fn require_unmapped_generation_step(
    state: VmmAllocationState,
    operation: &'static str,
    current_generation: u32,
    next_generation: u32,
) -> Result<(), VmmAllocationError> {
    match state {
        VmmAllocationState::Unmapped { generation } if generation == current_generation => {}
        VmmAllocationState::Unmapped { generation } => {
            return Err(VmmAllocationError::GenerationMismatch {
                expected: current_generation,
                actual: generation,
            });
        }
        state => return Err(VmmAllocationError::InvalidState { operation, state }),
    }
    let expected_next = current_generation
        .checked_add(1)
        .ok_or(VmmAllocationError::GenerationOverflow(current_generation))?;
    if next_generation != expected_next {
        return Err(VmmAllocationError::InvalidGenerationStep {
            current: current_generation,
            next: next_generation,
        });
    }
    Ok(())
}

trait VmmOps {
    fn join_all_lanes(&mut self) -> Result<(), VmmAllocationError>;

    unsafe fn copy_d2h(
        &mut self,
        destination: NonNull<c_void>,
        source: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError>;

    fn sync_main(&mut self) -> Result<(), VmmAllocationError>;
    fn sync_transfer(&mut self) -> Result<(), VmmAllocationError>;
    fn unmap_release(&mut self, expected_generation: u32) -> Result<(), VmmAllocationError>;
    fn remap_next(
        &mut self,
        current_generation: u32,
        next_generation: u32,
    ) -> Result<(), VmmAllocationError>;
    fn lane_count(&self) -> usize;
    fn fork_lane(&mut self, lane: usize) -> Result<(), VmmAllocationError>;

    unsafe fn copy_h2d(
        &mut self,
        destination: NonNull<c_void>,
        source: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError>;
}

struct CudaVmmOps<'a> {
    allocation: NonNull<c_void>,
    context: &'a CudaExecContext,
    joined: Option<JoinedCudaLanes<'a>>,
    quiescence: Option<CudaQuiescence>,
    transfer_pending: bool,
}

impl<'a> CudaVmmOps<'a> {
    fn new(allocation: NonNull<c_void>, context: &'a CudaExecContext) -> Self {
        Self {
            allocation,
            context,
            joined: None,
            quiescence: None,
            transfer_pending: false,
        }
    }
}

impl VmmOps for CudaVmmOps<'_> {
    fn join_all_lanes(&mut self) -> Result<(), VmmAllocationError> {
        if self.joined.is_some() || self.quiescence.is_some() {
            return Err(VmmAllocationError::SequenceViolation("join_all_lanes"));
        }
        self.joined = Some(self.context.join_all_lanes_for_vmm()?);
        Ok(())
    }

    unsafe fn copy_d2h(
        &mut self,
        destination: NonNull<c_void>,
        source: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError> {
        if self.transfer_pending {
            return Err(VmmAllocationError::SequenceViolation("copy_d2h_pending"));
        }
        self.transfer_pending = true;
        if let Some(joined) = &self.joined {
            unsafe {
                joined.memcpy_d2h_async(destination.as_ptr(), source.as_ptr(), bytes)?;
            }
        } else if self.quiescence.is_some() {
            unsafe {
                self.context
                    .memcpy_d2h_async(destination.as_ptr(), source.as_ptr(), bytes)?;
            }
        } else {
            return Err(VmmAllocationError::SequenceViolation("copy_d2h"));
        }
        Ok(())
    }

    fn sync_main(&mut self) -> Result<(), VmmAllocationError> {
        let joined = self
            .joined
            .take()
            .ok_or(VmmAllocationError::SequenceViolation("sync_main"))?;
        self.quiescence = Some(joined.sync_main()?);
        self.transfer_pending = false;
        Ok(())
    }

    fn sync_transfer(&mut self) -> Result<(), VmmAllocationError> {
        if !self.transfer_pending {
            return Err(VmmAllocationError::SequenceViolation("sync_transfer"));
        }
        self.context.sync()?;
        self.transfer_pending = false;
        Ok(())
    }

    fn unmap_release(&mut self, expected_generation: u32) -> Result<(), VmmAllocationError> {
        if self.transfer_pending {
            return Err(VmmAllocationError::SequenceViolation(
                "unmap_pending_transfer",
            ));
        }
        let quiescence = self
            .quiescence
            .take()
            .ok_or(VmmAllocationError::SequenceViolation("unmap_release"))?;
        if quiescence.context_token() != self.context.identity_token() {
            return Err(VmmAllocationError::ContextMismatch);
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_unmap_release(
                self.allocation.as_ptr(),
                self.context.identity_token().as_ptr(),
                expected_generation,
            )
        };
        check_cuda("vmm_allocation_unmap_release", code)?;
        Ok(())
    }

    fn remap_next(
        &mut self,
        current_generation: u32,
        next_generation: u32,
    ) -> Result<(), VmmAllocationError> {
        if self.transfer_pending {
            return Err(VmmAllocationError::SequenceViolation(
                "remap_pending_transfer",
            ));
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_remap_next(
                self.allocation.as_ptr(),
                self.context.identity_token().as_ptr(),
                current_generation,
                next_generation,
            )
        };
        check_cuda("vmm_allocation_remap_next", code)?;
        Ok(())
    }

    fn lane_count(&self) -> usize {
        self.context.lane_count()
    }

    fn fork_lane(&mut self, lane: usize) -> Result<(), VmmAllocationError> {
        self.context.fork_lane(lane)?;
        Ok(())
    }

    unsafe fn copy_h2d(
        &mut self,
        destination: NonNull<c_void>,
        source: NonNull<c_void>,
        bytes: usize,
    ) -> Result<(), VmmAllocationError> {
        if self.transfer_pending {
            return Err(VmmAllocationError::SequenceViolation("copy_h2d_pending"));
        }
        self.transfer_pending = true;
        unsafe {
            self.context.memcpy_h2d_async(
                destination.as_ptr(),
                source.as_ptr().cast_const(),
                bytes,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
unsafe fn spill_transition(
    state: &mut VmmAllocationState,
    operations: &mut impl VmmOps,
    expected_generation: u32,
    host_destination: NonNull<c_void>,
    device_source: NonNull<c_void>,
    bytes: usize,
) -> Result<(), VmmAllocationError> {
    if let Err(error) = require_mapped_generation(*state, "spill", expected_generation) {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    if let Err(error) = operations.join_all_lanes() {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    if let Err(error) = unsafe { operations.copy_d2h(host_destination, device_source, bytes) } {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    if let Err(error) = operations.sync_main() {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    if let Err(error) = operations.unmap_release(expected_generation) {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    *state = VmmAllocationState::Unmapped {
        generation: expected_generation,
    };
    Ok(())
}

#[cfg(test)]
unsafe fn restore_transition(
    state: &mut VmmAllocationState,
    operations: &mut impl VmmOps,
    current_generation: u32,
    next_generation: u32,
    device_destination: NonNull<c_void>,
    host_source: NonNull<c_void>,
    bytes: usize,
) -> Result<(), VmmAllocationError> {
    if let Err(error) =
        require_unmapped_generation_step(*state, "restore", current_generation, next_generation)
    {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    if let Err(error) = operations.remap_next(current_generation, next_generation) {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    if let Err(error) = unsafe { operations.copy_h2d(device_destination, host_source, bytes) } {
        *state = VmmAllocationState::Poisoned;
        return Err(error);
    }
    for lane in 0..operations.lane_count() {
        if let Err(error) = operations.fork_lane(lane) {
            *state = VmmAllocationState::Poisoned;
            return Err(error);
        }
    }
    *state = VmmAllocationState::Mapped {
        generation: next_generation,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        JoinAll,
        D2h,
        Sync,
        TransferSync,
        Unmap(u32),
        Remap(u32, u32),
        H2d,
        Fork(usize),
    }

    #[derive(Default)]
    struct MockOps {
        calls: Vec<Call>,
        fail_at: Option<Call>,
    }

    impl MockOps {
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
            self.invoke(Call::D2h)
        }

        fn sync_main(&mut self) -> Result<(), VmmAllocationError> {
            self.invoke(Call::Sync)
        }

        fn sync_transfer(&mut self) -> Result<(), VmmAllocationError> {
            self.invoke(Call::TransferSync)
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
            self.invoke(Call::H2d)
        }
    }

    fn pointer() -> NonNull<c_void> {
        NonNull::dangling()
    }

    #[test]
    fn lifecycle_is_exact_and_orders_quiescence_before_unmap() {
        let mut state = VmmAllocationState::Mapped { generation: 0 };
        let mut spill = MockOps::default();
        unsafe {
            spill_transition(&mut state, &mut spill, 0, pointer(), pointer(), 64).unwrap();
        }
        assert_eq!(
            spill.calls,
            [Call::JoinAll, Call::D2h, Call::Sync, Call::Unmap(0)]
        );
        assert_eq!(state, VmmAllocationState::Unmapped { generation: 0 });

        let mut restore = MockOps::default();
        unsafe {
            restore_transition(&mut state, &mut restore, 0, 1, pointer(), pointer(), 64).unwrap();
        }
        assert_eq!(
            restore.calls,
            [
                Call::Remap(0, 1),
                Call::H2d,
                Call::Fork(0),
                Call::Fork(1),
                Call::Fork(2),
            ]
        );
        assert_eq!(state, VmmAllocationState::Mapped { generation: 1 });

        let mut rejected = MockOps::default();
        assert_eq!(
            unsafe { spill_transition(&mut state, &mut rejected, 0, pointer(), pointer(), 64) },
            Err(VmmAllocationError::GenerationMismatch {
                expected: 0,
                actual: 1,
            })
        );
        assert!(rejected.calls.is_empty());
        assert_eq!(state, VmmAllocationState::Poisoned);
    }

    #[test]
    fn every_spill_failure_stops_before_later_steps_and_poison_state() {
        let cases = [
            (Call::JoinAll, vec![Call::JoinAll]),
            (Call::D2h, vec![Call::JoinAll, Call::D2h]),
            (Call::Sync, vec![Call::JoinAll, Call::D2h, Call::Sync]),
            (
                Call::Unmap(0),
                vec![Call::JoinAll, Call::D2h, Call::Sync, Call::Unmap(0)],
            ),
        ];
        for (fail_at, expected) in cases {
            let mut state = VmmAllocationState::Mapped { generation: 0 };
            let mut operations = MockOps {
                fail_at: Some(fail_at),
                ..MockOps::default()
            };
            assert!(unsafe {
                spill_transition(&mut state, &mut operations, 0, pointer(), pointer(), 64)
            }
            .is_err());
            assert_eq!(operations.calls, expected);
            assert_eq!(state, VmmAllocationState::Poisoned);
        }
    }

    #[test]
    fn every_restore_and_partial_fork_failure_poison_state_and_cannot_retry() {
        for (fail_at, expected) in [
            (Call::Remap(0, 1), vec![Call::Remap(0, 1)]),
            (Call::H2d, vec![Call::Remap(0, 1), Call::H2d]),
            (
                Call::Fork(0),
                vec![Call::Remap(0, 1), Call::H2d, Call::Fork(0)],
            ),
            (
                Call::Fork(1),
                vec![Call::Remap(0, 1), Call::H2d, Call::Fork(0), Call::Fork(1)],
            ),
            (
                Call::Fork(2),
                vec![
                    Call::Remap(0, 1),
                    Call::H2d,
                    Call::Fork(0),
                    Call::Fork(1),
                    Call::Fork(2),
                ],
            ),
        ] {
            let mut state = VmmAllocationState::Unmapped { generation: 0 };
            let mut operations = MockOps {
                fail_at: Some(fail_at),
                ..MockOps::default()
            };
            assert!(unsafe {
                restore_transition(&mut state, &mut operations, 0, 1, pointer(), pointer(), 64)
            }
            .is_err());
            assert_eq!(operations.calls, expected);
            assert_eq!(state, VmmAllocationState::Poisoned);

            let mut retry = MockOps::default();
            assert!(unsafe {
                restore_transition(&mut state, &mut retry, 0, 1, pointer(), pointer(), 64)
            }
            .is_err());
            assert!(retry.calls.is_empty());
        }
    }

    #[test]
    fn full_allocation_geometry_is_exact() {
        assert!(valid_geometry(128 * 1024, 64 * 1024));
        assert!(!valid_geometry(96 * 1024, 64 * 1024));
        assert!(!valid_geometry(64 * 1024, 48 * 1024));
        assert_eq!(require_exact_bytes(64, 64), Ok(()));
        assert_eq!(
            require_exact_bytes(64, 63),
            Err(VmmAllocationError::SizeMismatch {
                expected: 64,
                actual: 63,
            })
        );
    }
}
