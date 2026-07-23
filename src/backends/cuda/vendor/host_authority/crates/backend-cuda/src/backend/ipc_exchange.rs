//! Dedicated same-node CUDA IPC exchange buffers for Track-A fleet edges.
//!
//! The exported allocation is never a proof slab or pool allocation. One owner
//! publishes into a 2 MiB-rounded `cudaMalloc` buffer; one exact peer imports
//! it, waits, copies the exact logical extent, and signals consumption.

use core::ffi::c_void;
use core::ptr::NonNull;

use super::exec_context::{check_cuda, CudaExecContext, CudaRuntimeError};

pub const IPC_EXCHANGE_ALLOCATION_ALIGNMENT: usize = 2 * 1024 * 1024;

#[path = "ipc_exchange_wire.rs"]
mod wire;
pub use wire::{
    CudaDeviceUuid, IpcExchangeDescriptor, IpcExchangeInstallDomain, IpcExchangeKey,
    IpcPeerCloseReceipt, CUDA_DEVICE_UUID_BYTES, CUDA_IPC_HANDLE_BYTES,
    IPC_EXCHANGE_CLOSE_RECEIPT_BYTES, IPC_EXCHANGE_DESCRIPTOR_BYTES,
    IPC_EXCHANGE_INSTALL_DOMAIN_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcExchangePhase {
    Published,
    Consumed,
    Reclaimed,
    Armed,
}

/// Backend-issued observation of one live CUDA execution context's device.
///
/// Unlike a UUID decoded from an IPC descriptor, this receipt can only be
/// constructed by querying a live [`CudaExecContext`]. Its private,
/// non-cloneable fields bind the context token, CUDA device ordinal and Driver
/// UUID observed by that query.
///
/// ```compile_fail
/// use stwo_backend_cuda::CudaDeviceIdentityReceipt;
///
/// fn duplicate(receipt: CudaDeviceIdentityReceipt) {
///     let _copy = receipt.clone();
/// }
/// ```
#[must_use = "consume this receipt when installing the fleet worker roster"]
pub struct CudaDeviceIdentityReceipt {
    _context_token: usize,
    device_ordinal: u32,
    device_uuid: CudaDeviceUuid,
}

impl CudaDeviceIdentityReceipt {
    pub const fn device_ordinal(&self) -> u32 {
        self.device_ordinal
    }

    pub const fn device_uuid(&self) -> CudaDeviceUuid {
        self.device_uuid
    }
}

/// Backend-issued authority that one exact IPC operation was accepted by CUDA.
///
/// The private fields and constructor prevent the coordinator from fabricating
/// progress. The receipt proves successful enqueue, while the IPC events carry
/// the corresponding device-ordering dependency.
#[must_use = "forward this receipt to the fleet coordinator"]
#[derive(Debug, Eq, PartialEq)]
pub struct IpcExchangePhaseReceipt {
    key: IpcExchangeKey,
    phase: IpcExchangePhase,
    generation: u64,
}

impl IpcExchangePhaseReceipt {
    const fn new(key: IpcExchangeKey, phase: IpcExchangePhase, generation: u64) -> Self {
        Self {
            key,
            phase,
            generation,
        }
    }

    pub const fn key(&self) -> IpcExchangeKey {
        self.key
    }

    pub const fn phase(&self) -> IpcExchangePhase {
        self.phase
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcExchangeOwnerState {
    Local { generation: u64 },
    Idle { generation: u64 },
    Published { generation: u64 },
    PeerClosed { generation: u64 },
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcExchangeImportState {
    Awaiting { generation: u64 },
    Consumed { generation: u64 },
    Poisoned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcExchangeError {
    Cuda(CudaRuntimeError),
    InvalidDeviceIdentity(&'static str),
    InvalidKey(&'static str),
    InvalidDescriptor(&'static str),
    DescriptorMismatch,
    SizeMismatch { expected: usize, actual: usize },
    GenerationMismatch { expected: u64, actual: u64 },
    InvalidOwnerState(IpcExchangeOwnerState),
    InvalidImportState(IpcExchangeImportState),
}

impl core::fmt::Display for IpcExchangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CUDA IPC exchange error: {self:?}")
    }
}

impl std::error::Error for IpcExchangeError {}

impl From<CudaRuntimeError> for IpcExchangeError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub fn cuda_context_device_identity(
    context: &CudaExecContext,
) -> Result<CudaDeviceIdentityReceipt, IpcExchangeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable.into());
    }
    let mut device = -1i32;
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_exec_context_device(
            context.identity_token().as_ptr(),
            &mut device,
        )
    };
    check_cuda("ipc_exchange_context_device", code)?;
    let device_ordinal = u32::try_from(device)
        .map_err(|_| IpcExchangeError::InvalidDeviceIdentity("negative CUDA device ordinal"))?;
    let device_uuid = cuda_context_device_uuid(context)?;
    if device_uuid.as_bytes() == &[0; CUDA_DEVICE_UUID_BYTES] {
        return Err(IpcExchangeError::InvalidDeviceIdentity(
            "zero CUDA device UUID",
        ));
    }
    Ok(CudaDeviceIdentityReceipt {
        _context_token: context.identity_token().as_ptr() as usize,
        device_ordinal,
        device_uuid,
    })
}

/// Query the UUID value used in an exchange key.
///
/// This copyable value is not context-identity authority. Fleet roster
/// installation must consume [`CudaDeviceIdentityReceipt`] instead.
pub fn cuda_context_device_uuid(
    context: &CudaExecContext,
) -> Result<CudaDeviceUuid, IpcExchangeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable.into());
    }
    let mut bytes = [0u8; CUDA_DEVICE_UUID_BYTES];
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_context_uuid(
            context.identity_token().as_ptr(),
            bytes.as_mut_ptr(),
        )
    };
    check_cuda("ipc_exchange_context_uuid", code)?;
    Ok(CudaDeviceUuid::from_bytes(bytes))
}

#[must_use = "an exported owner must be closed after a peer-close receipt"]
pub struct CudaIpcExchangeOwner<'context> {
    handle: Option<NonNull<c_void>>,
    context: &'context CudaExecContext,
    descriptor: IpcExchangeDescriptor,
    state: IpcExchangeOwnerState,
}

impl<'context> CudaIpcExchangeOwner<'context> {
    pub fn new(
        context: &'context CudaExecContext,
        key: IpcExchangeKey,
    ) -> Result<Self, IpcExchangeError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(CudaRuntimeError::Unavailable.into());
        }
        let mut raw_handle = core::ptr::null_mut();
        let mut raw_pointer = core::ptr::null_mut();
        let mut allocation_bytes = 0usize;
        let mut memory_handle = [0u8; CUDA_IPC_HANDLE_BYTES];
        let mut ready_event_handle = [0u8; CUDA_IPC_HANDLE_BYTES];
        let mut consumed_event_handle = [0u8; CUDA_IPC_HANDLE_BYTES];
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_create(
                context.identity_token().as_ptr(),
                key.logical_bytes,
                key.initial_generation,
                key.owner_device.as_bytes().as_ptr(),
                &mut raw_handle,
                &mut raw_pointer,
                &mut allocation_bytes,
                memory_handle.as_mut_ptr(),
                ready_event_handle.as_mut_ptr(),
                consumed_event_handle.as_mut_ptr(),
            )
        };
        check_cuda("ipc_exchange_owner_create", code)?;
        let handle = NonNull::new(raw_handle).ok_or(CudaRuntimeError::NullPointer {
            operation: "ipc_exchange_owner_create_handle",
        })?;
        if raw_pointer.is_null() || allocation_bytes != rounded_allocation_bytes(key.logical_bytes)?
        {
            unsafe {
                let _ = stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_mark_peer_closed(
                    handle.as_ptr(),
                    context.identity_token().as_ptr(),
                    key.initial_generation,
                );
                let _ = stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_close(
                    handle.as_ptr(),
                    context.identity_token().as_ptr(),
                );
            }
            return Err(IpcExchangeError::InvalidDescriptor("native geometry"));
        }
        Ok(Self {
            handle: Some(handle),
            context,
            descriptor: IpcExchangeDescriptor {
                key,
                allocation_bytes,
                memory_handle,
                ready_event_handle,
                consumed_event_handle,
            },
            state: IpcExchangeOwnerState::Local {
                generation: key.initial_generation,
            },
        })
    }

    pub const fn state(&self) -> IpcExchangeOwnerState {
        self.state
    }

    pub const fn allocation_bytes(&self) -> usize {
        self.descriptor.allocation_bytes
    }

    pub fn export(&mut self) -> Result<IpcExchangeDescriptor, IpcExchangeError> {
        let IpcExchangeOwnerState::Local { generation } = self.state else {
            return Err(IpcExchangeError::InvalidOwnerState(self.state));
        };
        self.state = IpcExchangeOwnerState::Idle { generation };
        Ok(self.descriptor.clone())
    }

    /// Copy the exact source extent into the dedicated buffer, then signal it.
    ///
    /// # Safety
    /// `source` must be a live owner-device range for exactly `bytes` and must
    /// remain live until later owner-stream ordering reaches the copy.
    pub unsafe fn publish(
        &mut self,
        source: NonNull<c_void>,
        bytes: usize,
        generation: u64,
    ) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
        require_bytes(self.descriptor.key.logical_bytes, bytes)?;
        let handle = self.raw_handle();
        let context = self.context.identity_token();
        owner_publish_transition(&mut self.state, self.descriptor.key, generation, || {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_publish(
                    handle.as_ptr(),
                    context.as_ptr(),
                    source.as_ptr(),
                    bytes,
                    generation,
                )
            };
            check_cuda("ipc_exchange_owner_publish", code)
        })
    }

    /// Enqueue a wait for the peer's consumed event before any buffer reuse.
    pub fn reclaim(
        &mut self,
        generation: u64,
    ) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
        let handle = self.raw_handle();
        let context = self.context.identity_token();
        owner_reclaim_transition(&mut self.state, self.descriptor.key, generation, || {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_reclaim(
                    handle.as_ptr(),
                    context.as_ptr(),
                    generation,
                )
            };
            check_cuda("ipc_exchange_owner_reclaim", code)
        })
    }

    pub fn accept_peer_close(
        &mut self,
        receipt: &IpcPeerCloseReceipt,
    ) -> Result<(), IpcExchangeError> {
        if receipt.key != self.descriptor.key {
            return Err(IpcExchangeError::DescriptorMismatch);
        }
        let IpcExchangeOwnerState::Idle { generation } = self.state else {
            return Err(IpcExchangeError::InvalidOwnerState(self.state));
        };
        if generation != receipt.generation {
            return Err(IpcExchangeError::GenerationMismatch {
                expected: generation,
                actual: receipt.generation,
            });
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_mark_peer_closed(
                self.raw_handle().as_ptr(),
                self.context.identity_token().as_ptr(),
                generation,
            )
        };
        check_cuda("ipc_exchange_owner_mark_peer_closed", code)?;
        self.state = IpcExchangeOwnerState::PeerClosed { generation };
        Ok(())
    }

    pub fn close(mut self) -> Result<(), IpcExchangeError> {
        if !matches!(self.state, IpcExchangeOwnerState::PeerClosed { .. }) {
            return Err(IpcExchangeError::InvalidOwnerState(self.state));
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_close(
                self.raw_handle().as_ptr(),
                self.context.identity_token().as_ptr(),
            )
        };
        if let Err(error) = check_cuda("ipc_exchange_owner_close", code) {
            self.state = IpcExchangeOwnerState::Poisoned;
            return Err(error.into());
        }
        self.handle = None;
        Ok(())
    }

    fn raw_handle(&self) -> NonNull<c_void> {
        self.handle.expect("live owner always has a native handle")
    }
}

impl Drop for CudaIpcExchangeOwner<'_> {
    fn drop(&mut self) {
        let Some(handle) = self.handle else { return };
        if let IpcExchangeOwnerState::Local { generation } = self.state {
            unsafe {
                let _ = stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_mark_peer_closed(
                    handle.as_ptr(),
                    self.context.identity_token().as_ptr(),
                    generation,
                );
                let _ = stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_owner_close(
                    handle.as_ptr(),
                    self.context.identity_token().as_ptr(),
                );
            }
        } else if !std::thread::panicking() {
            eprintln!(
                "stwo-backend-cuda: leaked exported IPC owner until process exit; peer-close receipt missing"
            );
        }
    }
}

#[must_use = "close the import and return its peer-close receipt"]
pub struct CudaIpcExchangeImport<'context> {
    handle: Option<NonNull<c_void>>,
    context: &'context CudaExecContext,
    descriptor: IpcExchangeDescriptor,
    state: IpcExchangeImportState,
}

impl<'context> CudaIpcExchangeImport<'context> {
    pub fn open(
        context: &'context CudaExecContext,
        expected_key: IpcExchangeKey,
        descriptor: IpcExchangeDescriptor,
    ) -> Result<Self, IpcExchangeError> {
        if expected_key != descriptor.key {
            return Err(IpcExchangeError::DescriptorMismatch);
        }
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(CudaRuntimeError::Unavailable.into());
        }
        let mut raw_handle = core::ptr::null_mut();
        let mut remote_pointer = core::ptr::null_mut();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_import_open(
                context.identity_token().as_ptr(),
                expected_key.logical_bytes,
                descriptor.allocation_bytes,
                expected_key.initial_generation,
                expected_key.peer_device.as_bytes().as_ptr(),
                descriptor.memory_handle.as_ptr(),
                descriptor.ready_event_handle.as_ptr(),
                descriptor.consumed_event_handle.as_ptr(),
                &mut raw_handle,
                &mut remote_pointer,
            )
        };
        check_cuda("ipc_exchange_import_open", code)?;
        let handle = NonNull::new(raw_handle).ok_or(CudaRuntimeError::NullPointer {
            operation: "ipc_exchange_import_open_handle",
        })?;
        if remote_pointer.is_null() {
            unsafe {
                let _ = stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_import_destroy(
                    handle.as_ptr(),
                );
            }
            return Err(CudaRuntimeError::NullPointer {
                operation: "ipc_exchange_import_open_pointer",
            }
            .into());
        }
        Ok(Self {
            handle: Some(handle),
            context,
            descriptor,
            state: IpcExchangeImportState::Awaiting {
                generation: expected_key.initial_generation,
            },
        })
    }

    pub const fn state(&self) -> IpcExchangeImportState {
        self.state
    }

    /// Wait for the owner signal, copy the exact extent, then signal consumed.
    ///
    /// # Safety
    /// `destination` must be a live, non-overlapping peer-device range for
    /// exactly `bytes` and remain live through later peer-stream ordering.
    pub unsafe fn consume_into(
        &mut self,
        destination: NonNull<c_void>,
        bytes: usize,
        generation: u64,
    ) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
        require_bytes(self.descriptor.key.logical_bytes, bytes)?;
        let handle = self.raw_handle();
        let context = self.context.identity_token();
        import_consume_transition(&mut self.state, self.descriptor.key, generation, || {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_import_consume(
                    handle.as_ptr(),
                    context.as_ptr(),
                    destination.as_ptr(),
                    bytes,
                    generation,
                )
            };
            check_cuda("ipc_exchange_import_consume", code)
        })
    }

    /// Arm only after the coordinator confirms the owner enqueued its consumed
    /// wait; this prevents a wait from binding the previous event generation.
    pub fn arm_next(
        &mut self,
        next_generation: u64,
    ) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
        let handle = self.raw_handle();
        let context = self.context.identity_token();
        import_arm_transition(
            &mut self.state,
            self.descriptor.key,
            next_generation,
            || {
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_import_arm_next(
                        handle.as_ptr(),
                        context.as_ptr(),
                        next_generation,
                    )
                };
                check_cuda("ipc_exchange_import_arm_next", code)
            },
        )
    }

    pub fn close(mut self) -> Result<IpcPeerCloseReceipt, IpcExchangeError> {
        let IpcExchangeImportState::Awaiting { generation } = self.state else {
            return Err(IpcExchangeError::InvalidImportState(self.state));
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_import_close(
                self.raw_handle().as_ptr(),
                self.context.identity_token().as_ptr(),
                generation,
            )
        };
        if let Err(error) = check_cuda("ipc_exchange_import_close", code) {
            self.state = IpcExchangeImportState::Poisoned;
            return Err(error.into());
        }
        self.handle = None;
        Ok(IpcPeerCloseReceipt {
            key: self.descriptor.key,
            generation,
        })
    }

    fn raw_handle(&self) -> NonNull<c_void> {
        self.handle.expect("live import always has a native handle")
    }
}

impl Drop for CudaIpcExchangeImport<'_> {
    fn drop(&mut self) {
        let Some(handle) = self.handle else { return };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ipc_exchange_import_destroy(handle.as_ptr())
        };
        if code != 0 && !std::thread::panicking() {
            eprintln!("stwo-backend-cuda: ipc_exchange_import_destroy failed with status {code}");
        }
    }
}

fn rounded_allocation_bytes(logical_bytes: usize) -> Result<usize, IpcExchangeError> {
    if logical_bytes == 0 {
        return Err(IpcExchangeError::InvalidKey("zero logical byte extent"));
    }
    logical_bytes
        .checked_add(IPC_EXCHANGE_ALLOCATION_ALIGNMENT - 1)
        .map(|bytes| bytes & !(IPC_EXCHANGE_ALLOCATION_ALIGNMENT - 1))
        .ok_or(IpcExchangeError::InvalidKey("allocation byte overflow"))
}

fn require_bytes(expected: usize, actual: usize) -> Result<(), IpcExchangeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(IpcExchangeError::SizeMismatch { expected, actual })
    }
}

fn require_generation(expected: u64, actual: u64) -> Result<(), IpcExchangeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(IpcExchangeError::GenerationMismatch { expected, actual })
    }
}

fn require_owner_generation(
    state: IpcExchangeOwnerState,
    generation: u64,
    published: bool,
) -> Result<(), IpcExchangeError> {
    let expected = match (state, published) {
        (IpcExchangeOwnerState::Idle { generation }, false)
        | (IpcExchangeOwnerState::Published { generation }, true) => generation,
        _ => return Err(IpcExchangeError::InvalidOwnerState(state)),
    };
    require_generation(expected, generation)
}

fn owner_publish_transition(
    state: &mut IpcExchangeOwnerState,
    key: IpcExchangeKey,
    generation: u64,
    operation: impl FnOnce() -> Result<(), CudaRuntimeError>,
) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
    require_owner_generation(*state, generation, false)?;
    if let Err(error) = operation() {
        *state = IpcExchangeOwnerState::Poisoned;
        return Err(error.into());
    }
    *state = IpcExchangeOwnerState::Published { generation };
    Ok(IpcExchangePhaseReceipt::new(
        key,
        IpcExchangePhase::Published,
        generation,
    ))
}

fn owner_reclaim_transition(
    state: &mut IpcExchangeOwnerState,
    key: IpcExchangeKey,
    generation: u64,
    operation: impl FnOnce() -> Result<(), CudaRuntimeError>,
) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
    require_owner_generation(*state, generation, true)?;
    let next = generation
        .checked_add(1)
        .ok_or(IpcExchangeError::GenerationMismatch {
            expected: generation,
            actual: generation,
        })?;
    if let Err(error) = operation() {
        *state = IpcExchangeOwnerState::Poisoned;
        return Err(error.into());
    }
    *state = IpcExchangeOwnerState::Idle { generation: next };
    Ok(IpcExchangePhaseReceipt::new(
        key,
        IpcExchangePhase::Reclaimed,
        generation,
    ))
}

fn import_consume_transition(
    state: &mut IpcExchangeImportState,
    key: IpcExchangeKey,
    generation: u64,
    operation: impl FnOnce() -> Result<(), CudaRuntimeError>,
) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
    let IpcExchangeImportState::Awaiting {
        generation: expected,
    } = *state
    else {
        return Err(IpcExchangeError::InvalidImportState(*state));
    };
    require_generation(expected, generation)?;
    if let Err(error) = operation() {
        *state = IpcExchangeImportState::Poisoned;
        return Err(error.into());
    }
    *state = IpcExchangeImportState::Consumed { generation };
    Ok(IpcExchangePhaseReceipt::new(
        key,
        IpcExchangePhase::Consumed,
        generation,
    ))
}

fn import_arm_transition(
    state: &mut IpcExchangeImportState,
    key: IpcExchangeKey,
    next_generation: u64,
    operation: impl FnOnce() -> Result<(), CudaRuntimeError>,
) -> Result<IpcExchangePhaseReceipt, IpcExchangeError> {
    let IpcExchangeImportState::Consumed { generation } = *state else {
        return Err(IpcExchangeError::InvalidImportState(*state));
    };
    let expected = generation
        .checked_add(1)
        .ok_or(IpcExchangeError::GenerationMismatch {
            expected: generation,
            actual: next_generation,
        })?;
    require_generation(expected, next_generation)?;
    if let Err(error) = operation() {
        *state = IpcExchangeImportState::Poisoned;
        return Err(error.into());
    }
    *state = IpcExchangeImportState::Awaiting {
        generation: next_generation,
    };
    Ok(IpcExchangePhaseReceipt::new(
        key,
        IpcExchangePhase::Armed,
        next_generation,
    ))
}

#[cfg(test)]
#[path = "ipc_exchange_tests.rs"]
mod tests;
