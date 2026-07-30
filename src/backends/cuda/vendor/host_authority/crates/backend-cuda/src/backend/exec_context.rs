//! Per-proof CUDA execution resources: an isolated stream/pool, a stable device
//! arena, and transcript-bounded dependency-graph capture. The main stream owns
//! transcript order; fixed auxiliary lanes express independent component work.
//!
//! There is deliberately no default/TLS context. A proof workspace owns one
//! [`DeviceArena`], which in turn owns its [`CudaExecContext`]. Graphs must be
//! destroyed before their arena because captured nodes contain arena addresses.

use core::cell::Cell;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::collections::BTreeMap;
use std::rc::Rc;

const CUDA_SUCCESS: i32 = 0;

/// Auditable host/runtime boundary counters for one proof-owned context. These
/// count API operations issued by the resident runtime; CUDA work replayed from
/// an instantiated graph is represented by `graph_launches`, not re-counted as
/// fresh host calls.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CudaExecTelemetry {
    pub sync_calls: u64,
    pub allocations: u64,
    pub allocation_bytes: u64,
    pub frees: u64,
    pub memset_bytes: u64,
    pub fill_words: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub d2d_bytes: u64,
    pub capture_begins: u64,
    pub capture_finishes: u64,
    pub capture_aborts: u64,
    pub graph_launches: u64,
    pub lane_forks: u64,
    pub lane_joins: u64,
    /// Kernel nodes submitted by graph replay. Capture-time execution is setup
    /// and excluded after the hot-path telemetry reset.
    pub kernel_launches: u64,
    pub graph_submit_gap_ns_total: u64,
    pub graph_submit_gap_ns_max: u64,
}

/// Current CUDA memory-pool footprint in bytes.
///
/// `used_bytes` is live application memory. `reserved_bytes` is device backing
/// still held by the pool, so their difference is allocator reserve/slack rather
/// than another allocation to add to the physical ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CudaPoolMemory {
    pub used_bytes: usize,
    pub reserved_bytes: usize,
}

/// Checked failure from the CUDA runtime boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaRuntimeError {
    /// This binary was built without the CUDA kernel archive.
    Unavailable,
    /// CUDA returned a non-zero status code.
    Cuda {
        operation: &'static str,
        code: i32,
    },
    /// CUDA reported success without returning the required opaque pointer.
    NullPointer {
        operation: &'static str,
    },
    /// A requested allocation size overflowed `usize` bytes.
    SizeOverflow,
    /// A graph or arena-backed plan was launched on a different context.
    ContextMismatch,
    /// A component scheduler selected a lane not owned by this context.
    InvalidLane {
        lane: usize,
        lane_count: usize,
    },
    TimingNotStarted,
    TimingIntervalCapacity {
        requested: usize,
        available: usize,
    },
    TimingIntervalCount {
        expected: usize,
        actual: usize,
    },
}

impl core::fmt::Display for CudaRuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("CUDA kernels are not available in this build"),
            Self::Cuda { operation, code } => {
                write!(f, "CUDA operation {operation} failed with status {code}")
            }
            Self::NullPointer { operation } => {
                write!(f, "CUDA operation {operation} returned a null pointer")
            }
            Self::SizeOverflow => f.write_str("CUDA allocation size overflow"),
            Self::ContextMismatch => f.write_str("CUDA context identity mismatch"),
            Self::InvalidLane { lane, lane_count } => {
                write!(
                    f,
                    "CUDA lane {lane} is outside the {lane_count} owned lanes"
                )
            }
            Self::TimingNotStarted => f.write_str("CUDA diagnostic timing was not started"),
            Self::TimingIntervalCapacity {
                requested,
                available,
            } => write!(
                f,
                "CUDA diagnostic timing requested {requested} intervals, capacity is {available}"
            ),
            Self::TimingIntervalCount { expected, actual } => {
                write!(
                    f,
                    "CUDA timing interval count mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for CudaRuntimeError {}

pub(crate) fn check_cuda(operation: &'static str, code: i32) -> Result<(), CudaRuntimeError> {
    if code == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(CudaRuntimeError::Cuda { operation, code })
    }
}

/// CUDA device state observed before resident process-global resources exist.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CudaDeviceSnapshot {
    pub count: u32,
    pub current: u32,
    pub sm_major: u32,
    pub sm_minor: u32,
}

pub fn cuda_device_snapshot() -> Result<CudaDeviceSnapshot, CudaRuntimeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable);
    }
    let mut snapshot = CudaDeviceSnapshot::default();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_cuda_device_snapshot(
            &mut snapshot.count,
            &mut snapshot.current,
            &mut snapshot.sm_major,
            &mut snapshot.sm_minor,
        )
    };
    check_cuda("cuda_device_snapshot", code)?;
    Ok(snapshot)
}

/// One proof's isolated non-blocking CUDA stream and never-release memory pool.
///
/// The native constructor fails closed if the custom pool cannot be created; it
/// never falls back to the process-wide default pool. The context may move to its
/// owning proof thread, but it is not shareable across threads.
pub struct CudaExecContext {
    handle: NonNull<c_void>,
    stream: NonNull<c_void>,
    lanes: Vec<NonNull<c_void>>,
    telemetry: Cell<CudaExecTelemetry>,
    last_graph_submit: Cell<Option<std::time::Instant>>,
    timing_interval_capacity: Cell<Option<usize>>,
    _not_sync: PhantomData<Cell<()>>,
}

// A context and its stream may be moved to one owning host thread. It is not Sync
// (the Cell marker above), so capture/enqueue cannot be driven concurrently.
unsafe impl Send for CudaExecContext {}

/// Copyable, non-owning launch handle for producers that must target a
/// [`DeviceArena`] before the higher-level prepared graph is constructed.
///
/// The owning [`CudaExecContext`] must outlive this value.  This deliberately
/// exposes only the stream and a fence: allocation and copies remain owned by
/// the arena/context API, while witness kernels can write their final columns
/// directly into borrowed arena slices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaLaunchContext {
    handle: NonNull<c_void>,
    stream: NonNull<c_void>,
}

/// Proof that every context-owned component lane has enqueued a join into the
/// main stream. Only the VMM spill path can construct or consume this token.
pub(super) struct JoinedCudaLanes<'a> {
    context: &'a CudaExecContext,
}

/// Proof that all joined lanes and subsequent main-stream work have completed.
/// VMM unmapping requires this token; a bare context sync cannot produce it.
pub(super) struct CudaQuiescence {
    context_token: NonNull<c_void>,
}

// CUDA streams may be enqueued from multiple host threads. Ownership and
// destruction remain with the non-Sync CudaExecContext.
unsafe impl Send for CudaLaunchContext {}
unsafe impl Sync for CudaLaunchContext {}

impl CudaLaunchContext {
    pub fn stream_raw(self) -> NonNull<c_void> {
        self.stream
    }

    pub(crate) fn identity_token(self) -> NonNull<c_void> {
        self.handle
    }

    /// Fence work issued through this borrowed handle. Resident witness code
    /// uses this only while migration-era host artifacts still require a
    /// completion boundary before their temporary inputs may be dropped.
    pub fn sync(self) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_stream_sync(
                self.handle.as_ptr(),
                self.stream.as_ptr(),
            )
        };
        check_cuda("exec_context_stream_sync", code)
    }
}

impl<'a> JoinedCudaLanes<'a> {
    /// Enqueue the full-allocation spill copy after every lane join.
    ///
    /// # Safety
    ///
    /// `dst` must be writable and `src` readable for `bytes`. Both ranges must
    /// remain live until [`Self::sync_main`] succeeds.
    pub(super) unsafe fn memcpy_d2h_async(
        &self,
        dst: *mut c_void,
        src: *const c_void,
        bytes: usize,
    ) -> Result<(), CudaRuntimeError> {
        unsafe { self.context.memcpy_d2h_async(dst, src, bytes) }
    }

    pub(super) fn sync_main(self) -> Result<CudaQuiescence, CudaRuntimeError> {
        self.context.sync()?;
        Ok(CudaQuiescence {
            context_token: self.context.identity_token(),
        })
    }
}

impl CudaQuiescence {
    pub(super) fn context_token(&self) -> NonNull<c_void> {
        self.context_token
    }
}

impl CudaExecContext {
    /// Create an isolated CUDA stream/pool context.
    pub fn new() -> Result<Self, CudaRuntimeError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(CudaRuntimeError::Unavailable);
        }

        let mut raw_handle = core::ptr::null_mut();
        let code =
            unsafe { stwo_backend_cuda_kernels::raw::stwo_exec_context_create(&mut raw_handle) };
        check_cuda("exec_context_create", code)?;
        let handle = NonNull::new(raw_handle).ok_or(CudaRuntimeError::NullPointer {
            operation: "exec_context_create",
        })?;

        let mut raw_stream = core::ptr::null_mut();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_stream(
                handle.as_ptr(),
                &mut raw_stream,
            )
        };
        if let Err(error) = check_cuda("exec_context_stream", code) {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_exec_context_destroy(handle.as_ptr());
            }
            return Err(error);
        }
        let Some(stream) = NonNull::new(raw_stream) else {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_exec_context_destroy(handle.as_ptr());
            }
            return Err(CudaRuntimeError::NullPointer {
                operation: "exec_context_stream",
            });
        };

        let mut lane_count = 0u32;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_lane_count(
                handle.as_ptr(),
                &mut lane_count,
            )
        };
        if let Err(error) = check_cuda("exec_context_lane_count", code) {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_exec_context_destroy(handle.as_ptr());
            }
            return Err(error);
        }
        let mut lanes = Vec::with_capacity(lane_count as usize);
        for lane in 0..lane_count {
            let mut raw_lane = core::ptr::null_mut();
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_exec_context_lane_stream(
                    handle.as_ptr(),
                    lane,
                    &mut raw_lane,
                )
            };
            if let Err(error) = check_cuda("exec_context_lane_stream", code) {
                unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_exec_context_destroy(handle.as_ptr());
                }
                return Err(error);
            }
            let Some(lane_stream) = NonNull::new(raw_lane) else {
                unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_exec_context_destroy(handle.as_ptr());
                }
                return Err(CudaRuntimeError::NullPointer {
                    operation: "exec_context_lane_stream",
                });
            };
            lanes.push(lane_stream);
        }

        Ok(Self {
            handle,
            stream,
            lanes,
            telemetry: Cell::new(CudaExecTelemetry::default()),
            last_graph_submit: Cell::new(None),
            timing_interval_capacity: Cell::new(None),
            _not_sync: PhantomData,
        })
    }

    pub fn telemetry(&self) -> CudaExecTelemetry {
        self.telemetry.get()
    }

    pub fn reset_telemetry(&self) {
        self.telemetry.set(CudaExecTelemetry::default());
        self.last_graph_submit.set(None);
    }

    fn record(&self, update: impl FnOnce(&mut CudaExecTelemetry)) {
        let mut telemetry = self.telemetry.get();
        update(&mut telemetry);
        self.telemetry.set(telemetry);
    }

    /// Opaque CUDA stream pointer for stream-explicit kernel launch wrappers.
    pub fn stream_raw(&self) -> NonNull<c_void> {
        self.stream
    }

    /// Begin a diagnostic-only device timeline on the proof's main stream.
    /// Timed events are allocated lazily by the native context and reused; the
    /// returned capacity is the maximum number of intervals that may be marked.
    pub fn begin_timing(&self) -> Result<usize, CudaRuntimeError> {
        let mut capacity = 0u32;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_timing_begin(
                self.handle.as_ptr(),
                &mut capacity,
            )
        };
        check_cuda("exec_context_timing_begin", code)?;
        let capacity = capacity as usize;
        self.timing_interval_capacity.set(Some(capacity));
        Ok(capacity)
    }

    /// Record the end of one asynchronously enqueued device interval.
    pub fn mark_timing(&self) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_timing_mark(self.handle.as_ptr())
        };
        check_cuda("exec_context_timing_mark", code)
    }

    /// Read adjacent event durations after the caller has drained the stream at
    /// its existing protocol fence. This method never synchronizes.
    pub fn elapsed_timing_ms(
        &self,
        expected_intervals: usize,
    ) -> Result<Vec<f32>, CudaRuntimeError> {
        let available = self
            .timing_interval_capacity
            .get()
            .ok_or(CudaRuntimeError::TimingNotStarted)?;
        if expected_intervals > available {
            return Err(CudaRuntimeError::TimingIntervalCapacity {
                requested: expected_intervals,
                available,
            });
        }
        let capacity = expected_intervals as u32;
        let mut elapsed = vec![0.0f32; expected_intervals];
        let mut actual = 0u32;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_timing_elapsed(
                self.handle.as_ptr(),
                elapsed.as_mut_ptr(),
                capacity,
                &mut actual,
            )
        };
        check_cuda("exec_context_timing_elapsed", code)?;
        let actual = actual as usize;
        if actual != expected_intervals {
            return Err(CudaRuntimeError::TimingIntervalCount {
                expected: expected_intervals,
                actual,
            });
        }
        Ok(elapsed)
    }

    pub fn launch_context(&self) -> CudaLaunchContext {
        CudaLaunchContext {
            handle: self.handle,
            stream: self.stream,
        }
    }

    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    pub fn lane(&self, lane: usize) -> Result<CudaLaunchContext, CudaRuntimeError> {
        let stream = self
            .lanes
            .get(lane)
            .copied()
            .ok_or(CudaRuntimeError::InvalidLane {
                lane,
                lane_count: self.lanes.len(),
            })?;
        Ok(CudaLaunchContext {
            handle: self.handle,
            stream,
        })
    }

    /// Fork one independent component wave from the main transcript stream.
    /// During capture this records the cross-stream dependency in the graph.
    pub fn fork_lane(&self, lane: usize) -> Result<CudaLaunchContext, CudaRuntimeError> {
        let launch = self.lane(lane)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_lane_fork(
                self.handle.as_ptr(),
                lane as u32,
            )
        };
        check_cuda("exec_context_lane_fork", code)?;
        self.record(|telemetry| telemetry.lane_forks += 1);
        Ok(launch)
    }

    /// Join one component lane back into the main transcript stream.
    pub fn join_lane(&self, lane: usize) -> Result<(), CudaRuntimeError> {
        self.lane(lane)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_lane_join(
                self.handle.as_ptr(),
                lane as u32,
            )
        };
        check_cuda("exec_context_lane_join", code)?;
        self.record(|telemetry| telemetry.lane_joins += 1);
        Ok(())
    }

    /// Join every owned lane into the main stream before a whole-allocation
    /// spill. Native code rejects this operation while graph capture is active.
    pub(super) fn join_all_lanes_for_vmm(&self) -> Result<JoinedCudaLanes<'_>, CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_join_all_lanes(self.handle.as_ptr())
        };
        check_cuda("exec_context_join_all_lanes", code)?;
        self.record(|telemetry| telemetry.lane_joins += self.lanes.len() as u64);
        Ok(JoinedCudaLanes { context: self })
    }

    pub(crate) fn identity_token(&self) -> NonNull<c_void> {
        self.handle
    }

    /// Block until every operation enqueued on this context's stream completes.
    pub fn sync(&self) -> Result<(), CudaRuntimeError> {
        let code =
            unsafe { stwo_backend_cuda_kernels::raw::stwo_exec_context_sync(self.handle.as_ptr()) };
        check_cuda("exec_context_sync", code)?;
        self.record(|telemetry| telemetry.sync_calls += 1);
        Ok(())
    }

    /// Checked current used/reserved bytes for this context's isolated pool.
    ///
    /// This is a non-synchronizing snapshot. Fence first when observing memory
    /// after an asynchronous free; a live resident arena needs no extra fence.
    pub fn pool_memory(&self) -> Result<CudaPoolMemory, CudaRuntimeError> {
        let mut used_bytes = 0usize;
        let mut reserved_bytes = 0usize;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_pool_current(
                self.handle.as_ptr(),
                &mut used_bytes,
                &mut reserved_bytes,
            )
        };
        check_cuda("exec_context_pool_current", code)?;
        Ok(CudaPoolMemory {
            used_bytes,
            reserved_bytes,
        })
    }

    /// Allocate `count` u32 words from this context's isolated pool.
    pub fn alloc_u32(&self, count: usize) -> Result<NonNull<u32>, CudaRuntimeError> {
        count
            .checked_mul(core::mem::size_of::<u32>())
            .ok_or(CudaRuntimeError::SizeOverflow)?;
        let mut raw_ptr = core::ptr::null_mut();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_alloc_u32(
                self.handle.as_ptr(),
                count,
                &mut raw_ptr,
            )
        };
        check_cuda("exec_context_alloc_u32", code)?;
        let pointer = NonNull::new(raw_ptr).ok_or(CudaRuntimeError::NullPointer {
            operation: "exec_context_alloc_u32",
        })?;
        self.record(|telemetry| {
            telemetry.allocations += 1;
            telemetry.allocation_bytes += (count * core::mem::size_of::<u32>()) as u64;
        });
        Ok(pointer)
    }

    /// Free a context allocation, ordered after prior work on this stream.
    ///
    /// # Safety
    ///
    /// `ptr` must have been returned by [`Self::alloc_u32`] on this context and
    /// must not have been freed already.
    pub unsafe fn free_u32(&self, ptr: NonNull<u32>) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_free_u32(
                self.handle.as_ptr(),
                ptr.as_ptr(),
            )
        };
        check_cuda("exec_context_free_u32", code)?;
        self.record(|telemetry| telemetry.frees += 1);
        Ok(())
    }

    /// Enqueue a byte memset on this context's stream.
    ///
    /// # Safety
    ///
    /// `dst..dst+bytes` must be a live device allocation that remains valid until
    /// this stream has passed the operation.
    pub unsafe fn memset_async(
        &self,
        dst: *mut c_void,
        value: u8,
        bytes: usize,
    ) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_memset_async(
                self.handle.as_ptr(),
                dst,
                i32::from(value),
                bytes,
            )
        };
        check_cuda("exec_context_memset_async", code)?;
        self.record(|telemetry| telemetry.memset_bytes += bytes as u64);
        Ok(())
    }

    /// Enqueue an arbitrary u32 fill on this context's stream.
    ///
    /// # Safety
    ///
    /// `dst..dst+count` must be a live device range that remains valid until
    /// this stream has passed the operation.
    pub unsafe fn fill_u32_async(
        &self,
        dst: *mut u32,
        value: u32,
        count: usize,
    ) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_fill_u32_async(
                self.handle.as_ptr(),
                dst,
                value,
                count,
            )
        };
        check_cuda("exec_context_fill_u32_async", code)?;
        self.record(|telemetry| telemetry.fill_words += count as u64);
        Ok(())
    }

    /// Enqueue a device-to-device copy on this context's stream.
    ///
    /// # Safety
    ///
    /// Both ranges must be live, non-overlapping device allocations of at least
    /// `bytes` and remain valid until this stream has passed the operation.
    pub unsafe fn memcpy_d2d_async(
        &self,
        dst: *mut c_void,
        src: *const c_void,
        bytes: usize,
    ) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_memcpy_d2d_async(
                self.handle.as_ptr(),
                dst,
                src,
                bytes,
            )
        };
        check_cuda("exec_context_memcpy_d2d_async", code)?;
        self.record(|telemetry| telemetry.d2d_bytes += bytes as u64);
        Ok(())
    }

    /// Enqueue a host-to-device copy on this context's stream.
    ///
    /// # Safety
    ///
    /// `src` must be readable and `dst` writable for `bytes`; both must remain
    /// valid until the operation completes. Pinned host memory is required for
    /// genuinely asynchronous transfer.
    pub unsafe fn memcpy_h2d_async(
        &self,
        dst: *mut c_void,
        src: *const c_void,
        bytes: usize,
    ) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_memcpy_h2d_async(
                self.handle.as_ptr(),
                dst,
                src,
                bytes,
            )
        };
        check_cuda("exec_context_memcpy_h2d_async", code)?;
        self.record(|telemetry| telemetry.h2d_bytes += bytes as u64);
        Ok(())
    }

    /// Enqueue a device-to-host copy on this context's stream.
    ///
    /// # Safety
    ///
    /// `src` must be readable and `dst` writable for `bytes`; both must remain
    /// valid until the operation completes. The host must not read `dst` before
    /// [`Self::sync`] succeeds.
    pub unsafe fn memcpy_d2h_async(
        &self,
        dst: *mut c_void,
        src: *const c_void,
        bytes: usize,
    ) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_memcpy_d2h_async(
                self.handle.as_ptr(),
                dst,
                src,
                bytes,
            )
        };
        check_cuda("exec_context_memcpy_d2h_async", code)?;
        self.record(|telemetry| telemetry.d2h_bytes += bytes as u64);
        Ok(())
    }

    /// Begin thread-local capture on this context's stream.
    pub fn capture(&self) -> Result<CudaGraphCapture<'_>, CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_graph_capture_begin(self.handle.as_ptr())
        };
        check_cuda("graph_capture_begin", code)?;
        self.record(|telemetry| telemetry.capture_begins += 1);
        Ok(CudaGraphCapture {
            context: self,
            active: true,
            _same_thread: PhantomData,
        })
    }
}

impl Drop for CudaExecContext {
    fn drop(&mut self) {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_exec_context_destroy(self.handle.as_ptr())
        };
        if code != CUDA_SUCCESS && !std::thread::panicking() {
            eprintln!("stwo-backend-cuda: exec_context_destroy failed with status {code}");
        }
    }
}

/// In-progress capture. Dropping without [`Self::finish`] exits capture mode and
/// discards the captured graph.
pub struct CudaGraphCapture<'a> {
    context: &'a CudaExecContext,
    active: bool,
    // cudaStreamCaptureModeThreadLocal requires begin/end on the same host thread.
    _same_thread: PhantomData<Rc<()>>,
}

impl CudaGraphCapture<'_> {
    /// Finish capture, instantiate it, and return an owned executable graph.
    pub fn finish(mut self) -> Result<CudaGraphExec, CudaRuntimeError> {
        let mut raw_exec = core::ptr::null_mut();
        let mut kernel_nodes = 0u64;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_graph_capture_end(
                self.context.handle.as_ptr(),
                &mut raw_exec,
                &mut kernel_nodes,
            )
        };
        // EndCapture exits capture mode even when instantiation later fails.
        self.active = false;
        check_cuda("graph_capture_end", code)?;
        self.context
            .record(|telemetry| telemetry.capture_finishes += 1);
        let handle = NonNull::new(raw_exec).ok_or(CudaRuntimeError::NullPointer {
            operation: "graph_capture_end",
        })?;
        Ok(CudaGraphExec {
            handle,
            context_token: self.context.identity_token(),
            kernel_nodes,
        })
    }

    /// Explicitly abort capture and discard any graph produced by EndCapture.
    pub fn abort(mut self) -> Result<(), CudaRuntimeError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_graph_capture_abort(self.context.handle.as_ptr())
        };
        self.active = false;
        check_cuda("graph_capture_abort", code)?;
        self.context
            .record(|telemetry| telemetry.capture_aborts += 1);
        Ok(())
    }
}

impl Drop for CudaGraphCapture<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_graph_capture_abort(self.context.handle.as_ptr())
        };
        self.active = false;
        if code != CUDA_SUCCESS && !std::thread::panicking() {
            eprintln!("stwo-backend-cuda: graph capture abort failed with status {code}");
        }
        if code == CUDA_SUCCESS {
            self.context
                .record(|telemetry| telemetry.capture_aborts += 1);
        }
    }
}

/// Instantiated CUDA graph. Captured pointer arguments must outlive this object.
pub struct CudaGraphExec {
    handle: NonNull<c_void>,
    context_token: NonNull<c_void>,
    kernel_nodes: u64,
}

unsafe impl Send for CudaGraphExec {}

impl CudaGraphExec {
    pub fn kernel_nodes(&self) -> u64 {
        self.kernel_nodes
    }

    /// Enqueue one replay on `context`'s stream.
    pub fn launch(&self, context: &CudaExecContext) -> Result<(), CudaRuntimeError> {
        if context.identity_token() != self.context_token {
            return Err(CudaRuntimeError::ContextMismatch);
        }
        let submitted_at = std::time::Instant::now();
        let gap_ns = context
            .last_graph_submit
            .replace(Some(submitted_at))
            .map(|previous| {
                u64::try_from(submitted_at.duration_since(previous).as_nanos()).unwrap_or(u64::MAX)
            });
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_graph_launch(
                self.handle.as_ptr(),
                context.handle.as_ptr(),
            )
        };
        check_cuda("graph_launch", code)?;
        context.record(|telemetry| {
            telemetry.graph_launches += 1;
            telemetry.kernel_launches += self.kernel_nodes;
            if let Some(gap_ns) = gap_ns {
                telemetry.graph_submit_gap_ns_total =
                    telemetry.graph_submit_gap_ns_total.saturating_add(gap_ns);
                telemetry.graph_submit_gap_ns_max = telemetry.graph_submit_gap_ns_max.max(gap_ns);
            }
        });
        Ok(())
    }
}

impl Drop for CudaGraphExec {
    fn drop(&mut self) {
        let code =
            unsafe { stwo_backend_cuda_kernels::raw::stwo_graph_destroy(self.handle.as_ptr()) };
        if code != CUDA_SUCCESS && !std::thread::panicking() {
            eprintln!("stwo-backend-cuda: graph_destroy failed with status {code}");
        }
    }
}

/// Stable logical identity for one arena slot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArenaSlotId(pub u32);

/// One statically planned stable range view in the arena slab.
///
/// [`ArenaLayout::new`] requires views to be spatially disjoint;
/// [`ArenaLayout::new_reused`] may validate epoch-disjoint address reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaSlotSpec {
    pub id: ArenaSlotId,
    pub offset_words: usize,
    pub len_words: usize,
    /// Required power-of-two alignment, measured in u32 words.
    pub alignment_words: usize,
}

/// One stable range view and the proof epochs in which its address is live.
///
/// The mask is consumed while constructing [`ArenaLayout`]; callers cannot
/// mutate reuse after validation or after graph capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaRangeSpec {
    pub slot: ArenaSlotSpec,
    pub live_mask: u16,
}

/// Rejected arena-plan condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArenaError {
    ZeroSizedArena,
    DuplicateSlot(ArenaSlotId),
    EmptySlot(ArenaSlotId),
    EmptyLiveMask(ArenaSlotId),
    InvalidAlignment(ArenaSlotId),
    Misaligned(ArenaSlotId),
    RangeOverflow(ArenaSlotId),
    OutOfBounds(ArenaSlotId),
    Overlap {
        first: ArenaSlotId,
        second: ArenaSlotId,
    },
    UnknownSlot(ArenaSlotId),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid CUDA arena: {self:?}")
    }
}

impl std::error::Error for ArenaError {}

impl From<CudaRuntimeError> for ArenaError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

/// Validated stable-address layout for one workspace and its graph captures.
#[derive(Clone, Debug)]
pub struct ArenaLayout {
    total_words: usize,
    slots: BTreeMap<ArenaSlotId, ArenaSlotSpec>,
}

impl ArenaLayout {
    /// Validate bounds, power-of-two alignment, duplicate identities, and static
    /// non-overlap before any device allocation occurs.
    pub fn new(total_words: usize, specs: &[ArenaSlotSpec]) -> Result<Self, ArenaError> {
        if total_words == 0 {
            return Err(ArenaError::ZeroSizedArena);
        }

        let mut slots = BTreeMap::new();
        let mut ranges = Vec::with_capacity(specs.len());
        for &spec in specs {
            let end = validate_arena_slot(total_words, spec)?;
            if slots.insert(spec.id, spec).is_some() {
                return Err(ArenaError::DuplicateSlot(spec.id));
            }
            ranges.push((spec.offset_words, end, spec.id));
        }

        ranges.sort_unstable_by_key(|&(start, end, id)| (start, end, id));
        reject_adjacent_overlaps(&ranges)?;
        Ok(Self { total_words, slots })
    }

    /// Validate stable range views whose addresses may be reused only across
    /// disjoint proof epochs.
    ///
    /// The constructor checks the declared masks independently, and
    /// [`DeviceArena`] still has no unchecked offset-binding API.
    ///
    /// # Safety
    ///
    /// Each mask must contain every execution epoch in which its range can be
    /// read or written, including work reachable from captured graphs. Epochs
    /// whose ranges overlap spatially must be totally ordered with no
    /// asynchronous execution across the boundary. Callers must also collapse
    /// semantically authorized exact aliases to one slot id before calling.
    pub unsafe fn new_reused(
        total_words: usize,
        specs: &[ArenaRangeSpec],
    ) -> Result<Self, ArenaError> {
        if total_words == 0 {
            return Err(ArenaError::ZeroSizedArena);
        }

        let mut slots = BTreeMap::new();
        let mut ranges_by_epoch: [Vec<(usize, usize, ArenaSlotId)>; u16::BITS as usize] =
            std::array::from_fn(|_| Vec::new());
        for &ArenaRangeSpec {
            slot: spec,
            live_mask,
        } in specs
        {
            if live_mask == 0 {
                return Err(ArenaError::EmptyLiveMask(spec.id));
            }
            let end = validate_arena_slot(total_words, spec)?;
            if slots.insert(spec.id, spec).is_some() {
                return Err(ArenaError::DuplicateSlot(spec.id));
            }
            for bit in 0..u16::BITS as usize {
                if live_mask & (1u16 << bit) != 0 {
                    ranges_by_epoch[bit].push((spec.offset_words, end, spec.id));
                }
            }
        }

        // Validate each epoch independently. A single global adjacent-pair
        // scan is insufficient when a disjoint-lifetime range is nested
        // between two ranges that are live together.
        for ranges in &mut ranges_by_epoch {
            ranges.sort_unstable_by_key(|&(start, end, id)| (start, end, id));
            reject_adjacent_overlaps(ranges)?;
        }

        Ok(Self { total_words, slots })
    }

    pub fn total_words(&self) -> usize {
        self.total_words
    }

    pub fn slot(&self, id: ArenaSlotId) -> Option<ArenaSlotSpec> {
        self.slots.get(&id).copied()
    }
}

fn validate_arena_slot(total_words: usize, spec: ArenaSlotSpec) -> Result<usize, ArenaError> {
    if spec.len_words == 0 {
        return Err(ArenaError::EmptySlot(spec.id));
    }
    if !spec.alignment_words.is_power_of_two() {
        return Err(ArenaError::InvalidAlignment(spec.id));
    }
    if spec.offset_words % spec.alignment_words != 0 {
        return Err(ArenaError::Misaligned(spec.id));
    }
    let end = spec
        .offset_words
        .checked_add(spec.len_words)
        .ok_or(ArenaError::RangeOverflow(spec.id))?;
    if end > total_words {
        return Err(ArenaError::OutOfBounds(spec.id));
    }
    Ok(end)
}

fn reject_adjacent_overlaps(ranges: &[(usize, usize, ArenaSlotId)]) -> Result<(), ArenaError> {
    for pair in ranges.windows(2) {
        let (_, first_end, first_id) = pair[0];
        let (second_start, _, second_id) = pair[1];
        if second_start < first_end {
            return Err(ArenaError::Overlap {
                first: first_id,
                second: second_id,
            });
        }
    }
    Ok(())
}

/// Non-owning view of a stable arena range. Dropping it never frees memory.
#[derive(Clone, Copy, Debug)]
pub struct ArenaSlice {
    id: ArenaSlotId,
    ptr: NonNull<u32>,
    len_words: usize,
    context_token: NonNull<c_void>,
}

impl ArenaSlice {
    pub fn id(self) -> ArenaSlotId {
        self.id
    }

    pub fn as_u32_ptr(self) -> *mut u32 {
        self.ptr.as_ptr()
    }

    pub fn as_void_ptr(self) -> *mut c_void {
        self.ptr.as_ptr().cast()
    }

    pub fn len_words(self) -> usize {
        self.len_words
    }

    pub fn len_bytes(self) -> usize {
        // Layout construction and allocation already proved this multiplication fits.
        self.len_words * core::mem::size_of::<u32>()
    }

    /// Checked stable view into a contiguous subrange of this logical slot.
    /// The child keeps the parent's slot identity and context token, so graph
    /// capture and workspace-alias validation continue to reason about one
    /// allocation while kernels observe only the requested words.
    pub fn checked_subslice(
        self,
        offset_words: usize,
        len_words: usize,
    ) -> Result<Self, ArenaError> {
        let end = offset_words
            .checked_add(len_words)
            .ok_or(ArenaError::RangeOverflow(self.id))?;
        if end > self.len_words {
            return Err(ArenaError::OutOfBounds(self.id));
        }
        let ptr = NonNull::new(self.ptr.as_ptr().wrapping_add(offset_words))
            .ok_or(ArenaError::RangeOverflow(self.id))?;
        Ok(Self {
            ptr,
            len_words,
            ..self
        })
    }

    /// Whether this non-owning view belongs to `context`.
    pub fn belongs_to(self, context: &CudaExecContext) -> bool {
        self.context_token == context.identity_token()
    }

    pub(crate) fn context_token(self) -> NonNull<c_void> {
        self.context_token
    }

    /// View of the first `len_words` words: same slot id, base pointer, and
    /// context token, shorter length.
    ///
    /// The arena colorer pools epoch-disjoint logical buffers into one
    /// physical slot sized to the LARGEST sharer, so a whole-slot slice may be
    /// longer than any single logical buffer. Every binder truncates the bound
    /// slice to its logical requirement before returning it, which makes
    /// `len_words()` the logical extent everywhere downstream — kernel
    /// extents, memsets, and END-relative indexing must never observe the
    /// pooled surplus.
    ///
    /// Panics if `len_words` exceeds the current length: growing a slice
    /// would fabricate capacity that was never validated.
    #[must_use]
    pub fn truncated(self, len_words: usize) -> Self {
        assert!(
            len_words <= self.len_words,
            "arena slice truncation cannot grow slot {:?}: {} > {}",
            self.id,
            len_words,
            self.len_words,
        );
        Self { len_words, ..self }
    }

    #[cfg(test)]
    pub(crate) fn dangling_for_test(id: u32, len_words: usize) -> Self {
        Self::dangling_at_for_test(id, id as usize * 16, len_words)
    }

    #[cfg(test)]
    pub(crate) fn dangling_at_for_test(id: u32, offset_words: usize, len_words: usize) -> Self {
        Self {
            id: ArenaSlotId(id),
            // Pointer-aligned sentinel address. Tests only inspect plan geometry;
            // they never dereference it.
            ptr: NonNull::new((32 + offset_words * core::mem::size_of::<u32>()) as *mut u32)
                .unwrap(),
            len_words,
            context_token: NonNull::dangling(),
        }
    }
}

/// One stable device allocation exposed through validated stable range views.
///
/// Views may reuse bytes only under an [`ArenaLayout::new_reused`] lifetime
/// contract. The slab is allocated once and never moved or individually freed
/// during the capture epoch. [`CudaExecContext`] is owned here to make the
/// free/stream/pool lifetime order structural rather than caller convention.
pub struct DeviceArena {
    context: CudaExecContext,
    base: NonNull<u32>,
    layout: ArenaLayout,
}

unsafe impl Send for DeviceArena {}

impl DeviceArena {
    pub fn new(context: CudaExecContext, layout: ArenaLayout) -> Result<Self, ArenaError> {
        layout
            .total_words
            .checked_mul(core::mem::size_of::<u32>())
            .ok_or(ArenaError::Cuda(CudaRuntimeError::SizeOverflow))?;
        let base = context.alloc_u32(layout.total_words)?;
        // Back the async allocation before exposing its address to setup work on
        // any other CUDA API. All subsequent arena work stays on this context.
        context.sync()?;
        Ok(Self {
            context,
            base,
            layout,
        })
    }

    pub fn context(&self) -> &CudaExecContext {
        &self.context
    }

    /// Process-local equality token for receipts installed on this arena's
    /// execution context. It is runtime admission evidence only and must never
    /// enter a semantic, artifact, program, or proof identity.
    pub fn exec_context_token(&self) -> u64 {
        self.context.identity_token().as_ptr() as usize as u64
    }

    pub fn base_ptr(&self) -> NonNull<u32> {
        self.base
    }

    pub fn layout(&self) -> &ArenaLayout {
        &self.layout
    }

    pub fn bind(&self, id: ArenaSlotId) -> Result<ArenaSlice, ArenaError> {
        let spec = self.layout.slot(id).ok_or(ArenaError::UnknownSlot(id))?;
        let ptr = unsafe { NonNull::new_unchecked(self.base.as_ptr().add(spec.offset_words)) };
        Ok(ArenaSlice {
            id,
            ptr,
            len_words: spec.len_words,
            context_token: self.context.identity_token(),
        })
    }
}

impl Drop for DeviceArena {
    fn drop(&mut self) {
        let result = unsafe { self.context.free_u32(self.base) };
        if let Err(error) = result {
            if !std::thread::panicking() {
                eprintln!("stwo-backend-cuda: arena free failed: {error}");
            }
        }
        // CudaExecContext drops next: it synchronizes the queued free before
        // destroying the stream and pool.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ArenaSlotId = ArenaSlotId(1);
    const B: ArenaSlotId = ArenaSlotId(2);

    fn valid_specs() -> [ArenaSlotSpec; 2] {
        [
            ArenaSlotSpec {
                id: A,
                offset_words: 0,
                len_words: 16,
                alignment_words: 8,
            },
            ArenaSlotSpec {
                id: B,
                offset_words: 16,
                len_words: 32,
                alignment_words: 8,
            },
        ]
    }

    #[test]
    fn context_is_unavailable_without_cuda() {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            assert!(matches!(
                CudaExecContext::new(),
                Err(CudaRuntimeError::Unavailable)
            ));
        }
    }

    #[test]
    fn device_snapshot_is_unavailable_without_cuda() {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            assert_eq!(cuda_device_snapshot(), Err(CudaRuntimeError::Unavailable));
        }
    }

    #[cfg(stwo_cuda_link)]
    #[test]
    fn device_snapshot_reports_a_valid_current_device() {
        let snapshot = cuda_device_snapshot().unwrap();
        assert!(snapshot.count > 0);
        assert!(snapshot.current < snapshot.count);
        assert!(snapshot.sm_major > 0);
    }

    #[test]
    fn arena_layout_accepts_aligned_non_overlapping_slots() {
        let layout = ArenaLayout::new(64, &valid_specs()).unwrap();
        assert_eq!(layout.total_words(), 64);
        assert_eq!(layout.slot(A).unwrap().len_words, 16);
        assert_eq!(layout.slot(B).unwrap().offset_words, 16);
    }

    #[test]
    fn truncated_slice_keeps_identity_and_base_but_shrinks_length() {
        let slice = ArenaSlice::dangling_for_test(7, 64);
        let truncated = slice.truncated(24);
        assert_eq!(truncated.id(), slice.id());
        assert_eq!(truncated.as_u32_ptr(), slice.as_u32_ptr());
        assert_eq!(truncated.context_token(), slice.context_token());
        assert_eq!(truncated.len_words(), 24);
        assert_eq!(truncated.len_bytes(), 24 * core::mem::size_of::<u32>());
        // Idempotent at the same length; zero-length views stay addressable.
        assert_eq!(truncated.truncated(24).len_words(), 24);
        assert_eq!(truncated.truncated(0).len_words(), 0);
    }

    #[test]
    fn checked_subslice_preserves_owner_and_rejects_every_oob_shape() {
        let slice = ArenaSlice::dangling_for_test(7, 64);
        let child = slice.checked_subslice(17, 23).unwrap();
        assert_eq!(child.id(), slice.id());
        assert_eq!(child.as_u32_ptr(), slice.as_u32_ptr().wrapping_add(17));
        assert_eq!(child.context_token(), slice.context_token());
        assert_eq!(child.len_words(), 23);
        assert_eq!(
            slice.checked_subslice(65, 0).unwrap_err(),
            ArenaError::OutOfBounds(slice.id())
        );
        assert_eq!(
            slice.checked_subslice(63, 2).unwrap_err(),
            ArenaError::OutOfBounds(slice.id())
        );
        assert_eq!(
            slice.checked_subslice(usize::MAX, 2).unwrap_err(),
            ArenaError::RangeOverflow(slice.id())
        );
    }

    #[test]
    #[should_panic(expected = "arena slice truncation cannot grow")]
    fn truncated_slice_rejects_growth() {
        let _ = ArenaSlice::dangling_for_test(7, 16).truncated(17);
    }

    #[test]
    fn arena_layout_rejects_duplicate_misaligned_overlapping_and_oob_slots() {
        let mut specs = valid_specs();
        specs[1].id = A;
        assert_eq!(
            ArenaLayout::new(64, &specs).unwrap_err(),
            ArenaError::DuplicateSlot(A)
        );

        let mut specs = valid_specs();
        specs[1].offset_words = 18;
        assert_eq!(
            ArenaLayout::new(64, &specs).unwrap_err(),
            ArenaError::Misaligned(B)
        );

        let mut specs = valid_specs();
        specs[1].offset_words = 8;
        assert_eq!(
            ArenaLayout::new(64, &specs).unwrap_err(),
            ArenaError::Overlap {
                first: A,
                second: B,
            }
        );

        let mut specs = valid_specs();
        specs[1].offset_words = 40;
        assert_eq!(
            ArenaLayout::new(64, &specs).unwrap_err(),
            ArenaError::OutOfBounds(B)
        );
    }

    #[test]
    fn reused_layout_accepts_only_epoch_disjoint_overlaps() {
        let reused = [
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: A,
                    offset_words: 0,
                    len_words: 16,
                    alignment_words: 8,
                },
                live_mask: 0b01,
            },
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: B,
                    offset_words: 0,
                    len_words: 8,
                    alignment_words: 8,
                },
                live_mask: 0b10,
            },
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: ArenaSlotId(3),
                    offset_words: 8,
                    len_words: 8,
                    alignment_words: 8,
                },
                live_mask: 0b10,
            },
        ];
        // SAFETY: these test masks exactly describe the only modeled epochs.
        let layout = unsafe { ArenaLayout::new_reused(16, &reused) }.unwrap();
        assert_eq!(layout.slot(A).unwrap().offset_words, 0);
        assert_eq!(layout.slot(B).unwrap().offset_words, 0);

        let mut overlapping = reused;
        overlapping[1].live_mask = 0b11;
        assert_eq!(
            unsafe { ArenaLayout::new_reused(16, &overlapping) }.unwrap_err(),
            ArenaError::Overlap {
                first: B,
                second: A,
            }
        );
    }

    #[test]
    fn reused_layout_checks_each_epoch_and_rejects_empty_masks() {
        let nested = [
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: A,
                    offset_words: 0,
                    len_words: 64,
                    alignment_words: 8,
                },
                live_mask: 1 << 15,
            },
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: B,
                    offset_words: 8,
                    len_words: 8,
                    alignment_words: 8,
                },
                live_mask: 0b10,
            },
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: ArenaSlotId(3),
                    offset_words: 24,
                    len_words: 8,
                    alignment_words: 8,
                },
                live_mask: 1 << 15,
            },
        ];
        assert_eq!(
            unsafe { ArenaLayout::new_reused(64, &nested) }.unwrap_err(),
            ArenaError::Overlap {
                first: A,
                second: ArenaSlotId(3),
            }
        );

        let mut empty = nested;
        empty[0].live_mask = 0;
        assert_eq!(
            unsafe { ArenaLayout::new_reused(64, &empty) }.unwrap_err(),
            ArenaError::EmptyLiveMask(A)
        );

        let duplicate = [
            ArenaRangeSpec {
                slot: nested[0].slot,
                live_mask: 0b01,
            },
            ArenaRangeSpec {
                slot: nested[0].slot,
                live_mask: 0b10,
            },
        ];
        assert_eq!(
            unsafe { ArenaLayout::new_reused(64, &duplicate) }.unwrap_err(),
            ArenaError::DuplicateSlot(A)
        );
    }

    /// Native graph gate: one captured D2D node replays against the same arena
    /// addresses while the source slot changes between launches.
    #[cfg(stwo_cuda_link)]
    #[test]
    fn diagnostic_timing_events_are_reused_without_an_internal_fence() {
        let context = CudaExecContext::new().unwrap();
        let capacity = context.begin_timing().unwrap();
        assert_eq!(capacity, 31);
        for _ in 0..capacity {
            context.mark_timing().unwrap();
        }
        assert!(context.mark_timing().is_err());
        context.sync().unwrap();
        let first = context.elapsed_timing_ms(capacity).unwrap();
        assert_eq!(first.len(), capacity);
        assert!(first.iter().all(|value| value.is_finite() && *value >= 0.0));

        assert_eq!(context.begin_timing().unwrap(), capacity);
        context.mark_timing().unwrap();
        context.sync().unwrap();
        assert_eq!(context.elapsed_timing_ms(1).unwrap().len(), 1);
    }

    #[cfg(stwo_cuda_link)]
    #[test]
    fn graph_capture_replays_over_stable_arena_slots() {
        let context = CudaExecContext::new().unwrap();
        let layout = ArenaLayout::new(64, &valid_specs()).unwrap();
        let arena = DeviceArena::new(context, layout).unwrap();
        let src = arena.bind(A).unwrap();
        let dst = arena.bind(B).unwrap();
        assert_eq!(arena.base_ptr(), src.ptr);

        let capture = arena.context().capture().unwrap();
        unsafe {
            arena
                .context()
                .memcpy_d2d_async(
                    dst.as_void_ptr(),
                    src.as_void_ptr().cast_const(),
                    src.len_bytes(),
                )
                .unwrap();
        }
        let graph = capture.finish().unwrap();

        let mut host = vec![0_u8; src.len_bytes()];
        for byte in [0x11, 0x7f, 0xa5, 0x00] {
            unsafe {
                arena
                    .context()
                    .memset_async(src.as_void_ptr(), byte, src.len_bytes())
                    .unwrap();
            }
            graph.launch(arena.context()).unwrap();
            unsafe {
                arena
                    .context()
                    .memcpy_d2h_async(
                        host.as_mut_ptr().cast(),
                        dst.as_void_ptr().cast_const(),
                        dst.len_bytes(),
                    )
                    .unwrap();
            }
            arena.context().sync().unwrap();
            assert!(host.iter().all(|&value| value == byte));
            assert_eq!(arena.base_ptr(), src.ptr);
        }

        drop(graph);
        drop(arena);
    }
}
