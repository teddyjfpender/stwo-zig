//! M8 job contract (design/riscv/rv64-m8-job-architecture.md §3.1).
//!
//! A proof is a `Job`. A per-GPU `DeviceWorker` runs it in three phases:
//!   1. `stage`   — preflight and inputs for job k+1 on the h2d stream (`Stager`);
//!   2. `enqueue` — the whole proof on the exec stream, no host waits (`Enqueue`);
//!   3. `finish`  — after the worker's single event wait and one pinned slab D2H.
//!
//! Rules (tests in lint.zig): `enqueue` never calls `stwo_exec_context_sync`,
//! `cudaStreamSynchronize`, `cudaEventSynchronize`, a host-read D2H or a lease API.
//! Remaining host steps run through `hostFn` (pinned memory only, no CUDA calls).
//! Preflight happens in `stage`, so `enqueue` cannot fail halfway for resources.
const std = @import("std");
const worker = @import("worker.zig");
pub const DeviceChannel = @import("channel.zig").DeviceChannel;
pub const ProofSlab = @import("slab.zig").ProofSlab;
pub const ProofLayout = @import("slab.zig").ProofLayout;
/// GPU-native request contract (slab regions, status words, class cache,
/// device checks, peer exchange): rv64-m8-gpu-native.md. Additive.
pub const gpu_native = @import("gpu_native.zig");

pub const Placement = @import("resources.zig").Placement;

pub const DeviceBuffer = struct {
    ptr: [*]u32,
    words: usize,
    pub fn slice(self: DeviceBuffer, first: usize, words: usize) !DeviceBuffer {
        if (first > self.words or words > self.words - first) return error.DeviceBufferOutOfRange;
        return .{ .ptr = self.ptr + first, .words = words };
    }
    pub fn bytes(self: DeviceBuffer) usize {
        return self.words * @sizeOf(u32);
    }
};

/// Static per-job memory plan (spec §3.7 hook). `device_words` is the class
/// plan's static peak of `Enqueue.alloc` + `Stager.alloc`; `staged_words` the
/// part allocated in phase 1; `slab_words` the proof slab; `pinned_words`
/// the job-lifetime pinned host memory requested through `Stager.pinned`.
pub const Footprint = @import("resources.zig").Footprint;
pub const Readback = @import("resources.zig").Readback;

/// Host step enqueued on the exec stream (cudaLaunchHostFunc). It may touch
/// pinned memory only and may not call CUDA. Errors are latched by the job.
pub const HostFn = struct {
    call: *const fn (?*anyopaque) callconv(.c) void,
    user: ?*anyopaque,
    purpose: enum { host_compute, capture_release } = .host_compute,
};

/// Synchronous host cancellation, not a CUDA stream callback. It may touch
/// capture control state and cannot be passed to Enqueue.hostFn by accident.
pub const HostAction = struct {
    call: *const fn (?*anyopaque) callconv(.c) void,
    user: ?*anyopaque,
};

/// Phase-3 view: the slab after the single event wait, in pinned host memory.
/// Valid only during `finish` (the pinned slot is reused): copy out what you keep.
pub const SlabView = struct {
    words: []const u32,
    layout: ?*const ProofLayout = null,
    /// request_slab: words is empty; publish checks the final request mirror.
    readback: Readback = .job_slab,
    /// Device-run receipt; waits/readbacks depend on the batch and policy.
    receipt: Receipt = .{},
};

pub const Receipt = struct {
    device: u32 = 0,
    sequence: u64 = 0,
    placement: Placement = .bottom,
    stage_ns: u64 = 0,
    enqueue_ns: u64 = 0,
    wait_ns: u64 = 0,
    host_waits: u32 = 0,
    d2h_bytes: u64 = 0,
    d2h_copies: u32 = 0,
    host_callbacks: u32 = 0,
    capture_release_callbacks: u32 = 0,
    readback: Readback = .job_slab,
    staged_words: u64 = 0,
    arena_peak_words: u64 = 0,
};

/// One per GPU. Owns the exec context (created on the worker thread, so it is
/// the context owner), an exec stream (lane 0), an h2d stream, the static
/// arena view and pinned host pools. See worker.zig.
pub const DeviceWorker = opaque {
    pub fn of(raw: *worker.Worker) *DeviceWorker {
        return @ptrCast(raw);
    }
};

/// Phase 1: inputs for job k+1 (h2d stream).
pub const Stager = struct {
    worker: *DeviceWorker,
    placement: Placement,
    /// Arena words on this job's placement side, live until the job finishes.
    pub fn alloc(self: *Stager, words: usize) !DeviceBuffer {
        return impl(self.worker).stageAlloc(words);
    }
    /// Pinned → device, async on the h2d stream. A source outside this job's
    /// pinned memory is first copied into it (so the caller's slice may die).
    pub fn upload(self: *Stager, dst: DeviceBuffer, src: []const u32) !void {
        return impl(self.worker).stageUpload(dst, src);
    }
    /// Job-lifetime pinned host memory (valid until `finish`/`abort` returns).
    pub fn pinned(self: *Stager, words: usize) ![]u32 {
        return impl(self.worker).stagePinned(words);
    }
    /// Worker-lifetime device memory keyed by class (warm class plans, FIXED
    /// trees, twiddles). `fresh` means this job must fill it (upload now or
    /// write it in enqueue); otherwise its contents are those of the first job.
    /// Addition to spec §3.1; see M8-INTERFACES.md (runtime).
    pub fn persistent(self: *Stager, key: [32]u8, words: usize) !Persistent {
        return impl(self.worker).persistent(key, words);
    }
    pub fn device(self: *Stager) u32 {
        return impl(self.worker).device_ordinal;
    }
    /// Borrow install-reserved events. The driver supplies its actual free
    /// parity slot; generation/request-id parity is not a resource identity.
    pub fn timingPair(self: *Stager, parity: u1, index: usize) !@import("job_timing.zig").Pair {
        return impl(self.worker).stageTimingPair(parity, index);
    }
    /// Request-scoped retained region (retained.zig): find-or-create the
    /// device region (request, name) of `words`. It survives this job (a
    /// later job of the same request on this worker finds it), is never
    /// evicted, and lives until `Worker.releaseRetained`/`releaseRequest`.
    /// `fresh` = this job created it (fill it). Pinned until this job is
    /// reported, so it is never freed under it. Create a region a LATER job
    /// stages against in `stage` (stage(k+1) runs before enqueue(k)).
    /// Addition (native-hybrid, M8-INTERFACES); additive.
    pub fn retain(self: *Stager, request: u64, name: [32]u8, words: usize) !Retained {
        return impl(self.worker).stageRetain(request, name, words, true);
    }
    /// Find-only (error.RetainedRegionNotFound when absent): a consumer job
    /// that must never create the region it reads.
    pub fn retained(self: *Stager, request: u64, name: [32]u8, words: usize) !DeviceBuffer {
        return (try impl(self.worker).stageRetain(request, name, words, false)).buffer;
    }
};

pub const Persistent = struct { buffer: DeviceBuffer, fresh: bool };
pub const Retained = struct { buffer: DeviceBuffer, fresh: bool };

/// Phase 2: the whole proof on the exec stream; no host waits.
pub const Enqueue = struct {
    worker: *DeviceWorker,
    placement: Placement,
    channel: *DeviceChannel, // device-resident transcript for this proof
    slab: *ProofSlab, // device proof buffer for this proof
    /// Native exec context for `stwo_*_on(ctx, lane = 0, ...)` kernels.
    pub fn ctx(self: *Enqueue) *anyopaque {
        return impl(self.worker).context;
    }
    /// The exec stream (lane 0 of `ctx`) for stream-level `stwo_*_on(..., stream)` stages.
    pub fn stream(self: *Enqueue) *anyopaque {
        return impl(self.worker).exec_stream;
    }
    /// One non-nested annotation on this worker's context. The caller owns
    /// label_buffer through range.deinit(); disabled tracing does no formatting.
    pub fn trace(self: *Enqueue, stage: @import("ops.zig").Trace.Stage, ordinal: u32, label_buffer: []u8) !@import("ops.zig").Trace.Range {
        const symbols = impl(self.worker).ops.exec.trace;
        if (symbols.push == null) return .{ .raw = self.ctx() };
        return symbols.begin(self.ctx(), try @import("ops.zig").Trace.formatLabel(label_buffer, stage, ordinal));
    }
    /// Stream-ordered arena allocation on this job's side.
    pub fn alloc(self: *Enqueue, words: usize) !DeviceBuffer {
        return impl(self.worker).enqueueAlloc(words);
    }
    /// Stream-ordered: legal immediately after the last enqueued consumer.
    pub fn free(self: *Enqueue, b: DeviceBuffer) void {
        impl(self.worker).enqueueFree(b);
    }
    /// cudaLaunchHostFunc on the exec stream: pure host compute, pinned only, no CUDA calls.
    pub fn hostFn(self: *Enqueue, f: HostFn) !void {
        return impl(self.worker).enqueueHostFn(f);
    }
    /// Exec stream waits (on the device) for the h2d event of this job's inputs.
    /// The worker already inserts this wait before calling `enqueue`, so the
    /// call is an idempotent no-op kept for contract stability (reason in
    /// M8-INTERFACES.md: a job that forgot it would read unstaged inputs).
    pub fn waitStaged(self: *Enqueue) !void {
        return impl(self.worker).enqueueWaitStaged();
    }
    pub fn device(self: *Enqueue) u32 {
        return impl(self.worker).device_ordinal;
    }
    /// The footprint the worker planned this job with (plan.zig Resolved):
    /// device_words is the class's MEASURED peak share when the memory policy
    /// plans the class, else the job's own declaration. A job that carves one
    /// work region from its window should size it from this, not from its own
    /// `footprint()`, so a fitted declaration and the measured policy agree.
    /// Addition (runtime-persist, M8-INTERFACES); additive.
    pub fn footprint(self: *Enqueue) Footprint {
        return impl(self.worker).enqueueFootprint();
    }
    /// True when `footprint()` comes from the memory policy (measured class).
    pub fn planned(self: *Enqueue) bool {
        return impl(self.worker).enqueuePlanned();
    }
    /// As `Stager.retain`, from phase 2 (stream-ordered allocation outside
    /// the arena). Addition (native-hybrid); additive.
    pub fn retain(self: *Enqueue, request: u64, name: [32]u8, words: usize) !Retained {
        return impl(self.worker).enqueueRetain(request, name, words, true);
    }
    pub fn retained(self: *Enqueue, request: u64, name: [32]u8, words: usize) !DeviceBuffer {
        return (try impl(self.worker).enqueueRetain(request, name, words, false)).buffer;
    }
};

pub const Job = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        class_key: *const fn (*anyopaque) [32]u8, // key affinity and class-plan caches
        footprint: *const fn (*anyopaque) Footprint, // from the class memory plan (static)
        stage: *const fn (*anyopaque, *Stager) anyerror!void, // phase 1
        enqueue: *const fn (*anyopaque, *Enqueue) anyerror!void, // phase 2
        finish: *const fn (*anyopaque, SlabView) anyerror!void, // phase 3: after the single event wait
        abort: *const fn (*anyopaque) void,
    };
    pub fn classKey(self: Job) [32]u8 {
        return self.vtable.class_key(self.ctx);
    }
    pub fn footprint(self: Job) Footprint {
        return self.vtable.footprint(self.ctx);
    }
    /// Adapter: build a Job from a pointer to any type with the six methods.
    pub fn from(comptime T: type, value: *T) Job {
        const G = struct {
            fn cast(raw: *anyopaque) *T {
                return @ptrCast(@alignCast(raw));
            }
            fn keyOf(raw: *anyopaque) [32]u8 {
                return cast(raw).classKey();
            }
            fn footprintOf(raw: *anyopaque) Footprint {
                return cast(raw).footprint();
            }
            fn stageOf(raw: *anyopaque, s: *Stager) anyerror!void {
                return cast(raw).stage(s);
            }
            fn enqueueOf(raw: *anyopaque, e: *Enqueue) anyerror!void {
                return cast(raw).enqueue(e);
            }
            fn finishOf(raw: *anyopaque, v: SlabView) anyerror!void {
                return cast(raw).finish(v);
            }
            fn abortOf(raw: *anyopaque) void {
                cast(raw).abort();
            }
            const vtable = VTable{ .class_key = keyOf, .footprint = footprintOf, .stage = stageOf, .enqueue = enqueueOf, .finish = finishOf, .abort = abortOf };
        };
        return .{ .ctx = value, .vtable = &G.vtable };
    }
};

/// Completion of one job as seen by its submitter (scheduler).
pub const Completion = struct {
    job: Job,
    result: anyerror!void,
    receipt: Receipt,
};

fn impl(w: *DeviceWorker) *worker.Worker {
    return @ptrCast(@alignCast(w));
}

test {
    _ = @import("resources.zig");
    _ = @import("api_test.zig");
}
