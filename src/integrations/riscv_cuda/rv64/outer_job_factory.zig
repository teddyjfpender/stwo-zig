//! OuterNodeJob request-layer adapter (M8 outer-job; runtime Stage A seam).
//! Outside rv64/jobs/ like outer_job_prestage.zig. One `Shared` per service
//! (resolved symbols), one `Prover` per DeviceWorker (its graph cache).
//!
//!   prove(node) = prestage (calling thread / host pool)
//!              -> OuterNodeJob submitted to the lane's worker
//!              -> completion (the worker's single event wait)
//!              -> assemble (calling thread) -> om31 prove.Produced
//!
//! The proof is the legacy controller's proof byte for byte
//! (vectors/reports/rv64-m8-20261106/outer-job/fixture-parity-01.json).
const std = @import("std");
const K = @import("jobs/outer_kernels.zig");
const Comp = @import("jobs/outer_composition.zig");
const NativePcs = @import("jobs/native_pcs.zig");
const Graphs = @import("jobs/outer_graph_cache.zig");
const Job = @import("jobs/outer_job.zig");
const api = @import("jobs/api.zig");
const Events = @import("cuda_events.zig");
const Heap = @import("jobs/outer_heap.zig");
const Checks = @import("jobs/outer_checks.zig");
const Enc = @import("jobs/outer_encode.zig");
const OodsAbi = @import("jobs/outer_encode_oods.zig");
const Seed = @import("jobs/outer_seed_device.zig");
const GnRecord = @import("outer_seed_record.zig");

pub const Shared = struct {
    kernels: K.Kernels,
    composition: Comp.Kernels,
    pcs: NativePcs.Symbols,
    wide: bool,
    graph_api: Graphs.Api,
    fs: std.DynLib,
    /// Base-image CUDA event symbols (cuda_events.zig); null: no GPU timing.
    events: ?Events.Api = null,
    /// Device acceptance checks from the addon (STWO_RV64_M8_OUTER_DEVICE_CHECKS=1).
    checks: ?Checks.Symbols = null,
    /// Device proof encoder (STWO_RV64_M8_OUTER_DEVICE_ENCODE=check|1).
    encode: ?Enc.Symbols = null,
    encode_mode: Enc.Mode = .off,
    /// Device node_oods_constraint check (with the encoder, check mode).
    oods: ?OodsAbi.Symbols = null,
    /// gn-node device seed fill (STWO_RV64_M8_GN_NODE=check|job).
    seed: ?Seed.Symbols = null,
    /// gn-node job mode: the addon's peer / verdict ops (NodeJob channel_order).
    peer: ?@import("jobs/ops.zig").Peer = null,
    compressed: ?@import("jobs/outer_packed_class.zig").Launch = null,
    /// `base` = frozen base image, `addon` = libstwo-rv64-jobs.so, both owned by
    /// the caller (ops.Libraries); `fs_path` = libstwo-rv64-outer-fs-ops.so.
    pub fn init(base: *std.DynLib, addon: *std.DynLib, fs_path: []const u8) !Shared {
        var fs = try std.DynLib.open(fs_path);
        errdefer fs.close();
        const Version = *const fn () callconv(.c) u32;
        return .{
            .kernels = try K.Kernels.load(base, &fs),
            .composition = try Comp.Kernels.load(base, addon),
            .pcs = try NativePcs.Symbols.load(addon),
            .wide = if (base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false,
            .graph_api = try Graphs.Api.load(addon),
            .compressed = addon.lookup(@import("jobs/outer_packed_class.zig").Launch, "stwo_rv64_outer_packed_class_v2_on"),
            .fs = fs,
            .events = Events.Api.load(base) catch null,
            .checks = if (try Checks.selected()) try Checks.Symbols.load(addon) else null,
            .encode = if (try Enc.mode() != .off or try GnRecord.liveSelected()) try Enc.Symbols.load(addon) else null,
            .encode_mode = try Enc.mode(),
            .oods = if (try Enc.mode() != .off or try GnRecord.liveSelected()) try OodsAbi.Symbols.load(addon) else null,
            .seed = if (try GnRecord.liveSelected()) try Seed.Symbols.load(addon) else null,
            .peer = if (GnRecord.jobSelected()) try @import("jobs/ops.zig").Peer.open(addon) else null,
        };
    }
    pub fn deinit(self: *Shared) void {
        self.fs.close();
        self.* = undefined;
    }
    pub fn whole(self: *const Shared) Job.Whole {
        return .{ .composition = &self.composition, .pcs = self.pcs, .wide = self.wide, .checks = self.checks };
    }
};

/// GPU time of one job body: two CUDA events on the worker's exec stream,
/// created and recorded on the worker thread (its device is current there)
/// outside any graph capture, resolved in finish after the completion wait.
/// Never synchronizes. 0 when the events are unavailable.
pub const Report = struct {
    outcome: Graphs.Outcome = .direct,
    launches: u32 = 0,
    /// GPU time of the node body (CUDA events), 0 if unavailable.
    gpu_ns: u64 = 0,
    kernel_nodes: u64 = 0,
    prestage_ns: u64 = 0,
    /// initWhole + footprint (stream plans, placeholder PCS framing), lane thread.
    init_ns: u64 = 0,
    /// Submit to completion (includes stage/enqueue/wait and finish).
    job_ns: u64 = 0,
    /// finish on the worker thread; deferred PCS proof decode on the lane thread.
    finish_ns: u64 = 0,
    decode_ns: u64 = 0,
    assemble_ns: u64 = 0,
    receipt: api.Receipt = .{},
    /// Class plan sizes (words): MAIN/INTER coefficients, evaluations, trees;
    /// composition coefficients and tree; FIXED coefficients and tree.
    plan_words: [10]u64 = @splat(0),
    heap_words: u64 = 0,
    heap_peak_words: u64 = 0,
    heap_allocations: u64 = 0,
    heap_high_words: u64 = 0,
    phase_peak_words: [Heap.Heap.n_phases]u64 = @splat(0),
    phase_high_words: [Heap.Heap.n_phases]u64 = @splat(0),
    staged_regions: [3]u64 = .{ 0, 0, 0 },
    max_alloc_words: u64 = 0,
    max_unguarded_alloc_words: u64 = 0,
    streamed: bool = false,
    fixed_handoff: bool = false,
    /// The job's declared footprint (class plan).
    footprint: api.Footprint = .{ .device_words = 0 },
    /// initWhole borrowed the class's cached WholePlan (STWO_RV64_M8_OUTER_CLASS_PLAN=1).
    borrowed_plan: bool = false,
    /// Device encoding (STWO_RV64_M8_OUTER_DEVICE_ENCODE=check): bytes, GPU
    /// time of the encoder launch (CUDA events), host mirror time.
    encoded_bytes: u64 = 0,
    encode_gpu_ns: u64 = 0,
    encode_mirror_ns: u64 = 0,
    encode_launches: u32 = 0,
    encode_identical: bool = false,
    /// gn-node check: device seed fill + statement (GnCheck).
    gn: GnReport = .{},
};
pub const GnReport = struct {
    ran: bool = false,
    children: u32 = 0,
    seeds: u64 = 0,
    gpu_ns: u64 = 0,
    host_ns: u64 = 0,
    warm_ns: u64 = 0,
    launches: u32 = 0,
    source_words: u64 = 0,
};

pub const Prover = @import("outer_node_prover.zig").Prover;
pub const NodeClasses = @import("outer_node_prover.zig").NodeClasses;
pub const Recorder = @import("outer_node_checks.zig").Recorder;
pub const Lane = @import("outer_hybrid_owner.zig").Lane;
pub const Hybrid = @import("outer_hybrid_owner.zig").Hybrid;
pub const FixedHandoff = @import("outer_hybrid_owner.zig").FixedHandoff;
pub const hybridSelected = @import("outer_hybrid_owner.zig").hybridSelected;
