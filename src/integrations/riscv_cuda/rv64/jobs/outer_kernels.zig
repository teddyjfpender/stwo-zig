//! Read-only reuse of the base image's enqueue-only entry points for the
//! outer job, plus the narrow device view the outer enqueue body runs on.
//! Every symbol here is an existing `*_on` kernel or exec-context async op;
//! none synchronizes, allocates, downloads or touches a lease.
const std = @import("std");
const Abi = @import("../abi.zig");
const Base = @import("stwo_cuda_backend").abi.stages.circuit_base;
const Transform = @import("stwo_cuda_backend").abi.stages.transform;

pub const Status = c_int;
// Native descriptor ABIs, restated from outer_source.zig / outer_assignment.zig
// (their import closures name lease/sync symbols the job lint forbids). Sizes
// are pinned below; outer_job_fixture.zig checks field equality against them.
pub const Fractions = extern struct { fixed: ?[*]const u32, main: [*]const u32, parameters: [*]const u32, numerators: [*]u32, denominators: [*]u32, status: *u32, fixed_words: u64, main_words: u64, numerator_words: u64, denominator_words: u64, component: u32, row_log: u32, reserved: [2]u32 = .{ 0, 0 } };
pub const Cumulative = extern struct { output: [*]u32, contributions: [*]const u32, claim: [*]const u32, stride: u64, row_log: u32, pairs: u32 };
pub const AssignmentJob = extern struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32, record_count: u32, index_count: u32, first: u32, count: u32, reserved: u32 = 0 };
pub const Launch = *const fn (*anyopaque, u32, *const AssignmentJob) callconv(.c) c_int;
pub const LaunchRun = *const fn (*anyopaque, u32, *const AssignmentJob, [*]const u32, u32) callconv(.c) c_int;
pub const LaunchChain = *const fn (*anyopaque, u32, *const AssignmentJob, [*]const u32, u32, u32) callconv(.c) c_int;
pub const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
pub const Copy = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub const BaseFn = *const @TypeOf(Base.stwo_circuit_base_witness_on);
pub const B2n = *const @TypeOf(Transform.stwo_ntt_b2n_columns_compact_on);
pub const N2bColumns = *const @TypeOf(Transform.stwo_lde_n2b_columns_on);
pub const Tree = *const @TypeOf(Abi.stwo_rv64_trace_tree_on);
pub const GlobalPairs = *const @TypeOf(Abi.stwo_rv64_global_pairs_on);
pub const FractionFn = *const fn (*anyopaque, u32, *const Fractions) callconv(.c) c_int;
pub const CumulativeFn = *const fn (*anyopaque, u32, *const Cumulative) callconv(.c) c_int;
pub const SampleCheck = *const fn (*anyopaque, u32, [*]const u32, u32, [*]const [*]const u32, u32, u32, [*]const u32, u32, [*]u32) callconv(.c) c_int;
pub const SamplePrefill = *const fn (*anyopaque, u32, [*]u32, u32, [*]const u32, [*]const u32, u32, [*]u32) callconv(.c) c_int;
pub const ChannelInit = *const @TypeOf(Abi.stwo_rv64_channel_init_on);
pub const ChannelMix = *const @TypeOf(Abi.stwo_rv64_channel_mix_on);
pub const ChannelDraw = *const @TypeOf(Abi.stwo_rv64_channel_draw_on);
pub const LookupParams = *const fn (*anyopaque, u32, [*]const u32, [*]u32, [*]u32) callconv(.c) c_int;
pub const Powers = *const fn (*anyopaque, u32, [*]const u32, u64, u32, [*]u32, [*]u32) callconv(.c) c_int;
/// Streamed Merkle leaves (trace_commit.zig streamRoot): mixed-height leaf
/// absorption from an optional seed state into a state bank or leaf hashes,
/// and one Blake2s layer. All take the exec stream; none synchronizes.
pub const MixedSeeded = *const fn (u32, u32, [*]const Abi.MixedSegment, u32, u32, ?*const anyopaque, ?*anyopaque, ?*anyopaque, *anyopaque) callconv(.c) c_int;
pub const MixedCompact = *const fn (u32, u32, [*]const Abi.MixedSegment, u32, u32, ?*const anyopaque, u64, ?*anyopaque, u64, ?*anyopaque, u64, *anyopaque) callconv(.c) c_int;
pub const Layer = *const fn (*const anyopaque, u32, *anyopaque, *anyopaque) callconv(.c) c_int;

/// The exec stream is lane 0 of the worker's exec context. Every outer
/// operation is ordered on it: one stream, no cross-lane joins.
pub const lane: u32 = 0;

pub const Kernels = struct {
    memset: Memset,
    h2d: Copy,
    d2d: Copy,
    seed: Launch,
    level: Launch,
    wide: ?Launch,
    chain: ?LaunchChain,
    narrow: ?LaunchRun,
    prefill: ?SamplePrefill,
    sample_check: ?SampleCheck,
    base: BaseFn,
    fractions: FractionFn,
    cumulative: CumulativeFn,
    global_pairs: GlobalPairs,
    b2n: B2n,
    n2b_columns: N2bColumns,
    tree: Tree,
    channel_init: ChannelInit,
    channel_mix: ChannelMix,
    channel_draw: ChannelDraw,
    lookup_params: LookupParams,
    powers: Powers,
    /// Optional streamed-commit kernels (outer_trace_commit.zig enqueueStreamed).
    mixed_seeded: ?MixedSeeded = null,
    mixed_compact: ?MixedCompact = null,
    layer: ?Layer = null,
    /// Compact eager state banks (8 + pending words per row instead of 24):
    /// only with STWO_RV64_COMPACT_EAGER_STATE=1 and the image capability,
    /// exactly as the legacy trace_commit.zig selects it.
    compact_eager: bool = false,

    fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
        return lib.lookup(T, name) orelse {
            std.log.err("OUTER_JOB missing symbol {s}", .{name});
            return error.MissingOuterJobSymbol;
        };
    }
    /// `base` is the frozen base image; `fs` the outer FS addon
    /// (libstwo-rv64-outer-fs-ops.so). Both stay open for the worker lifetime.
    pub fn load(base: *std.DynLib, fs: *std.DynLib) !Kernels {
        return .{
            .memset = try sym(Memset, base, "stwo_exec_context_memset_async"),
            .h2d = try sym(Copy, base, "stwo_exec_context_memcpy_h2d_async"),
            .d2d = try sym(Copy, base, "stwo_exec_context_memcpy_d2d_async"),
            .seed = try sym(Launch, base, "stwo_circuit_assignment_seed_on"),
            .level = try sym(Launch, base, "stwo_circuit_assignment_level_on"),
            .wide = base.lookup(Launch, "stwo_circuit_assignment_wide_level_on"),
            .chain = base.lookup(LaunchChain, "stwo_circuit_assignment_chain_run_on"),
            .narrow = base.lookup(LaunchRun, "stwo_circuit_assignment_narrow_run_on"),
            .prefill = base.lookup(SamplePrefill, "stwo_circuit_blake_sample_prefill_on"),
            .sample_check = base.lookup(SampleCheck, "stwo_circuit_blake_sample_inputs_check_on"),
            .base = try sym(BaseFn, base, "stwo_circuit_base_witness_on"),
            .fractions = try sym(FractionFn, base, "stwo_circuit_om31_fractions_on"),
            .cumulative = try sym(CumulativeFn, base, "stwo_circuit_om31_cumulative_on"),
            .global_pairs = try sym(GlobalPairs, base, "stwo_rv64_global_pairs_on"),
            .b2n = try sym(B2n, base, "stwo_ntt_b2n_columns_compact_on"),
            .n2b_columns = try sym(N2bColumns, base, "stwo_lde_n2b_columns_on"),
            .tree = try sym(Tree, base, "stwo_rv64_trace_tree_on"),
            .channel_init = try sym(ChannelInit, base, "stwo_rv64_channel_init_on"),
            .channel_mix = try sym(ChannelMix, base, "stwo_rv64_channel_mix_on"),
            .channel_draw = try sym(ChannelDraw, base, "stwo_rv64_channel_draw_on"),
            .lookup_params = try sym(LookupParams, fs, "stwo_rv64_outer_fs_lookup_params_on"),
            .powers = try sym(Powers, fs, "stwo_rv64_outer_fs_powers_on"),
            .mixed_seeded = base.lookup(MixedSeeded, "stwo_blake2s_mixed_seeded_eager_on") orelse base.lookup(MixedSeeded, "stwo_blake2s_mixed_seeded_on"),
            .mixed_compact = base.lookup(MixedCompact, "stwo_blake2s_mixed_seeded_eager_compact_on"),
            .layer = base.lookup(Layer, "stwo_blake2s_layer_on"),
            .compact_eager = compactEager(base),
        };
    }
};

fn compactEager(base: *std.DynLib) bool {
    const v = std.posix.getenv("STWO_RV64_COMPACT_EAGER_STATE") orelse return false;
    if (!std.mem.eql(u8, v, "1")) return false;
    const Capability = *const fn () callconv(.c) c_int;
    const capability = base.lookup(Capability, "stwo_rv64_compact_eager_state_capability") orelse return false;
    return capability() == 1 and base.lookup(MixedCompact, "stwo_blake2s_mixed_seeded_eager_compact_on") != null;
}

pub const Buffer = struct {
    ptr: [*]u32,
    words: usize,
    pub fn at(self: Buffer, offset: u64) [*]u32 {
        std.debug.assert(offset <= self.words);
        return self.ptr + @as(usize, @intCast(offset));
    }
};

/// Host-API launch accounting for one node. `api` counts every host call
/// that enqueues device work (kernel wrappers, async copies/memsets, channel
/// steps); `internal` adds launches reported by wrappers that issue several.
pub const Counters = struct {
    api: u32 = 0,
    internal: u32 = 0,
    copies: u32 = 0,
    channel: u32 = 0,
    graph_launches: u32 = 0,
    pub fn total(self: Counters) u32 {
        return self.api + self.internal;
    }
};

/// The device view an outer enqueue body runs on. It is filled from the
/// runtime's api.Enqueue (ctx/stream/alloc/free) and DeviceChannel (mix/draw)
/// by outer_job.zig, or by a test double. Every operation is stream ordered.
pub const Device = struct {
    ctx: *anyopaque,
    stream: *anyopaque,
    impl: *anyopaque,
    vtable: *const VTable,
    kernels: *const Kernels,
    counters: Counters = .{},
    /// Optional measurement hook: the body announces its phase (outer_heap
    /// Phase ordinal) so per-phase memory peaks can be attributed.
    phase_hook: ?*const fn (*anyopaque, u8) void = null,
    pub fn phase(self: *Device, which: u8) void {
        if (self.phase_hook) |hook| hook(self.impl, which);
    }

    pub const VTable = struct {
        alloc: *const fn (*anyopaque, usize) anyerror!Buffer,
        free: *const fn (*anyopaque, Buffer) void,
        /// Mix `words` device words (field=true: canonical OM31 coordinates).
        mix: *const fn (*anyopaque, [*]const u32, u32, bool) anyerror!void,
        /// Draw `felts` OM31 felts (8 words each) into device memory.
        draw: *const fn (*anyopaque, u32, [*]u32) anyerror!void,
    };
    pub fn alloc(self: *Device, words: usize) !Buffer {
        return self.vtable.alloc(self.impl, @max(words, 1));
    }
    pub fn free(self: *Device, buffer: Buffer) void {
        self.vtable.free(self.impl, buffer);
    }
    pub fn mix(self: *Device, words: [*]const u32, count: u32, field: bool) !void {
        self.counters.channel += 1;
        self.counters.api += 1;
        return self.vtable.mix(self.impl, words, count, field);
    }
    pub fn draw(self: *Device, felts: u32, out: [*]u32) !void {
        self.counters.channel += 1;
        self.counters.api += 1;
        return self.vtable.draw(self.impl, felts, out);
    }
    pub fn check(self: *Device, status: Status) !void {
        self.counters.api += 1;
        if (status != 0) {
            std.log.err("OUTER_JOB enqueue native_status={d} api_call={d} return_address=0x{x}", .{ status, self.counters.api, @returnAddress() });
            return error.OuterJobEnqueueFailed;
        }
    }
    pub fn clear(self: *Device, ptr: [*]u32, words: u64) !void {
        if (words == 0) return;
        try self.check(self.kernels.memset(self.ctx, ptr, 0, @intCast(words * 4)));
    }
    pub fn copy(self: *Device, to: [*]u32, from: [*]const u32, words: u64) !void {
        if (words == 0) return;
        self.counters.copies += 1;
        try self.check(self.kernels.d2d(self.ctx, to, from, @intCast(words * 4)));
    }
};

/// Device channel over the existing native OM31 channel kernels, with the
/// step/chain protocol and one boundary snapshot per step. This is the
/// fallback the outer job uses until the runtime's DeviceChannel lands, and
/// the reference the parity harness compares that channel against.
pub const RawChannel = struct {
    kernels: *const Kernels,
    ctx: *anyopaque,
    state: [*]u32,
    boundaries: [*]u32,
    capacity: u32,
    step: u32 = 0,
    chain: u64,
    pub fn chainBase(ordinal: u32) u64 {
        return 0x4f4d333100000000 | @as(u64, ordinal);
    }
    /// `seed` = device copy of digest[8] ++ draws (9 words), from pre-stage.
    pub fn init(kernels: *const Kernels, ctx: *anyopaque, state: [*]u32, seed: [*]const u32, boundaries: [*]u32, capacity: u32, chain: u64) !RawChannel {
        if (@intFromPtr(state) % 8 != 0) return error.InvalidOuterChannelState;
        if (kernels.channel_init(ctx, lane, state, seed, chain) != 0) return error.OuterJobEnqueueFailed;
        return .{ .kernels = kernels, .ctx = ctx, .state = state, .boundaries = boundaries, .capacity = capacity, .chain = chain };
    }
    fn boundary(self: *RawChannel) ![*]u32 {
        if (self.step >= self.capacity) return error.OuterChannelBoundaryOverflow;
        return self.boundaries + 16 * @as(usize, self.step);
    }
    pub fn mix(raw: *anyopaque, words: [*]const u32, count: u32, field: bool) anyerror!void {
        const self: *RawChannel = @ptrCast(@alignCast(raw));
        const next = self.chain + 1;
        if (self.kernels.channel_mix(self.ctx, lane, self.state, self.step, self.chain, next, words, count, @intFromBool(field), try self.boundary()) != 0) return error.OuterJobEnqueueFailed;
        self.step += 1;
        self.chain = next;
    }
    pub fn draw(raw: *anyopaque, felts: u32, out: [*]u32) anyerror!void {
        const self: *RawChannel = @ptrCast(@alignCast(raw));
        const next = self.chain + 1;
        if (self.kernels.channel_draw(self.ctx, lane, self.state, self.step, self.chain, next, felts, out, try self.boundary()) != 0) return error.OuterJobEnqueueFailed;
        self.step += 1;
        self.chain = next;
    }
};

test "outer kernel descriptors keep their native ABI" {
    try std.testing.expectEqual(@as(usize, 96), @sizeOf(Fractions));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(Cumulative));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(AssignmentJob));
    try std.testing.expectEqual(@as(usize, 72), @sizeOf(Abi.GlobalPairs));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(Abi.MixedSegment));
    try std.testing.expectEqual(@as(u64, 0x4f4d33310000002a), RawChannel.chainBase(42));
}
