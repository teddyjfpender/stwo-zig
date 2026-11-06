//! Enqueue-only trace commitment for job paths. Same transforms, same order,
//! same Merkle kernel as trace_commit.zig's non-streamed beta=1 path
//! (separate compact coefficients + stwo_lde_n2b_columns_on), so the root is
//! byte-identical. Differences are custody only: no lease, no join, no D2H.
//! The root stays in the tree buffer (`rootPointer`) for the device channel;
//! coefficients stay in the caller's buffer for PCS.
//!
//! The evaluation input may be a separate image (MAIN: the INTER kernels still
//! read it after the commit) or the coefficient buffer itself (INTER, FIXED:
//! interpolated in place, which B2N supports for exactly aliased strides).
const std = @import("std");
const Abi = @import("../abi.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");

/// Class-static inputs, staged once: per-sorted-column log sizes (read by the
/// LDE wrapper from device memory) and the eval-height twiddle tree.
pub const Statics = struct {
    sorted_logs: [*]const u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    itwiddles: [*]const u32,
    itwiddle_words: u32,
};

pub const Commit = struct {
    /// Evaluations in sorted commit layout (`plan.offsets`); may alias `coefficients`.
    evaluations: [*]const u32,
    coefficients: [*]u32,
    /// Merkle tree + prefix banks (`plan.tree_words + plan.prefix_words`),
    /// allocated by the caller below its transient buffers so the worker's
    /// LIFO arena reclaims the LDE scratch this call frees.
    tree: K.Buffer,
    statics: Statics,
};

pub fn rootPointer(plan: *const Plan.TreePlan, tree: K.Buffer) [*]const u32 {
    return tree.at(plan.rootOffset());
}

/// Words of the host sorted-log table for `plan` (staged as a class static).
pub fn sortedLogs(plan: *const Plan.TreePlan, out: []u32) void {
    std.debug.assert(out.len == plan.order.len);
    for (out, plan.order) |*log, original| log.* = plan.logs[original];
}

/// Enqueues interpolation, LDE and Merkle hashing. The LDE scratch is
/// allocated and freed (stream ordered, LIFO) inside; `commit.tree` must live
/// until PCS has opened it. The root is `rootPointer(plan, commit.tree)`.
pub fn enqueue(device: *K.Device, plan: *const Plan.TreePlan, commit: Commit) !void {
    if (plan.beta != 1) return error.UnsupportedOuterJobBlowup;
    const s = commit.statics;
    // 1. Coefficients: one compact B2N per height group, in sorted order.
    try interpolate(device, plan, commit.evaluations, commit.coefficients, s);
    // 2. Evaluations at blowup, one LDE call per height group.
    const capacity = plan.tree_words + plan.prefix_words;
    if (commit.tree.words < capacity) return error.OuterTreeBufferTooSmall;
    const scratch = try device.alloc(@intCast(plan.evaluation_words));
    defer device.free(scratch);
    var segments: [64]Abi.MixedSegment = undefined;
    if (plan.groups.len > segments.len) return error.InvalidOuterTreePlan;
    for (plan.groups, 0..) |group, i| {
        const coefficient_rows: u64 = @as(u64, 1) << @intCast(group.log);
        const log = group.log + plan.beta;
        const rows: u64 = @as(u64, 1) << @intCast(log);
        if (rows / 2 > s.twiddle_words) return error.InvalidOuterTwiddles;
        var launches: u32 = 0;
        try device.check(device.kernels.n2b_columns(
            commit.coefficients + group.coefficient_offset,
            @intCast(coefficient_rows),
            s.sorted_logs + group.first,
            scratch.at(group.evaluation_offset),
            @intCast(rows),
            log,
            group.count,
            s.twiddles + (s.twiddle_words - rows / 2),
            @intCast(rows / 2),
            @intCast(rows / 2),
            device.stream,
            &launches,
        ));
        device.counters.internal += launches -| 1;
        segments[i] = .{ .columns = scratch.at(group.evaluation_offset), .stride_words = rows, .capacity_words = rows * group.count, .source_size = @intCast(rows) };
    }
    // 3. Merkle tree + prefix banks; the root is the tree's last 8 words.
    try device.check(device.kernels.tree(device.ctx, K.lane, &segments, @intCast(plan.groups.len), plan.eval_log, commit.tree.ptr, capacity));
}

// ---------------------------------------------------------------------------
// Streamed (chunk-bounded) commit. Same transforms, same Merkle root as
// `enqueue`, but the LDE is never materialised: one bounded chunk of
// evaluations is hashed into an unfinalized per-row Blake2s state at a time
// (trace_stream_plan.zig; the legacy trace_commit.zig streamRoot schedule,
// which is the deployed default and byte-identical to stwo_rv64_trace_tree_on
// because a lifted leaf is one sponge over the columns in commit order and
// may be split at any column boundary). Peak scratch is
//   one chunk (<= budget words) + two state banks (rows x 8..24 words),
// independent of the column count, and the tree is built in the bank that is
// dead after the final absorption. Only the root survives: it is copied to
// `root_out` (8 words) before the banks are freed, so nothing tree-sized
// outlives the commit (the PCS rebuilds every tree it opens and finish
// checks the rebuilt roots against these).

const StreamPlan = @import("../trace_stream_plan.zig");

/// Default evaluation chunk of the job path (words). The banks, not the
/// chunk, dominate at large heights; 2^26 keeps the chunk a minor term.
pub const default_stream_chunk_words: usize = 1 << 26;

/// STWO_RV64_M8_OUTER_STREAM: unset/"1" -> streamed commits when the base
/// image exports the mixed-leaf kernels; "0" -> the full-LDE tree path.
/// STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS bounds one chunk. Neither changes a
/// committed word.
pub fn streamSelected(kernels: *const K.Kernels) bool {
    if (std.posix.getenv("STWO_RV64_M8_OUTER_STREAM")) |v| if (std.mem.eql(u8, v, "0")) return false;
    return kernels.layer != null and (kernels.mixed_compact != null or kernels.mixed_seeded != null);
}
pub fn streamChunkWords() usize {
    const v = std.posix.getenv("STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS") orelse return default_stream_chunk_words;
    const words = std.fmt.parseUnsigned(usize, v, 10) catch return default_stream_chunk_words;
    return if (words == 0) default_stream_chunk_words else words;
}

/// Class-static stream schedule of one tree (host only; built in pre-stage).
pub const Stream = struct {
    plan: StreamPlan.Plan,
    /// Sorted-order LDE rows of every column (plan input, kept for enqueue).
    rows: []u32,
    compact: bool,

    pub fn init(a: std.mem.Allocator, tree: *const Plan.TreePlan, budget_words: usize, compact: bool) !Stream {
        const rows = try a.alloc(u32, tree.order.len);
        errdefer a.free(rows);
        for (rows, tree.order) |*r, original| r.* = @as(u32, 1) << @intCast(tree.logs[original] + tree.beta);
        return .{ .plan = try StreamPlan.planSelected(a, rows, budget_words, compact), .rows = rows, .compact = compact };
    }
    pub fn deinit(self: *Stream, a: std.mem.Allocator) void {
        self.plan.deinit(a);
        a.free(self.rows);
        self.* = undefined;
    }
    /// Device words the commit allocates (chunk + both banks, granule rounded).
    pub fn scratchWords(self: *const Stream) u64 {
        const g = struct {
            fn r(w: usize) u64 {
                return std.mem.alignForward(u64, @max(w, 1), 64);
            }
        }.r;
        return g(self.plan.chunk_words) + g(self.plan.bank_words[0]) + g(self.plan.bank_words[1]);
    }
};

/// How the LDE twiddle arguments are formed for a column of `lde_rows` rows:
/// `.tail` = the eval-height tree's last rows/2 words (TC convention),
/// `.whole` = the tree as staged with an explicit domain size (RC commit).
pub const TwiddleMode = enum { tail, whole };

pub const StreamCommit = struct {
    evaluations: [*]const u32,
    coefficients: [*]u32,
    /// 8 device words that receive the root (e.g. a slab section field).
    root_out: [*]u32,
    statics: Statics,
    twiddle_mode: TwiddleMode = .tail,
    /// Skip interpolation: `coefficients` already hold coefficients (RC).
    interpolate: bool = true,
};

/// Enqueues interpolation (unless disabled), the streamed LDE -> mixed-leaf
/// absorption and the Merkle layers; copies the root to `root_out`. All
/// scratch is allocated and freed (stream ordered) inside.
pub fn enqueueStreamed(device: *K.Device, plan: *const Plan.TreePlan, stream: *const Stream, commit: StreamCommit) !void {
    if (plan.beta != 1) return error.UnsupportedOuterJobBlowup;
    const layer = device.kernels.layer orelse return error.MissingOuterStreamKernels;
    if (stream.compact and device.kernels.mixed_compact == null) return error.MissingOuterStreamKernels;
    if (!stream.compact and device.kernels.mixed_seeded == null) return error.MissingOuterStreamKernels;
    if (stream.rows.len != plan.order.len) return error.InvalidOuterTreePlan;
    const s = commit.statics;
    if (commit.interpolate) try interpolate(device, plan, commit.evaluations, commit.coefficients, s);
    const p = &stream.plan;
    // Chunk first, then the banks: the last-allocated bank (1) is freed first.
    const chunk = try device.alloc(@max(p.chunk_words, 1));
    defer device.free(chunk);
    var banks: [2]K.Buffer = undefined;
    banks[0] = try device.alloc(@max(p.bank_words[0], 1));
    defer device.free(banks[0]);
    banks[1] = try device.alloc(@max(p.bank_words[1], 1));
    defer device.free(banks[1]);
    var hashes: [*]u32 = banks[0].ptr;
    for (p.calls) |c| {
        var segments: [StreamPlan.max_segments]Abi.MixedSegment = undefined;
        var count: u32 = 0;
        var cursor: usize = 0;
        var i: usize = c.first;
        while (i < c.end) {
            // Equal-height sorted columns are contiguous in the packed
            // coefficient buffer: one LDE call and one segment per run.
            var j = i + 1;
            while (j < c.end and stream.rows[j] == stream.rows[i]) : (j += 1) {}
            const lde_rows: usize = stream.rows[i];
            const n = lde_rows >> @intCast(plan.beta);
            const log: u32 = @intCast(std.math.log2_int(usize, lde_rows));
            const destination = chunk.ptr + cursor;
            const tw: [*]const u32, const tw_words: u32 = switch (commit.twiddle_mode) {
                .tail => blk: {
                    if (lde_rows / 2 > s.twiddle_words) return error.InvalidOuterTwiddles;
                    break :blk .{ s.twiddles + (s.twiddle_words - lde_rows / 2), @intCast(lde_rows / 2) };
                },
                .whole => .{ s.twiddles, s.twiddle_words },
            };
            var launches: u32 = 0;
            try device.check(device.kernels.n2b_columns(
                commit.coefficients + @as(usize, @intCast(plan.offsets[plan.order[i]])),
                n,
                s.sorted_logs + i,
                destination,
                lde_rows,
                log,
                @intCast(j - i),
                tw,
                tw_words,
                @intCast(lde_rows / 2),
                device.stream,
                &launches,
            ));
            device.counters.internal += launches -| 1;
            if (count == segments.len) return error.InvalidOuterTreePlan;
            segments[count] = .{ .columns = destination, .stride_words = lde_rows, .capacity_words = lde_rows * (j - i), .source_size = @intCast(lde_rows) };
            count += 1;
            cursor += lde_rows * (j - i);
            i = j;
        }
        if (cursor > chunk.words) return error.InvalidOuterTreePlan;
        const seed: ?*const anyopaque = if (c.seed_bank) |bank| @ptrCast(banks[bank].ptr) else null;
        const out: *anyopaque = @ptrCast(banks[c.out_bank].ptr);
        if (stream.compact) {
            const seed_words: u64 = if (c.seed_bank) |bank| p.bank_words[bank] else 0;
            const out_words: u64 = p.bank_words[c.out_bank];
            try device.check(device.kernels.mixed_compact.?(c.size, count, &segments, c.absorbed, c.seed_size, seed, seed_words, if (c.final) null else out, if (c.final) 0 else out_words, if (c.final) out else null, if (c.final) out_words else 0, device.stream));
        } else {
            try device.check(device.kernels.mixed_seeded.?(c.size, count, &segments, c.absorbed, c.seed_size, seed, if (c.final) null else out, if (c.final) out else null, device.stream));
        }
        if (c.final) hashes = banks[c.out_bank].ptr;
    }
    // Merkle layers above the leaves, in the dead final bank (legacy
    // streamRoot / stwo_rv64_trace_tree_on layer loop).
    var offset: usize = 0;
    var next_offset: usize = p.leaves;
    var nodes: usize = p.leaves;
    while (nodes > 1) : (nodes >>= 1) {
        try device.check(layer(@ptrCast(hashes + offset * 8), @intCast(nodes / 2), @ptrCast(hashes + next_offset * 8), device.stream));
        offset = next_offset;
        next_offset += nodes / 2;
    }
    try device.copy(commit.root_out, hashes + (p.tree_words - 8), 8);
}

fn interpolate(device: *K.Device, plan: *const Plan.TreePlan, evaluations: [*]const u32, coefficients: [*]u32, s: Statics) !void {
    for (plan.groups) |group| {
        const rows: u64 = @as(u64, 1) << @intCast(group.log);
        if (rows / 2 > s.itwiddle_words) return error.InvalidOuterTwiddles;
        var launches: u32 = 0;
        try device.check(device.kernels.b2n(
            evaluations + group.coefficient_offset,
            @intCast(rows),
            coefficients + group.coefficient_offset,
            @intCast(rows),
            group.log,
            group.count,
            s.itwiddles + (s.itwiddle_words - rows / 2),
            @intCast(rows / 2),
            @intCast(rows / 2),
            device.stream,
            &launches,
        ));
        device.counters.internal += launches -| 1;
    }
}

// ---------------------------------------------------------------------------
// Host test double: records every call so the enqueue order, strides and
// twiddle tails are checked against trace_commit.zig without a GPU.
const testing = std.testing;
const Fake = struct {
    var calls: std.ArrayList([]const u8) = .empty;
    var last_tree_capacity: u64 = 0;
    var last_segments: u32 = 0;
    var arena_words: usize = 0;
    var heap: [1 << 14]u32 = undefined;
    fn note(name: []const u8) void {
        calls.append(testing.allocator, name) catch unreachable;
    }
    fn b2n(_: [*]const u32, stride: usize, _: [*]u32, out_stride: usize, log: u32, _: u32, _: [*]const u32, words: u32, size: u32, _: *anyopaque, launches: *u32) callconv(.c) c_int {
        if (stride != out_stride or stride != @as(usize, 1) << @intCast(log) or words != size or words * 2 != stride) return 1;
        launches.* = 2;
        note("b2n");
        return 0;
    }
    fn n2b(_: [*]const u32, stride: usize, _: [*]const u32, _: [*]u32, eval_stride: usize, log: u32, _: u32, _: [*]const u32, words: u32, _: u32, _: *anyopaque, launches: *u32) callconv(.c) c_int {
        if (eval_stride != @as(usize, 1) << @intCast(log) or eval_stride != 2 * stride or words * 2 != eval_stride) return 1;
        launches.* = 1;
        note("n2b");
        return 0;
    }
    fn tree(_: *anyopaque, lane: u32, _: [*]const Abi.MixedSegment, n: u32, _: u32, _: [*]u32, capacity: u64) callconv(.c) c_int {
        if (lane != 0) return 1;
        last_segments = n;
        last_tree_capacity = capacity;
        note("tree");
        return 0;
    }
    fn alloc(_: *anyopaque, words: usize) anyerror!K.Buffer {
        const at = arena_words;
        arena_words += words;
        if (arena_words > heap.len) return error.OutOfMemory;
        return .{ .ptr = heap[at..].ptr, .words = words };
    }
    fn free(_: *anyopaque, _: K.Buffer) void {}
    fn mix(_: *anyopaque, _: [*]const u32, _: u32, _: bool) anyerror!void {}
    fn draw(_: *anyopaque, _: u32, _: [*]u32) anyerror!void {}
};

test "enqueue-only commit follows the legacy group order and leaves the root on device" {
    const a = testing.allocator;
    defer Fake.calls.deinit(a);
    var plan = try Plan.TreePlan.init(a, &.{ 5, 4, 5, 4, 6 }, 1);
    defer plan.deinit(a);
    var kernels: K.Kernels = undefined;
    kernels.b2n = Fake.b2n;
    kernels.n2b_columns = Fake.n2b;
    kernels.tree = Fake.tree;
    var dummy: u8 = 0;
    const vtable = K.Device.VTable{ .alloc = Fake.alloc, .free = Fake.free, .mix = Fake.mix, .draw = Fake.draw };
    var device = K.Device{ .ctx = &dummy, .stream = &dummy, .impl = &dummy, .vtable = &vtable, .kernels = &kernels };
    var tw: [128]u32 = undefined;
    var logs: [5]u32 = undefined;
    sortedLogs(&plan, &logs);
    try testing.expectEqualSlices(u32, &.{ 4, 4, 5, 5, 6 }, &logs);
    var coefficients: [160]u32 = undefined;
    const tree = try device.alloc(@intCast(plan.tree_words + plan.prefix_words));
    try enqueue(&device, &plan, .{ .evaluations = &coefficients, .coefficients = &coefficients, .tree = tree, .statics = .{ .sorted_logs = &logs, .twiddles = &tw, .twiddle_words = 128, .itwiddles = &tw, .itwiddle_words = 128 } });
    const expected = [_][]const u8{ "b2n", "b2n", "b2n", "n2b", "n2b", "n2b", "tree" };
    try testing.expectEqual(expected.len, Fake.calls.items.len);
    for (expected, Fake.calls.items) |e, actual| try testing.expectEqualStrings(e, actual);
    try testing.expectEqual(@as(u32, 3), Fake.last_segments);
    try testing.expectEqual(plan.tree_words + plan.prefix_words, Fake.last_tree_capacity);
    try testing.expectEqual(@as([*]const u32, tree.ptr + (plan.tree_words - 8)), rootPointer(&plan, tree));
    try testing.expectEqual(@as(u32, 7), device.counters.api);
    try testing.expectEqual(@as(u32, 3), device.counters.internal);
}
