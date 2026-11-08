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
const Env = @import("outer_env.zig");

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
/// STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS bounds one chunk (unset/0: the
/// default). Neither changes a committed word. Invalid values fail closed.
pub fn streamSelected(kernels: *const K.Kernels) !bool {
    if (!try Env.flag("STWO_RV64_M8_OUTER_STREAM", true)) return false;
    return kernels.layer != null and (kernels.mixed_compact != null or kernels.mixed_seeded != null);
}
pub fn streamChunkWords() !usize {
    const words = try Env.unsigned(usize, "STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS", default_stream_chunk_words);
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

pub fn interpolate(device: *K.Device, plan: *const Plan.TreePlan, evaluations: [*]const u32, coefficients: [*]u32, s: Statics) !void {
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

// Recording double for the streamed commit: every LDE, mixed-leaf, layer and
// copy call is kept with its arguments, so the run grouping, the compact vs
// seeded marshalling, both twiddle modes, the Merkle layer offsets and the
// root copy are checked against the plan without a GPU.
const Rec = struct {
    const Lde = struct { coefficients: usize, n: usize, logs: usize, out: usize, rows: usize, count: u32, tw: usize, tw_words: u32 };
    const Mixed = struct { compact: bool, size: u32, count: u32, absorbed: u32, seed_size: u32, seed: usize, seed_words: u64, out: usize, out_words: u64, final_out: usize, final_words: u64, columns: u32 };
    const LayerCall = struct { src: usize, nodes: u32, dst: usize };
    var lde: std.ArrayList(Lde) = .empty;
    var mixed: std.ArrayList(Mixed) = .empty;
    var layers: std.ArrayList(LayerCall) = .empty;
    var b2ns: u32 = 0;
    var copy_to: usize = 0;
    var copy_from: usize = 0;
    var copy_bytes: usize = 0;
    var allocs: [8]K.Buffer = undefined;
    var n_allocs: usize = 0;
    var heap: [1 << 16]u32 = undefined;
    var used: usize = 0;
    fn reset() void {
        lde.clearRetainingCapacity();
        mixed.clearRetainingCapacity();
        layers.clearRetainingCapacity();
        b2ns = 0;
        n_allocs = 0;
        used = 0;
        copy_to = 0;
    }
    fn deinit() void {
        lde.deinit(testing.allocator);
        mixed.deinit(testing.allocator);
        layers.deinit(testing.allocator);
    }
    fn addr(p: anytype) usize {
        return @intFromPtr(p);
    }
    fn b2n(_: [*]const u32, _: usize, _: [*]u32, _: usize, _: u32, _: u32, _: [*]const u32, _: u32, _: u32, _: *anyopaque, launches: *u32) callconv(.c) c_int {
        b2ns += 1;
        launches.* = 1;
        return 0;
    }
    fn n2b(c: [*]const u32, n: usize, logs: [*]const u32, out: [*]u32, rows: usize, _: u32, count: u32, tw: [*]const u32, tw_words: u32, _: u32, _: *anyopaque, launches: *u32) callconv(.c) c_int {
        lde.append(testing.allocator, .{ .coefficients = addr(c), .n = n, .logs = addr(logs), .out = addr(out), .rows = rows, .count = count, .tw = addr(tw), .tw_words = tw_words }) catch return 1;
        launches.* = 1;
        return 0;
    }
    fn columns(segments: [*]const Abi.MixedSegment, count: u32) u32 {
        var n: u32 = 0;
        for (segments[0..count]) |s| n += @intCast(s.capacity_words / s.stride_words);
        return n;
    }
    fn seeded(size: u32, count: u32, segments: [*]const Abi.MixedSegment, absorbed: u32, seed_size: u32, seed: ?*const anyopaque, out: ?*anyopaque, final_out: ?*anyopaque, _: *anyopaque) callconv(.c) c_int {
        mixed.append(testing.allocator, .{ .compact = false, .size = size, .count = count, .absorbed = absorbed, .seed_size = seed_size, .seed = if (seed) |p| addr(p) else 0, .seed_words = 0, .out = if (out) |p| addr(p) else 0, .out_words = 0, .final_out = if (final_out) |p| addr(p) else 0, .final_words = 0, .columns = columns(segments, count) }) catch return 1;
        return 0;
    }
    fn compact(size: u32, count: u32, segments: [*]const Abi.MixedSegment, absorbed: u32, seed_size: u32, seed: ?*const anyopaque, seed_words: u64, out: ?*anyopaque, out_words: u64, final_out: ?*anyopaque, final_words: u64, _: *anyopaque) callconv(.c) c_int {
        mixed.append(testing.allocator, .{ .compact = true, .size = size, .count = count, .absorbed = absorbed, .seed_size = seed_size, .seed = if (seed) |p| addr(p) else 0, .seed_words = seed_words, .out = if (out) |p| addr(p) else 0, .out_words = out_words, .final_out = if (final_out) |p| addr(p) else 0, .final_words = final_words, .columns = columns(segments, count) }) catch return 1;
        return 0;
    }
    fn layer(src: *const anyopaque, nodes: u32, dst: *anyopaque, _: *anyopaque) callconv(.c) c_int {
        layers.append(testing.allocator, .{ .src = addr(src), .nodes = nodes, .dst = addr(dst) }) catch return 1;
        return 0;
    }
    fn d2d(_: *anyopaque, to: *anyopaque, from: *const anyopaque, bytes: usize) callconv(.c) c_int {
        copy_to = addr(to);
        copy_from = addr(from);
        copy_bytes = bytes;
        return 0;
    }
    fn alloc(_: *anyopaque, words: usize) anyerror!K.Buffer {
        const at = used;
        used += std.mem.alignForward(usize, words, 64);
        if (used > heap.len) return error.OutOfMemory;
        const b = K.Buffer{ .ptr = heap[at..].ptr, .words = words };
        allocs[n_allocs] = b;
        n_allocs += 1;
        return b;
    }
    fn free(_: *anyopaque, _: K.Buffer) void {}
};

test "streamed commit: seeded and compact calls, both twiddle modes, layer offsets and the root copy follow the plan" {
    const a = testing.allocator;
    defer Rec.deinit();
    var plan = try Plan.TreePlan.init(a, &.{ 5, 4, 5, 4, 6 }, 1);
    defer plan.deinit(a);
    var kernels: K.Kernels = undefined;
    kernels.b2n = Rec.b2n;
    kernels.n2b_columns = Rec.n2b;
    kernels.d2d = Rec.d2d;
    kernels.layer = Rec.layer;
    kernels.mixed_seeded = Rec.seeded;
    kernels.mixed_compact = Rec.compact;
    var dummy: u8 = 0;
    const vtable = K.Device.VTable{ .alloc = Rec.alloc, .free = Rec.free, .mix = Fake.mix, .draw = Fake.draw };
    var tw: [256]u32 = undefined;
    var logs: [5]u32 = undefined;
    sortedLogs(&plan, &logs);
    var coefficients: [160]u32 = undefined;
    var root: [8]u32 = undefined;
    const statics = Statics{ .sorted_logs = &logs, .twiddles = &tw, .twiddle_words = 256, .itwiddles = &tw, .itwiddle_words = 256 };
    for ([_]bool{ false, true }) |compact| for ([_]TwiddleMode{ .tail, .whole }) |mode| {
        Rec.reset();
        // A 96-word chunk forces several calls (rows 32,32,64,64,128).
        var stream = try Stream.init(a, &plan, 96, compact);
        defer stream.deinit(a);
        try testing.expect(stream.plan.calls.len > 1);
        var device = K.Device{ .ctx = &dummy, .stream = &dummy, .impl = &dummy, .vtable = &vtable, .kernels = &kernels };
        try enqueueStreamed(&device, &plan, &stream, .{ .evaluations = &coefficients, .coefficients = &coefficients, .root_out = &root, .statics = statics, .twiddle_mode = mode, .interpolate = mode == .tail });
        // Interpolation only when requested (one B2N per height group).
        try testing.expectEqual(@as(u32, if (mode == .tail) @intCast(plan.groups.len) else 0), Rec.b2ns);
        // Allocation order: chunk, bank 0, bank 1.
        try testing.expectEqual(@as(usize, 3), Rec.n_allocs);
        const chunk = Rec.allocs[0];
        const banks = [2]K.Buffer{ Rec.allocs[1], Rec.allocs[2] };
        // Every sorted column is expanded exactly once, in order, from its
        // packed coefficient offset, into the chunk.
        var column: usize = 0;
        for (Rec.lde.items) |l| {
            try testing.expectEqual(Rec.addr(&coefficients) + 4 * @as(usize, @intCast(plan.offsets[plan.order[column]])), l.coefficients);
            try testing.expectEqual(Rec.addr(&logs) + 4 * column, l.logs);
            try testing.expectEqual(l.rows >> 1, l.n);
            try testing.expect(l.out >= Rec.addr(chunk.ptr) and l.out + 4 * l.rows * l.count <= Rec.addr(chunk.ptr) + 4 * chunk.words);
            switch (mode) {
                .tail => {
                    try testing.expectEqual(Rec.addr(&tw) + 4 * (256 - l.rows / 2), l.tw);
                    try testing.expectEqual(@as(u32, @intCast(l.rows / 2)), l.tw_words);
                },
                .whole => {
                    try testing.expectEqual(Rec.addr(&tw), l.tw);
                    try testing.expectEqual(@as(u32, 256), l.tw_words);
                },
            }
            for (column..column + l.count) |k| try testing.expectEqual(stream.rows[column], stream.rows[k]);
            column += l.count;
        }
        try testing.expectEqual(plan.order.len, column);
        // One mixed call per plan call, with the plan's banks and the right ABI.
        try testing.expectEqual(stream.plan.calls.len, Rec.mixed.items.len);
        var final_bank: usize = 0;
        for (stream.plan.calls, Rec.mixed.items) |c, m| {
            try testing.expectEqual(compact, m.compact);
            try testing.expectEqual(c.end - c.first, m.columns);
            try testing.expectEqual(c.size, m.size);
            try testing.expectEqual(c.absorbed, m.absorbed);
            try testing.expectEqual(c.seed_size, m.seed_size);
            try testing.expectEqual(if (c.seed_bank) |b| Rec.addr(banks[b].ptr) else 0, m.seed);
            const out = Rec.addr(banks[c.out_bank].ptr);
            try testing.expectEqual(if (c.final) 0 else out, m.out);
            try testing.expectEqual(if (c.final) out else 0, m.final_out);
            if (compact) {
                try testing.expectEqual(if (c.seed_bank) |b| @as(u64, stream.plan.bank_words[b]) else 0, m.seed_words);
                try testing.expectEqual(if (c.final) 0 else @as(u64, stream.plan.bank_words[c.out_bank]), m.out_words);
                try testing.expectEqual(if (c.final) @as(u64, stream.plan.bank_words[c.out_bank]) else 0, m.final_words);
            }
            if (c.final) final_bank = c.out_bank;
        }
        // Merkle layers in the final bank: leaves, leaves/2, ... at 8-word nodes.
        const hashes = Rec.addr(banks[final_bank].ptr);
        var offset: usize = 0;
        var nodes: usize = stream.plan.leaves;
        for (Rec.layers.items) |l| {
            try testing.expectEqual(hashes + 32 * offset, l.src);
            try testing.expectEqual(@as(u32, @intCast(nodes / 2)), l.nodes);
            try testing.expectEqual(hashes + 32 * (offset + nodes), l.dst);
            offset += nodes;
            nodes >>= 1;
        }
        try testing.expectEqual(@as(usize, 1), nodes);
        try testing.expectEqual(std.math.log2_int(u32, stream.plan.leaves), @as(u32, @intCast(Rec.layers.items.len)));
        // The root is the tree's last 8 words, copied to root_out.
        try testing.expectEqual(hashes + 4 * (stream.plan.tree_words - 8), Rec.copy_from);
        try testing.expectEqual(Rec.addr(&root), Rec.copy_to);
        try testing.expectEqual(@as(usize, 32), Rec.copy_bytes);
    };
}
