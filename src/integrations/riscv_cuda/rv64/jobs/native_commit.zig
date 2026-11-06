//! Enqueue-only MAIN/INTER trace commitment for the native jobs (spec §3.5:
//! "MAIN commit (trace_commit kernels, root mixed on device)", INTER commit).
//!
//! Same kernels and word layout as the legacy resident commitment
//! (rv64/trace_commit.zig Job.run, the beta = 1 "separate coefficients"
//! full-LDE path): columns sorted by height (stable), one compact coefficient
//! image, B2N for evaluation-encoded runs, N2B column LDE per height, one
//! mixed-height Blake2s tree. The streamed rebuild (trace_commit streamRoot) is
//! a storage schedule with identical roots and is not used here.
//!
//! Differences (the point of the job path): no lease, no join, no 32-byte
//! root readback. The root is D2D-copied into a slab field and, when asked,
//! mixed straight from the device tree into the job's DeviceChannel. The
//! coefficient image stays a job-arena buffer for the PCS (column views in
//! ORIGINAL order).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");

pub const Encoding = enum { evaluations, coefficients };
/// Geometry only: fixed per class, known at stage time.
pub const Shape = struct { log_size: u32, encoding: Encoding };
/// One input column at enqueue: device words in the job's exec context
/// (`device`) or host words staged by `CommitPlan.stage` (`host`).
pub const Input = struct { device: ?[*]const u32 = null, host: []const u32 = &.{} };

pub const MixedSegment = extern struct {
    columns: [*]const u32,
    stride_words: u64,
    capacity_words: u64,
    source_size: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(MixedSegment) != 32) @compileError("trace commitment ABI mismatch");
}
// Exported by the frozen base image; signatures as rv64/trace_commit.zig binds them.
pub const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
pub const N2bColumns = *const fn ([*]const u32, usize, [*]const u32, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
pub const Tree = *const fn (*anyopaque, u32, [*]const MixedSegment, u32, u32, [*]u32, u64) callconv(.c) c_int;
pub const PrefixWorkspace = *const fn ([*]const MixedSegment, u32, *u64) callconv(.c) c_int;
pub const CopyD2d = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub const Symbols = struct {
    b2n: B2n,
    n2b_columns: N2bColumns,
    tree: Tree,
    prefix_workspace: ?PrefixWorkspace,
    copy_d2d: CopyD2d,
    pub fn load(base: *std.DynLib) !Symbols {
        return .{
            .b2n = base.lookup(B2n, "stwo_ntt_b2n_columns_compact_on") orelse return error.MissingTraceCommitSymbol,
            .n2b_columns = base.lookup(N2bColumns, "stwo_lde_n2b_columns_on") orelse return error.MissingTraceCommitSymbol,
            .tree = base.lookup(Tree, "stwo_rv64_trace_tree_on") orelse return error.MissingTraceCommitSymbol,
            .prefix_workspace = base.lookup(PrefixWorkspace, "stwo_rv64_trace_prefix_workspace_words"),
            .copy_d2d = base.lookup(CopyD2d, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingTraceCommitSymbol,
        };
    }
};

/// Result of `enqueue`: the compact coefficient image (job arena; free it
/// after the PCS) and per-column views in ORIGINAL column order.
pub const Committed = struct {
    coefficients: api.DeviceBuffer,
    root: [*]const u32,
    pub fn column(self: Committed, plan: *const CommitPlan, original: usize) api.DeviceBuffer {
        return .{ .ptr = self.coefficients.ptr + plan.offsets[original], .words = @as(usize, 1) << @intCast(plan.shapes[original].log_size) };
    }
};

pub const CommitPlan = struct {
    a: std.mem.Allocator,
    shapes: []Shape,
    order: []usize,
    offsets: []usize,
    /// Sorted-order coefficient logs (the N2B per-column log vector).
    logs: []u32,
    beta: u32,
    coefficient_cells: usize,
    eval_cells: usize,
    eval_log: u32,
    tree_words: usize,
    tw: engine.poly.twiddles.TwiddleTree([]core.fields.m31.M31),
    // Staged in phase 1.
    twiddles: ?api.DeviceBuffer = null,
    logs_device: ?api.DeviceBuffer = null,
    host_staged: ?api.DeviceBuffer = null,
    host_offsets: []usize,

    pub fn init(a: std.mem.Allocator, shapes: []const Shape, beta: u32) !CommitPlan {
        if (shapes.len == 0 or beta != 1) return error.UnsupportedTraceCommitGeometry;
        const own = try a.dupe(Shape, shapes);
        errdefer a.free(own);
        const order = try a.alloc(usize, shapes.len);
        errdefer a.free(order);
        const offsets = try a.alloc(usize, shapes.len);
        errdefer a.free(offsets);
        const logs = try a.alloc(u32, shapes.len);
        errdefer a.free(logs);
        const host_offsets = try a.alloc(usize, shapes.len);
        errdefer a.free(host_offsets);
        for (order, 0..) |*i, k| i.* = k;
        const Sort = struct {
            s: []const Shape,
            fn less(self: @This(), x: usize, y: usize) bool {
                return self.s[x].log_size < self.s[y].log_size or (self.s[x].log_size == self.s[y].log_size and x < y);
            }
        };
        std.mem.sort(usize, order, Sort{ .s = own }, Sort.less);
        var cells: usize = 0;
        var max_log: u32 = 0;
        for (order, logs) |original, *log| {
            const s = own[original];
            if (s.log_size < 3 or s.log_size + beta > 28) return error.UnsupportedTraceCommitGeometry;
            offsets[original] = cells;
            cells = try std.math.add(usize, cells, @as(usize, 1) << @intCast(s.log_size));
            max_log = @max(max_log, s.log_size);
            log.* = s.log_size;
        }
        const eval_log = max_log + beta;
        var tw = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain().half_coset);
        errdefer engine.poly.twiddles.deinitM31(a, &tw);
        return .{ .a = a, .shapes = own, .order = order, .offsets = offsets, .logs = logs, .beta = beta, .coefficient_cells = cells, .eval_cells = try std.math.mul(usize, cells, @as(usize, 1) << @intCast(beta)), .eval_log = eval_log, .tree_words = ((@as(usize, 2) << @intCast(eval_log)) - 1) * 8, .tw = tw, .host_offsets = host_offsets };
    }
    pub fn deinit(self: *CommitPlan) void {
        engine.poly.twiddles.deinitM31(self.a, &self.tw);
        inline for (.{ "shapes", "order", "offsets", "logs", "host_offsets" }) |f| self.a.free(@field(self, f));
        self.* = undefined;
    }
    fn twiddleWords(self: *const CommitPlan) usize {
        return self.tw.twiddles.len + self.tw.itwiddles.len;
    }
    /// Upper bound of enqueue-time arena words (coefficients + LDE + tree + prefix banks).
    pub fn deviceWords(self: *const CommitPlan) usize {
        // Prefix banks: at most 48 words per row of the largest non-final height (trace_commit.zig).
        return self.coefficient_cells + self.eval_cells + self.tree_words + 48 * (@as(usize, 1) << @intCast(self.eval_log - 1)) + 3 * 64;
    }
    /// Phase-1 arena words (logs + staged host columns); twiddles are persistent.
    pub fn stagedWords(self: *const CommitPlan, host_words: usize) usize {
        return self.logs.len + host_words;
    }
    /// Phase 1: class twiddles (persistent, keyed by eval log), the log vector
    /// and every host-encoded column (`inputs[i].host`, original order).
    pub fn stage(self: *CommitPlan, s: *api.Stager, inputs: []const Input) !void {
        if (inputs.len != self.shapes.len) return error.TraceCommitInputCount;
        var key: [32]u8 = @splat(0);
        @memcpy(key[0..16], "rv64-m8-trace-tw");
        key[16] = @intCast(self.eval_log);
        const tw = try s.persistent(key, self.twiddleWords());
        if (tw.fresh) {
            try s.upload(try tw.buffer.slice(0, self.tw.twiddles.len), mWords(self.tw.twiddles));
            try s.upload(try tw.buffer.slice(self.tw.twiddles.len, self.tw.itwiddles.len), mWords(self.tw.itwiddles));
        }
        self.twiddles = tw.buffer;
        const logs = try s.alloc(self.logs.len);
        try s.upload(logs, self.logs);
        self.logs_device = logs;
        var host_words: usize = 0;
        for (inputs, self.shapes, self.host_offsets) |input, shape, *offset| {
            offset.* = host_words;
            if (input.device != null) continue;
            if (input.host.len != @as(usize, 1) << @intCast(shape.log_size)) return error.InvalidTraceCommitInput;
            host_words += input.host.len;
        }
        self.host_staged = null;
        if (host_words != 0) {
            const staged = try s.alloc(host_words);
            for (inputs, self.host_offsets) |input, offset| if (input.device == null) try s.upload(try staged.slice(offset, input.host.len), input.host);
            self.host_staged = staged;
        }
    }
    /// Phase 2. `root_out`: 8-word slab field. `mix`: mix the root into e.channel.
    pub fn enqueue(self: *const CommitPlan, sym: Symbols, e: anytype, inputs: []const Input, root_out: api.DeviceBuffer, mix: bool) !Committed {
        return self.enqueueInto(sym, e, inputs, try e.alloc(self.coefficient_cells), root_out, mix);
    }
    /// `enqueue` into caller-owned coefficient storage (e.g. class-persistent
    /// FIXED memory from Stager.persistent) of `coefficient_cells` words.
    pub fn enqueueInto(self: *const CommitPlan, sym: Symbols, e: anytype, inputs: []const Input, coefficients: api.DeviceBuffer, root_out: api.DeviceBuffer, mix: bool) !Committed {
        if (inputs.len != self.shapes.len or root_out.words < 8 or coefficients.words < self.coefficient_cells) return error.TraceCommitInputCount;
        const ctx = e.ctx();
        const stream = e.stream();
        const tw = self.twiddles orelse return error.TraceCommitNotStaged;
        const logs = self.logs_device orelse return error.TraceCommitNotStaged;
        // Ingress in sorted order (the legacy copyInputs order).
        for (self.order) |original| {
            const count = @as(usize, 1) << @intCast(self.shapes[original].log_size);
            const source: [*]const u32 = if (inputs[original].device) |d| d else (self.host_staged orelse return error.TraceCommitNotStaged).ptr + self.host_offsets[original];
            try check(sym.copy_d2d(ctx, coefficients.ptr + self.offsets[original], source, count * 4));
        }
        var launches: u32 = 0;
        const fwd = tw.ptr;
        const inv = tw.ptr + self.tw.twiddles.len;
        // B2N on adjacent evaluation runs of one height (never a coefficient column).
        var first: usize = 0;
        while (first < self.order.len) {
            const shape = self.shapes[self.order[first]];
            if (shape.encoding != .evaluations) {
                first += 1;
                continue;
            }
            var end = first + 1;
            while (end < self.order.len and self.shapes[self.order[end]].log_size == shape.log_size and self.shapes[self.order[end]].encoding == .evaluations) : (end += 1) {}
            const rows = @as(usize, 1) << @intCast(shape.log_size);
            const at = coefficients.ptr + self.offsets[self.order[first]];
            try check(sym.b2n(at, rows, at, rows, shape.log_size, @intCast(end - first), inv + self.tw.itwiddles.len - rows / 2, @intCast(rows / 2), @intCast(rows / 2), stream, &launches));
            first = end;
        }
        const evaluations = try e.alloc(self.eval_cells);
        var segments: [96]MixedSegment = undefined;
        var segment_count: usize = 0;
        var eval_offset: usize = 0;
        first = 0;
        while (first < self.order.len) {
            const log = self.shapes[self.order[first]].log_size + self.beta;
            var end = first + 1;
            while (end < self.order.len and self.shapes[self.order[end]].log_size + self.beta == log) : (end += 1) {}
            const rows = @as(usize, 1) << @intCast(log);
            const count = @as(usize, 1) << @intCast(self.shapes[self.order[first]].log_size);
            try check(sym.n2b_columns(coefficients.ptr + self.offsets[self.order[first]], count, logs.ptr + first, evaluations.ptr + eval_offset, rows, log, @intCast(end - first), fwd + self.tw.twiddles.len - rows / 2, @intCast(rows / 2), @intCast(rows / 2), stream, &launches));
            if (segment_count == segments.len) return error.UnsupportedTraceCommitGeometry;
            segments[segment_count] = .{ .columns = evaluations.ptr + eval_offset, .stride_words = rows, .capacity_words = rows * (end - first), .source_size = @intCast(rows) };
            segment_count += 1;
            eval_offset += rows * (end - first);
            first = end;
        }
        var prefix_rows: usize = 0;
        for (segments[0 .. segment_count - 1]) |s| prefix_rows = @max(prefix_rows, s.source_size);
        var prefix_words = prefix_rows * 48;
        if (sym.prefix_workspace) |query| {
            var words: u64 = 0;
            try check(query(&segments, @intCast(segment_count), &words));
            if (words > prefix_words) return error.InvalidTracePrefixWorkspace;
            prefix_words = @intCast(words);
        }
        const tree = try e.alloc(self.tree_words + prefix_words);
        try check(sym.tree(ctx, 0, &segments, @intCast(segment_count), self.eval_log, tree.ptr, tree.words));
        const root = tree.ptr + self.tree_words - 8;
        try check(sym.copy_d2d(ctx, root_out.ptr, root, 32));
        if (mix) try e.channel.mixRootFromTree(.{ .ptr = root_out.ptr, .words = 8 });
        e.free(tree);
        e.free(evaluations);
        return .{ .coefficients = coefficients, .root = root_out.ptr };
    }
};

fn mWords(values: []const core.fields.m31.M31) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}
fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

test "commit plan sorts by height stably and lays out the compact coefficient image" {
    var plan = try CommitPlan.init(std.testing.allocator, &.{ .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients }, .{ .log_size = 3, .encoding = .evaluations } }, 1);
    defer plan.deinit();
    try std.testing.expectEqualSlices(usize, &.{ 1, 3, 0, 2 }, plan.order);
    try std.testing.expectEqualSlices(usize, &.{ 16, 0, 48, 8 }, plan.offsets);
    try std.testing.expectEqualSlices(u32, &.{ 3, 3, 5, 5 }, plan.logs);
    try std.testing.expectEqual(@as(usize, 80), plan.coefficient_cells);
    try std.testing.expectEqual(@as(u32, 6), plan.eval_log);
    try std.testing.expectEqual(@as(usize, (2 * 64 - 1) * 8), plan.tree_words);
    try std.testing.expectError(error.UnsupportedTraceCommitGeometry, CommitPlan.init(std.testing.allocator, &.{.{ .log_size = 5, .encoding = .coefficients }}, 2));
}
