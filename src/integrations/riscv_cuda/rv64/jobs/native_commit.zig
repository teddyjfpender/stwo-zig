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
/// Descriptor-addressed LDE (rv64/trace_commit.zig `n2b`, the beta >= 2 path).
pub const N2bAddressed = *const fn ([*]u32, usize, ?*const anyopaque, u32, usize, u32, [*]const u32, u32, u32, *anyopaque, u32, *u32) callconv(.c) c_int;
pub const Symbols = struct {
    b2n: B2n,
    n2b_columns: N2bColumns,
    n2b_addressed: ?N2bAddressed = null,
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
            .n2b_addressed = base.lookup(N2bAddressed, "stwo_lde_n2b_addressed_on"),
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
    /// beta >= 2: per-placement LDE descriptors (6 words per sorted column,
    /// then the sorted logs), addressed from the lower of the coefficient and
    /// evaluation buffers, which enqueue allocates back to back.
    descriptors_device: ?api.DeviceBuffer = null,
    placement: api.Placement = .bottom,

    pub fn init(a: std.mem.Allocator, shapes: []const Shape, beta: u32) !CommitPlan {
        if (shapes.len == 0 or beta < 1 or beta > 4) return error.UnsupportedTraceCommitGeometry;
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
        // beta >= 2 with caller storage also holds a temporary coefficient region.
        const extra = if (self.beta == 1) 0 else self.auxWords() + 3 * 64;
        return self.coefficient_cells + self.eval_cells + self.tree_words + 48 * (@as(usize, 1) << @intCast(self.eval_log - 1)) + 3 * 64 + extra;
    }
    /// Phase-1 arena words (logs + staged host columns); twiddles are persistent.
    pub fn stagedWords(self: *const CommitPlan, host_words: usize) usize {
        return self.logs.len + host_words + if (self.beta == 1) 0 else 7 * self.logs.len + 64;
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
        self.placement = s.placement;
        if (self.beta != 1) {
            const words = try s.pinned(7 * self.logs.len);
            self.addressedDescriptors(s.placement, words);
            const d = try s.alloc(words.len);
            try s.upload(d, words);
            self.descriptors_device = d;
        }
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
    fn granule() usize {
        return @import("worker.zig").Arena.granule;
    }
    /// The addressed LDE reads its descriptors and twiddles from inside its
    /// arena range (legacy co-locates them), so enqueue allocates an aux region
    /// {forward twiddles, descriptors} right after the evaluations.
    fn auxWords(self: *const CommitPlan) usize {
        return self.tw.twiddles.len + 7 * self.order.len;
    }
    /// Word offsets {coefficients, evaluations, aux} inside the one region the
    /// addressed path allocates. The {evaluations, aux} tail sits on the side
    /// the arena reclaims first (high end on bottom, low end on top), so it is
    /// freed after the tree while the coefficients stay for the PCS.
    fn addressedBases(self: *const CommitPlan, placement: api.Placement) [3]usize {
        const c = std.mem.alignForward(usize, self.coefficient_cells, granule());
        const v = std.mem.alignForward(usize, self.eval_cells, granule());
        const x = std.mem.alignForward(usize, self.auxWords(), granule());
        return if (placement == .bottom) .{ 0, c, c + v } else .{ x + v, x, 0 };
    }
    /// The legacy descriptor table (trace_commit.zig): per sorted column
    /// {coefficient offset u64, evaluation offset u64, log, 0}, then the logs.
    pub fn addressedDescriptors(self: *const CommitPlan, placement: api.Placement, out: []u32) void {
        const bases = self.addressedBases(placement);
        const n = self.order.len;
        std.debug.assert(out.len == 7 * n);
        var eval_offset: usize = bases[1];
        for (self.order, 0..) |original, i| {
            const log = self.shapes[original].log_size;
            const coefficient = bases[0] + self.offsets[original];
            out[6 * i ..][0..6].* = .{ @truncate(coefficient), @truncate(@as(u64, coefficient) >> 32), @truncate(eval_offset), @truncate(@as(u64, eval_offset) >> 32), log, 0 };
            out[6 * n + i] = log;
            eval_offset += @as(usize, 1) << @intCast(log + self.beta);
        }
    }
    fn regionWords(self: *const CommitPlan) usize {
        // Every part is granule-rounded: the top layout puts aux first.
        return std.mem.alignForward(usize, self.coefficient_cells, granule()) + std.mem.alignForward(usize, self.eval_cells, granule()) + std.mem.alignForward(usize, self.auxWords(), granule());
    }
    fn tail(self: *const CommitPlan, region: api.DeviceBuffer) api.DeviceBuffer {
        const bases = self.addressedBases(self.placement);
        return if (self.placement == .bottom) .{ .ptr = region.ptr + bases[1], .words = region.words - bases[1] } else .{ .ptr = region.ptr, .words = bases[0] };
    }
    /// Phase 2. `root_out`: 8-word slab field. `mix`: mix the root into e.channel.
    pub fn enqueue(self: *const CommitPlan, sym: Symbols, e: anytype, inputs: []const Input, root_out: api.DeviceBuffer, mix: bool) !Committed {
        if (self.beta != 1) {
            const region = try e.alloc(self.regionWords());
            return self.enqueueAddressed(sym, e, inputs, region, root_out, mix);
        }
        return self.enqueueInto(sym, e, inputs, try e.alloc(self.coefficient_cells), root_out, mix);
    }
    /// beta >= 2 (the D2 native profile, blowup 4): the legacy arena path, in
    /// one `regionWords` allocation {coefficients, evaluations, aux}. Returns
    /// the coefficient view; the evaluation/aux tail is freed after the tree.
    fn enqueueAddressed(self: *const CommitPlan, sym: Symbols, e: anytype, inputs: []const Input, region: api.DeviceBuffer, root_out: api.DeviceBuffer, mix: bool) !Committed {
        const n2b = sym.n2b_addressed orelse return error.MissingTraceCommitSymbol;
        const descriptors = self.descriptors_device orelse return error.TraceCommitNotStaged;
        const tw = self.twiddles orelse return error.TraceCommitNotStaged;
        if (inputs.len != self.shapes.len or root_out.words < 8 or region.words < self.regionWords()) return error.TraceCommitInputCount;
        const bases = self.addressedBases(self.placement);
        const coefficients = try region.slice(bases[0], self.coefficient_cells);
        const evaluations = try region.slice(bases[1], self.eval_cells);
        const aux = try region.slice(bases[2], self.auxWords());
        const stream = e.stream();
        try self.ingressAndInterpolate(sym, e.ctx(), stream, inputs, coefficients);
        const base = region.ptr;
        const span = region.words;
        const tw_words = self.tw.twiddles.len;
        try check(sym.copy_d2d(e.ctx(), aux.ptr, tw.ptr, tw_words * 4));
        try check(sym.copy_d2d(e.ctx(), aux.ptr + tw_words, descriptors.ptr, 7 * self.order.len * 4));
        var launches: u32 = 0;
        var segments: [96]MixedSegment = undefined;
        var segment_count: usize = 0;
        var eval_offset: usize = 0;
        var first: usize = 0;
        while (first < self.order.len) {
            const log = self.shapes[self.order[first]].log_size + self.beta;
            var end = first + 1;
            while (end < self.order.len and self.shapes[self.order[end]].log_size + self.beta == log) : (end += 1) {}
            const rows = @as(usize, 1) << @intCast(log);
            try checkAt(@src().line, n2b(base, span, aux.ptr + tw_words + 6 * first, @intCast(end - first), bases[1] + eval_offset, log, aux.ptr + tw_words - rows / 2, @intCast(rows / 2), @intCast(rows / 2), stream, 1, &launches));
            if (segment_count == segments.len) return error.UnsupportedTraceCommitGeometry;
            segments[segment_count] = .{ .columns = evaluations.ptr + eval_offset, .stride_words = rows, .capacity_words = rows * (end - first), .source_size = @intCast(rows) };
            segment_count += 1;
            eval_offset += rows * (end - first);
            first = end;
        }
        try self.treeAndRoot(sym, e, segments[0..segment_count], root_out, mix);
        e.free(self.tail(region));
        return .{ .coefficients = coefficients, .root = root_out.ptr };
    }
    fn ingressAndInterpolate(self: *const CommitPlan, sym: Symbols, ctx: *anyopaque, stream: *anyopaque, inputs: []const Input, coefficients: api.DeviceBuffer) !void {
        const tw = self.twiddles orelse return error.TraceCommitNotStaged;
        for (self.order) |original| {
            const count = @as(usize, 1) << @intCast(self.shapes[original].log_size);
            const source: [*]const u32 = if (inputs[original].device) |d| d else (self.host_staged orelse return error.TraceCommitNotStaged).ptr + self.host_offsets[original];
            try check(sym.copy_d2d(ctx, coefficients.ptr + self.offsets[original], source, count * 4));
        }
        var launches: u32 = 0;
        const inv = tw.ptr + self.tw.twiddles.len;
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
    }
    fn treeAndRoot(self: *const CommitPlan, sym: Symbols, e: anytype, segments: []const MixedSegment, root_out: api.DeviceBuffer, mix: bool) !void {
        var prefix_rows: usize = 0;
        for (segments[0 .. segments.len - 1]) |s| prefix_rows = @max(prefix_rows, s.source_size);
        var prefix_words = prefix_rows * 48;
        if (sym.prefix_workspace) |query| {
            var words: u64 = 0;
            try check(query(segments.ptr, @intCast(segments.len), &words));
            if (words > prefix_words) return error.InvalidTracePrefixWorkspace;
            prefix_words = @intCast(words);
        }
        const tree = try e.alloc(self.tree_words + prefix_words);
        try checkAt(@src().line, sym.tree(e.ctx(), 0, segments.ptr, @intCast(segments.len), self.eval_log, tree.ptr, tree.words));
        try check(sym.copy_d2d(e.ctx(), root_out.ptr, tree.ptr + self.tree_words - 8, 32));
        if (mix) try e.channel.mixRootFromTree(.{ .ptr = root_out.ptr, .words = 8 });
        e.free(tree);
    }
    /// `enqueue` into caller-owned coefficient storage (e.g. class-persistent
    /// FIXED memory from Stager.persistent) of `coefficient_cells` words.
    pub fn enqueueInto(self: *const CommitPlan, sym: Symbols, e: anytype, inputs: []const Input, coefficients: api.DeviceBuffer, root_out: api.DeviceBuffer, mix: bool) !Committed {
        if (inputs.len != self.shapes.len or root_out.words < 8 or coefficients.words < self.coefficient_cells) return error.TraceCommitInputCount;
        if (self.beta != 1) {
            const region = try e.alloc(self.regionWords());
            const scratch = try self.enqueueAddressed(sym, e, inputs, region, root_out, mix);
            try check(sym.copy_d2d(e.ctx(), coefficients.ptr, scratch.coefficients.ptr, self.coefficient_cells * 4));
            e.free(.{ .ptr = scratch.coefficients.ptr, .words = std.mem.alignForward(usize, self.coefficient_cells, granule()) });
            return .{ .coefficients = coefficients, .root = root_out.ptr };
        }
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
/// Failure-only diagnostic (names the call site and native status).
fn checkAt(line: u32, code: c_int) !void {
    if (code != 0) {
        std.debug.print("M8_NATIVE_COMMIT_ENQUEUE_FAILED line={} status={}\n", .{ line, code });
        return error.CudaEnqueueFailed;
    }
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
    try std.testing.expectError(error.UnsupportedTraceCommitGeometry, CommitPlan.init(std.testing.allocator, &.{.{ .log_size = 5, .encoding = .coefficients }}, 5));
}

test "beta 2 descriptors address coefficients and evaluations from the lower buffer per placement" {
    var plan = try CommitPlan.init(std.testing.allocator, &.{ .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .coefficients } }, 2);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 40), plan.coefficient_cells);
    try std.testing.expectEqual(@as(usize, 160), plan.eval_cells);
    var bottom: [14]u32 = undefined;
    plan.addressedDescriptors(.bottom, &bottom);
    // sorted: [1] (log 3) then [0] (log 5); evaluations start at align64(40) = 64.
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 64, 0, 3, 0, 8, 0, 96, 0, 5, 0, 3, 5 }, &bottom);
    var top: [14]u32 = undefined;
    plan.addressedDescriptors(.top, &top);
    // top: aux (64 tw + 14 descriptor words -> 128) lowest, then 192 evaluation
    // words, then the coefficients at 128 + 192 = 320.
    try std.testing.expectEqual(@as(usize, 64 + 14), plan.auxWords());
    try std.testing.expectEqualSlices(u32, &.{ 320, 0, 128, 0, 3, 0, 328, 0, 160, 0, 5, 0, 3, 5 }, &top);
}

test "beta 2 region: the evaluation/aux tail is the side the arena reclaims first" {
    var plan = try CommitPlan.init(std.testing.allocator, &.{ .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .coefficients } }, 2);
    defer plan.deinit();
    // align64(40) + align64(160) + align64(64 tw + 14 descriptor words)
    try std.testing.expectEqual(@as(usize, 64 + 192 + 128), plan.regionWords());
    // Both layouts fit the region exactly.
    for ([_]api.Placement{ .bottom, .top }) |side| {
        const bases = plan.addressedBases(side);
        try std.testing.expect(bases[0] + plan.coefficient_cells <= plan.regionWords() and bases[1] + plan.eval_cells <= plan.regionWords() and bases[2] + plan.auxWords() <= plan.regionWords());
    }
    const region = api.DeviceBuffer{ .ptr = @ptrFromInt(4096), .words = plan.regionWords() };
    plan.placement = .bottom;
    const b = plan.tail(region);
    try std.testing.expectEqual(@as(usize, 4096 + 4 * 64), @intFromPtr(b.ptr));
    try std.testing.expectEqual(@as(usize, 192 + 128), b.words);
    plan.placement = .top;
    const t = plan.tail(region);
    try std.testing.expectEqual(@as(usize, 4096), @intFromPtr(t.ptr));
    try std.testing.expectEqual(@as(usize, 128 + 192), t.words);
}

test "commit plan paths are analyzed" {
    _ = &CommitPlan.enqueue;
    _ = &CommitPlan.enqueueInto;
    _ = &CommitPlan.stage;
}
