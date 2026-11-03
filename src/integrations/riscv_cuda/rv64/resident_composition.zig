//! Actual native CPU-worker composition on its persistent GPU owner. Coefficients
//! are ingress only; quotient buckets, interpolation and final coefficients never
//! return to the host. The sole numerical readback is the committed root.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = CPU.rv64_device_pcs;
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Service = @import("pcs_native.zig");
const G = @import("joined_codegen.zig");
const Oracle = @import("joined_fixture_support.zig");
const Hybrid = @import("real_composition.zig");
const Abi = @import("abi.zig");
const O = D.O;
const M = D.M;
const Items = CPU.rv64_gkr_cpu_components;
const Trace = engine.air.component_prover.ForField(O).Trace;
const Twiddle = engine.poly.twiddles.TwiddleTree([]M);
const N2b = *const fn ([*]u32, usize, ?*const anyopaque, u32, usize, u32, [*]const u32, u32, u32, *anyopaque, u32, *u32) callconv(.c) c_int;
const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const Copy = Native.CopyDevice;
const Clear = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
fn check(status: c_int) !void {
    if (status != 0) return error.CudaResidentCompositionFailed;
}
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingResidentCompositionSymbol;
}
fn words(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}
fn felts(a: std.mem.Allocator, values: []const O) ![]u32 {
    const out = try a.alloc(u32, values.len * 8);
    for (values, 0..) |v, i| for (v.toM31Array(), 0..) |w, j| {
        out[i * 8 + j] = w.v;
    };
    return out;
}
pub const Context = struct {
    allocator: std.mem.Allocator,
    service: *Service.Context,
    session_api: SC.Api,
    role: *const @TypeOf(Abi.stwo_rv64_composition_role_on),
    finish: *const @TypeOf(Abi.stwo_rv64_composition_finish_on),
    auxiliary: *const @TypeOf(Abi.stwo_rv64_composition_auxiliary_on),
    tree: *const @TypeOf(Abi.stwo_rv64_trace_tree_on),
    n2b: N2b,
    b2n: B2n,
    copy: Copy,
    clear: Clear,
    artifacts: [49]G.Artifact,
    twiddles: [29]?Twiddle = @splat(null),
    mutex: std.Thread.Mutex = .{},
    log_blowup: u32 = 1,
    result_columns: std.ArrayList([]D.Column) = .empty,
    pub fn init(a: std.mem.Allocator, service: *Service.Context) !Context {
        var result: Context = .{ .allocator = a, .service = service, .session_api = .{
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .role = try sym(*const @TypeOf(Abi.stwo_rv64_composition_role_on), &service.library, "stwo_rv64_composition_role_on"), .finish = try sym(*const @TypeOf(Abi.stwo_rv64_composition_finish_on), &service.library, "stwo_rv64_composition_finish_on"), .auxiliary = try sym(*const @TypeOf(Abi.stwo_rv64_composition_auxiliary_on), &service.library, "stwo_rv64_composition_auxiliary_on"), .tree = try sym(*const @TypeOf(Abi.stwo_rv64_trace_tree_on), &service.library, "stwo_rv64_trace_tree_on"), .n2b = try sym(N2b, &service.library, "stwo_lde_n2b_addressed_on"), .b2n = try sym(B2n, &service.library, "stwo_ntt_b2n_columns_compact_on"), .copy = try sym(Copy, &service.library, "stwo_exec_context_memcpy_d2d_async"), .clear = try sym(Clear, &service.library, "stwo_exec_context_memset_async"), .artifacts = undefined };
        var made: usize = 0;
        errdefer for (result.artifacts[0..made]) |*item| item.deinit();
        for (Oracle.descriptors(), &result.artifacts) |d, *artifact| {
            artifact.* = try G.record(a, d);
            made += 1;
        }
        return result;
    }
    pub fn deinit(self: *Context) void {
        for (&self.artifacts) |*artifact| artifact.deinit();
        for (&self.twiddles) |*cached| if (cached.*) |*value| engine.poly.twiddles.deinitM31(self.allocator, value);
        for (self.result_columns.items) |columns| self.allocator.free(columns);
        self.result_columns.deinit(self.allocator);
        self.* = undefined;
    }
    fn tw(self: *Context, log: u32) !*const Twiddle {
        if (self.twiddles[log] == null) self.twiddles[log] = try engine.poly.twiddles.precomputeM31(self.allocator, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        return &self.twiddles[log].?;
    }
    pub fn stage(self: *Context) CPU.rv64_gkr_cpu_worker.ResidentCompositionStage {
        return .{ .context = self, .evaluate_and_commit = evaluate };
    }
    fn evaluate(raw: *anyopaque, a: std.mem.Allocator, items: []const Items.Item, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope) !D.Tree {
        const self: *Context = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        var timer = try std.time.Timer.start();
        var job = Job{ .backend = self, .allocator = a, .items = items, .alpha = alpha, .log = log, .split = split, .total = total, .trace = @ptrCast(@alignCast(trace_raw)), .scope = scope };
        if (self.service.submit(self.service.session, Job.callback, &job) != 0) return job.failure orelse error.CudaResidentCompositionFailed;
        const result = job.result orelse return error.CudaResidentCompositionFailed;
        try self.result_columns.append(self.allocator, @constCast(result.columns));
        std.debug.print("GPU_COMPOSITION_RESIDENT roles={} total_ns={} quotient_d2h_bytes=0 coefficient_d2h_bytes=0 root_d2h_bytes=32\n", .{ items.len, timer.read() });
        return result;
    }
};
const Job = struct {
    backend: *Context,
    allocator: std.mem.Allocator,
    items: []const Items.Item,
    alpha: O,
    log: u32,
    split: u32,
    total: usize,
    trace: *const Trace,
    scope: D.Scope,
    result: ?D.Tree = null,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        const a = self.allocator;
        const b = self.backend;
        var context = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.scope), .api = &b.session_api };
        defer context.active = false;
        var leases: std.ArrayList(Native.Lease) = .empty;
        defer {
            context.join() catch {};
            for (leases.items) |*lease| context.release(lease) catch {};
            leases.deinit(a);
        }
        var buckets: [29]?Native.Lease = @splat(null);
        const powers = try a.alloc(O, self.total);
        defer a.free(powers);
        var power = O.one();
        for (powers) |*p| {
            p.* = power;
            power = power.mul(self.alpha);
        }
        var next = self.total;
        for (self.items) |*item| switch (item.*) {
            inline else => |*c| {
                const T = @TypeOf(c.*);
                const descriptor = Hybrid.descriptor(T, c);
                const id = try Hybrid.caseId(descriptor);
                const artifact = &b.artifacts[id];
                if (artifact.program.roots.len != c.nConstraints()) return error.WrongResidentConstraintCount;
                const rl = G.Authority.RoleGeometry.logSize(c);
                const el = c.maxConstraintLogDegreeBound();
                if (el != rl + 1 or el > self.log) return error.UnsupportedResidentCompositionDomain;
                const n = @as(usize, 1) << @intCast(el);
                const shape = c.mainShape();
                const iw = G.Authority.RoleGeometry.interWidth(c);
                const aux: usize = if (comptime @hasField(T, "data")) 10 else 0;
                const widths = [3]usize{ shape.fixed, shape.main, iw + aux };
                const column_count = widths[0] + widths[1] + widths[2];
                var sources: std.ArrayList(engine.air.component_prover.ForField(O).Poly) = .empty;
                defer sources.deinit(a);
                const offsets = c.columnOffsets();
                try sources.appendSlice(a, self.trace.polys.items[0][offsets[0]..][0..widths[0]]);
                try sources.appendSlice(a, self.trace.polys.items[1][offsets[1]..][0..widths[1]]);
                try sources.appendSlice(a, self.trace.polys.items[2][c.inter_offset..][0..iw]);
                var source_words: usize = aux * (@as(usize, 1) << @intCast(rl));
                for (sources.items) |source| {
                    const p = source.coefficients orelse return error.DevicePcsCoefficientsRequired;
                    source_words += p.coefficients().len;
                }
                const tw = try b.tw(el);
                const eval_base = source_words;
                const tw_base = eval_base + column_count * n;
                const desc_base = tw_base + tw.twiddles.len;
                var arena = try context.allocate(desc_base + column_count * 6, 0);
                defer {
                    context.join() catch {};
                    context.release(&arena) catch {};
                }
                const arena_ptr = arena.words.?;
                var coefficient_offset: usize = 0;
                var descriptors: std.ArrayList(u32) = .empty;
                defer descriptors.deinit(a);
                for (sources.items, 0..) |source, i| {
                    const p = source.coefficients.?;
                    const values = p.coefficients();
                    const original = D.Column{ .log_size = p.logSize(), .coefficients = values };
                    const target = arena_ptr + coefficient_offset;
                    const source_tree: u32 = if (i < widths[0]) 0 else if (i < widths[0] + widths[1]) 1 else 2;
                    const original_index = switch (source_tree) {
                        0 => offsets[0] + i,
                        1 => offsets[1] + i - widths[0],
                        else => c.inter_offset + i - widths[0] - widths[1],
                    };
                    if (b.service.retainedColumn(context.scope, source_tree, original_index, original)) |device| {
                        try check(b.service.lease_validate_range(b.service.session, device.words, device.count, device.context_token, device.generation, &context.scope));
                        try check(b.copy(raw, @ptrCast(target), @ptrCast(device.words), values.len * 4));
                    } else try check(b.session_api.upload(raw, @ptrCast(target), values.ptr, values.len * 4));
                    const dst = eval_base + i * n;
                    try descriptors.appendSlice(a, &.{ @truncate(coefficient_offset), @truncate(@as(u64, coefficient_offset) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), p.logSize(), 0 });
                    coefficient_offset += values.len;
                }
                if (comptime @hasField(T, "data")) {
                    var hc: [2 * 22 * 8]u32 = undefined;
                    for (0..2) |half| for (0..rl) |i| for ((if (half == 0) c.data.point.hc0[i] else c.data.point.hc1[i]).toM31Array(), 0..) |word, j| {
                        hc[(half * rl + i) * 8 + j] = word.v;
                    };
                    const h = try upload(a, &context, &leases, hc[0 .. 16 * rl]);
                    const role_tw = try b.tw(rl);
                    const it = try upload(a, &context, &leases, words(role_tw.itwiddles));
                    try context.join();
                    var stream: ?*anyopaque = null;
                    try check(b.session_api.lane_stream(raw, 1, &stream));
                    var launches: u32 = 0;
                    try check(b.auxiliary(raw, 1, h.words.?, arena_ptr + coefficient_offset, rl, &launches));
                    const rows = @as(usize, 1) << @intCast(rl);
                    try check(b.b2n(arena_ptr + coefficient_offset, rows, arena_ptr + coefficient_offset, rows, rl, 10, it.words.?, @intCast(role_tw.itwiddles.len), @intCast(rows / 2), stream.?, &launches));
                    for (0..10) |i| {
                        const src = coefficient_offset + i * rows;
                        const dst = eval_base + (sources.items.len + i) * n;
                        try descriptors.appendSlice(a, &.{ @truncate(src), @truncate(@as(u64, src) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), rl, 0 });
                    }
                }
                try check(b.session_api.upload(raw, @ptrCast(arena_ptr + tw_base), tw.twiddles.ptr, tw.twiddles.len * 4));
                try check(b.session_api.upload(raw, @ptrCast(arena_ptr + desc_base), descriptors.items.ptr, descriptors.items.len * 4));
                const metadata = Hybrid.metadata(T, c, descriptor);
                const parameters = try a.alloc(O, artifact.parameter_slots.len);
                defer a.free(parameters);
                for (parameters, artifact.parameter_slots) |*p, slot| p.* = metadata[slot];
                const parameter_words = try felts(a, parameters);
                defer a.free(parameter_words);
                const params = try upload(a, &context, &leases, parameter_words);
                if (artifact.program.roots.len > next) return error.NotEnoughCoefficients;
                next -= artifact.program.roots.len;
                const power_words = try felts(a, powers[next..][0..artifact.program.roots.len]);
                defer a.free(power_words);
                const pw = try upload(a, &context, &leases, power_words);
                const mask_offsets = try a.alloc(u64, artifact.program.inputs.len);
                defer a.free(mask_offsets);
                for (mask_offsets, artifact.program.inputs) |*off, mask| off.* = @as(u64, mask.column) * n;
                const masks = try upload(a, &context, &leases, @as([*]const u32, @ptrCast(mask_offsets.ptr))[0 .. mask_offsets.len * 2]);
                const ds = try A.geometry.denominatorInverses(a, rl, el);
                defer a.free(ds);
                const denom = try upload(a, &context, &leases, words(ds));
                if (buckets[el] == null) {
                    buckets[el] = try allocate(a, &context, &leases, 8 * n, 0);
                    try check(b.clear(raw, @ptrCast(buckets[el].?.words.?), 0, 8 * n * 4));
                }
                try context.join();
                var stream: ?*anyopaque = null;
                try check(b.session_api.lane_stream(raw, 1, &stream));
                var launches: u32 = 0;
                try check(b.n2b(arena_ptr, arena.count, arena_ptr + desc_base, @intCast(column_count), eval_base, el, arena_ptr + tw_base, @intCast(tw.twiddles.len), @intCast(n / 2), stream.?, 1, &launches));
                const packet = Abi.CompositionRole{ .role = id, .trace_log = rl, .eval_log = el, .first_row = 0, .row_count = @intCast(n), .trees = .{ arena_ptr + eval_base, arena_ptr + eval_base + widths[0] * n, arena_ptr + eval_base + (widths[0] + widths[1]) * n }, .tree_words = .{ widths[0] * n, widths[1] * n, widths[2] * n }, .column_offsets = @ptrCast(@alignCast(masks.words.?)), .mask_count = mask_offsets.len, .parameters = params.words.?, .parameter_count = parameters.len, .powers = pw.words.?, .constraint_count = artifact.program.roots.len, .denominator_inverses = denom.words.?, .output = buckets[el].?.words.? };
                try check(b.role(raw, 1, &packet, &launches));
                try context.join();
            },
        };
        if (next != 0) return error.UnusedCompositionCoefficients;
        const n = @as(usize, 1) << @intCast(self.log);
        const coeff_count = 8 * n;
        const chunk_log = self.log - self.split;
        const count = @as(usize, 8) << @intCast(self.split);
        const beta = b.log_blowup;
        if (beta < 1 or beta > 4) return error.UnsupportedResidentCompositionBlowup;
        const commit_log = chunk_log + beta;
        const commit_rows = @as(usize, 1) << @intCast(commit_log);
        const eval_words = count * commit_rows;
        if (commit_log > 28) return error.UnsupportedResidentCompositionBlowup;
        const tw = try b.tw(commit_log);
        const composition_tw = try b.tw(self.log);
        var output = try context.allocate(coeff_count + eval_words + tw.twiddles.len + count * 6, 2);
        errdefer context.release(&output) catch {};
        const accumulator = try allocate(a, &context, &leases, coeff_count, 0);
        const inv = try upload(a, &context, &leases, words(composition_tw.itwiddles));
        var list: std.ArrayList(Abi.CompositionBucket) = .empty;
        defer list.deinit(a);
        for (buckets, 0..) |bucket, log| if (bucket) |value| try list.append(a, .{ .words = value.words.?, .log = @intCast(log) });
        try context.join();
        var launches: u32 = 0;
        try check(b.finish(raw, 1, list.items.ptr, @intCast(list.items.len), accumulator.words.?, output.words.?, self.log, self.split, inv.words.?, @intCast(composition_tw.itwiddles.len), &launches));
        const output_tw = coeff_count + eval_words;
        const output_desc = output_tw + tw.twiddles.len;
        var descriptors: std.ArrayList(u32) = .empty;
        defer descriptors.deinit(a);
        for (0..count) |i| {
            const src = i * (@as(usize, 1) << @intCast(chunk_log));
            const dst = coeff_count + i * commit_rows;
            try descriptors.appendSlice(a, &.{ @truncate(src), @truncate(@as(u64, src) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), chunk_log, 0 });
        }
        try check(b.session_api.upload(raw, @ptrCast(output.words.? + output_tw), tw.twiddles.ptr, tw.twiddles.len * 4));
        try check(b.session_api.upload(raw, @ptrCast(output.words.? + output_desc), descriptors.items.ptr, descriptors.items.len * 4));
        try context.join();
        var stream: ?*anyopaque = null;
        try check(b.session_api.lane_stream(raw, 1, &stream));
        try check(b.n2b(output.words.?, output.count, output.words.? + output_desc, @intCast(count), coeff_count, commit_log, output.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), stream.?, 1, &launches));
        const tree_words = (2 * commit_rows - 1) * 8;
        const tree = try allocate(a, &context, &leases, tree_words, 0);
        const segment = Abi.MixedSegment{ .columns = output.words.? + coeff_count, .stride_words = commit_rows, .capacity_words = eval_words, .source_size = @intCast(commit_rows), .reserved = 0 };
        try check(b.tree(raw, 1, @ptrCast(&segment), 1, commit_log, tree.words.?, tree_words));
        try context.join();
        var root_words: [8]u32 = undefined;
        try check(b.session_api.download(raw, &root_words, @ptrCast(tree.words.? + tree_words - 8), 32));
        try context.join();
        var root: [32]u8 = undefined;
        for (root_words, 0..) |v, i| std.mem.writeInt(u32, root[i * 4 ..][0..4], v, .little);
        const columns = try b.allocator.alloc(D.Column, count);
        errdefer b.allocator.free(columns);
        for (columns, 0..) |*column, i| column.* = .{ .log_size = chunk_log, .device = .{ .words = output.words.? + i * (@as(usize, 1) << @intCast(chunk_log)), .count = @as(u64, 1) << @intCast(chunk_log), .context_token = output.context_token, .generation = output.generation } };
        try b.service.retainDeviceLease(context.scope, output);
        self.result = .{ .root = root, .columns = columns };
    }
};
fn allocate(a: std.mem.Allocator, c: *SC.Context, list: *std.ArrayList(Native.Lease), n: usize, kind: u32) !Native.Lease {
    var lease = try c.allocate(n, kind);
    errdefer c.release(&lease) catch {};
    try list.append(a, lease);
    return lease;
}
fn upload(a: std.mem.Allocator, c: *SC.Context, list: *std.ArrayList(Native.Lease), data: []const u32) !Native.Lease {
    const lease = try allocate(a, c, list, @max(@as(usize, 1), data.len), 0);
    if (data.len != 0) try check(c.api.upload(c.native_context, @ptrCast(lease.words.?), data.ptr, data.len * 4));
    return lease;
}

test "resident composition adapter binds the actual worker callback" {
    var context: Context = undefined;
    const stage = context.stage();
    try std.testing.expectEqual(@intFromPtr(&context), @intFromPtr(stage.context));
    _ = Context.init;
    _ = Job.callback;
}
