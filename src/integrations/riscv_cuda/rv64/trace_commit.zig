//! Resident MAIN/INTER commitment. One ingress, explicit evaluation/coefficient
//! encodings, GPU interpolation/LDE/hash, and a 32-byte root readback. The
//! compact coefficient lease outlives transform scratch and is consumed by PCS.
const std = @import("std");
const DeviceCopy = @import("scoped_device_copy.zig");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const A = @import("abi.zig");
const Native = @import("pcs_native_abi.zig");
const Service = @import("pcs_native.zig");
const SC = @import("session_context.zig");
const M = D.M;
const N2b = *const fn ([*]u32, usize, ?*const anyopaque, u32, usize, u32, [*]const u32, u32, u32, *anyopaque, u32, *u32) callconv(.c) c_int;
const N2bColumns = *const @TypeOf(@import("stwo_cuda_backend").abi.stages.transform.stwo_lde_n2b_columns_on);
const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingTraceCommitSymbol;
}
fn check(status: c_int) !void {
    if (status != 0) {
        std.debug.print("GPU_TRACE_COMMIT native_status={}\n", .{status});
        return error.CudaTraceCommitFailed;
    }
}
pub const Context = struct {
    // Production MAIN/INTER must be produced on device. A qualification-only
    // mixed-encoding oracle may explicitly opt out; production never does.
    require_device_input: bool = true,
    service: *Service.Context,
    api: SC.Api,
    n2b: N2b,
    n2b_columns: ?N2bColumns,
    b2n: B2n,
    copy: Native.CopyDevice,
    tree: *const @TypeOf(A.stwo_rv64_trace_tree_on),
    rebind: Native.LeaseRebind,
    returned: std.ArrayList([]D.Column) = .empty,
    twiddles: [29]?engine.poly.twiddles.TwiddleTree([]M) = @splat(null),
    mutex: std.Thread.Mutex = .{},
    pub fn init(service: *Service.Context) !Context {
        return .{ .service = service, .api = .{
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .n2b = try sym(N2b, &service.library, "stwo_lde_n2b_addressed_on"), .n2b_columns = service.library.lookup(N2bColumns, "stwo_lde_n2b_columns_on"), .b2n = try sym(B2n, &service.library, "stwo_ntt_b2n_columns_compact_on"), .copy = try sym(Native.CopyDevice, &service.library, "stwo_exec_context_memcpy_d2d_async"), .tree = try sym(*const @TypeOf(A.stwo_rv64_trace_tree_on), &service.library, "stwo_rv64_trace_tree_on"), .rebind = try sym(Native.LeaseRebind, &service.library, "stwo_rv64_gpu_lease_rebind") };
    }
    pub fn deinit(self: *Context) void {
        for (self.returned.items) |columns| std.heap.page_allocator.free(columns);
        self.returned.deinit(std.heap.page_allocator);
        for (&self.twiddles) |*cached| if (cached.*) |*value| engine.poly.twiddles.deinitM31(std.heap.page_allocator, value);
        self.* = undefined;
    }
    fn tw(self: *Context, log: u32) !*const engine.poly.twiddles.TwiddleTree([]M) {
        if (self.twiddles[log] == null) self.twiddles[log] = try engine.poly.twiddles.precomputeM31(std.heap.page_allocator, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        return &self.twiddles[log].?;
    }
    pub fn stage(self: *Context) D.TraceCommitStage {
        return .{ .context = self, .commit = commit };
    }
    fn commit(raw: *anyopaque, a: std.mem.Allocator, request: D.TraceCommitRequest) !D.Tree {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (request.tree_index < 1 or request.tree_index > 2 or request.columns.len == 0 or request.columns.len > 65535) return error.InvalidTraceCommitRequest;
        if (request.expected_main_root) |expected| {
            if (request.tree_index != 1 or std.mem.allEqual(u8, &expected, 0) or !std.mem.eql(u8, &request.scope.main, &expected)) return error.InvalidTraceReplayScope;
        } else if (request.tree_index == 1 and !std.mem.allEqual(u8, &request.scope.main, 0)) return error.InvalidTraceCommitRequest;
        const beta = request.config.fri_config.log_blowup_factor;
        if (beta < 1 or beta > 4) return error.InvalidTraceCommitRequest;
        for (request.columns) |column| {
            try column.validate();
            if (self.require_device_input and column.device == null) return error.HostWitnessDisallowedInResidentProof;
            if (column.log_size + beta > 28) return error.InvalidTraceCommitRequest;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.returned.ensureUnusedCapacity(std.heap.page_allocator, 1);
        var job = Job{ .backend = self, .a = a, .request = request };
        const status = self.service.submit(self.service.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try check(status);
        const result = job.result orelse return error.CudaTraceCommitFailed;
        self.returned.appendAssumeCapacity(@constCast(result.columns));
        return result;
    }
};
const Job = struct {
    backend: *Context,
    a: std.mem.Allocator,
    request: D.TraceCommitRequest,
    result: ?D.Tree = null,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, user: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(user orelse return 1));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        const b = self.backend;
        const a = self.a;
        const r = self.request;
        const beta = r.config.fri_config.log_blowup_factor;
        const scope = @import("pcs_scope.zig").identity(r.scope);
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = scope, .api = &b.api };
        const order = try a.alloc(usize, r.columns.len);
        defer a.free(order);
        const offsets = try a.alloc(usize, r.columns.len);
        defer a.free(offsets);
        for (order, 0..) |*i, k| i.* = k;
        const Sort = struct {
            columns: []const D.TraceColumn,
            fn less(s: @This(), x: usize, y: usize) bool {
                return s.columns[x].log_size < s.columns[y].log_size or (s.columns[x].log_size == s.columns[y].log_size and x < y);
            }
        };
        std.mem.sort(usize, order, Sort{ .columns = r.columns }, Sort.less);
        var coefficient_cells: usize = 0;
        var max_log: u32 = 0;
        for (order) |original| {
            offsets[original] = coefficient_cells;
            coefficient_cells = try std.math.add(usize, coefficient_cells, @as(usize, 1) << @intCast(r.columns[original].log_size));
            max_log = @max(max_log, r.columns[original].log_size);
        }
        const eval_cells = try std.math.mul(usize, coefficient_cells, @as(usize, 1) << @intCast(beta));
        const eval_log = max_log + beta;
        const tw = try b.tw(eval_log);
        // The established column LDE ABI accepts a compact coefficient stride
        // when beta=1. Keep these coefficients in their final owned lease:
        // committing must not allocate and copy a second full coefficient slab.
        const separate_coefficients = beta == 1 and b.n2b_columns != null;
        var coefficients = Native.Lease{};
        var transferred = false;
        defer if (!transferred and coefficients.words != null) {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, &coefficients);
        };
        if (separate_coefficients) coefficients = try ctx.allocate(coefficient_cells, 2);
        const tw_base = try std.math.add(usize, if (separate_coefficients) 0 else coefficient_cells, eval_cells);
        const inverse_base = try std.math.add(usize, tw_base, tw.twiddles.len);
        const desc_base = std.mem.alignForward(usize, try std.math.add(usize, inverse_base, tw.itwiddles.len), 2);
        const arena_cells = try std.math.add(usize, desc_base, try std.math.mul(usize, r.columns.len, 7));
        var arena = try ctx.allocate(arena_cells, 0);
        defer {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, &arena);
        }
        const ptr = arena.words.?;
        const arena_slice = try ctx.borrow(arena);
        const coefficient_slice = if (separate_coefficients) try ctx.borrow(coefficients) else arena_slice;
        const coefficient_ptr = if (separate_coefficients) coefficients.words.? else ptr;
        const descriptors = try a.alloc(u32, 7 * order.len);
        defer a.free(descriptors);
        var eval_offset: usize = if (separate_coefficients) 0 else coefficient_cells;
        var segments: std.ArrayList(A.MixedSegment) = .empty;
        defer segments.deinit(a);
        var pending_copy: ?DeviceCopy.Run = null;
        for (order, 0..) |original, i| {
            const column = r.columns[original];
            const count = @as(usize, 1) << @intCast(column.log_size);
            const rows = count << @intCast(beta);
            if (column.device) |device| {
                if (device.count != count) return error.InvalidDeviceTraceColumn;
                const next = try DeviceCopy.Run.init(@intFromPtr(device.words), offsets[original], count, device.context_token, device.generation);
                if (pending_copy) |*copy_run| {
                    if (!try copy_run.append(next)) {
                        try DeviceCopy.execute(&ctx, b.copy, coefficient_slice, copy_run.*);
                        pending_copy = next;
                    }
                } else pending_copy = next;
            } else {
                if (pending_copy) |copy_run| try DeviceCopy.execute(&ctx, b.copy, coefficient_slice, copy_run);
                pending_copy = null;
                try check(b.api.upload(raw, coefficient_ptr + offsets[original], column.host.ptr, count * 4));
            }
            descriptors[6 * order.len + i] = column.log_size;
            descriptors[6 * i ..][0..6].* = .{ @truncate(offsets[original]), @truncate(@as(u64, offsets[original]) >> 32), @truncate(eval_offset), @truncate(@as(u64, eval_offset) >> 32), column.log_size, 0 };
            if (segments.items.len != 0 and segments.items[segments.items.len - 1].source_size == rows) segments.items[segments.items.len - 1].capacity_words += rows else try segments.append(a, .{ .columns = ptr + eval_offset, .stride_words = rows, .capacity_words = rows, .source_size = @intCast(rows), .reserved = 0 });
            eval_offset += rows;
        }
        if (pending_copy) |copy_run| try DeviceCopy.execute(&ctx, b.copy, coefficient_slice, copy_run);
        try check(b.api.upload(raw, ptr + tw_base, tw.twiddles.ptr, tw.twiddles.len * 4));
        try check(b.api.upload(raw, ptr + inverse_base, tw.itwiddles.ptr, tw.itwiddles.len * 4));
        try check(b.api.upload(raw, ptr + desc_base, descriptors.ptr, descriptors.len * 4));
        try ctx.join();
        var stream: ?*anyopaque = null;
        try check(b.api.lane_stream(raw, 1, &stream));
        const lane = stream orelse return error.InvalidLane;
        var launches: u32 = 0;
        var interpolation_first: usize = 0;
        while (interpolation_first < order.len) {
            const original = order[interpolation_first];
            const column = r.columns[original];
            if (column.encoding != .evaluations) {
                interpolation_first += 1;
                continue;
            }
            // Sorting preserves native order within a height. Batch only
            // adjacent evaluation columns; a coefficient column splits a run
            // and must never be interpolated a second time.
            var interpolation_end = interpolation_first + 1;
            while (interpolation_end < order.len and
                r.columns[order[interpolation_end]].log_size == column.log_size and
                r.columns[order[interpolation_end]].encoding == .evaluations) : (interpolation_end += 1)
            {}
            const rows = @as(usize, 1) << @intCast(column.log_size);
            const inverse_offset = inverse_base + tw.itwiddles.len - rows / 2;
            try check(b.b2n(coefficient_ptr + offsets[original], rows, coefficient_ptr + offsets[original], rows, column.log_size, @intCast(interpolation_end - interpolation_first), ptr + inverse_offset, @intCast(rows / 2), @intCast(rows / 2), lane, &launches));
            interpolation_first = interpolation_end;
        }
        var first: usize = 0;
        while (first < order.len) {
            const log = r.columns[order[first]].log_size + beta;
            var end = first + 1;
            while (end < order.len and r.columns[order[end]].log_size + beta == log) : (end += 1) {}
            const rows = @as(usize, 1) << @intCast(log);
            const destination = @as(u64, descriptors[6 * first + 2]) | (@as(u64, descriptors[6 * first + 3]) << 32);
            if (separate_coefficients) {
                const count = @as(usize, 1) << @intCast(r.columns[order[first]].log_size);
                try check(b.n2b_columns.?(coefficient_ptr + offsets[order[first]], count, ptr + desc_base + 6 * order.len + first, ptr + @as(usize, @intCast(destination)), rows, log, @intCast(end - first), ptr + tw_base + tw.twiddles.len - rows / 2, @intCast(rows / 2), @intCast(rows / 2), lane, &launches));
            } else try check(b.n2b(ptr, arena.count, ptr + desc_base + 6 * first, @intCast(end - first), @intCast(destination), log, ptr + tw_base + tw.twiddles.len - rows / 2, @intCast(rows / 2), @intCast(rows / 2), lane, 1, &launches));
            first = end;
        }
        const tree_words = ((@as(usize, 2) << @intCast(eval_log)) - 1) * 8;
        var tree = try ctx.allocate(tree_words, 0);
        defer {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, &tree);
        }
        try check(b.tree(raw, 1, @ptrCast(segments.items.ptr), @intCast(segments.items.len), eval_log, tree.words.?, tree_words));
        try ctx.join();
        var root_words: [8]u32 = undefined;
        try check(b.api.download(raw, &root_words, tree.words.? + tree_words - 8, 32));
        try ctx.join();
        var root: [32]u8 = undefined;
        for (root_words, 0..) |v, i| std.mem.writeInt(u32, root[4 * i ..][0..4], v, .little);
        if (r.expected_main_root) |expected| if (!std.mem.eql(u8, &root, &expected)) return error.DeviceMainReplayRootMismatch;
        var final_scope = r.scope;
        if (r.tree_index == 1) final_scope.main = root;
        const promoted = @import("pcs_scope.zig").identity(final_scope);
        if (!separate_coefficients) {
            coefficients = try ctx.allocate(coefficient_cells, 2);
            try check(b.copy(raw, coefficients.words.?, ptr, coefficient_cells * 4));
            try ctx.join();
        }
        std.debug.print("GPU_TRACE_OWNERSHIP tree={} coefficient_words={} scratch_words={} final_coefficient_copy_words={}\n", .{ r.tree_index, coefficient_cells, arena_cells, if (separate_coefficients) @as(usize, 0) else coefficient_cells });
        const columns = try std.heap.page_allocator.alloc(D.Column, r.columns.len);
        errdefer std.heap.page_allocator.free(columns);
        for (columns, r.columns, 0..) |*column, input, i| column.* = .{ .log_size = input.log_size, .device = .{ .words = coefficients.words.? + offsets[i], .count = @as(u64, 1) << @intCast(input.log_size), .context_token = coefficients.context_token, .generation = coefficients.generation } };
        try check(b.rebind(b.service.session, &coefficients, &scope, &promoted));
        try b.service.retainDeviceLease(promoted, coefficients);
        transferred = true;
        self.result = .{ .root = root, .columns = columns };
    }
};
test "resident trace commitment instantiates the typed mixed-encoding callback" {
    std.testing.refAllDecls(Context);
}
