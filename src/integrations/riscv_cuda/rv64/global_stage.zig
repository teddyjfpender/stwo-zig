//! Native global LogUp witness generation from committed device MAIN.
//! Only independently derived setup/manifest metadata enters from the host.
//! Wide rows, paired fractions, inverses and centered prefixes stay on device.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const W = @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker;
const DG = W.DeviceGlobal;
const G = @import("global_codegen.zig");
const Aot = @import("global_aot.zig");
const Service = @import("pcs_native.zig");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Abi = @import("abi.zig");
const Prefix = @import("prefix_plan.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Launch = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, [*]const u32, [*]u32, [*]u32, [*]u32, u32) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
fn sym(comptime T: type, library: *std.DynLib, name: [:0]const u8) !T {
    return library.lookup(T, name) orelse error.MissingResidentGlobalSymbol;
}
fn checked(status: c_int) !void {
    if (status != 0) return error.CudaGlobalWitnessFailed;
}
const Entry = struct { artifact: G.Artifact, launch: Launch };
pub const Context = struct {
    service: *Service.Context,
    api: SC.Api,
    copy: Native.CopyDevice,
    n2b: N2b,
    pairs: *const @TypeOf(Abi.stwo_rv64_global_pairs_on),
    entries: std.ArrayList(*Entry) = .empty,
    twiddles: [23]?engine.poly.twiddles.TwiddleTree([]M) = @splat(null),
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
        }, .copy = try sym(Native.CopyDevice, &service.library, "stwo_exec_context_memcpy_d2d_async"), .n2b = try sym(N2b, &service.library, "stwo_ntt_n2b_columns_on"), .pairs = try sym(*const @TypeOf(Abi.stwo_rv64_global_pairs_on), &service.library, "stwo_rv64_global_pairs_on") };
    }
    pub fn deinit(self: *Context) void {
        for (self.entries.items) |cached| {
            cached.artifact.deinit();
            std.heap.page_allocator.destroy(cached);
        }
        self.entries.deinit(std.heap.page_allocator);
        for (&self.twiddles) |*tw| if (tw.*) |*tree| engine.poly.twiddles.deinitM31(std.heap.page_allocator, tree);
        self.* = undefined;
    }
    pub fn stage(self: *Context) DG.Stage {
        return .{ .context = self, .generate = generate };
    }
    fn entry(self: *Context, descriptor: G.Source.Descriptor) !*Entry {
        for (self.entries.items) |e| if (std.meta.eql(e.artifact.descriptor, descriptor)) return e;
        const a = std.heap.page_allocator;
        const e = try a.create(Entry);
        errdefer a.destroy(e);
        e.artifact = try G.record(a, descriptor);
        errdefer e.artifact.deinit();
        const name = try Aot.name(a, &e.artifact);
        defer a.free(name);
        const z = try a.dupeZ(u8, name);
        defer a.free(z);
        e.launch = try sym(Launch, &self.service.library, z);
        try self.entries.append(a, e);
        return e;
    }
    fn generate(raw: *anyopaque, a: std.mem.Allocator, scope: D.Scope, item: DG.Item, shared: DG.Shared, budget: usize) !DG.Witness {
        const self: *Context = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = try self.entry(item.descriptor);
        if (item.log_size < 5 or item.log_size > 22) return error.InvalidGlobalGeometry;
        const shape = try G.Authority.shape(item.descriptor);
        if (item.fixed.len != shape.fixed or item.main.len != shape.main) return error.InvalidGlobalGeometry;
        const width = G.Authority.Global.layout(item.descriptor.origin).width();
        const rows = @as(usize, 1) << @intCast(item.log_size);
        const output_words = try std.math.mul(usize, width, rows);
        if (try std.math.mul(usize, output_words, 4) > budget) return error.WideCpuGlobalBudget;
        const prefix = try Prefix.Plan.init(item.log_size);
        const input_words = try std.math.mul(usize, shape.fixed + shape.main, rows);
        const numerator_words = try std.math.mul(usize, 8 * @as(usize, e.artifact.ram_pairs + e.artifact.other_pairs), rows);
        var admitted_words = try std.math.add(usize, output_words, input_words);
        admitted_words = try std.math.add(usize, admitted_words, numerator_words);
        admitted_words = try std.math.add(usize, admitted_words, rows); // immutable twiddle ingress upper bound
        admitted_words = try std.math.add(usize, admitted_words, prefix.scratch_words + 17 + e.artifact.parameter_slots.len * 8);
        if (try std.math.mul(usize, admitted_words, 4) > budget) return error.WideCpuGlobalBudget;
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        const columns = try a.alloc(D.TraceColumn, width);
        errdefer a.free(columns);
        const claims = try a.alloc(O, 1 + @as(usize, @intFromBool(e.artifact.other_pairs != 0)));
        errdefer a.free(claims);
        owner.* = .{ .allocator = a, .service = self.service, .columns = columns, .claims = claims };
        errdefer if (owner.output.words != null) {
            _ = self.service.submit(self.service.session, Owner.releaseDevice, owner);
        };
        var job = Job{ .backend = self, .entry = e, .scope = scope, .item = item, .owner = owner };
        @memset(&job.parameters, O.zero());
        job.parameters[G.P.source_public + G.Source.Public.sponge_first_id] = O.fromBase(M.fromCanonical(item.sponge_first_id));
        job.parameters[G.P.ram] = shared.ram.offset;
        @memcpy(job.parameters[G.P.ram + 1 ..][0..shared.ram.coefficients.len], &shared.ram.coefficients);
        job.parameters[G.P.kio] = shared.kio.offset;
        @memcpy(job.parameters[G.P.kio + 1 ..][0..shared.kio.coefficients.len], &shared.kio.coefficients);
        job.parameters[G.P.wire] = shared.wire.offset;
        @memcpy(job.parameters[G.P.wire + 1 ..][0..shared.wire.coefficients.len], &shared.wire.coefficients);
        if (self.twiddles[item.log_size] == null) self.twiddles[item.log_size] = try engine.poly.twiddles.precomputeM31(std.heap.page_allocator, core.poly.circle.canonic.CanonicCoset.new(item.log_size).circleDomain().half_coset);
        try checked(self.service.submit(self.service.session, Job.callback, &job));
        if (job.failure) |err| return err;
        const result = DG.Witness{ .columns = columns, .claims = claims, .owner = owner, .release_fn = Owner.release };
        try result.validate(item);
        return result;
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    service: *Service.Context,
    output: Native.Lease = .{},
    columns: []D.TraceColumn,
    claims: []O,
    fn releaseDevice(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(raw.?));
        return self.service.lease_release(self.service.session, &self.output);
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        _ = self.service.submit(self.service.session, releaseDevice, self);
        self.allocator.free(self.columns);
        self.allocator.free(self.claims);
        self.allocator.destroy(self);
    }
};
const Job = struct {
    backend: *Context,
    entry: *Entry,
    scope: D.Scope,
    item: DG.Item,
    owner: *Owner,
    parameters: [G.P.count]O = undefined,
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
        const b = self.backend;
        const a = self.owner.allocator;
        const rows = @as(usize, 1) << @intCast(self.item.log_size);
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.scope), .api = &b.api };
        var temporary: std.ArrayList(Native.Lease) = .empty;
        defer {
            ctx.join() catch {};
            for (temporary.items) |*lease| ctx.release(lease) catch {};
            temporary.deinit(a);
        }
        const source_words = try std.math.mul(usize, self.item.fixed.len + self.item.main.len, rows);
        const source = try ctx.allocate(source_words, 0);
        try temporary.append(a, source);
        var offset: usize = 0;
        inline for (.{ self.item.fixed, self.item.main }, 0..) |columns, tree| for (columns) |column| {
            if (column.log_size != self.item.log_size) return error.InvalidGlobalGeometry;
            const destination = source.words.? + offset;
            if (column.device) |device| {
                if (device.count != rows or column.coefficients.len != 0) return error.InvalidDeviceTraceColumn;
                const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
                const borrowed = Slice{ .address = @intFromPtr(device.words), .len = rows, .owner = @intCast(device.context_token), .generation = device.generation };
                const from = try ctx.deviceSlicePointer(u32, borrowed, rows);
                try checked(b.copy(raw, destination, from, rows * 4));
            } else {
                // FIXED is immutable setup. A host MAIN slice is always a bug.
                if (tree != 0 or column.coefficients.len != rows) return error.ResidentGlobalMainRequired;
                if (b.service.retainedColumn(ctx.scope, 0, self.item.fixed_offset + offset / rows, column)) |device| {
                    const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
                    const borrowed = Slice{ .address = @intFromPtr(device.words), .len = rows, .owner = @intCast(device.context_token), .generation = device.generation };
                    const from = try ctx.deviceSlicePointer(u32, borrowed, rows);
                    try checked(b.copy(raw, destination, from, rows * 4));
                } else try ctx.upload(try (try ctx.borrow(source)).sub(offset, rows), @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..rows]);
            }
            offset += rows;
        };
        const tw = &b.twiddles[self.item.log_size].?;
        const twiddle = try ctx.allocate(tw.twiddles.len, 0);
        try temporary.append(a, twiddle);
        try ctx.upload(try ctx.borrow(twiddle), @as([*]const u32, @ptrCast(tw.twiddles.ptr))[0..tw.twiddles.len]);
        const parameters = try a.alloc(O, self.entry.artifact.parameter_slots.len);
        defer a.free(parameters);
        for (parameters, self.entry.artifact.parameter_slots) |*value, slot| value.* = self.parameters[slot];
        const parameter = try ctx.allocate(parameters.len * 8, 0);
        try temporary.append(a, parameter);
        try ctx.upload(try ctx.borrow(parameter), @as([*]const u32, @ptrCast(parameters.ptr))[0 .. parameters.len * 8]);
        // All host staging survives the ingress join, including parameters.
        try ctx.join();
        var stream: ?*anyopaque = null;
        try checked(b.api.lane_stream(raw, 1, &stream));
        const lane = stream orelse return error.InvalidLane;
        var launches: u32 = 0;
        const tw_count = @as(u32, 1) << @intCast(self.item.log_size - 1);
        try checked(b.n2b(source.words.?, rows, self.item.log_size, @intCast(self.item.fixed.len + self.item.main.len), twiddle.words.? + tw.twiddles.len - tw_count, tw_count, tw_count, lane, &launches));
        const art = &self.entry.artifact;
        const pairs = art.ram_pairs + art.other_pairs;
        const width = self.owner.columns.len;
        self.owner.output = try ctx.allocate(width * rows, 0);
        const numerator = try ctx.allocate(pairs * 8 * rows, 0);
        try temporary.append(a, numerator);
        const scan = try Prefix.Plan.init(self.item.log_size);
        const scratch = try ctx.allocate(scan.scratch_words + 8 * self.owner.claims.len + 1, 0);
        try temporary.append(a, scratch);
        const claim = scratch.words.? + scan.scratch_words;
        const status = claim + 8 * self.owner.claims.len;
        const verdict_zero = [_]u32{0};
        try ctx.upload(try (try ctx.borrow(scratch)).sub(scratch.count - 1, 1), &verdict_zero);
        try ctx.join();
        try checked(self.entry.launch(raw, 1, source.words.?, source.words.? + self.item.fixed.len * rows, parameter.words.?, numerator.words.?, self.owner.output.words.?, status, self.item.log_size));
        var group_offset: usize = 0;
        var pair_offset: usize = 0;
        for ([_]u32{ art.ram_pairs, art.other_pairs }, 0..) |count, group| {
            if (count == 0) continue;
            const job = Abi.GlobalPairs{ .output = self.owner.output.words.? + group_offset * rows, .contributions = numerator.words.? + pair_offset * 8 * rows, .scan_scratch = scratch.words.?, .claim = claim + group * 8, .status = status, .stride = rows, .scan_words = scan.scratch_words, .row_log = self.item.log_size, .pairs = count };
            try checked(b.pairs(raw, 1, &job));
            group_offset += 8 * (count + 1);
            pair_offset += count;
        }
        // Producer publishes only the tiny claims and verdict. No witness D2H.
        try ctx.join();
        try ctx.download(try (try ctx.borrow(scratch)).sub(scan.scratch_words, 8 * self.owner.claims.len), @as([*]u32, @ptrCast(self.owner.claims.ptr))[0 .. 8 * self.owner.claims.len]);
        var verdict: [1]u32 = undefined;
        try ctx.download(try (try ctx.borrow(scratch)).sub(scratch.count - 1, 1), &verdict);
        try ctx.join();
        if (verdict[0] != 0) return error.CudaGlobalWitnessRejected;
        for (self.owner.columns, 0..) |*column, i| column.* = .{ .log_size = self.item.log_size, .encoding = .evaluations, .device = .{ .words = self.owner.output.words.? + i * rows, .count = rows, .context_token = self.owner.output.context_token, .generation = self.owner.output.generation } };
    }
};
test "resident global witness callback is concrete" {
    std.testing.refAllDecls(Context);
}
