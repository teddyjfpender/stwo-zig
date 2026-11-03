//! Production-worker GKR numerical adapter on the caller's persistent session.
//! Physical MAIN is reconstructed from the actual committed coefficients. Raw
//! fractions, relation draws and traversal stay on device. Native services still
//! owns terminal binding and final acceptance; this is not that admission gate.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Child = @import("stwo_riscv_cpu_integration").rv64_gkr_child;
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const R = @import("resident.zig");
const G = @import("gkr.zig");
const Results = @import("gkr_result.zig");
const Sources = @import("gkr_sources.zig");
const Source = @import("projection_codegen.zig").Source;
const N = @import("runtime_api.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const O = core.fields.om31.OM31;
const Proof = engine.lookups.gkr_verifier.ForField(O).GkrBatchProof;
const Projection = extern struct {
    fixed: [*]const u32,
    main: [*]const u32,
    public_values: [*]const u32,
    offsets: [*]const u64,
    parameters: [*]const u32,
    n: [*]u32,
    d: [*]u32,
    status: [*]u32,
    log: u32,
    first: u32,
    rows: u32,
};
const Launch = *const fn (*anyopaque, *const Projection) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const Gather = *const fn (*anyopaque, u32, [*]const u32, [*]u32, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;
const Functions = struct {
    submit: Native.Submit,
    copy_device: Native.CopyDevice,
    n2b: N2b,
    gather: Gather,
    channel_init: *const @TypeOf(@import("abi.zig").stwo_rv64_channel_init_on),
    channel_mix: *const @TypeOf(@import("abi.zig").stwo_rv64_channel_mix_on),
    channel_draw: *const @TypeOf(@import("abi.zig").stwo_rv64_channel_draw_on),
    launch: [@import("projection_fixture_support.zig").count]Launch,
};
fn symbol(comptime T: type, library: *std.DynLib, name: [:0]const u8) !T {
    return library.lookup(T, name) orelse return error.MissingCudaGkrSymbol;
}
fn checked(status: c_int) !void {
    if (status != 0) return error.CudaGkrStageFailed;
}
pub const CoefficientSink = struct {
    context: *anyopaque,
    /// Owner-thread publication. Success adopts the lease and copies only
    /// metadata; failure must leave lease ownership with the caller.
    publish: *const fn (*anyopaque, [8]u32, Native.Lease, []const @import("stwo_riscv_cpu_integration").rv64_device_pcs.Column, []const @import("stwo_riscv_cpu_integration").rv64_device_pcs.Column, []const usize) anyerror!void,
};
pub const Backend = struct {
    coefficient_sink: ?CoefficientSink = null,
    allocator: std.mem.Allocator,
    session: *anyopaque,
    session_api: SC.Api,
    numerical: N.Api,
    functions: Functions,
    catalogue: Sources.Catalogue,
    byte_cap: usize,
    pub fn init(a: std.mem.Allocator, library: *std.DynLib, session: *anyopaque, byte_cap: usize) !Backend {
        var catalogue = try Sources.Catalogue.init(a);
        errdefer catalogue.deinit();
        var functions = Functions{
            .submit = try symbol(Native.Submit, library, "stwo_rv64_gpu_session_submit"),
            .copy_device = try symbol(Native.CopyDevice, library, "stwo_exec_context_memcpy_d2d_async"),
            .n2b = try symbol(N2b, library, "stwo_ntt_n2b_columns_on"),
            .gather = try symbol(Gather, library, "stwo_rv64_parameter_gather_on"),
            .channel_init = try symbol(*const @TypeOf(@import("abi.zig").stwo_rv64_channel_init_on), library, "stwo_rv64_channel_init_on"),
            .channel_mix = try symbol(*const @TypeOf(@import("abi.zig").stwo_rv64_channel_mix_on), library, "stwo_rv64_channel_mix_on"),
            .channel_draw = try symbol(*const @TypeOf(@import("abi.zig").stwo_rv64_channel_draw_on), library, "stwo_rv64_channel_draw_on"),
            .launch = undefined,
        };
        for (&functions.launch, 0..) |*launch, i| {
            var name: [32]u8 = undefined;
            const text = try std.fmt.bufPrintZ(&name, "launch_{}", .{i});
            launch.* = try symbol(Launch, library, text);
        }
        return .{ .allocator = a, .session = session, .session_api = .{
            .allocate = try symbol(Native.LeaseAllocate, library, "stwo_rv64_gpu_lease_allocate"),
            .release = try symbol(Native.LeaseRelease, library, "stwo_rv64_gpu_lease_release"),
            .validate_range = try symbol(Native.LeaseValidateRange, library, "stwo_rv64_gpu_lease_validate_range"),
            .upload = try symbol(Native.Upload, library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try symbol(Native.Download, library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try symbol(Native.Sync, library, "stwo_exec_context_sync"),
            .lane_stream = try symbol(Native.LaneStream, library, "stwo_exec_context_lane_stream"),
        }, .numerical = try N.Api.load(library), .functions = functions, .catalogue = catalogue, .byte_cap = byte_cap };
    }
    pub fn deinit(self: *Backend) void {
        self.catalogue.deinit();
        self.* = undefined;
    }
    pub fn stage(self: *Backend) Child.NumericalStage {
        return .{ .context = self, .prove = prove };
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) !Proof {
        const self: *Backend = @ptrCast(@alignCast(raw));
        var job = Job{ .backend = self, .allocator = a, .request = request };
        const status = self.functions.submit(self.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try checked(status);
        return job.proof orelse error.CudaGkrStageFailed;
    }
};
const Job = struct {
    backend: *Backend,
    allocator: std.mem.Allocator,
    request: Child.NumericalStage.Request,
    proof: ?Proof = null,
    failure: ?anyerror = null,
    fn callback(raw_context: *anyopaque, token: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(raw orelse return 1));
        self.execute(raw_context, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn execute(self: *Job, raw_context: *anyopaque, token: u64) !void {
        const a = self.allocator;
        const b = self.backend;
        var context = SC.Context{ .session = b.session, .native_context = raw_context, .token = token, .scope = @import("pcs_scope.zig").identity(self.request.scope), .api = &b.session_api };
        defer context.active = false;
        var source = try Sources.Plan.init(a, self.request, &b.catalogue);
        defer source.deinit();
        const variables = try a.alloc(u32, source.items.len);
        defer a.free(variables);
        var input_words: usize = 0;
        for (source.items, variables) |item, *v| {
            v.* = item.log + std.math.log2_int(u32, item.lanes);
            input_words = try std.math.add(usize, input_words, @as(usize, item.facts) * 9);
        }
        const native_source = self.request.native_source orelse return error.NativeGkrSourceRequired;
        if (self.request.instances[0].origin != .core or self.request.instances[0].origin.core != .cpu) return error.InvalidGkrSourceColumn;
        const v3 = native_source.core.cpu.u8_pairs;
        if (source.items[0].terms != Source.Fractions.cpuTerms(v3)) return error.InvalidGkrSourceColumn;
        const relations = comptime std.enums.values(Source.Fractions.Relation);
        const relation_count: u32 = if (v3) @intCast(relations.len) else @intFromEnum(Source.Fractions.Relation.byte_pair);
        const cap = @min(b.byte_cap, self.request.byte_cap);
        const plan = try G.Plan.init(variables, cap);
        const twiddle_words = @as(usize, 1) << @intCast(source.max_log - 1);
        var metadata_words: usize = 9 + 16 + 16 + 310 * 8 + 1 + 3 + 2 * @as(usize, relation_count);
        for (source.items) |item| {
            const parameter_words = try std.math.mul(usize, b.catalogue.artifacts[item.kernel].source_slots.len, 8);
            const item_words = try std.math.add(usize, try std.math.mul(usize, item.offsets.len, 2), try std.math.add(usize, item.public.len, parameter_words));
            metadata_words = try std.math.add(usize, metadata_words, item_words);
        }
        const requested = try std.math.add(usize, metadata_words, try std.math.add(usize, plan.total_words, try std.math.add(usize, input_words, try std.math.add(usize, source.cells * 2, twiddle_words))));
        if (try std.math.mul(usize, requested, 4) > cap) return error.GkrWorkspaceBudgetExceeded;
        var leases: std.ArrayList(Native.Lease) = .empty;
        var published_generation: u64 = 0;
        defer {
            for (leases.items) |*lease| if (lease.generation != published_generation) {
                context.release(lease) catch {};
            };
            leases.deinit(a);
        }
        const coeff = try allocateKind(a, &context, &leases, source.cells, 2);
        const coefficient_lease = leases.items[0];
        const values = try allocate(a, &context, &leases, source.cells);
        const tw = try allocate(a, &context, &leases, twiddle_words);
        var offset: usize = 0;
        for (source.columns) |column| {
            try context.upload(try coeff.sub(offset, column.coefficients.len), @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..column.coefficients.len]);
            offset += column.coefficients.len;
        }
        var twiddles = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(source.max_log).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &twiddles);
        try context.upload(tw, @as([*]const u32, @ptrCast(twiddles.twiddles.ptr))[0..twiddles.twiddles.len]);
        try context.join();
        try checked(b.functions.copy_device(raw_context, @ptrFromInt(values.address), @ptrFromInt(coeff.address), source.cells * 4));
        try context.join();
        var stream: ?*anyopaque = null;
        try checked(b.session_api.lane_stream(raw_context, 1, &stream));
        const assigned_stream = stream orelse return error.InvalidLane;
        for (source.groups) |group| {
            var launches: u32 = 0;
            const count = @as(u32, 1) << @intCast(group.log - 1);
            try checked(b.functions.n2b(@ptrFromInt(values.address + 4 * group.offset), @as(usize, 1) << @intCast(group.log), group.log, group.count, @ptrFromInt(tw.address + 4 * (twiddle_words - count)), count, count, assigned_stream, &launches));
        }
        const seed = try allocate(a, &context, &leases, 9);
        var seed_words: [9]u32 = undefined;
        for (seed_words[0..8], 0..) |*word, i| word.* = std.mem.readInt(u32, self.request.source_channel.inner.digest[4 * i ..][0..4], .little);
        seed_words[8] = self.request.source_channel.inner.n_draws;
        try context.upload(seed, &seed_words);
        const channel = try allocate(a, &context, &leases, 16);
        const boundary = try allocate(a, &context, &leases, 16);
        const reservoir = try allocate(a, &context, &leases, 310 * 8);
        const status = try allocate(a, &context, &leases, 1);
        try context.upload(status, &.{0});
        const zeros: [310 * 8]u32 = @splat(0);
        try context.upload(reservoir, &zeros);
        var metadata: [3 + 2 * relations.len]u32 = undefined;
        metadata[0..3].* = .{ if (v3) 0x4c474b33 else 0x4c474b31, 8, relation_count };
        for (relations[0..relation_count], 0..) |relation, i| {
            metadata[3 + 2 * i] = @intCast(i);
            metadata[4 + 2 * i] = @intCast(relation.arity());
        }
        const constants = try upload(a, &context, &leases, metadata[0 .. 3 + 2 * relation_count]);
        try context.join();
        var step: u32 = 0;
        var chain: u64 = 0x47524b5300000000;
        try checked(b.functions.channel_init(raw_context, 1, @ptrFromInt(channel.address), @ptrFromInt(seed.address), chain));
        try checked(b.functions.channel_mix(raw_context, 1, @ptrFromInt(channel.address), step, chain, chain + 1, @ptrFromInt(constants.address), 3, 0, @ptrFromInt(boundary.address)));
        step += 1;
        chain += 1;
        for (relations[0..relation_count], 0..) |relation, i| {
            try checked(b.functions.channel_mix(raw_context, 1, @ptrFromInt(channel.address), step, chain, chain + 1, @ptrFromInt(constants.address + 4 * (3 + 2 * i)), 2, 0, @ptrFromInt(boundary.address)));
            step += 1;
            chain += 1;
            const draws: u32 = 1 + if (relation == .range8) @as(u32, 0) else @as(u32, @intCast(relation.arity()));
            try checked(b.functions.channel_draw(raw_context, 1, @ptrFromInt(channel.address), step, chain, chain + 1, draws, @ptrFromInt(reservoir.address + 4 * i * 31 * 8), @ptrFromInt(boundary.address)));
            step += 1;
            chain += 1;
        }
        const fractions = try a.alloc(R.Fraction, source.items.len);
        defer a.free(fractions);
        const packets = try a.alloc(Projection, source.items.len);
        defer a.free(packets);
        for (source.items, fractions, packets) |item, *fraction, *packet| {
            const artifact = &b.catalogue.artifacts[item.kernel];
            const offsets = try upload(a, &context, &leases, @as([*]const u32, @ptrCast(item.offsets.ptr))[0 .. item.offsets.len * 2]);
            const public = try upload(a, &context, &leases, &item.public);
            const parameters = try allocate(a, &context, &leases, artifact.source_slots.len * 8);
            const numerator = try allocate(a, &context, &leases, item.facts);
            const denominator = try allocate(a, &context, &leases, @as(usize, item.facts) * 8);
            packet.* = .{ .fixed = @ptrFromInt(values.address), .main = @ptrFromInt(values.address), .public_values = @ptrFromInt(public.address), .offsets = @ptrFromInt(offsets.address), .parameters = @ptrFromInt(parameters.address), .n = @ptrFromInt(numerator.address), .d = @ptrFromInt(denominator.address), .status = @ptrFromInt(status.address), .log = item.log, .first = 0, .rows = @as(u32, 1) << @intCast(item.log) };
            fraction.* = .{ .n = .{ .data = numerator, .stride = item.facts, .coordinates = 1 }, .d = .{ .data = denominator, .stride = item.facts, .coordinates = 8 }, .count = item.facts };
        }
        const workspace = try allocate(a, &context, &leases, plan.total_words);
        try context.join();
        for (source.items, packets) |item, *packet| {
            const artifact = &b.catalogue.artifacts[item.kernel];
            try checked(b.functions.gather(raw_context, 1, @ptrFromInt(reservoir.address), @constCast(packet.parameters), artifact.source_slots.ptr, @intCast(artifact.source_slots.len), relation_count, @ptrFromInt(status.address)));
            try checked(b.functions.launch[item.kernel](assigned_stream, packet));
        }
        var commands = R.Commands(SC.Context, N.Api){ .context = &context, .api = &b.numerical, .lane_index = 1 };
        const traversal = try G.enqueueWithClosure(&commands, fractions, try channel.sub(0, 9), workspace, cap, chain, status);
        try context.join();
        var verdict: [1]u32 = undefined;
        var header_words: [20]u32 = undefined;
        var channel_words: [16]u32 = undefined;
        try context.download(status, &verdict);
        try context.download(try traversal.traversal.state.sub(0, 20), &header_words);
        try context.download(channel, &channel_words);
        const roots = try a.alloc(u32, source.items.len * 16);
        defer a.free(roots);
        try context.download(traversal.traversal.roots, roots);
        const layers = try a.alloc(Results.Layer, traversal.traversal.layers);
        defer a.free(layers);
        var made: usize = 0;
        defer for (layers[0..made]) |layer| {
            a.free(layer.records);
            a.free(layer.masks);
        };
        for (layers, traversal.traversal.proof[0..traversal.traversal.layers]) |*layer, device| {
            const records = try a.alloc(u32, device.records.len);
            const masks = a.alloc(u32, device.masks.len) catch |err| {
                a.free(records);
                return err;
            };
            layer.* = .{ .records = records, .masks = masks };
            made += 1;
            if (records.len != 0) try context.download(device.records, records);
            try context.download(device.masks, masks);
        }
        try context.join();
        const header: G.Header = @bitCast(header_words);
        try traversal.validate(header, verdict[0]);
        const snapshot: @import("channel.zig").Snapshot = @bitCast(channel_words);
        try snapshot.validate(step, chain);
        for (snapshot.digest, 0..) |word, i| if (word != std.mem.readInt(u32, self.request.channel.inner.digest[4 * i ..][0..4], .little)) return error.InvalidDeviceTranscript;
        if (snapshot.draws != self.request.channel.inner.n_draws) return error.InvalidDeviceTranscript;
        var proof = try Results.assemble(a, .{ .variables = variables, .roots = roots, .layers = layers });
        errdefer proof.deinit(a);
        if (b.coefficient_sink) |sink| {
            try sink.publish(sink.context, context.scope, coefficient_lease, self.request.native_fixed_columns, self.request.native_main_columns, source.offsets);
            published_generation = coefficient_lease.generation;
        }
        self.proof = proof;
    }
};
fn allocate(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: usize) !Slice {
    return allocateKind(a, context, leases, words, 0);
}
fn allocateKind(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: usize, kind: u32) !Slice {
    var lease = try context.allocate(words, kind);
    errdefer context.release(&lease) catch {};
    try leases.append(a, lease);
    return context.borrow(lease);
}
fn upload(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: []const u32) !Slice {
    const out = try allocate(a, context, leases, words.len);
    try context.upload(out, words);
    return out;
}

test "resident GKR worker callback is fully typed without a CUDA link" {
    _ = &Backend.init;
    _ = &Backend.stage;
}
