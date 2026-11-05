//! Native-GKR production numerical stage on the persistent PCS owner session.
//! Decodes actual committed coefficients once per invocation; every original
//! fraction stays implicit through ingress AND the final GKR gate. No raw N/D
//! planes or wide host witness are constructed. The v2 receiver replays all
//! transcript/security/closure checks before publishing a section.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const V = CPU.rv64_native_gkr_v2;
const Roster = @FieldType(CPU.rv64_native_gkr_roster.Plan, "roster");
const S = CPU.rv64_native_gkr_section;
const D = CPU.rv64_device_pcs;
const Code = @import("native_gkr_codegen.zig");
const P = Code.P;
const Native = @import("pcs_native_abi.zig");
const Service = @import("pcs_native.zig");
const SC = @import("session_context.zig");
const R = @import("resident.zig");
const G = @import("gkr.zig");
const Results = @import("gkr_result.zig");
const N = @import("runtime_api.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const O = core.fields.om31.OM31;
const Proof = engine.lookups.gkr_verifier.ForField(O).GkrBatchProof;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
pub const Descriptor = extern struct {
    fixed: [*]const u32,
    main: [*]const u32,
    parameters: [*]const u32,
    status: [*]u32,
    fixed_words: u64,
    main_words: u64,
    row_log: u32,
    kind: u32,
    reserved0: u32 = 0,
    reserved1: u32 = 0,
};
comptime {
    if (@sizeOf(Descriptor) != 64) @compileError("native GKR source ABI changed");
}
pub const Callbacks = struct {
    validate: @FieldType(R.ProjectedSource, "validate"),
    layer: @FieldType(R.ProjectedSource, "layer"),
    sum: @FieldType(R.ProjectedSource, "sum"),
    fold: @FieldType(R.ProjectedSource, "fold"),
    mask: @FieldType(R.ProjectedSource, "mask"),
    pub fn load(library: *std.DynLib, name: []const u8) !Callbacks {
        var out: Callbacks = undefined;
        inline for (std.meta.fields(Callbacks)) |field| {
            var buf: [256]u8 = undefined;
            const symbol = try std.fmt.bufPrintZ(&buf, "{s}_{s}", .{ name, field.name });
            @field(out, field.name) = library.lookup(field.type, symbol) orelse return error.MissingNativeGkrSourceSymbol;
        }
        return out;
    }
};
/// Source-owned artifact/callback association is resolved by the worker's fixed
/// class catalogue, never decoded from the proof or selected by its descriptor.
pub const Item = struct {
    artifact: *const Code.Artifact,
    callbacks: Callbacks,
    fixed: []const D.Column,
    main: []const D.Column,
    /// Semantic public/shared parameters. Fresh local elements overwrite their
    /// reserved slots on EACH bounded salt attempt, before program packing.
    parameters: *const [P.count]O,
};
pub const Request = struct { scope: S.Scope, roster: *const Roster, items: []const Item, byte_cap: usize };
pub const Context = struct {
    service: *Service.Context,
    api: SC.Api,
    numerical: N.Api,
    copy: Native.CopyDevice,
    n2b: N2b,
    twiddles: @import("gkr_twiddles.zig").Cache,
    /// Share the physical wide-stage gate with native composition/PCS.
    phase_mutex: ?*std.Thread.Mutex = null,
    pub fn init(service: *Service.Context, a: std.mem.Allocator) !Context {
        const library = &service.library;
        return .{ .service = service, .api = .{ .allocate = service.lease_allocate, .release = service.lease_release, .validate_range = service.lease_validate_range, .upload = try sym(Native.Upload, library, "stwo_exec_context_memcpy_h2d_async"), .download = try sym(Native.Download, library, "stwo_exec_context_memcpy_d2h_async"), .sync = try sym(Native.Sync, library, "stwo_exec_context_sync"), .lane_stream = try sym(Native.LaneStream, library, "stwo_exec_context_lane_stream") }, .numerical = try N.Api.load(library), .copy = try sym(Native.CopyDevice, library, "stwo_exec_context_memcpy_d2d_async"), .n2b = try sym(N2b, library, "stwo_ntt_n2b_columns_on"), .twiddles = .{ .allocator = a } };
    }
    pub fn deinit(self: *Context) void {
        self.twiddles.deinit();
        self.* = undefined;
    }
    pub fn prove(self: *Context, a: std.mem.Allocator, channel: *const S.RawChannel, request: Request) !S.Section {
        if (self.phase_mutex) |mutex| mutex.lock();
        defer if (self.phase_mutex) |mutex| mutex.unlock();
        try validate(request);
        return V.proveWith(a, channel, request.roster, &request.scope, Adapter{ .context = self, .request = request });
    }
    /// Bounded numerical entry point used by source lowering qualification.
    /// This returns an untrusted proof; only V2.proveWith/verify accepts a section.
    pub fn numericalProof(self: *Context, a: std.mem.Allocator, request: Request, elements: V.LocalElements, seed: S.RawChannel) !Proof {
        try validate(request);
        return (Adapter{ .context = self, .request = request }).prove(a, request.roster, elements, seed);
    }
    const Adapter = struct {
        context: *Context,
        request: Request,
        pub fn prove(self: @This(), a: std.mem.Allocator, roster: *const Roster, elements: V.LocalElements, seed: S.RawChannel) !Proof {
            if (roster != self.request.roster) return error.NativeGkrSourceRoster;
            var job = Job{ .backend = self.context, .a = a, .request = self.request, .elements = elements, .seed = seed };
            const status = self.context.service.submit(self.context.service.session, Job.run, &job);
            if (job.failure) |failure| return failure;
            try check(status);
            return job.proof orelse error.NativeGkrTraversalIncomplete;
        }
    };
};
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingNativeGkrStageSymbol;
}
fn check(status: c_int) !void {
    if (status != 0) return error.NativeGkrDeviceFailed;
}
pub fn validate(request: Request) !void {
    try V.validate(request.roster);
    if (request.items.len != request.roster.components.len or request.scope.ordinal >= 256) return error.NativeGkrSourceRoster;
    for (request.items, request.roster.components) |item, component| {
        const shape = try Code.Authority.shape(item.artifact.descriptor);
        if (item.artifact.mode != .fractions or !std.mem.eql(u32, &item.artifact.terms, &component.terms) or
            !std.mem.eql(u32, &Code.Source.Frame.originWords(item.artifact.descriptor.origin), &component.origin) or
            item.fixed.len != shape.fixed or item.main.len != shape.main or component.row_log < 5 or component.row_log > 23) return error.NativeGkrSourceRoster;
        const rows = @as(usize, 1) << @intCast(component.row_log);
        for (item.fixed) |column| if (column.log_size != component.row_log or (column.device == null and column.coefficients.len != rows)) return error.NativeGkrSourceColumn;
        for (item.main) |column| if (column.log_size != component.row_log or (column.device == null and column.coefficients.len != rows)) return error.NativeGkrSourceColumn;
        for (item.parameters) |value| for (value.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.NoncanonicalNativeGkrParameter;
    }
}
/// Pure device payload census for the global admission planner. Retained PCS
/// coefficient owners and immutable cache entries are external live inputs;
/// `transient_bytes` is the additional simultaneous allocation of this stage.
pub const Cost = struct {
    workspace_bytes: usize,
    decoded_source_bytes: usize,
    twiddle_bytes: usize,
    metadata_bytes: usize,
    transient_bytes: usize,
};
pub fn cost(request: Request) !Cost {
    try validate(request);
    var variables: [V.MAX_INSTANCES]u32 = undefined;
    for (request.roster.instances, variables[0..request.roster.instances.len]) |instance, *v| v.* = instance.variables();
    const plan = try G.Plan.init(variables[0..request.roster.instances.len], request.byte_cap);
    var metadata_words: usize = 10;
    var values_words: usize = 0;
    var max_log: u32 = 0;
    for (request.items, request.roster.components) |item, component| {
        max_log = @max(max_log, component.row_log);
        values_words = try std.math.add(usize, values_words, try std.math.mul(usize, item.fixed.len + item.main.len, @as(usize, 1) << @intCast(component.row_log)));
        metadata_words = try std.math.add(usize, metadata_words, try std.math.mul(usize, 8, item.artifact.parameter_slots.len));
    }
    const twiddle_words = @as(usize, 1) << @intCast(max_log - 1);
    const total_words = try std.math.add(usize, plan.total_words, try std.math.add(usize, values_words, try std.math.add(usize, metadata_words, twiddle_words)));
    const total_bytes = try std.math.mul(usize, total_words, 4);
    if (total_bytes > request.byte_cap) return error.NativeGkrWorkspaceBudget;
    return .{ .workspace_bytes = plan.total_words * 4, .decoded_source_bytes = values_words * 4, .twiddle_bytes = twiddle_words * 4, .metadata_bytes = metadata_words * 4, .transient_bytes = total_bytes };
}
const Job = struct {
    backend: *Context,
    a: std.mem.Allocator,
    request: Request,
    elements: V.LocalElements,
    seed: S.RawChannel,
    failure: ?anyerror = null,
    proof: ?Proof = null,
    fn run(raw: *anyopaque, token: u64, user: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(user orelse return 1));
        self.execute(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn execute(self: *Job, raw: *anyopaque, token: u64) !void {
        const a = self.a;
        const b = self.backend;
        const request = self.request;
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(request.scope), .api = &b.api };
        defer ctx.active = false;
        var leases: std.ArrayList(Native.Lease) = .empty;
        defer {
            ctx.join() catch {};
            for (leases.items) |*lease| ctx.release(lease) catch {};
            leases.deinit(a);
        }
        const count = request.roster.instances.len;
        const variables = try a.alloc(u32, count);
        defer a.free(variables);
        for (variables, request.roster.instances) |*v, instance| v.* = instance.variables();
        const cap = @min(request.byte_cap, b.service.byte_cap);
        const plan = try G.Plan.init(variables, cap);
        var bounded = request;
        bounded.byte_cap = cap;
        const estimate = try cost(bounded);
        const values_words = estimate.decoded_source_bytes / 4;
        const tw_words = estimate.twiddle_bytes / 4;
        var max_log: u32 = 0;
        for (request.roster.components) |component| max_log = @max(max_log, component.row_log);
        const values = try allocate(a, &ctx, &leases, values_words);
        const tw = try allocate(a, &ctx, &leases, tw_words);
        const status = try upload(a, &ctx, &leases, &.{0});
        var seed_words: [9]u32 = undefined;
        for (seed_words[0..8], 0..) |*word, i| word.* = std.mem.readInt(u32, self.seed.inner.digest[4 * i ..][0..4], .little);
        seed_words[8] = self.seed.inner.n_draws;
        const seed = try upload(a, &ctx, &leases, &seed_words);
        var twiddles = try b.twiddles.acquire(max_log);
        defer twiddles.deinit();
        try ctx.upload(tw, @as([*]const u32, @ptrCast(twiddles.values.ptr))[0..twiddles.values.len]);
        const packets = try a.alloc(Descriptor, count);
        defer a.free(packets);
        const fractions = try a.alloc(R.Fraction, count);
        defer a.free(fractions);
        const borrowed = try a.alloc([5]Slice, count);
        defer a.free(borrowed);
        const fixed_values = try a.alloc(Slice, request.items.len);
        defer a.free(fixed_values);
        const main_values = try a.alloc(Slice, request.items.len);
        defer a.free(main_values);
        const params = try a.alloc(Slice, request.items.len);
        defer a.free(params);
        var offset: usize = 0;
        for (request.items, request.roster.components, fixed_values, main_values, params) |item, component, *fixed, *main, *parameters| {
            const rows = @as(usize, 1) << @intCast(component.row_log);
            fixed.* = try values.sub(offset, item.fixed.len * rows);
            offset += fixed.len;
            main.* = try values.sub(offset, item.main.len * rows);
            offset += main.len;
            try copyColumns(b, &ctx, fixed.*, item.fixed);
            try copyColumns(b, &ctx, main.*, item.main);
            var semantic = item.parameters.*;
            for (self.elements.z, self.elements.alpha, 0..) |z, alpha, i| {
                semantic[P.local + 2 * i] = z;
                semantic[P.local + 2 * i + 1] = alpha;
            }
            const packed_parameters = try a.alloc(O, item.artifact.parameter_slots.len);
            defer a.free(packed_parameters);
            for (packed_parameters, item.artifact.parameter_slots) |*value, slot| value.* = semantic[slot];
            parameters.* = try upload(a, &ctx, &leases, @as([*]const u32, @ptrCast(packed_parameters.ptr))[0 .. packed_parameters.len * 8]);
            // Upload API enqueues from borrowed host memory; join before freeing.
            try ctx.join();
        }
        var stream: ?*anyopaque = null;
        try check(b.api.lane_stream(raw, 1, &stream));
        const assigned = stream orelse return error.InvalidLane;
        for (request.items, request.roster.components, fixed_values, main_values) |item, component, fixed, main| {
            const tw_count = @as(u32, 1) << @intCast(component.row_log - 1);
            var launches: u32 = 0;
            for ([2]Slice{ fixed, main }, [2]usize{ item.fixed.len, item.main.len }) |slab, width| {
                try check(b.n2b(@ptrFromInt(slab.address), @as(usize, 1) << @intCast(component.row_log), component.row_log, @intCast(width), @ptrFromInt(tw.address + 4 * (tw_words - tw_count)), tw_count, tw_count, assigned, &launches));
            }
        }
        for (request.roster.instances, packets, fractions, borrowed) |instance, *packet, *fraction, *reads| {
            const component = instance.component;
            const item = request.items[component];
            const fixed = fixed_values[component];
            const main = main_values[component];
            const parameters = params[component];
            packet.* = .{ .fixed = @ptrFromInt(fixed.address), .main = @ptrFromInt(main.address), .parameters = @ptrFromInt(parameters.address), .status = @ptrFromInt(status.address), .fixed_words = fixed.len, .main_words = main.len, .row_log = instance.row_log, .kind = @intFromEnum(instance.kind) };
            reads.* = .{ fixed, main, parameters, status, tw };
            fraction.* = .{ .count = @intCast(instance.facts()), .projected = .{ .descriptor = packet, .borrowed = reads, .validate = item.callbacks.validate, .layer = item.callbacks.layer, .sum = item.callbacks.sum, .fold = item.callbacks.fold, .mask = item.callbacks.mask } };
        }
        try ctx.join();
        const workspace = try allocate(a, &ctx, &leases, plan.total_words);
        var commands = R.Commands(SC.Context, N.Api){ .context = &ctx, .api = &b.numerical, .lane_index = 1 };
        const traversal = try G.enqueue(&commands, fractions, seed, workspace, cap, 0x4e47563200000000);
        try ctx.join();
        var header_words: [20]u32 = undefined;
        var verdict: [1]u32 = undefined;
        try ctx.download(try traversal.state.sub(0, 20), &header_words);
        try ctx.download(status, &verdict);
        const roots = try a.alloc(u32, 16 * count);
        defer a.free(roots);
        try ctx.download(traversal.roots, roots);
        const layers = try a.alloc(Results.Layer, traversal.layers);
        defer a.free(layers);
        var made: usize = 0;
        defer for (layers[0..made]) |layer| {
            a.free(layer.records);
            a.free(layer.masks);
        };
        for (layers, traversal.proof[0..traversal.layers]) |*layer, device| {
            const records = try a.alloc(u32, device.records.len);
            errdefer a.free(records);
            const masks = try a.alloc(u32, device.masks.len);
            layer.* = .{ .records = records, .masks = masks };
            made += 1;
            if (records.len != 0) try ctx.download(device.records, records);
            try ctx.download(device.masks, masks);
        }
        try ctx.join();
        try (@as(G.Header, @bitCast(header_words))).validate(traversal);
        if (verdict[0] & ~@as(u32, 4) != 0) return error.NativeGkrSourceRejected;
        if (verdict[0] != 0) return error.NativeGkrSourcePole;
        self.proof = try Results.assemble(a, .{ .variables = variables, .roots = roots, .layers = layers });
        std.debug.print("GPU_NATIVE_GKR ordinal={} instances={} facts={} decoded_bytes={} raw_fraction_bytes=0 workspace_bytes={} launches={}\n", .{ request.scope.ordinal, count, request.roster.gkrFacts(), values_words * 4, plan.total_words * 4, commands.launches });
    }
};
fn allocate(a: std.mem.Allocator, ctx: *SC.Context, leases: *std.ArrayList(Native.Lease), words: usize) !Slice {
    var lease = try ctx.allocate(words, 0);
    errdefer ctx.release(&lease) catch {};
    try leases.append(a, lease);
    return ctx.borrow(lease);
}
fn upload(a: std.mem.Allocator, ctx: *SC.Context, leases: *std.ArrayList(Native.Lease), words: []const u32) !Slice {
    const output = try allocate(a, ctx, leases, words.len);
    try ctx.upload(output, words);
    return output;
}
fn copyColumns(b: *Context, ctx: *SC.Context, target: Slice, columns: []const D.Column) !void {
    var offset: usize = 0;
    for (columns) |column| {
        const rows = @as(usize, 1) << @intCast(column.log_size);
        const to = try target.sub(offset, rows);
        if (column.device) |device| {
            if (device.count != rows) return error.NativeGkrSourceColumn;
            const source = Slice{ .address = @intFromPtr(device.words), .len = rows, .owner = @intCast(device.context_token), .generation = device.generation };
            const from = try ctx.deviceSlicePointer(u32, source, rows);
            try check(b.copy(ctx.native_context, @ptrFromInt(to.address), from, rows * 4));
        } else try ctx.upload(to, @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..rows]);
        offset += rows;
    }
}
test "native GKR owner callback remains fully typed" {
    var instantiate: bool = false;
    std.mem.doNotOptimizeAway(&instantiate);
    if (instantiate) {
        var context: Context = undefined;
        var channel: S.RawChannel = undefined;
        var section = try context.prove(std.testing.allocator, &channel, undefined);
        section.deinit(std.testing.allocator);
    }
}
