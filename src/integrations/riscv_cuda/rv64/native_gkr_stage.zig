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
/// Exact logical allocation schedule for Footprint.allocations in the shared
/// static-arena planner. The planner owns slab/chunk rounding and all external
/// retained inputs. The caller frees this small host list.
pub fn allocationBytes(a: std.mem.Allocator, request: Request) ![]usize {
    const estimate = try cost(request);
    const sizes = try a.alloc(usize, 5 + request.items.len);
    sizes[0..4].* = .{ estimate.decoded_source_bytes, estimate.twiddle_bytes, 4, 36 };
    for (request.items, sizes[4..][0..request.items.len]) |item, *size| size.* = try std.math.mul(usize, 32, item.artifact.parameter_slots.len);
    sizes[sizes.len - 1] = estimate.workspace_bytes;
    return sizes;
}
/// DIAGNOSTIC ONLY: incomplete host allocation/lifetime sketch. The slack
/// allowance is not a proven bound. Never set runtime host_known from this
/// estimate until the exact allocator/phase audit is completed.
pub const HostCost = struct {
    known: bool = false,
    twiddle_new_bytes: usize,
    readback_bytes: usize,
    proof_bytes_upper: usize,
    metadata_bytes: usize,
    stack_allocator_verifier_slack_bytes: usize,
    additional_peak_bytes: usize,
};
pub fn hostCost(request: Request) !HostCost {
    const device = try cost(request);
    const n = request.roster.instances.len;
    const items = request.items.len;
    const layers: usize = request.roster.layers();
    var variable_sum: usize = 0;
    var max_parameters: usize = 0;
    var readback_words: usize = try std.math.mul(usize, 16, n);
    for (request.roster.instances) |instance| variable_sum = try std.math.add(usize, variable_sum, instance.variables());
    for (request.items) |item| max_parameters = @max(max_parameters, item.artifact.parameter_slots.len);
    const rounds = try std.math.mul(usize, layers, layers - 1) / 2;
    readback_words = try std.math.add(usize, readback_words, try std.math.mul(usize, 44, rounds));
    readback_words = try std.math.add(usize, readback_words, try std.math.mul(usize, 32, variable_sum));
    const readback = try std.math.mul(usize, 4, readback_words);
    // The canonical wire already contains the full four-coefficient bound and
    // all mask/root values. 2x additionally covers their native slice headers.
    const proof = try std.math.mul(usize, 8, S.wordCount(request.roster));
    var metadata = try std.math.mul(usize, n, 4 + @sizeOf(Descriptor) + @sizeOf(R.Fraction) + @sizeOf([5]Slice));
    metadata = try std.math.add(usize, metadata, try std.math.mul(usize, items, 3 * @sizeOf(Slice)));
    metadata = try std.math.add(usize, metadata, try std.math.mul(usize, layers, @sizeOf(Results.Layer)));
    metadata = try std.math.add(usize, metadata, try std.math.mul(usize, max_parameters, @sizeOf(O)));
    const lease_capacity = try std.math.add(usize, try std.math.mul(usize, 3, 5 + items), 8);
    metadata = try std.math.add(usize, metadata, try std.math.mul(usize, lease_capacity, @sizeOf(Native.Lease)));
    // One KiB per possible proof/replay allocation is deliberately above the
    // logical payload; source-bounded verifier vectors add no row-sized data.
    const allocation_count = try std.math.add(usize, 128 + try std.math.mul(usize, 4, items), try std.math.mul(usize, 2, try std.math.add(usize, variable_sum, rounds)));
    var slack = try std.math.mul(usize, allocation_count, 1024);
    slack = try std.math.add(usize, slack, 8 * @sizeOf(G.Plan) + 4 * P.count * @sizeOf(O) + (2 << 20));
    const twiddles = try std.math.mul(usize, 2, device.twiddle_bytes);
    var total = try std.math.add(usize, twiddles, readback);
    total = try std.math.add(usize, total, proof);
    total = try std.math.add(usize, total, metadata);
    total = try std.math.add(usize, total, slack);
    return .{ .twiddle_new_bytes = twiddles, .readback_bytes = readback, .proof_bytes_upper = proof, .metadata_bytes = metadata, .stack_allocator_verifier_slack_bytes = slack, .additional_peak_bytes = total };
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

test "native GKR exact allocation census matches the qualified six-lease fixture" {
    const a = std.testing.allocator;
    var artifact = try Code.record(a, .{ .origin = .{ .bridge = .keccak } }, .fractions);
    defer artifact.deinit();
    const Spec = std.meta.Child(@FieldType(Roster, "components"));
    var roster = try V.derive(a, &[_]Spec{.{ .origin = Code.Source.Frame.originWords(artifact.descriptor.origin), .row_log = 5, .terms = artifact.terms }});
    defer roster.deinit();
    const shape = try Code.Authority.shape(artifact.descriptor);
    const coefficients: [32]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
    const fixed = try a.alloc(D.Column, shape.fixed);
    defer a.free(fixed);
    const main = try a.alloc(D.Column, shape.main);
    defer a.free(main);
    for (fixed) |*column| column.* = .{ .log_size = 5, .coefficients = &coefficients };
    for (main) |*column| column.* = .{ .log_size = 5, .coefficients = &coefficients };
    const parameters: [P.count]O = @splat(O.zero());
    const request = Request{ .scope = .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .shared = @splat(4), .ordinal = 0 }, .roster = &roster, .byte_cap = 512 << 20, .items = &.{.{ .artifact = &artifact, .callbacks = undefined, .fixed = fixed, .main = main, .parameters = &parameters }} };
    const sizes = try allocationBytes(a, request);
    defer a.free(sizes);
    try std.testing.expectEqual(@as(usize, 6), sizes.len);
    try std.testing.expectEqual(@as(usize, 9216), sizes[0]);
    try std.testing.expectEqual(@as(usize, 64), sizes[1]);
    try std.testing.expectEqual(@as(usize, 188288), sizes[sizes.len - 1]);
    var total: usize = 0;
    for (sizes) |size| total += size;
    try std.testing.expectEqual((try cost(request)).transient_bytes, total);
    const host = try hostCost(request);
    try std.testing.expectEqual((try cost(request)).twiddle_bytes * 2, host.twiddle_new_bytes);
    try std.testing.expect(host.additional_peak_bytes >= host.twiddle_new_bytes + host.readback_bytes + host.proof_bytes_upper + host.metadata_bytes);
    try std.testing.expect(host.additional_peak_bytes < 16 << 20);
    var bounded = request;
    bounded.byte_cap = total - 1;
    try std.testing.expectError(error.NativeGkrWorkspaceBudget, cost(bounded));
}
