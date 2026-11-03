//! Concrete resident native-OM31 circuit factory. Production binds the original
//! trace-only graph and compact proof/public seeds atomically. The legacy
//! assignment ingress remains explicit. MAIN, lookup histograms, O8 INTER,
//! composition and PCS stay in one scoped session; no host-wide fallback.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const Dev = Outer.device_prove;
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Service = @import("pcs_native.zig");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const RC = @import("resident_composition.zig");
const TC = @import("trace_commit.zig");
const Assignment = @import("outer_assignment.zig");
const Aot = @import("outer_aot.zig");
const Code = @import("composition_codegen.zig");
const Abi = @import("abi.zig");
const Base = @import("stwo_cuda_backend").abi.stages.circuit_base;
pub const BaseFn = *const @TypeOf(Base.stwo_circuit_base_witness_on);
pub const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
pub const Fractions = extern struct { fixed: ?[*]const u32, main: [*]const u32, parameters: [*]const u32, numerators: [*]u32, denominators: [*]u32, status: *u32, fixed_words: u64, main_words: u64, numerator_words: u64, denominator_words: u64, component: u32, row_log: u32, reserved: [2]u32 = .{ 0, 0 } };
pub const Cumulative = extern struct { output: [*]u32, contributions: [*]const u32, claim: [*]const u32, stride: u64, row_log: u32, pairs: u32 };
const FractionFn = *const fn (*anyopaque, u32, *const Fractions) callconv(.c) c_int;
const CumulativeFn = *const fn (*anyopaque, u32, *const Cumulative) callconv(.c) c_int;
const IdentityFn = *const fn (u32, [*]u8) callconv(.c) c_int;
pub fn checked(status: c_int) !void {
    if (status != 0) {
        std.debug.print("GPU_OUTER native_status={}\n", .{status});
        return error.CudaOuterStageFailed;
    }
}
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingOm31OuterKernel;
}
pub const Entry = struct { group: Aot.Group, metadata: RC.KernelMetadata };
pub const Context = struct {
    allocator: std.mem.Allocator,
    service: *Service.Context,
    trace_commit: *TC.Context,
    composition: *RC.Context,
    api: SC.Api,
    base: BaseFn,
    clear: Memset,
    copy: Native.CopyDevice,
    fractions: FractionFn,
    cumulative: CumulativeFn,
    global_pairs: *const @TypeOf(Abi.stwo_rv64_global_pairs_on),
    identity: IdentityFn,
    role: *const @TypeOf(Abi.stwo_rv64_composition_role_on),
    entries: std.ArrayList(Entry) = .empty,
    body_identity: ?[32]u8 = null,
    metadata_bytes: usize = 0,
    metadata_cap_bytes: usize = 4 << 20,
    active: ?*Owner = null,
    assignment: ?Assignment.Prepared = null,
    mutex: std.Thread.Mutex = .{},
    pub fn init(a: std.mem.Allocator, service: *Service.Context, trace_commit: *TC.Context, composition: *RC.Context) !Context {
        return .{ .allocator = a, .service = service, .trace_commit = trace_commit, .composition = composition, .api = .{ .allocate = service.lease_allocate, .release = service.lease_release, .validate_range = service.lease_validate_range, .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"), .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"), .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"), .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream") }, .base = try sym(BaseFn, &service.library, "stwo_circuit_base_witness_on"), .clear = try sym(Memset, &service.library, "stwo_exec_context_memset_async"), .copy = try sym(Native.CopyDevice, &service.library, "stwo_exec_context_memcpy_d2d_async"), .fractions = try sym(FractionFn, &service.library, "stwo_circuit_om31_fractions_on"), .cumulative = try sym(CumulativeFn, &service.library, "stwo_circuit_om31_cumulative_on"), .global_pairs = try sym(*const @TypeOf(Abi.stwo_rv64_global_pairs_on), &service.library, "stwo_rv64_global_pairs_on"), .identity = try sym(IdentityFn, &service.library, "stwo_circuit_om31_composition_identity"), .role = try sym(*const @TypeOf(Abi.stwo_rv64_composition_role_on), &service.library, "stwo_circuit_om31_composition_role_on") };
    }
    pub fn deinit(self: *Context) void {
        std.debug.assert(self.active == null);
        if (self.assignment) |*assignment| assignment.deinit();
        for (self.entries.items) |*e| e.metadata.deinit();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn factory(self: *Context) Dev.Factory {
        return .{ .context = self, .prepare = prepare, .prepare_from_circuit = prepareFromCircuit };
    }
    /// Fail before constructing a production verifier graph when the image
    /// lacks deterministic generation kernels. Legacy ingress stays explicit.
    pub fn factoryForTraceOnly(self: *Context) !Dev.Factory {
        try Assignment.requireProductionCapabilities(&self.service.library);
        return self.factory();
    }
    /// Explicit opt-in generation from this finalized original graph. The
    /// graph must outlive prove(); the legacy factory keeps its upload path.
    pub fn factoryForWitness(self: *Context, graph: *const circuit.builder.Context(Outer.protocol.Q)) !Dev.Factory {
        if (graph.trace_only) return error.TraceOnlyGraphRequiresAtomicIngress;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.active != null) return error.OuterProofAlreadyActive;
        var prepared = try Assignment.Prepared.init(self.allocator, graph, &self.service.library);
        errdefer prepared.deinit();
        if (self.assignment) |*old| old.deinit();
        self.assignment = prepared;
        return self.factory();
    }
    fn ensureCatalogue(self: *Context, key: *const Outer.prove.Authority) !void {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(CPU.air.bundle_sha256);
        var word: [8]u8 = undefined;
        for (key.bound.components) |component| for (component.parts) |part| {
            std.mem.writeInt(u64, &word, part.program.semanticHash(), .little);
            hash.update(&word);
        };
        const identity = hash.finalResult();
        if (self.body_identity) |cached| {
            if (!std.mem.eql(u8, &cached, &identity)) return error.ChangedOm31CircuitProgram;
            return;
        }
        const groups = try Aot.groups(self.allocator, &key.bound);
        defer self.allocator.free(groups);
        errdefer {
            for (self.entries.items) |*e| e.metadata.deinit();
            self.entries.clearRetainingCapacity();
            self.metadata_bytes = 0;
        }
        for (groups, 0..) |group, id| {
            var artifact = try Outer.record.record(self.allocator, &key.bound.components[group.component], group.part, group.first, group.count);
            defer artifact.deinit();
            var actual: [64]u8 = undefined;
            try checked(self.identity(@intCast(id), &actual));
            if (!std.mem.eql(u8, actual[0..32], &artifact.program.identity) or !std.mem.eql(u8, actual[32..], &(try Code.identity(&artifact.program)))) return error.Om31OuterAotIdentityMismatch;
            const bytes = artifact.program.inputs.len * @sizeOf(@import("stwo_prover_engine").air.secure_polynomial_program_v2.Input) + artifact.program.roots.len * 4 + artifact.parameter_slots.len * 4;
            if (bytes > self.metadata_cap_bytes - @min(self.metadata_cap_bytes, self.metadata_bytes)) return error.OuterMetadataBudgetExceeded;
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
            const metadata = try RC.KernelMetadata.fromProgram(self.allocator, &artifact.program, &artifact.parameter_slots);
            self.entries.appendAssumeCapacity(.{ .group = group, .metadata = metadata });
            self.metadata_bytes += bytes;
        }
        self.body_identity = identity;
    }
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, key: *const Outer.prove.Authority, values: []const Outer.protocol.Q, scope: D.Scope) !Dev.Source {
        return prepareImpl(raw, a, key, values, scope, null);
    }
    fn prepareFromCircuit(raw: *anyopaque, a: std.mem.Allocator, key: *const Outer.prove.Authority, graph: *const circuit.builder.Context(Outer.protocol.Q), scope: D.Scope) !Dev.Source {
        if (!graph.trace_only or !graph.finalized or !graph.record_gates) return error.TraceOnlyGraphRequired;
        return prepareImpl(raw, a, key, &.{}, scope, graph);
    }
    fn prepareImpl(raw: *anyopaque, a: std.mem.Allocator, key: *const Outer.prove.Authority, values: []const Outer.protocol.Q, scope: D.Scope, graph: ?*const circuit.builder.Context(Outer.protocol.Q)) !Dev.Source {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (graph == null and (values.len == 0 or values.len > std.math.maxInt(u32) / 4)) return error.InvalidOuterAssignment;
        if (comptime @hasDecl(Outer.prove.Authority, "requireProverData")) try key.requireProverData();
        self.mutex.lock();
        var locked = true;
        defer if (locked) self.mutex.unlock();
        if (self.active != null) return error.OuterProofAlreadyActive;
        var owns_assignment = false;
        var previous_assignment: ?Assignment.Prepared = null;
        // Until an Owner takes custody, every failure retires the bounded
        // request allocation while its allocator is still alive and restores
        // any explicit persistent legacy plan unchanged.
        errdefer if (owns_assignment) {
            self.assignment.?.deinit();
            self.assignment = previous_assignment;
        };
        if (graph) |ctx| {
            const prepared = try Assignment.Prepared.init(a, ctx, &self.service.library);
            previous_assignment = self.assignment;
            self.assignment = prepared;
            owns_assignment = true;
        }
        const value_count = if (graph != null) blk: {
            const assignment = self.assignment orelse return error.TraceOnlySourceRequired;
            if (assignment.reference != null or assignment.count == 0 or assignment.count > std.math.maxInt(u32) / 4) return error.TraceOnlySourceRequired;
            break :blk assignment.count;
        } else values.len;
        if (graph == null) if (self.assignment) |assignment| if (assignment.reference != values.ptr or assignment.count != values.len) return error.OuterWitnessGraphMismatch;
        // Raw FIXED evaluations are borrowed together while generating MAIN and
        // INTER. The original alias scope is released before composition borrows
        // the coefficient forest; immutable aliases must never be evicted live.
        var fixed_bytes: u64 = 0;
        for (key.pp.columns) |column| fixed_bytes = try std.math.add(u64, fixed_bytes, try std.math.mul(u64, column.values.len, @sizeOf(u32)));
        if (self.service.immutable_setup == null) try self.service.enableImmutableSetup(@min(self.service.byte_cap, 2 << 30));
        const immutable_limit = self.service.immutable_setup.?.limit;
        const schedule_bytes: u64 = if (self.assignment) |assignment| try std.math.mul(u64, try std.math.add(u64, assignment.tasks.len * 8, assignment.indices.len), 4) else 0;
        const required_immutable = try std.math.add(u64, fixed_bytes, schedule_bytes);
        if (required_immutable > immutable_limit) {
            std.debug.print("GPU_OUTER fixed_forest_bytes={} schedule_bytes={} required_immutable_bytes={} immutable_limit_bytes={} device_limit_bytes={} logs={any}\n", .{ fixed_bytes, schedule_bytes, required_immutable, immutable_limit, self.service.byte_cap, key.logs.toArray() });
            return error.OuterFixedForestExceedsImmutableBudget;
        }
        std.debug.print("GPU_OUTER fixed_forest_bytes={} immutable_limit_bytes={} device_limit_bytes={} assignment_bytes={} schedule_bytes={} logs={any}\n", .{ fixed_bytes, immutable_limit, self.service.byte_cap, values.len * @sizeOf(Outer.protocol.Q), schedule_bytes, key.logs.toArray() });
        try self.ensureCatalogue(key);
        const owner = try a.create(Owner);
        owner.* = .{ .allocator = a, .backend = self, .key = key, .input = values, .value_count = value_count, .owns_assignment = owns_assignment, .previous_assignment = previous_assignment, .initial_scope = scope, .scope = scope, .main_columns = &.{}, .inter_columns = &.{}, .pcs = self.service.stage(), .composition_stage = .{ .context = owner, .evaluate_and_commit = Owner.compose } };
        self.active = owner;
        owns_assignment = false;
        previous_assignment = null;
        self.mutex.unlock();
        locked = false;
        errdefer Owner.release(owner);
        owner.main_columns = try a.alloc(D.TraceColumn, 114);
        owner.inter_columns = try a.alloc(D.TraceColumn, 304);
        try owner.run(@import("outer_source_main.zig").generate);
        // MAIN generation joined every metadata upload and witness kernel.
        // INTER/PCS retain device columns only; no CPU plan escapes its budget.
        owner.retireAssignment();
        owner.input = &.{};
        const commit = self.trace_commit.stage();
        owner.main = try commit.commit(commit.context, a, .{ .scope = scope, .config = try Outer.protocol.targetConfig(), .tree_index = 1, .columns = owner.main_columns });
        owner.scope.main = owner.main.?.root;
        return .{ .context = owner, .scope = owner.scope, .main = owner.main.?, .pcs = &owner.pcs, .composition = &owner.composition_stage, .generate = Owner.interact, .release = Owner.release };
    }
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    backend: *Context,
    key: *const Outer.prove.Authority,
    input: []const Outer.protocol.Q,
    value_count: usize,
    owns_assignment: bool = false,
    previous_assignment: ?Assignment.Prepared = null,
    initial_scope: D.Scope,
    scope: D.Scope,
    raw_fixed: [45]Native.Lease = undefined,
    main_evaluations: Native.Lease = .{},
    main_columns: []D.TraceColumn,
    inter_columns: []D.TraceColumn,
    leases: std.ArrayList(Native.Lease) = .empty,
    main: ?D.Tree = null,
    claims: Outer.witness.Claims = undefined,
    z: Outer.protocol.O = undefined,
    alpha: Outer.protocol.O = undefined,
    inter_ready: bool = false,
    pcs: D.Stage,
    composition_stage: @import("stwo_prover_api").device_composition.ResidentOm31Stage,
    failure: ?anyerror = null,
    operation: *const fn (*Owner, *anyopaque, u64) anyerror!void = undefined,
    pub fn run(self: *Owner, operation: *const fn (*Owner, *anyopaque, u64) anyerror!void) !void {
        self.operation = operation;
        self.failure = null;
        const status = self.backend.service.submit(self.backend.service.session, callback, self);
        if (self.failure) |err| return err;
        try checked(status);
    }
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        self.operation(self, raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    pub fn context(self: *Owner, raw: *anyopaque, token: u64, scope: D.Scope) SC.Context {
        return .{ .session = self.backend.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(scope), .api = &self.backend.api };
    }
    pub fn owned(self: *Owner, ctx: *SC.Context, words: usize) !Native.Lease {
        var lease = try ctx.allocate(words, 1);
        errdefer ctx.release(&lease) catch {};
        try self.leases.append(self.allocator, lease);
        return lease;
    }
    fn interact(raw: *anyopaque, a: std.mem.Allocator, key: *const Outer.prove.Authority, scope: D.Scope, z: Outer.protocol.O, alpha: Outer.protocol.O) !Dev.Interaction {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.inter_ready or key != self.key or !std.meta.eql(scope, self.scope)) return error.InvalidOuterInteractionScope;
        self.z = z;
        self.alpha = alpha;
        try self.run(@import("outer_source_interaction.zig").generate);
        // INTER generation has joined all readers. Its commitment consumes only
        // INTER evaluations; MAIN coefficients already have independent custody.
        try self.run(dropMainEvaluations);
        const commit = self.backend.trace_commit.stage();
        const tree = try commit.commit(commit.context, a, .{ .scope = scope, .config = try Outer.protocol.targetConfig(), .tree_index = 2, .columns = self.inter_columns });
        self.inter_ready = true;
        try self.run(dropEvaluations);
        self.backend.service.finishProofScope(self.initial_scope);
        return .{ .tree = tree, .claims = self.claims };
    }
    fn compose(raw: *anyopaque, a: std.mem.Allocator, randomness: Outer.protocol.O, log: u32, split: u32, total: usize, trace: *const anyopaque) !D.Tree {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (!self.inter_ready) return error.OuterInteractionsNotReady;
        return @import("outer_source_composition.zig").evaluate(self, a, randomness, log, split, total, trace);
    }
    fn dropMainEvaluations(self: *Owner, _: *anyopaque, _: u64) !void {
        const main = self.main_evaluations;
        if (main.words == null) return;
        for (self.leases.items, 0..) |*lease, i| {
            if (lease.words != main.words or lease.count != main.count or lease.context_token != main.context_token or lease.generation != main.generation or lease.kind != main.kind or lease.reserved != main.reserved) continue;
            const bytes = main.count * 4;
            // Native release joins the owner lanes before freeing the allocation.
            // Do not remove ownership on a failed release.
            try checked(self.backend.service.lease_release(self.backend.service.session, lease));
            _ = self.leases.swapRemove(i);
            self.main_evaluations = .{};
            std.log.info("GPU_OUTER released_main_evaluation_bytes={d} before_INTER_commit", .{bytes});
            return;
        }
        return error.OuterMainEvaluationLeaseNotOwned;
    }
    fn dropEvaluations(self: *Owner, _: *anyopaque, _: u64) !void {
        for (self.leases.items) |*lease| if (lease.words != null) try checked(self.backend.service.lease_release(self.backend.service.session, lease));
        self.leases.clearRetainingCapacity();
        self.main_evaluations = .{};
    }
    fn retireAssignment(self: *Owner) void {
        self.backend.mutex.lock();
        defer self.backend.mutex.unlock();
        self.retireAssignmentLocked();
    }
    fn retireAssignmentLocked(self: *Owner) void {
        if (!self.owns_assignment) return;
        std.debug.assert(self.backend.active == self);
        var assignment = self.backend.assignment orelse @panic("missing owned atomic circuit plan");
        self.backend.assignment = self.previous_assignment;
        self.previous_assignment = null;
        self.owns_assignment = false;
        assignment.deinit();
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const b = self.backend;
        const a = self.allocator;
        _ = b.service.submit(b.service.session, releaseDevice, self);
        b.service.finishProofScope(self.scope);
        if (!std.meta.eql(self.scope, self.initial_scope)) b.service.finishProofScope(self.initial_scope);
        self.leases.deinit(a);
        a.free(self.main_columns);
        a.free(self.inter_columns);
        b.mutex.lock();
        std.debug.assert(b.active == self);
        self.retireAssignmentLocked();
        b.active = null;
        b.mutex.unlock();
        a.destroy(self);
    }
    fn releaseDevice(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        for (self.leases.items) |*lease| if (lease.words != null) {
            if (self.backend.service.lease_release(self.backend.service.session, lease) != 0) return 1;
        };
        return 0;
    }
};
pub fn lookupIndices(a: std.mem.Allocator, key: *const Outer.prove.Authority, component: usize) ![]u32 {
    const pp = circuit.common.preprocessed;
    const list = .{ &pp.EQ_COLUMN_IDS, &pp.QM31_OPS_COLUMN_IDS, &pp.TRIPLE_XOR_COLUMN_IDS, &pp.M31_TO_U32_COLUMN_IDS, &pp.BLAKE_G_GATE_COLUMN_IDS, &.{ "bitwise_xor_8_0", "bitwise_xor_8_1", "bitwise_xor_8_2" }, &.{}, &.{ "bitwise_xor_4_0", "bitwise_xor_4_1", "bitwise_xor_4_2" }, &.{ "bitwise_xor_7_0", "bitwise_xor_7_1", "bitwise_xor_7_2" }, &.{ "bitwise_xor_9_0", "bitwise_xor_9_1", "bitwise_xor_9_2" }, &.{"seq_16"} };
    inline for (list, 0..) |names, ci| if (component == ci) {
        const indices = try a.alloc(u32, names.len);
        errdefer a.free(indices);
        inline for (names, 0..) |name, local| indices[local] = for (key.layout.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.id, name)) break @intCast(i);
        } else return error.MissingOuterFixedColumn;
        return indices;
    };
    return error.InvalidOuterComponent;
}

test "outer GPU factory is explicit and rejects empty assignment before touching resources" {
    var backend: Context = undefined;
    var key: Outer.prove.Authority = undefined;
    const factory = backend.factory();
    const scope = D.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(0), .ordinal = 0 };
    try std.testing.expectError(error.InvalidOuterAssignment, factory.prepare(factory.context, std.testing.allocator, &key, &.{}, scope));
}

// Only deinitialization fields are initialized: these tests exercise ownership
// without constructing a native session or invoking a device callback.
fn testAssignment(a: std.mem.Allocator, tag: u8) !Assignment.Prepared {
    var result: Assignment.Prepared = undefined;
    result.allocator = a;
    result.plan = .{ .allocator = a, .tasks = &.{}, .seeds = &.{}, .level_ends = &.{} };
    result.tasks = &.{};
    result.indices = try a.alloc(u32, 1);
    result.seeds = &.{};
    result.identity = @splat(tag);
    return result;
}

test "atomic circuit plan retires after MAIN while restoring persistent legacy plan" {
    const a = std.testing.allocator;
    var backend: Context = undefined;
    backend.mutex = .{};
    backend.assignment = try testAssignment(a, 2);
    var owner: Owner = undefined;
    owner.backend = &backend;
    owner.owns_assignment = true;
    owner.previous_assignment = try testAssignment(a, 1);
    backend.active = &owner;
    owner.retireAssignment();
    try std.testing.expect(backend.active == &owner);
    try std.testing.expect(!owner.owns_assignment);
    try std.testing.expect(owner.previous_assignment == null);
    try std.testing.expectEqual(@as(u8, 1), backend.assignment.?.identity[0]);
    owner.retireAssignment();
    backend.assignment.?.deinit();
}

test "failed atomic owner releases bounded plan before allowing another proof" {
    const a = std.testing.allocator;
    const Fake = struct {
        fn submit(_: *anyopaque, _: Native.Callback, _: ?*anyopaque) callconv(.c) c_int {
            return 0;
        }
    };
    var service: Service.Context = undefined;
    service.submit = Fake.submit;
    service.session = @ptrCast(&service);
    service.cache_mutex = .{};
    service.cache = .empty;
    service.immutable_setup = null;
    var backend: Context = undefined;
    backend.service = &service;
    backend.mutex = .{};
    backend.assignment = try testAssignment(a, 3);
    const owner = try a.create(Owner);
    owner.* = undefined;
    owner.allocator = a;
    owner.backend = &backend;
    owner.owns_assignment = true;
    owner.previous_assignment = null;
    owner.scope = .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    owner.initial_scope = owner.scope;
    owner.leases = .empty;
    owner.main_columns = &.{};
    owner.inter_columns = &.{};
    backend.active = owner;
    Owner.release(owner);
    try std.testing.expect(backend.active == null);
    try std.testing.expect(backend.assignment == null);
}
