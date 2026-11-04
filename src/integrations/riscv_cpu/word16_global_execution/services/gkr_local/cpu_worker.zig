//! CPU services worker for the explicitly versioned OM/GKR protocol. Stage one
//! retains compact committed columns and narrow metadata, never a wide MAIN copy.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const W = @import("worker_protocol.zig");
const Fixed = @import("fixed_authority.zig");
const O = W.O;
const M = core.fields.m31.M31;
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const Manifest = @import("manifest.zig");
const Frame = @import("frame.zig");
const Child = @import("child.zig");
const Components = @import("cpu_components.zig");
const Classic = @import("classic_witness.zig");
pub const DeviceGlobal = @import("device_global.zig");
const Global = @import("global_cpu.zig");
const Metadata = @import("global_metadata.zig");
const Commit = @import("../../../word16_execution/main_ownership.zig").Commit;
pub const CpuEncoded = struct {
    bytes: []u8,
    claims: []O,
    pub fn deinit(self: *CpuEncoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.claims);
        self.* = undefined;
    }
};
fn hashValue(h: *std.crypto.hash.blake2.Blake2s256, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int => {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, @intCast(value), .little);
            h.update(&b);
        },
        .bool => h.update(&.{@intFromBool(value)}),
        .@"enum" => hashValue(h, @intFromEnum(value)),
        .array => for (value) |v| hashValue(h, v),
        .pointer => |p| switch (p.size) {
            .slice => {
                hashValue(h, value.len);
                for (value) |v| hashValue(h, v);
            },
            else => @compileError("statement must contain values, not pointers"),
        },
        .optional => {
            hashValue(h, value != null);
            if (value) |v| hashValue(h, v);
        },
        .@"struct" => |s| inline for (s.fields) |f| hashValue(h, @field(value, f.name)),
        else => @compileError("unsupported statement value"),
    }
}
pub fn firstVector(first: anytype) [@import("../types.zig").FAMILIES]u32 {
    comptime if (first.len != 3 and first.len != @import("../types.zig").FAMILIES) @compileError("first IDs must be the frozen v2 prefix or the complete service vector");
    var out: [@import("../types.zig").FAMILIES]u32 = @splat(1);
    inline for (0..first.len) |i| out[i] = first[i];
    return out;
}
/// T.Logs fields of the v3 GKR CPU statement, in their original order.
pub const V3_STATEMENT_BRIDGES = .{ "keccak", "add", "double", "sha256", "arith256_mod", "bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul", "bls12_381_fp2_mul", "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double", "bulk", "sponge", "ls_dword", "ls_dword_tail" };
pub fn cpuStatement(setup: *const R.CpuSetup, request: P.Request, first: anytype, config: W.PcsConfig) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update(Manifest.PROFILE);
    hashValue(&h, setup.materials.program.identity);
    // The v2 statement predates fused-tail/U8-pair flags. False fields omitted
    // from JSON must also be absent from this binary transcript projection.
    // Freeze the original field order rather than hashing an extensible struct.
    inline for (.{ "cpu_log", "alu_log", "alu_tail_log", "binary_log", "binary_tail_log", "shift_log", "shift_tail_log", "jalr_log", "division_log", "omit_empty_division", "multiplication_log", "ls_log", "ls_tail_log", "boundary_log", "initial_log", "terminal_log" }) |name|
        hashValue(&h, @field(setup.materials.geometry, name));
    // Preserve the exact pre-v3 prefix so unchanged V2 statements stay byte-identical.
    // Qualified V3 geometry, bridges and calls are domain-separated below.
    hashValue(&h, struct { keccak: ?u32, add: ?u32, double: ?u32 }{ .keccak = setup.bridges.keccak, .add = setup.bridges.add, .double = setup.bridges.double });
    hashValue(&h, struct { base: @TypeOf(request.base), calls: [3]u32 }{ .base = request.base, .calls = request.calls[0..3].* });
    const ids = firstVector(first);
    hashValue(&h, ids[0..3].*);
    hashValue(&h, config);
    var extra = false;
    for (request.calls[3..]) |count| extra = extra or count != 0;
    if (extra or setup.materials.geometry.cpu_fused_tail or setup.materials.geometry.cpu_u8_pairs or setup.bridges.sponge.any() or setup.bridges.ls_dword != null or setup.bridges.ls_dword_tail != null or request.sponge.any() or request.ls_dword != 0) {
        h.update("RV64-SERVICES-GKR-V3-STATEMENT-1");
        hashValue(&h, setup.materials.geometry.cpu_fused_tail);
        hashValue(&h, setup.materials.geometry.cpu_u8_pairs);
        // Frozen pre-Zbb Logs projection: an appended optional bridge (Zbb,
        // never admitted here; see service_scope.bridges) must not change v3
        // statement bytes even when null.
        inline for (V3_STATEMENT_BRIDGES) |name| hashValue(&h, @field(setup.bridges, name));
        hashValue(&h, request.calls);
        hashValue(&h, request.sponge);
        hashValue(&h, request.ls_dword);
        hashValue(&h, ids);
    }
    // Compact decode changes CPU MAIN, the ROM fixed tuple and AUIPC/JAL
    // FUNCTION facts. Absent (false) it leaves every older statement byte-identical.
    if (setup.materials.geometry.cpu_compact_decode) {
        h.update("RV64-CPU-COMPACT-DECODE-GKR-STATEMENT-1");
        hashValue(&h, @import("stwo_riscv_frontend").rv64_air.word16_execution.features.compactIdentity());
    }
    if (setup.bridges.bulk.any() or request.bulk.any()) {
        h.update("RV64-BULK-GKR-V3-STATEMENT-1");
        hashValue(&h, setup.bridges.bulk);
        hashValue(&h, request.bulk);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
pub fn cpuStatementWithAuthority(setup: *const R.CpuSetup, request: P.Request, first: anytype, config: W.PcsConfig, fixed: ?*const Fixed.Binding) [32]u8 {
    const base = cpuStatement(setup, request, first, config);
    return if (fixed) |binding| binding.statement(base) else base;
}
pub fn cpuMass(request: P.Request) !Manifest.Mass {
    return (try @import("mass_authority.zig").cpu(request)).absolute();
}

pub fn wirePresent(logs: @import("../types.zig").Logs) bool {
    for (@import("std").enums.values(@import("../types.zig").Family)) |family| if (family != .keccak and logs.at(family) != null) return true;
    return false;
}
fn validate(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.ExpectedWorker, first: anytype, config: W.PcsConfig, fixed: ?*const Fixed.Binding) !void {
    if (fixed) |binding| try binding.require(&setup.key, config) else try W.validateConfig(config);
    const root = if (fixed) |binding| binding.root() else setup.key.root;
    if (expected.kind != .cpu or !std.mem.eql(u8, &expected.fixed, &root) or !std.mem.eql(u8, &expected.statement, &cpuStatementWithAuthority(setup, request, first, config, fixed))) return error.WideCpuStatementMismatch;
    const roster = try @import("roster.zig").fromSetup(a, setup);
    defer a.free(roster);
    const admitted = expected.local_instances orelse return error.WideCpuLocalRequired;
    if (roster.len != admitted.len) return error.WideCpuRosterMismatch;
    for (roster, admitted) |x, y| if (!std.meta.eql(x, y)) return error.WideCpuRosterMismatch;
    if (!std.meta.eql(expected.mass, try cpuMass(request))) return error.WideCpuMassMismatch;
    const presence = Manifest.Relations{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = wirePresent(setup.bridges) };
    if (!std.meta.eql(expected.global_relations, presence)) return error.WideCpuRelationMismatch;
}
fn checkManifest(expected: Manifest.ExpectedWorker, pending: *const Manifest.PendingManifest, index: usize) !void {
    if (index != expected.ordinal or index >= pending.entries.len) return error.WideCpuStatementMismatch;
    const entry = pending.entries[index];
    if (entry.kind != .cpu or entry.local == null or entry.scope.ordinal != expected.ordinal or
        !std.meta.eql(entry.mass, expected.mass) or !std.meta.eql(entry.global_relations, expected.global_relations) or
        !std.mem.eql(u8, &entry.scope.statement, &expected.statement) or !std.mem.eql(u8, &entry.scope.fixed, &expected.fixed)) return error.WideCpuManifestMismatch;
}
fn publicClaims(request: P.Request, plan: *const Components.Plan, shared: Manifest.Shared, claims: []const O) !void {
    if (claims.len != plan.claim_count) return error.InvalidWideCpuClaims;
    for (claims) |value| for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalWideCpuClaim;
    for (plan.slots) |slot| switch (slot.origin) {
        .core => |role| if (role == .initial or role == .terminal) {
            const initial = role == .initial;
            const expected = try @import("expected_boundary.zig").claim(if (initial) request.base.memory.initial else request.base.memory.terminal, initial, shared.ram);
            if (!claims[slot.claim_offset].eql(expected)) return error.WideCpuPublicRamMismatch;
        },
        else => {},
    };
}
fn releaseSlice(a: std.mem.Allocator, values: anytype) void {
    a.free(values.*);
    values.* = &.{};
}
fn releaseLsLocals(source: anytype) void {
    inline for (.{ "fixed", "counts16", "counts8", "selection_counts" }) |name| releaseSlice(source.allocator, &@field(source, name));
}
fn releaseBridgeLocals(source: anytype) void {
    inline for (.{ "fixed", "counts16", "counts8" }) |name| releaseSlice(source.allocator, &@field(source, name));
}
/// Optional caller-owned diagnostics. gkr_ns includes metadata projection and
/// durable terminal-binding construction; these times never enter a transcript.
pub const SealTiming = struct { main_commit_ns: u64 = 0, gkr_ns: u64 = 0, inputs_ns: u64 = 0, numerical_ns: u64 = 0, binding_ns: u64 = 0, numerical_requested_peak_bytes: usize = 0, including_binding_requested_peak_bytes: usize = 0, admitted_gkr_peak_bytes: usize = 0, gkr_allocator_limit_bytes: usize = 0 };
/// Frontend-owned hybrid bridge. Items contain receiver-derived public/local/
/// shared metadata; the callback never reconstructs it from producer bytes.
pub const CompositionStage = struct {
    context: *anyopaque,
    evaluate: *const fn (*anyopaque, std.mem.Allocator, []const Components.Item, O, u32, usize, *const anyopaque, *anyopaque) anyerror!bool,
};
pub const ResidentCompositionStage = struct {
    context: *anyopaque,
    evaluate_and_commit: *const fn (*anyopaque, std.mem.Allocator, []const Components.Item, O, u32, u32, usize, *const anyopaque, @import("stwo_prover_api").device_pcs.Scope) anyerror!@import("stwo_prover_api").device_pcs.Tree,
};
const ResidentCompositionInvocation = struct {
    stage: ResidentCompositionStage,
    items: []const Components.Item,
    scope: @import("stwo_prover_api").device_pcs.Scope,
    fn evaluateAndCommit(ctx: *anyopaque, a: std.mem.Allocator, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque) anyerror!@import("stwo_prover_api").device_pcs.Tree {
        const invocation: *const @This() = @ptrCast(@alignCast(ctx));
        return invocation.stage.evaluate_and_commit(invocation.stage.context, a, invocation.items, alpha, log, split, total, trace, invocation.scope);
    }
};
const CompositionInvocation = struct {
    stage: CompositionStage,
    items: []const Components.Item,
    fn evaluate(ctx: *anyopaque, a: std.mem.Allocator, alpha: O, log: u32, total: usize, trace: *const anyopaque, result: *anyopaque) anyerror!bool {
        const invocation: *const CompositionInvocation = @ptrCast(@alignCast(ctx));
        return invocation.stage.evaluate(invocation.stage.context, a, invocation.items, alpha, log, total, trace, result);
    }
};
pub const CpuWorker = struct {
    replay: ?@import("cpu_replay.zig").Owner = null,
    device_global_stage: ?DeviceGlobal.Stage = null,
    om31_composition_stage: ?CompositionStage = null,
    resident_composition_stage: ?ResidentCompositionStage = null,
    device_trace_commit_stage: ?@import("stwo_prover_api").device_pcs.TraceCommitStage = null,
    numerical_gkr_stage: ?Child.NumericalStage = null,
    allocator: std.mem.Allocator,
    setup: *const R.CpuSetup,
    request: P.Request,
    source: R.Sources,
    expected: Manifest.ExpectedWorker,
    instances: []Frame.Instance,
    first: [@import("../types.zig").FAMILIES]u32,
    config: W.PcsConfig,
    plan: Components.Plan,
    scheme: W.Scheme,
    channel: W.Channel,
    child: ?*Child.Unbound = null,
    gkr_budget: usize,
    tree_policy: ?Child.TreePolicy = null,
    defer_local_binding: bool = false,
    sealed: bool = false,
    consumed: bool = false,
    owns_scheme: bool = true,
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    local_metadata_retired: bool = false,
    seal_timing: ?*SealTiming = null,
    fixed_authority: ?Fixed.Binding = null,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, source: R.Sources, expected: Manifest.ExpectedWorker, config: W.PcsConfig, first: anytype, gkr_budget: usize) !CpuWorker {
        return initWithAuthority(a, setup, request, source, expected, config, first, gkr_budget, null);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, source: R.Sources, expected: Manifest.ExpectedWorker, config: W.PcsConfig, first: anytype, gkr_budget: usize, fixed: ?*const Fixed.Binding) !CpuWorker {
        try validate(a, setup, request, expected, first, config, fixed);
        const instances = try @import("roster.zig").fromSetup(a, setup);
        errdefer a.free(instances);
        var plan = try Components.Plan.init(a, setup);
        errdefer plan.deinit();
        var scheme = try W.Prover.init(a, config);
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        var own_expected = expected;
        own_expected.local_instances = instances;
        return .{ .allocator = a, .setup = setup, .request = request, .source = source, .expected = own_expected, .instances = instances, .first = firstVector(first), .config = config, .plan = plan, .scheme = scheme, .channel = if (fixed) |binding| binding.begin(config, expected) else W.begin(config, expected), .fixed_authority = if (fixed) |binding| binding.retain() else null, .gkr_budget = gkr_budget };
    }
    /// Local fractions and a durable full binding OR terminal projection exist.
    /// Their MAIN authentication remains pending until physical verification.
    /// Retain only RAM/bridge metadata for the later global challenge. Retired
    /// source fields are tombstones and are never read or destroyed again.
    pub fn retireLocalMetadata(self: *CpuWorker) !void {
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        if (self.local_metadata_retired) return;
        const source = &self.source.core;
        if (self.source.device_generated) {
            // Device sources keep valid empty host owners and compact public
            // headers. Only capture records become dead after joined GKR.
            source.cpu.allocator.free(source.cpu.metadata);
            source.cpu.metadata = &.{};
            source.cpu.releaseFacts();
            self.local_metadata_retired = true;
            return;
        }
        inline for (.{ "range8", "range16", "shift_table", "and_table", "multiplication", "division", "tails", "jalr", "shift", "binary", "alu", "rom", "cpu" }) |name| @field(source, name).deinit();
        source.allocator.free(source.counts16);
        source.allocator.free(source.counts8);
        source.allocator.free(source.boundary);
        const memory = &source.memory;
        releaseLsLocals(&memory.ls);
        if (memory.ls_tail) |*tail| releaseLsLocals(tail);
        inline for (.{ "initial", "terminal" }) |name| {
            const boundary = &@field(memory, name);
            releaseSlice(boundary.allocator, &boundary.fixed);
        }
        inline for (.{ "fixed", "main", "interaction" }) |name| releaseSlice(memory.selection.allocator, &@field(memory.selection, name));
        memory.selection.counts = &.{};
        if (memory.selection_counts) |counts| memory.allocator.free(counts);
        memory.selection_counts = null;
        releaseSlice(memory.allocator, &memory.counts16);
        releaseSlice(memory.allocator, &memory.counts8);
        if (self.source.keccak) |*bridge| releaseBridgeLocals(bridge);
        if (self.source.add) |*bridge| releaseBridgeLocals(bridge);
        if (self.source.double) |*bridge| releaseBridgeLocals(bridge);
        for (&self.source.bulk) |*bulk| if (bulk.*) |*src| @import("bulk_metadata.zig").retireLocal(src);
        if (self.source.sha256) |*bridge| releaseBridgeLocals(bridge);
        if (self.source.arith256_mod) |*bridge| releaseBridgeLocals(bridge);
        for (&self.source.curves) |*bridge| if (bridge.*) |*v| releaseBridgeLocals(v);
        for (&self.source.sponge) |*sponge_source| if (sponge_source.*) |*v| @import("sponge_metadata.zig").retireLocal(v);
        for (&self.source.ls_dword) |*dword_source| if (dword_source.*) |*v| {
            inline for (.{ "fixed", "counts16", "counts8" }) |field| releaseSlice(v.allocator, &@field(v, field));
        };
        self.local_metadata_retired = true;
    }
    /// Stage-one barrier ownership seam. The field-neutral retained store owns
    /// mapped/parked buffers; its explicit admission remains the caller's duty.
    pub fn spillMain(self: *CpuWorker, store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        if (self.scheme.device_om31_trace_trees[1] != null) return 0;
        return store.spill(self.allocator, &self.scheme.trees.items[1]);
    }
    pub fn restoreMain(self: *CpuWorker, store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        if (self.scheme.device_om31_trace_trees[1] != null) return 0;
        return store.restore(&self.scheme.trees.items[1]);
    }
    fn deviceBindingColumns(child: *Child.Unbound) !?[]const @import("stwo_prover_api").device_pcs.Column {
        if (comptime @hasDecl(Child.Unbound, "deviceBindingColumns")) {
            if (child.device_binding != null) return try child.deviceBindingColumns();
        }
        return null;
    }
    fn mainRoot(self: *const CpuWorker) [32]u8 {
        return if (self.scheme.device_om31_trace_trees[1]) |tree| tree.root else self.scheme.trees.items[1].root();
    }
    pub fn seal(self: *CpuWorker, a: std.mem.Allocator) !Manifest.StageOne {
        if (!@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, self.allocator)) return error.WideCpuAllocatorMismatch;
        if (self.sealed or self.consumed) return error.WideCpuPhase;
        var clock: ?std.time.Timer = if (self.seal_timing != null) try std.time.Timer.start() else null;
        if (self.seal_timing) |output| output.* = .{};
        // Failure consumes the worker: owned commitment consumes storage on errors too.
        self.consumed = true;
        if (self.fixed_authority) |*binding| try binding.append(a, &self.setup.key, self.expected.fixed, &self.scheme, &self.channel) else try W.appendFixed(a, &self.setup.key, self.expected.fixed, &self.scheme, &self.channel);
        if (self.device_trace_commit_stage) |stage| {
            if (self.scheme.device_om31_pcs_stage == null or self.numerical_gkr_stage == null or self.resident_composition_stage == null) return error.DeviceTraceRequiresResidentStages;
            const columns = try self.source.mainTraceColumns(a, self.setup);
            defer a.free(columns);
            const committed = try stage.commit(stage.context, a, .{ .scope = .{ .statement = self.expected.statement, .fixed = self.expected.fixed, .main = @splat(0), .ordinal = @intCast(self.expected.ordinal) }, .tree_index = 1, .config = self.config, .columns = columns });
            if (committed.columns.len != columns.len) return error.DeviceTraceColumnMismatch;
            for (committed.columns, columns) |actual, expected| if (actual.log_size != expected.log_size) return error.DeviceTraceColumnMismatch;
            try self.scheme.adoptDeviceOm31TraceTree(1, committed, &self.channel);
            try self.source.releaseMain();
        } else {
            const main = try self.source.takeMain(self.setup);
            try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        }
        const root = self.mainRoot();
        if (clock) |*timer| self.seal_timing.?.main_commit_ns = timer.lap();
        // Borrow the actual committed coefficients. A numerical device stage
        // reconstructs native physical rows itself; no raw N/D matrices are
        // allocated or uploaded by this seam. The scheme retains every owner
        // until the synchronous stage and terminal binding return.
        var native_columns = Child.NativeColumns{};
        defer if (self.numerical_gkr_stage != null) {
            a.free(native_columns.fixed);
            a.free(native_columns.main);
        };
        if (self.numerical_gkr_stage != null) {
            const D = @import("stwo_prover_api").device_pcs;
            const fixed_coefficients = self.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
            const main_coefficients = if (self.scheme.device_om31_trace_trees[1] == null) self.scheme.trees.items[1].coefficients orelse return error.DeviceGkrCoefficientsRequired else null;
            const fixed_columns = try a.alloc(D.Column, fixed_coefficients.len);
            native_columns.fixed = fixed_columns;
            const main_columns = try a.alloc(D.Column, if (main_coefficients) |values| values.len else self.scheme.device_om31_trace_trees[1].?.columns.len);
            native_columns.main = main_columns;
            for (fixed_coefficients, fixed_columns) |coefficient, *column| column.* = .{ .log_size = coefficient.logSize(), .coefficients = coefficient.coefficients() };
            if (main_coefficients) |values| {
                for (values, main_columns) |coefficient, *column| column.* = .{ .log_size = coefficient.logSize(), .coefficients = coefficient.coefficients() };
            } else @memcpy(main_columns, self.scheme.device_om31_trace_trees[1].?.columns);
        }
        var phase_timing = Child.PhaseTiming{};
        const policy = if (self.tree_policy) |value| value else try Child.readTreePolicy(a);
        // Observation only (lane rusage); never proof authority.
        var gkr_scope = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "local_gkr_prove", "Local GKR inputs, layers and sumchecks");
        defer gkr_scope.end();
        self.scheme.device_om31_scope = .{ .statement = self.expected.statement, .fixed = self.expected.fixed, .main = root, .ordinal = @intCast(self.expected.ordinal) };
        self.child = try Child.Unbound.proveTimedWithNumericalStage(a, self.gkr_budget, .{ .statement = self.expected.statement, .fixed = self.expected.fixed, .main = root, .ordinal = self.expected.ordinal }, self.instances, @import("native_provider.zig").Provider{ .source = &self.source }, policy, self.defer_local_binding, if (self.seal_timing != null) &phase_timing else null, self.numerical_gkr_stage, native_columns);
        if (self.seal_timing) |timing| {
            timing.inputs_ns = phase_timing.inputs_ns;
            timing.numerical_ns = phase_timing.numerical_ns;
            timing.binding_ns = phase_timing.binding_ns;
            timing.numerical_requested_peak_bytes = phase_timing.numerical_requested_peak_bytes;
            timing.including_binding_requested_peak_bytes = phase_timing.including_binding_requested_peak_bytes;
            timing.admitted_gkr_peak_bytes = phase_timing.admitted_gkr_peak_bytes;
            timing.gkr_allocator_limit_bytes = phase_timing.gkr_allocator_limit_bytes;
        }
        if (clock) |*timer| self.seal_timing.?.gkr_ns = timer.read();
        self.sealed = true;
        self.consumed = false;
        return .{ .main = root, .local = .{ .proof = &self.child.?.result.proof, .receipt_digest = self.child.?.digest } };
    }
    pub fn complete(self: *CpuWorker, a: std.mem.Allocator, pending: *const Manifest.PendingManifest, index: usize, global_budget: usize) !CpuEncoded {
        if (!@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, self.allocator)) return error.WideCpuAllocatorMismatch;
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        const root = self.mainRoot();
        try checkManifest(self.expected, pending, index);
        try pending.checkPhysicalRoots(index, self.expected.fixed, root);
        if (index != self.expected.ordinal or !std.mem.eql(u8, &pending.entries[index].scope.statement, &self.expected.statement)) return error.WideCpuStatementMismatch;
        const local = &(pending.entries[index].local orelse return error.WideCpuLocalRequired);
        {
            var binding_scope = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "binding_finalize", "Deferred local Eq/prefix completion");
            defer binding_scope.end();
            try self.child.?.completeBinding(self.instances);
        }
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "interaction_generation", "CPU global classic interactions");
        defer generation.end();
        if (self.device_global_stage != null and self.device_trace_commit_stage == null) return error.ResidentGlobalRequiresDeviceTrace;
        const device_witnesses = try a.alloc(?DeviceGlobal.Witness, self.plan.slots.len);
        defer a.free(device_witnesses);
        @memset(device_witnesses, null);
        defer for (device_witnesses) |*w| if (w.*) |*value| value.deinit();
        const witnesses = try a.alloc(?Classic.Witness, self.plan.slots.len);
        defer a.free(witnesses);
        @memset(witnesses, null);
        defer for (witnesses) |*w| if (w.*) |*v| v.deinit();
        const claims = try a.alloc(O, self.plan.claim_count);
        errdefer a.free(claims);
        var remaining = global_budget;
        for (self.plan.slots, witnesses, device_witnesses) |slot, *w, *device_witness| {
            const n = Global.claimCount(slot.origin);
            if (n == 0) continue;
            if (self.device_global_stage) |stage| {
                const D = @import("stwo_prover_api").device_pcs;
                const descriptor = @import("source_authority.zig").Descriptor{ .origin = slot.origin };
                const shape = try @import("constraint_authority.zig").shape(descriptor);
                const fixed = try a.alloc(D.Column, shape.fixed);
                defer a.free(fixed);
                const fixed_coefficients = self.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
                if (slot.fixed_offset + fixed.len > fixed_coefficients.len) return error.InvalidWideGlobalShape;
                for (fixed_coefficients[slot.fixed_offset..][0..fixed.len], fixed) |coefficient, *column| column.* = .{ .log_size = coefficient.logSize(), .coefficients = coefficient.coefficients() };
                const main_tree = self.scheme.device_om31_trace_trees[1] orelse return error.ResidentGlobalMainRequired;
                if (slot.main_offset + shape.main > main_tree.columns.len) return error.InvalidWideGlobalShape;
                const item = DeviceGlobal.Item{ .descriptor = descriptor, .log_size = slot.log, .fixed = fixed, .fixed_offset = slot.fixed_offset, .main = main_tree.columns[slot.main_offset..][0..shape.main], .sponge_first_id = if (slot.origin == .sponge) (self.source.sponge[@intFromEnum(slot.origin.sponge)] orelse return error.MissingLocalGkrBridge).first_id else 0 };
                device_witness.* = try stage.generate(stage.context, a, self.scheme.device_om31_scope orelse return error.ResidentCompositionScopeRequired, item, pending.shared, remaining);
                try device_witness.*.?.validate(item);
                const rows = @as(usize, 1) << @intCast(slot.log);
                const bytes = try std.math.mul(usize, try std.math.mul(usize, rows, device_witness.*.?.columns.len), @sizeOf(M));
                if (bytes > remaining) return error.WideCpuGlobalBudget;
                remaining -= bytes;
                @memcpy(claims[slot.claim_offset..][0..n], device_witness.*.?.claims);
                continue;
            }
            const provider = Metadata.Provider{ .source = &self.source, .origin = slot.origin, .log_size = slot.log, .shared = pending.shared };
            w.* = if (slot.origin == .core and (slot.origin.core == .initial or slot.origin.core == .terminal)) try Classic.Witness.initPublicBoundary(a, slot.log, try Metadata.groups(slot.origin), provider, remaining) else if (slot.origin == .sponge) try Classic.Witness.initTruth(a, slot.log, try Metadata.groups(slot.origin), provider, remaining) else try Classic.Witness.init(a, slot.log, try Metadata.groups(slot.origin), provider, remaining);
            const bytes = try std.math.mul(usize, w.*.?.data.len, @sizeOf(M));
            if (bytes > remaining) return error.WideCpuGlobalBudget;
            remaining -= bytes;
            @memcpy(claims[slot.claim_offset..][0..n], w.*.?.claimSlice());
        }
        generation.end();
        try publicClaims(self.request, &self.plan, pending.shared, claims);
        var set = try Components.Set.init(a, self.setup, self.request, self.first, &self.plan, local, pending.shared, claims);
        defer set.deinit();
        const handles = try set.provers(a);
        defer a.free(handles);
        if (self.device_trace_commit_stage) |stage| {
            const D = @import("stwo_prover_api").device_pcs;
            const columns = try a.alloc(D.TraceColumn, self.plan.inter_columns);
            defer a.free(columns);
            const resident_binding = try deviceBindingColumns(self.child.?);
            for (self.plan.slots, witnesses, device_witnesses) |slot, witness, device_witness| {
                const rows = @as(usize, 1) << @intCast(slot.log);
                var offset = slot.inter_offset;
                if (slot.binding_index) |binding_index| {
                    if (resident_binding) |binding| {
                        if (binding_index * 16 + 16 > binding.len) return error.WideCpuBindingShape;
                        for (columns[offset..][0..16], binding[binding_index * 16 ..][0..16]) |*column, input| {
                            if (input.log_size != slot.log or input.device == null or input.coefficients.len != 0) return error.WideCpuBindingShape;
                            column.* = .{ .log_size = slot.log, .encoding = .coefficients, .device = input.device };
                        }
                    } else {
                        const data = self.child.?.binding.columns[binding_index];
                        if (data.len != rows * 16) return error.WideCpuBindingShape;
                        for (columns[offset..][0..16], 0..) |*column, i| column.* = .{ .log_size = slot.log, .encoding = .evaluations, .host = data[i * rows ..][0..rows] };
                    }
                    offset += 16;
                }
                if (device_witness) |value| {
                    @memcpy(columns[offset..][0..value.columns.len], value.columns);
                } else if (witness) |value| {
                    for (columns[offset..][0..value.width()], 0..) |*column, i| column.* = .{ .log_size = slot.log, .encoding = .evaluations, .host = value.data[i * rows ..][0..rows] };
                }
            }
            self.consumed = true;
            W.mixManifestAndClaims(&self.channel, pending.digest, claims);
            const committed = try stage.commit(stage.context, a, .{ .scope = self.scheme.device_om31_scope orelse return error.ResidentCompositionScopeRequired, .tree_index = 2, .config = self.config, .columns = columns });
            if (committed.columns.len != columns.len) return error.DeviceTraceColumnMismatch;
            for (committed.columns, columns) |actual, expected| if (actual.log_size != expected.log_size) return error.DeviceTraceColumnMismatch;
            try self.scheme.adoptDeviceOm31TraceTree(2, committed, &self.channel);
        } else {
            const headers = try a.alloc(engine.pcs.ColumnEvaluation, self.plan.inter_columns);
            var owns_buffers = true;
            errdefer if (owns_buffers) a.free(headers);
            const backing_count = self.plan.binding_count + blk: {
                var n: usize = 0;
                for (witnesses) |w| {
                    n += @intFromBool(w != null);
                }
                break :blk n;
            };
            const backings = try a.alloc([]M, backing_count);
            errdefer if (owns_buffers) a.free(backings);
            var b: usize = 0;
            for (self.plan.slots, witnesses) |slot, w| {
                const rows = @as(usize, 1) << @intCast(slot.log);
                var offset = slot.inter_offset;
                if (slot.binding_index) |i| {
                    const data = self.child.?.binding.columns[i];
                    if (data.len != rows * 16) return error.WideCpuBindingShape;
                    backings[b] = data;
                    b += 1;
                    for (headers[offset..][0..16], 0..) |*c, j| c.* = .{ .log_size = slot.log, .values = data[j * rows ..][0..rows] };
                    offset += 16;
                }
                if (w) |v| {
                    backings[b] = v.data;
                    b += 1;
                    for (headers[offset..][0..v.width()], 0..) |*c, j| c.* = .{ .log_size = slot.log, .values = v.data[j * rows ..][0..rows] };
                }
            }
            // All allocations and validation completed. Transfer backing ownership once.
            self.consumed = true;
            const detached = try self.child.?.takeBindingBackings();
            a.free(detached);
            for (witnesses) |*w| if (w.*) |*v| {
                v.data = &.{};
            };
            W.mixManifestAndClaims(&self.channel, pending.digest, claims);
            owns_buffers = false;
            try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, headers, backings, 64, self.native_recorder, &self.channel);
        }
        var scheme = self.scheme;
        self.scheme = undefined;
        self.owns_scheme = false;
        var resident_invocation: ResidentCompositionInvocation = undefined;
        var resident_stage: @import("stwo_prover_api").device_composition.ResidentOm31Stage = undefined;
        if (self.resident_composition_stage) |selected| {
            resident_invocation = .{ .stage = selected, .items = set.items, .scope = scheme.device_om31_scope orelse return error.ResidentCompositionScopeRequired };
            resident_stage = .{ .context = &resident_invocation, .evaluate_and_commit = ResidentCompositionInvocation.evaluateAndCommit };
            scheme.device_om31_composition_stage = &resident_stage;
        }
        var invocation: CompositionInvocation = undefined;
        const stage: ?@import("stwo_prover_api").device_composition.Om31Stage = if (self.om31_composition_stage) |selected| blk: {
            invocation = .{ .stage = selected, .items = set.items };
            break :blk .{ .context = &invocation, .evaluate = CompositionInvocation.evaluate };
        } else null;
        var proof = try W.Prover.prove(a, handles, &self.channel, scheme, .{ .recorder = self.native_recorder, .om31_composition_stage = stage });
        defer proof.deinit(a);
        return .{ .bytes = try W.encodePhysical(a, proof.proof), .claims = claims };
    }
    pub fn deinit(self: *CpuWorker, a: std.mem.Allocator) void {
        if (self.replay) |*owner| owner.deinit();
        if (self.child) |c| c.deinit();
        if (self.local_metadata_retired and !self.source.device_generated) {
            self.source.core.memory.deinit();
            if (self.source.keccak) |*source| source.deinit();
            if (self.source.add) |*source| source.deinit();
            if (self.source.double) |*source| source.deinit();
            for (&self.source.bulk) |*bulk| if (bulk.*) |*src| src.deinit();
            if (self.source.sha256) |*source| source.deinit();
            if (self.source.arith256_mod) |*source| source.deinit();
            for (&self.source.curves) |*source| if (source.*) |*v| v.deinit();
            for (&self.source.sponge) |*source| if (source.*) |*v| v.deinit();
            if (self.source.sponge_plan) |plan| {
                plan.deinit(self.allocator);
                self.allocator.destroy(plan);
            }
            for (&self.source.ls_dword) |*source| if (source.*) |*v| v.deinit();
        } else self.source.deinit();
        if (self.owns_scheme) self.scheme.deinit(a);
        self.plan.deinit();
        a.free(self.instances);
        if (self.fixed_authority) |*binding| binding.deinit();
        self.* = undefined;
    }
};
pub fn verifyCpu(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.ExpectedWorker, first: anytype, pending: *const Manifest.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const CpuEncoded) !Manifest.Claims {
    return verifyCpuWithAuthority(a, setup, request, expected, first, pending, index, config, encoded, null);
}
pub fn verifyCpuWithAuthority(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.ExpectedWorker, first: anytype, pending: *const Manifest.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const CpuEncoded, fixed: ?*const Fixed.Binding) !Manifest.Claims {
    try validate(a, setup, request, expected, first, config, fixed);
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    try checkManifest(expected, pending, index);
    var proof = try W.decodePhysical(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, config) or proof.commitment_scheme_proof.revision_config != null) return error.WideCpuProofShape;
    try pending.checkPhysicalRoots(index, roots[0], roots[1]);
    try publicClaims(request, &plan, pending.shared, encoded.claims);
    const local = &(pending.entries[index].local orelse return error.WideCpuLocalRequired);
    var set = try Components.Set.init(a, setup, request, first, &plan, local, pending.shared, encoded.claims);
    defer set.deinit();
    const handles = try set.verifiers(a);
    defer a.free(handles);
    var ch = if (fixed) |binding| binding.begin(config, expected) else W.begin(config, expected);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    const f = try setup.logs(a, 0);
    defer a.free(f);
    const m = try setup.logs(a, 1);
    defer a.free(m);
    const i = try plan.interLogs(a);
    defer a.free(i);
    try receiver.commit(a, roots[0], f, &ch);
    try receiver.commit(a, roots[1], m, &ch);
    W.mixManifestAndClaims(&ch, pending.digest, encoded.claims);
    try receiver.commit(a, roots[2], i, &ch);
    owns = false;
    try core.verifier.ForField(O).verify(W.H, W.MC, a, handles, &ch, &receiver, proof);
    return Components.Set.aggregate(&plan, encoded.claims);
}
