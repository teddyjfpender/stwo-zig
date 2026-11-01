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
pub fn cpuStatement(setup: *const R.CpuSetup, request: P.Request, first: [3]u32, config: W.PcsConfig) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update(Manifest.PROFILE);
    hashValue(&h, setup.materials.program.identity);
    hashValue(&h, setup.materials.geometry);
    hashValue(&h, setup.bridges);
    hashValue(&h, request);
    hashValue(&h, first);
    hashValue(&h, config);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
pub fn cpuStatementWithAuthority(setup: *const R.CpuSetup, request: P.Request, first: [3]u32, config: W.PcsConfig, fixed: ?*const Fixed.Binding) [32]u8 {
    const base = cpuStatement(setup, request, first, config);
    return if (fixed) |binding| binding.statement(base) else base;
}
pub fn cpuMass(request: P.Request) !Manifest.Mass {
    return (try @import("mass_authority.zig").cpu(request)).absolute();
}

fn validate(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.ExpectedWorker, first: [3]u32, config: W.PcsConfig, fixed: ?*const Fixed.Binding) !void {
    if (fixed) |binding| try binding.require(&setup.key, config) else try W.validateConfig(config);
    const root = if (fixed) |binding| binding.root() else setup.key.root;
    if (expected.kind != .cpu or !std.mem.eql(u8, &expected.fixed, &root) or !std.mem.eql(u8, &expected.statement, &cpuStatementWithAuthority(setup, request, first, config, fixed))) return error.WideCpuStatementMismatch;
    const roster = try @import("roster.zig").fromSetup(a, setup);
    defer a.free(roster);
    const admitted = expected.local_instances orelse return error.WideCpuLocalRequired;
    if (roster.len != admitted.len) return error.WideCpuRosterMismatch;
    for (roster, admitted) |x, y| if (!std.meta.eql(x, y)) return error.WideCpuRosterMismatch;
    if (!std.meta.eql(expected.mass, try cpuMass(request))) return error.WideCpuMassMismatch;
    const presence = Manifest.Relations{ .ram = true, .kio = setup.bridges.keccak != null, .wire = setup.bridges.add != null or setup.bridges.double != null };
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
pub const SealTiming = struct { main_commit_ns: u64 = 0, gkr_ns: u64 = 0, inputs_ns: u64 = 0, numerical_ns: u64 = 0, binding_ns: u64 = 0 };
pub const CpuWorker = struct {
    allocator: std.mem.Allocator,
    setup: *const R.CpuSetup,
    request: P.Request,
    source: R.Sources,
    expected: Manifest.ExpectedWorker,
    instances: []Frame.Instance,
    first: [3]u32,
    config: W.PcsConfig,
    plan: Components.Plan,
    scheme: W.Scheme,
    channel: W.Channel,
    child: ?*Child.Unbound = null,
    gkr_budget: usize,
    sealed: bool = false,
    consumed: bool = false,
    owns_scheme: bool = true,
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    local_metadata_retired: bool = false,
    seal_timing: ?*SealTiming = null,
    fixed_authority: ?Fixed.Binding = null,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, source: R.Sources, expected: Manifest.ExpectedWorker, config: W.PcsConfig, first: [3]u32, gkr_budget: usize) !CpuWorker {
        return initWithAuthority(a, setup, request, source, expected, config, first, gkr_budget, null);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, source: R.Sources, expected: Manifest.ExpectedWorker, config: W.PcsConfig, first: [3]u32, gkr_budget: usize, fixed: ?*const Fixed.Binding) !CpuWorker {
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
        return .{ .allocator = a, .setup = setup, .request = request, .source = source, .expected = own_expected, .instances = instances, .first = first, .config = config, .plan = plan, .scheme = scheme, .channel = if (fixed) |binding| binding.begin(config, expected) else W.begin(config, expected), .fixed_authority = if (fixed) |binding| binding.retain() else null, .gkr_budget = gkr_budget };
    }
    /// Local fractions and their authenticated binding are durable now. Retain
    /// only RAM/bridge metadata needed for the later global challenge. Retired
    /// source fields are tombstones and are never read or destroyed again.
    pub fn retireLocalMetadata(self: *CpuWorker) !void {
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        if (self.local_metadata_retired) return;
        const source = &self.source.core;
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
        self.local_metadata_retired = true;
    }
    /// Stage-one barrier ownership seam. The field-neutral retained store owns
    /// mapped/parked buffers; its explicit admission remains the caller's duty.
    pub fn spillMain(self: *CpuWorker, store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        return store.spill(self.allocator, &self.scheme.trees.items[1]);
    }
    pub fn restoreMain(self: *CpuWorker, store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        return store.restore(&self.scheme.trees.items[1]);
    }
    pub fn seal(self: *CpuWorker, a: std.mem.Allocator) !Manifest.StageOne {
        if (!@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, self.allocator)) return error.WideCpuAllocatorMismatch;
        if (self.sealed or self.consumed) return error.WideCpuPhase;
        var clock: ?std.time.Timer = if (self.seal_timing != null) try std.time.Timer.start() else null;
        if (self.seal_timing) |output| output.* = .{};
        // Failure consumes the worker: owned commitment consumes storage on errors too.
        self.consumed = true;
        if (self.fixed_authority) |*binding| try binding.append(a, &self.setup.key, self.expected.fixed, &self.scheme, &self.channel) else try W.appendFixed(a, &self.setup.key, self.expected.fixed, &self.scheme, &self.channel);
        const main = try self.source.takeMain(self.setup);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        const root = self.scheme.trees.items[1].root();
        if (clock) |*timer| self.seal_timing.?.main_commit_ns = timer.lap();
        var phase_timing = Child.PhaseTiming{};
        self.child = try Child.Unbound.proveTimed(a, self.gkr_budget, .{ .statement = self.expected.statement, .fixed = self.expected.fixed, .main = root, .ordinal = self.expected.ordinal }, self.instances, @import("native_provider.zig").Provider{ .source = &self.source }, if (self.seal_timing != null) &phase_timing else null);
        if (self.seal_timing) |timing| {
            timing.inputs_ns = phase_timing.inputs_ns;
            timing.numerical_ns = phase_timing.numerical_ns;
            timing.binding_ns = phase_timing.binding_ns;
        }
        if (clock) |*timer| self.seal_timing.?.gkr_ns = timer.read();
        self.sealed = true;
        self.consumed = false;
        return .{ .main = root, .local = .{ .proof = &self.child.?.result.proof, .receipt_digest = self.child.?.digest } };
    }
    pub fn complete(self: *CpuWorker, a: std.mem.Allocator, pending: *const Manifest.PendingManifest, index: usize, global_budget: usize) !CpuEncoded {
        if (!@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, self.allocator)) return error.WideCpuAllocatorMismatch;
        if (!self.sealed or self.consumed) return error.WideCpuPhase;
        const root = self.scheme.trees.items[1].root();
        try checkManifest(self.expected, pending, index);
        try pending.checkPhysicalRoots(index, self.expected.fixed, root);
        if (index != self.expected.ordinal or !std.mem.eql(u8, &pending.entries[index].scope.statement, &self.expected.statement)) return error.WideCpuStatementMismatch;
        const local = &(pending.entries[index].local orelse return error.WideCpuLocalRequired);
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "interaction_generation", "CPU global classic interactions");
        defer generation.end();
        const witnesses = try a.alloc(?Classic.Witness, self.plan.slots.len);
        defer a.free(witnesses);
        @memset(witnesses, null);
        defer for (witnesses) |*w| if (w.*) |*v| v.deinit();
        const claims = try a.alloc(O, self.plan.claim_count);
        errdefer a.free(claims);
        var remaining = global_budget;
        for (self.plan.slots, witnesses) |slot, *w| {
            const n = Global.claimCount(slot.origin);
            if (n == 0) continue;
            const provider = Metadata.Provider{ .source = &self.source, .origin = slot.origin, .log_size = slot.log, .shared = pending.shared };
            w.* = try Classic.Witness.init(a, slot.log, try Metadata.groups(slot.origin), provider, remaining);
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
        const detached = self.child.?.takeBindingBackings();
        a.free(detached);
        for (witnesses) |*w| if (w.*) |*v| {
            v.data = &.{};
        };
        W.mixManifestAndClaims(&self.channel, pending.digest, claims);
        owns_buffers = false;
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, headers, backings, 64, self.native_recorder, &self.channel);
        const scheme = self.scheme;
        self.scheme = undefined;
        self.owns_scheme = false;
        var proof = try W.Prover.prove(a, handles, &self.channel, scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(a);
        return .{ .bytes = try W.encodePhysical(a, proof.proof), .claims = claims };
    }
    pub fn deinit(self: *CpuWorker, a: std.mem.Allocator) void {
        if (self.child) |c| c.deinit();
        if (self.local_metadata_retired) {
            self.source.core.memory.deinit();
            if (self.source.keccak) |*source| source.deinit();
            if (self.source.add) |*source| source.deinit();
            if (self.source.double) |*source| source.deinit();
        } else self.source.deinit();
        if (self.owns_scheme) self.scheme.deinit(a);
        self.plan.deinit();
        a.free(self.instances);
        if (self.fixed_authority) |*binding| binding.deinit();
        self.* = undefined;
    }
};
pub fn verifyCpu(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.ExpectedWorker, first: [3]u32, pending: *const Manifest.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const CpuEncoded) !Manifest.Claims {
    return verifyCpuWithAuthority(a, setup, request, expected, first, pending, index, config, encoded, null);
}
pub fn verifyCpuWithAuthority(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.ExpectedWorker, first: [3]u32, pending: *const Manifest.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const CpuEncoded, fixed: ?*const Fixed.Binding) !Manifest.Claims {
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
