//! OP-only complete CPU physical worker: pure P2v2 PCS, local GKR and manifest.
//! Shared source AIR and terminal/global binding equations are unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("pure_p2_worker_protocol.zig");
const W = Protocol.W;
const O = W.O;
const M = core.fields.m31.M31;
const Key = @import("pure_p2_fixed_key.zig").Key;
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Child = @import("pure_p2_native.zig");
const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
const Classic = @import("../word16_global_execution/services/gkr_local/classic_witness.zig");
const Global = @import("../word16_global_execution/services/gkr_local/global_cpu.zig");
const Metadata = @import("../word16_global_execution/services/gkr_local/global_metadata.zig");
const Legacy = @import("../word16_global_execution/services/gkr_local/cpu_worker.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Roster = @import("../word16_global_execution/services/gkr_local/roster.zig");
pub const Encoded = Legacy.CpuEncoded;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Retention = @import("../word16_global_execution/services/gkr_local/retention_plan.zig");
/// Bounds numerical/local-binding and classic-global buffers, not setup,
/// capture/source construction, commitment trees or PCS/FFT scratch.
pub const Limits = struct { gkr_bytes: usize, global_bytes: usize };
pub const Worker = struct {
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    allocator: std.mem.Allocator,
    setup: *const R.CpuSetup,
    request: P.Request,
    op_span: ?T.OpTowerSpan = null,
    local_budget: ?*Budget = null,
    global_budget: ?*Budget = null,
    retention: ?Retention.RetentionPlan = null,
    global_limit: usize = 2 << 30,
    source: R.Sources,
    expected: Manifest.Expected,
    first: [@import("../word16_global_execution/services/types.zig").FAMILIES]u32,
    key: *const Key,
    instances: []@import("../word16_global_execution/services/gkr_local/frame.zig").Instance,
    plan: Components.Plan,
    scheme: W.Scheme,
    channel: W.Channel,
    child: ?Child.Unbound = null,
    owns_scheme: bool = true,
    sealed: bool = false,
    consumed: bool = false,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, source: R.Sources, expected: Manifest.Expected, first: anytype, key: *const Key) !Worker {
        return initMode(a, setup, request, null, source, expected, first, key, null);
    }
    pub fn initForOp(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, source: R.Sources, expected: Manifest.Expected, first: anytype, key: *const Key, limits: Limits) !Worker {
        return initMode(a, setup, request, span, source, expected, first, key, limits);
    }
    fn initMode(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: ?T.OpTowerSpan, source: R.Sources, expected: Manifest.Expected, first: anytype, key: *const Key, limits: ?Limits) !Worker {
        try validate(a, setup, request, span, expected, first, key);
        const instances = if (span != null) try Roster.fromOpSetup(a, setup) else try Roster.fromSetup(a, setup);
        errdefer a.free(instances);
        var plan = if (span != null) try Components.Plan.initForOp(a, setup) else try Components.Plan.init(a, setup);
        errdefer plan.deinit();
        const retention = if (span) |op| blk: {
            const cap = limits orelse return error.MissingLocalGkrBudget;
            break :blk try Retention.forOpCpuWithSourceStorage(a, setup, request, op, key.profile.config(), cap.gkr_bytes, cap.global_bytes, true);
        } else null;
        const local_budget = if (limits) |cap| try Budget.createRetainingParent(a, cap.gkr_bytes) else null;
        errdefer if (local_budget) |budget| budget.destroy();
        const global_budget = if (limits) |cap| try Budget.createRetainingParent(a, cap.global_bytes) else null;
        errdefer if (global_budget) |budget| budget.destroy();
        var scheme = try W.Prover.init(a, key.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        var own = expected;
        own.local_instances = instances;
        return .{ .allocator = a, .setup = setup, .request = request, .op_span = span, .local_budget = local_budget, .global_budget = global_budget, .retention = retention, .global_limit = if (limits) |cap| cap.global_bytes else 2 << 30, .source = source, .expected = own, .first = Legacy.firstVector(first), .key = key, .instances = instances, .plan = plan, .scheme = scheme, .channel = Protocol.begin(key.profile, expected, key.identity, key.root) };
    }
    fn localAllocator(self: *const Worker, fallback: std.mem.Allocator) std.mem.Allocator {
        return if (self.local_budget) |budget| budget.allocator() else fallback;
    }
    fn globalAllocator(self: *const Worker, fallback: std.mem.Allocator) std.mem.Allocator {
        return if (self.global_budget) |budget| budget.allocator() else fallback;
    }
    fn mainRoot(self: *const Worker) W.H.Hash {
        return self.scheme.trees.items[1].root();
    }
    pub fn seal(self: *Worker, a: std.mem.Allocator) !Manifest.StageOne {
        if (self.sealed or self.consumed) return error.PoseidonNativePhase;
        self.consumed = true;
        try self.key.append(a, &self.scheme, &self.channel);
        const main = try self.source.takeMain(self.setup);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        const root = self.mainRoot();
        var local_gkr = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "local_gkr_prove", "Source projection and local GKR layers/sumchecks");
        defer local_gkr.end();
        self.child = try Child.proveUnbound(self.localAllocator(a), .{ .statement = self.expected.statement, .fixed = self.expected.fixed, .main = root, .ordinal = self.expected.ordinal }, self.instances, @import("../word16_global_execution/services/gkr_local/native_provider.zig").Provider{ .source = &self.source });
        self.sealed = true;
        self.consumed = false;
        return .{ .main = root, .local = .{ .proof = &self.child.?.result.proof, .receipt = self.child.?.digest } };
    }
    pub fn complete(self: *Worker, a: std.mem.Allocator, pending: *const Manifest.Pending, index: usize) !Encoded {
        if (!self.sealed or self.consumed or index != self.expected.ordinal or index >= pending.entries.len) return error.PoseidonNativePhase;
        try checkManifest(self.expected, pending, index);
        try pending.checkPhysicalRoots(index, self.key.scope(), self.mainRoot());
        const local = &(pending.entries[index].local orelse return error.PoseidonNativeLocalRequired);
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "interaction_generation", "Local binding and global classic interaction generation");
        defer generation.end();
        var binding = try @import("../word16_global_execution/services/gkr_local/witness.zig").Witness.initFromProvider(self.localAllocator(a), self.localAllocator(a), self.instances, &self.child.?.challenges, @import("../word16_global_execution/services/gkr_local/native_provider.zig").Provider{ .source = &self.source }, &self.child.?.result.artifact, self.child.?.eta);
        defer binding.deinit();
        const witnesses = try a.alloc(?Classic.Witness, self.plan.slots.len);
        defer a.free(witnesses);
        @memset(witnesses, null);
        defer for (witnesses) |*w| if (w.*) |*v| v.deinit();
        const claims = try a.alloc(O, self.plan.claim_count);
        errdefer a.free(claims);
        for (self.plan.slots, witnesses) |slot, *w| {
            const n = Global.claimCount(slot.origin);
            if (n == 0) continue;
            const provider = Metadata.Provider{ .source = &self.source, .origin = slot.origin, .log_size = slot.log, .shared = pending.shared };
            w.* = if (slot.origin == .core and (slot.origin.core == .initial or slot.origin.core == .terminal)) try Classic.Witness.initPublicBoundary(self.globalAllocator(a), slot.log, try Metadata.groups(slot.origin), provider, self.global_limit) else if (slot.origin == .sponge) try Classic.Witness.initTruth(self.globalAllocator(a), slot.log, try Metadata.groups(slot.origin), provider, self.global_limit) else try Classic.Witness.init(self.globalAllocator(a), slot.log, try Metadata.groups(slot.origin), provider, self.global_limit);
            @memcpy(claims[slot.claim_offset..][0..n], w.*.?.claimSlice());
        }
        try publicClaims(self.request, &self.plan, pending.shared, claims);
        var set = if (self.op_span) |span| try Components.Set.initForOpChecked(a, self.setup, self.request, self.first, span, &self.plan, local.checkedTerminal(), pending.shared, claims) else try Components.Set.initChecked(a, self.setup, self.request, self.first, &self.plan, local.checkedTerminal(), pending.shared, claims);
        defer set.deinit();
        const handles = try set.provers(a);
        defer a.free(handles);
        const headers = try a.alloc(engine.pcs.ColumnEvaluation, self.plan.inter_columns);
        defer a.free(headers);
        for (self.plan.slots, witnesses) |slot, w| {
            const rows = @as(usize, 1) << @intCast(slot.log);
            var offset = slot.inter_offset;
            if (slot.binding_index) |i| {
                const data = binding.columns[i];
                if (data.len != rows * 16) return error.PoseidonNativeBindingShape;
                for (headers[offset..][0..16], 0..) |*c, j| c.* = .{ .log_size = slot.log, .values = data[j * rows ..][0..rows] };
                offset += 16;
            }
            if (w) |v| for (headers[offset..][0..v.width()], 0..) |*c, j| {
                c.* = .{ .log_size = slot.log, .values = v.data[j * rows ..][0..rows] };
            };
        }
        generation.end();
        Protocol.mixManifestAndClaims(&self.channel, pending.digest, claims);
        try self.scheme.commitBorrowedStreamingWithRecorder(a, headers, 64, self.native_recorder, &self.channel);
        self.consumed = true;
        const scheme = self.scheme;
        self.scheme = undefined;
        self.owns_scheme = false;
        var proof = try W.Prover.prove(a, handles, &self.channel, scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(a);
        return .{ .bytes = try W.Wire.encodeProofBytesBinary(a, proof.proof), .claims = claims };
    }
    pub fn deinit(self: *Worker) void {
        if (self.child) |*child| child.deinit(self.localAllocator(self.allocator));
        self.source.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.plan.deinit();
        self.allocator.free(self.instances);
        if (self.local_budget) |budget| budget.destroy();
        if (self.global_budget) |budget| budget.destroy();
        self.* = undefined;
    }
};
fn validate(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: ?T.OpTowerSpan, expected: Manifest.Expected, first: anytype, key: *const Key) !void {
    if (span) |op| {
        try key.requireForOp(setup, key.profile);
        try op.validate(setup.bridges);
    } else try key.require(setup, key.profile);
    if (expected.profile != key.profile or !std.mem.eql(u8, &expected.fixed_identity, &key.identity)) return error.PoseidonNativeFixedAuthorityMismatch;
    if (expected.kind != .cpu or !std.mem.eql(u8, &expected.fixed, &key.scope()) or !std.mem.eql(u8, &expected.statement, &(if (span) |op| try key.statementForOp(setup, request, first, op) else key.statement(setup, request, first)))) return error.PoseidonNativeStatementMismatch;
    const instances = if (span != null) try Roster.fromOpSetup(a, setup) else try Roster.fromSetup(a, setup);
    defer a.free(instances);
    const admitted = expected.local_instances orelse return error.PoseidonNativeLocalRequired;
    if (instances.len != admitted.len) return error.PoseidonNativeRosterMismatch;
    for (instances, admitted) |x, y| if (!std.meta.eql(x, y)) return error.PoseidonNativeRosterMismatch;
    if (!std.meta.eql(expected.mass, try cpuMass(setup, request, span))) return error.PoseidonNativeMassMismatch;
    const presence = Manifest.Relations{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = Legacy.wirePresent(setup.bridges) or (span != null and span.?.calls != 0) };
    if (!std.meta.eql(expected.global_relations, presence)) return error.PoseidonNativeRelationMismatch;
}
fn publicClaims(request: P.Request, plan: *const Components.Plan, shared: Manifest.Shared, claims: []const O) !void {
    if (claims.len != plan.claim_count) return error.PoseidonNativeClaims;
    for (claims) |value| for (value.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.PoseidonNativeClaims;
    for (plan.slots) |slot| switch (slot.origin) {
        .core => |role| if (role == .initial or role == .terminal) {
            const initial = role == .initial;
            const expected = try @import("../word16_global_execution/services/gkr_local/expected_boundary.zig").claim(if (initial) request.base.memory.initial else request.base.memory.terminal, initial, shared.ram);
            if (!expected.eql(claims[slot.claim_offset])) return error.PoseidonNativePublicRam;
        },
        else => {},
    };
}
/// Same source/public admission and core verifier as production, with optional
/// complete PCS capture for the new recursive hash family.
pub fn verify(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.Expected, first: anytype, pending: *const Manifest.Pending, index: usize, key: *const Key, encoded: *const Encoded, capture: anytype) !Manifest.Claims {
    return verifyMode(a, setup, request, null, expected, first, pending, index, key, encoded, capture);
}
pub fn verifyForOp(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, expected: Manifest.Expected, first: anytype, pending: *const Manifest.Pending, index: usize, key: *const Key, encoded: *const Encoded, capture: anytype) !Manifest.Claims {
    return verifyMode(a, setup, request, span, expected, first, pending, index, key, encoded, capture);
}
fn verifyMode(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: ?T.OpTowerSpan, expected: Manifest.Expected, first: anytype, pending: *const Manifest.Pending, index: usize, key: *const Key, encoded: *const Encoded, capture: anytype) !Manifest.Claims {
    try validate(a, setup, request, span, expected, first, key);
    try checkManifest(expected, pending, index);
    if (index != expected.ordinal or index >= pending.entries.len) return error.PoseidonNativeOrdinal;
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.root)) return error.PoseidonNativeProofShape;
    try pending.checkPhysicalRoots(index, key.scope(), roots[1]);
    if (!std.mem.eql(u8, &pending.entries[index].scope.statement, &expected.statement)) return error.PoseidonNativeStatementMismatch;
    var plan = if (span != null) try Components.Plan.initForOp(a, setup) else try Components.Plan.init(a, setup);
    defer plan.deinit();
    try publicClaims(request, &plan, pending.shared, encoded.claims);
    const local = &(pending.entries[index].local orelse return error.PoseidonNativeLocalRequired);
    var set = if (span) |op| try Components.Set.initForOpChecked(a, setup, request, first, op, &plan, local.checkedTerminal(), pending.shared, encoded.claims) else try Components.Set.initChecked(a, setup, request, first, &plan, local.checkedTerminal(), pending.shared, encoded.claims);
    defer set.deinit();
    const handles = try set.verifiers(a);
    defer a.free(handles);
    var ch = Protocol.begin(key.profile, expected, key.identity, key.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.profile.config());
    defer receiver.deinit(a);
    for (0..2) |tree| {
        const logs = try setup.logs(a, tree);
        defer a.free(logs);
        try receiver.commit(a, roots[tree], logs, &ch);
    }
    Protocol.mixManifestAndClaims(&ch, pending.digest, encoded.claims);
    const logs = try plan.interLogs(a);
    defer a.free(logs);
    try receiver.commit(a, roots[2], logs, &ch);
    if (comptime @TypeOf(capture) == @TypeOf(null)) {
        var temporary: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
        try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, handles, &ch, &receiver, &proof, &temporary);
        temporary.deinit(a);
    } else try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, handles, &ch, &receiver, &proof, capture);
    return Components.Set.aggregate(&plan, encoded.claims);
}

/// Extra physical debts are source-owned; local OWNER remains in the GKR roster.
pub fn cpuMass(setup: *const R.CpuSetup, request: P.Request, span: ?T.OpTowerSpan) !@import("../word16_global_execution/services/gkr_local/manifest.zig").Mass {
    var mass = try Legacy.cpuMass(request);
    if (span) |op| {
        if (!setup.op_only) return error.UnqualifiedOpSetup;
        const extra = try op.mass(setup.bridges);
        mass.ram = try std.math.add(u64, mass.ram, extra.ram);
        mass.wire = try std.math.add(u64, mass.wire, extra.wire);
    } else if (setup.op_only or setup.bridges.tower != null) return error.UnqualifiedOpProtocol;
    inline for (.{ "ram", "kio", "wire" }) |name| if (@field(mass, name) >= core.fields.m31.Modulus) return error.GlobalGkrCharacteristicBound;
    return mass;
}
fn checkManifest(expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize) !void {
    if (index != expected.ordinal or index >= pending.entries.len) return error.PoseidonNativeOrdinal;
    const entry = pending.entries[index];
    const actual = entry.authority;
    if (actual.kind != expected.kind or actual.ordinal != expected.ordinal or actual.profile != expected.profile or
        !std.meta.eql(actual.mass, expected.mass) or !std.meta.eql(actual.global_relations, expected.global_relations) or
        !std.mem.eql(u8, &actual.statement, &expected.statement) or !std.mem.eql(u8, &actual.fixed_identity, &expected.fixed_identity) or
        !std.mem.eql(u8, &actual.fixed, &expected.fixed) or !std.meta.eql(entry.global_relations, expected.global_relations) or
        entry.scope.ordinal != expected.ordinal or !std.mem.eql(u8, &entry.scope.statement, &expected.statement) or
        !std.mem.eql(u8, &entry.scope.fixed, &expected.fixed)) return error.PoseidonNativeManifestMismatch;
}
