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
pub const Encoded = Legacy.CpuEncoded;
pub const Worker = struct {
    allocator: std.mem.Allocator,
    setup: *const R.CpuSetup,
    request: P.Request,
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
        try validate(a, setup, request, expected, first, key);
        const instances = try @import("../word16_global_execution/services/gkr_local/roster.zig").fromSetup(a, setup);
        errdefer a.free(instances);
        var plan = try Components.Plan.init(a, setup);
        errdefer plan.deinit();
        var scheme = try W.Prover.init(a, key.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        var own = expected;
        own.local_instances = instances;
        return .{ .allocator = a, .setup = setup, .request = request, .source = source, .expected = own, .first = Legacy.firstVector(first), .key = key, .instances = instances, .plan = plan, .scheme = scheme, .channel = Protocol.begin(key.profile, expected, key.identity, key.root) };
    }
    fn mainRoot(self: *const Worker) W.H.Hash {
        return self.scheme.trees.items[1].root();
    }
    pub fn seal(self: *Worker, a: std.mem.Allocator) !Manifest.StageOne {
        if (self.sealed or self.consumed) return error.PoseidonNativePhase;
        self.consumed = true;
        try self.key.append(a, &self.scheme, &self.channel);
        const main = try self.source.takeMain(self.setup);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, null, &self.channel);
        const root = self.mainRoot();
        self.child = try Child.proveUnbound(a, .{ .statement = self.expected.statement, .fixed = self.expected.fixed, .main = root, .ordinal = self.expected.ordinal }, self.instances, @import("../word16_global_execution/services/gkr_local/native_provider.zig").Provider{ .source = &self.source });
        self.sealed = true;
        self.consumed = false;
        return .{ .main = root, .local = .{ .proof = &self.child.?.result.proof, .receipt = self.child.?.digest } };
    }
    pub fn complete(self: *Worker, a: std.mem.Allocator, pending: *const Manifest.Pending, index: usize) !Encoded {
        if (!self.sealed or self.consumed or index != self.expected.ordinal or index >= pending.entries.len) return error.PoseidonNativePhase;
        try pending.checkPhysicalRoots(index, self.key.scope(), self.mainRoot());
        const local = &(pending.entries[index].local orelse return error.PoseidonNativeLocalRequired);
        var binding = try @import("../word16_global_execution/services/gkr_local/witness.zig").Witness.initFromProvider(a, a, self.instances, &self.child.?.challenges, @import("../word16_global_execution/services/gkr_local/native_provider.zig").Provider{ .source = &self.source }, &self.child.?.result.artifact, self.child.?.eta);
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
            w.* = if (slot.origin == .core and (slot.origin.core == .initial or slot.origin.core == .terminal)) try Classic.Witness.initPublicBoundary(a, slot.log, try Metadata.groups(slot.origin), provider, 2 << 30) else if (slot.origin == .sponge) try Classic.Witness.initTruth(a, slot.log, try Metadata.groups(slot.origin), provider, 2 << 30) else try Classic.Witness.init(a, slot.log, try Metadata.groups(slot.origin), provider, 2 << 30);
            @memcpy(claims[slot.claim_offset..][0..n], w.*.?.claimSlice());
        }
        try publicClaims(self.request, &self.plan, pending.shared, claims);
        var set = try Components.Set.initChecked(a, self.setup, self.request, self.first, &self.plan, local.checkedTerminal(), pending.shared, claims);
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
        Protocol.mixManifestAndClaims(&self.channel, pending.digest, claims);
        try self.scheme.commitBorrowedStreaming(a, headers, 64, &self.channel);
        self.consumed = true;
        const scheme = self.scheme;
        self.scheme = undefined;
        self.owns_scheme = false;
        var proof = try W.Prover.prove(a, handles, &self.channel, scheme, .{});
        defer proof.deinit(a);
        return .{ .bytes = try W.Wire.encodeProofBytesBinary(a, proof.proof), .claims = claims };
    }
    pub fn deinit(self: *Worker) void {
        if (self.child) |*child| child.deinit(self.allocator);
        self.source.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.plan.deinit();
        self.allocator.free(self.instances);
        self.* = undefined;
    }
};
fn validate(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, expected: Manifest.Expected, first: anytype, key: *const Key) !void {
    try key.require(setup, key.profile);
    if (expected.profile != key.profile or !std.mem.eql(u8, &expected.fixed_identity, &key.identity)) return error.PoseidonNativeFixedAuthorityMismatch;
    if (expected.kind != .cpu or !std.mem.eql(u8, &expected.fixed, &key.scope()) or !std.mem.eql(u8, &expected.statement, &key.statement(setup, request, first))) return error.PoseidonNativeStatementMismatch;
    const instances = try @import("../word16_global_execution/services/gkr_local/roster.zig").fromSetup(a, setup);
    defer a.free(instances);
    const admitted = expected.local_instances orelse return error.PoseidonNativeLocalRequired;
    if (instances.len != admitted.len) return error.PoseidonNativeRosterMismatch;
    for (instances, admitted) |x, y| if (!std.meta.eql(x, y)) return error.PoseidonNativeRosterMismatch;
    if (!std.meta.eql(expected.mass, try Legacy.cpuMass(request))) return error.PoseidonNativeMassMismatch;
    const presence = Manifest.Relations{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = Legacy.wirePresent(setup.bridges) };
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
    try validate(a, setup, request, expected, first, key);
    if (index != expected.ordinal or index >= pending.entries.len) return error.PoseidonNativeOrdinal;
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.root)) return error.PoseidonNativeProofShape;
    try pending.checkPhysicalRoots(index, key.scope(), roots[1]);
    if (!std.mem.eql(u8, &pending.entries[index].scope.statement, &expected.statement)) return error.PoseidonNativeStatementMismatch;
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    try publicClaims(request, &plan, pending.shared, encoded.claims);
    const local = &(pending.entries[index].local orelse return error.PoseidonNativeLocalRequired);
    var set = try Components.Set.initChecked(a, setup, request, first, &plan, local.checkedTerminal(), pending.shared, encoded.claims);
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
