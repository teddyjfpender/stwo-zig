//! Closed OP Miller truth worker: one PCS for frontier and arithmetic, source
//! owned fixed authority, shared manifest Wire35 and explicit local SSA closure.
//! Verifying this fragment is never acceptance of an execution inventory.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.bn254_tower.narrow;
const E = N.equations;
const S = N.source;
const O = core.fields.om31.OM31;
const M31 = core.fields.m31.M31;
const Protocol = @import("pure_p2_worker_protocol.zig");
const W = Protocol.W;
const Manifest = @import("pure_p2_manifest.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Commit = @import("../word16_execution/main_ownership.zig").Commit;
const F = N.ForField(O).Component(.frontier);
const C = N.ForField(O).Component(.arithmetic);
const LF = F.L;
const LC = C.L;
const SF = N.trace.SourceForField(.frontier, O);
const SC = N.trace.SourceForField(.arithmetic, O);
pub const Span = struct { calls: u32, first_id: u32 };
/// Explicit worker allocations, including PCS/FFT/prover scratch, are hard
/// capped. Independently cached immutable Key, caller input, shared-pool stacks
/// and returned serialized proof bytes remain separately caller-owned.
pub const Limits = struct { live_bytes: usize, main_bytes: usize, interaction_bytes: usize, advice_bytes: usize };
pub const ResourcePlan = struct {
    main_bytes: usize,
    interaction_bytes: usize,
    advice_bytes: usize,
    interaction_scratch_bytes: usize,
    pub fn derive(key: *const Key, span: Span) !ResourcePlan {
        try key.validateSpan(span);
        const f = @as(usize, 1) << @intCast(key.frontier_log);
        const c = @as(usize, 1) << @intCast(key.arithmetic_log);
        return .{
            .main_bytes = 4 * (LF.MAIN * f + LC.MAIN * c),
            .interaction_bytes = 4 * (LF.INTERACTION * f + LC.INTERACTION * c),
            .advice_bytes = @as(usize, span.calls) * (@sizeOf(N.trace.Input) + @sizeOf(N.micro.Advice)) + 2 * 256 * @sizeOf(u32) + N.micro.CARRY_LIMIT * @sizeOf(u32),
            .interaction_scratch_bytes = 2 * N.micro.CARRY_LIMIT * @sizeOf(O) + 3 * 128 * 9 * @sizeOf(O) + 256 * @sizeOf(O),
        };
    }
    pub fn admit(self: ResourcePlan, limits: Limits) !void {
        if (limits.live_bytes == 0 or limits.main_bytes == 0 or limits.interaction_bytes == 0 or limits.advice_bytes == 0) return error.OpTowerBudgetMissing;
        const source_floor = self.advice_bytes + @max(self.main_bytes, self.interaction_bytes + self.interaction_scratch_bytes);
        if (self.main_bytes > limits.main_bytes or self.interaction_bytes > limits.interaction_bytes or self.advice_bytes > limits.advice_bytes or source_floor > limits.live_bytes) return error.OpTowerBudgetExceeded;
    }
};
pub const Encoded = struct {
    bytes: []u8,
    /// Frontier SSA/Wire, then arithmetic SSA/Wire. Each enters the transcript.
    claims: [4]O,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
const ENVELOPE = "OPMLP201";
const HEADER_BYTES = 8 + 4 * 8 * 4 + 8;
pub fn encode(a: std.mem.Allocator, proof: *const Encoded) ![]u8 {
    try checkClaims(proof.claims);
    const bytes = try a.alloc(u8, try std.math.add(usize, HEADER_BYTES, proof.bytes.len));
    @memcpy(bytes[0..8], ENVELOPE);
    for (proof.claims, 0..) |claim, j| for (claim.toM31Array(), 0..) |value, i| std.mem.writeInt(u32, bytes[8 + 32 * j + 4 * i ..][0..4], value.v, .little);
    std.mem.writeInt(u64, bytes[HEADER_BYTES - 8 ..][0..8], proof.bytes.len, .little);
    @memcpy(bytes[HEADER_BYTES..], proof.bytes);
    return bytes;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, max_bytes: usize) !Encoded {
    if (bytes.len < HEADER_BYTES or bytes.len > max_bytes or !std.mem.eql(u8, bytes[0..8], ENVELOPE)) return error.OpTowerEnvelope;
    if (std.mem.readInt(u64, bytes[HEADER_BYTES - 8 ..][0..8], .little) != bytes.len - HEADER_BYTES) return error.OpTowerEnvelope;
    var claims: [4]O = undefined;
    for (&claims, 0..) |*claim, j| {
        var coordinates: [8]M31 = undefined;
        for (&coordinates, 0..) |*coordinate, i| {
            const value = std.mem.readInt(u32, bytes[8 + 32 * j + 4 * i ..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.OpTowerNoncanonicalClaim;
            coordinate.* = M31.fromCanonical(value);
        }
        claim.* = O.fromM31Array(coordinates);
    }
    try checkClaims(claims);
    return .{ .bytes = try a.dupe(u8, bytes[HEADER_BYTES..]), .claims = claims };
}

fn columns(storage: []const M31, log: u32, output: []engine.pcs.ColumnEvaluation) void {
    const rows = @as(usize, 1) << @intCast(log);
    std.debug.assert(storage.len == rows * output.len);
    for (output, 0..) |*column, i| column.* = .{ .log_size = log, .values = storage[i * rows ..][0..rows] };
}
pub const Key = struct {
    allocator: std.mem.Allocator,
    profile: Protocol.Profile,
    frontier_log: u32,
    arithmetic_log: u32,
    identity: [32]u8,
    root: W.H.Hash,
    tree: W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, profile: Protocol.Profile, frontier_log: u32, arithmetic_log: u32) !Key {
        if (profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        try LF.validateGeometry(1, 1, frontier_log);
        try LC.validateGeometry(1, 1, arithmetic_log);
        const front = try N.trace.fixed(a, .frontier, frontier_log);
        defer a.free(front);
        const arithmetic = try N.trace.fixed(a, .arithmetic, arithmetic_log);
        defer a.free(arithmetic);
        var fixed: [2 * S.FIXED]engine.pcs.ColumnEvaluation = undefined;
        columns(front, frontier_log, fixed[0..S.FIXED]);
        columns(arithmetic, arithmetic_log, fixed[S.FIXED..]);
        var scheme = try W.Prover.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.setStorePolynomialsCoefficients();
        scheme.setCompactPolynomialStorage(1);
        var channel = W.Channel.init();
        try scheme.commitBorrowedStreaming(a, &fixed, 64, &channel);
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        try tree.share(a);
        const root = tree.root();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("opstack-pure-p2/miller-source-fixed/v1\x00");
        h.update(S.AUTHORITY_VERSION);
        h.update(&profile.identity());
        h.update(&root);
        var geometry: [8]u8 = undefined;
        std.mem.writeInt(u32, geometry[0..4], frontier_log, .little);
        std.mem.writeInt(u32, geometry[4..8], arithmetic_log, .little);
        h.update(&geometry);
        // A lifted root alone does not bind native heights of individual zero
        // columns. Bind every ordered tree width and its source-owned height.
        for ([_][2]usize{ .{ S.FIXED, S.FIXED }, .{ LF.MAIN, LC.MAIN }, .{ LF.INTERACTION, LC.INTERACTION } }) |widths| {
            std.mem.writeInt(u32, geometry[0..4], @intCast(widths[0]), .little);
            std.mem.writeInt(u32, geometry[4..8], @intCast(widths[1]), .little);
            h.update(&geometry);
            for (widths, [_]u32{ frontier_log, arithmetic_log }) |width, log| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, log, .little);
                for (0..width) |_| h.update(&bytes);
            }
        }
        return .{ .allocator = a, .profile = profile, .frontier_log = frontier_log, .arithmetic_log = arithmetic_log, .identity = h.finalResult(), .root = root, .tree = tree };
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn validateSpan(self: *const Key, span: Span) !void {
        try LF.validateGeometry(span.calls, span.first_id, self.frontier_log);
        try LC.validateGeometry(span.calls, span.first_id, self.arithmetic_log);
        if (!std.mem.eql(u8, &self.root, &self.tree.root())) return error.OpTowerFixedAuthorityMismatch;
    }
    pub fn statement(self: *const Key, span: Span) ![32]u8 {
        try self.validateSpan(span);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("opstack-pure-p2/miller-source-statement/v1\x00");
        h.update(&self.identity);
        h.update(&self.root);
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..4], span.calls, .little);
        std.mem.writeInt(u32, bytes[4..8], span.first_id, .little);
        h.update(&bytes);
        return h.finalResult();
    }
    pub fn expected(self: *const Key, span: Span, ordinal: u32) !Manifest.Expected {
        return .{ .kind = .delegation, .ordinal = ordinal, .profile = self.profile, .global_relations = .{ .ram = false, .kio = false, .wire = true }, .mass = .{ .ram = 0, .kio = 0, .wire = 32 * @as(u64, span.calls) }, .fixed_identity = self.identity, .fixed = self.root, .statement = try self.statement(span), .local_instances = null };
    }
    pub fn logs(self: *const Key, a: std.mem.Allocator, tree: usize) ![]u32 {
        const widths = switch (tree) {
            0 => [2]usize{ S.FIXED, S.FIXED },
            1 => [2]usize{ LF.MAIN, LC.MAIN },
            2 => [2]usize{ LF.INTERACTION, LC.INTERACTION },
            else => return error.OpTowerProofShape,
        };
        const out = try a.alloc(u32, widths[0] + widths[1]);
        @memset(out[0..widths[0]], self.frontier_log);
        @memset(out[widths[0]..], self.arithmetic_log);
        return out;
    }
    fn append(self: *const Key, a: std.mem.Allocator, scheme: *W.Scheme, channel: *W.Channel) !void {
        if (scheme.trees.items.len != 0 or !std.meta.eql(scheme.config, self.profile.config())) return error.OpTowerPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, channel);
    }
};
fn validate(key: *const Key, span: Span, expected: Manifest.Expected) !void {
    if (!std.meta.eql(expected, try key.expected(span, expected.ordinal))) return error.OpTowerStatementMismatch;
}
fn checkPending(key: *const Key, span: Span, expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize) !void {
    try validate(key, span, expected);
    if (index != expected.ordinal or index >= pending.entries.len) return error.OpTowerOrdinal;
    if (!std.meta.eql(pending.entries[index].authority, expected) or pending.entries[index].local != null) return error.OpTowerManifestMismatch;
}
fn drawLocal(channel: *W.Channel, manifest: W.H.Hash, shared: Manifest.Shared) E.ChallengesFor(O) {
    channel.mixU32s(&.{ 0x4f50544c, 1, 9, 35 });
    channel.mixRoot(manifest);
    return .{ .bytes = channel.drawSecureFelt(), .carries = channel.drawSecureFelt(), .ssa = A.crypto.curves.equations.WireFor(O).draw(channel), .wire = shared.wire };
}
fn components(key: *const Key, span: Span, ch: E.ChallengesFor(O), claims: [4]O) struct { F, C } {
    return .{
        F{ .log_size = key.frontier_log, .public = .{ .calls = span.calls, .first_id = span.first_id }, .claims = .{ .ssa = claims[0], .wire = claims[1] }, .challenges = ch },
        C{ .log_size = key.arithmetic_log, .public = .{ .calls = span.calls, .first_id = span.first_id }, .claims = .{ .ssa = claims[2], .wire = claims[3] }, .challenges = ch, .offsets = .{ S.FIXED, LF.MAIN, LF.INTERACTION } },
    };
}
fn checkClaims(claims: [4]O) !void {
    for (claims) |value| for (value.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.OpTowerNoncanonicalClaim;
    if (!claims[0].add(claims[2]).isZero()) return error.OpTowerSsaNotClosed;
}
pub const Worker = struct {
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    allocator: std.mem.Allocator,
    parent_allocator: std.mem.Allocator,
    budget: *Budget,
    resources: ResourcePlan,
    key: *const Key,
    span: Span,
    expected: Manifest.Expected,
    frontier: SF,
    arithmetic: SC,
    scheme: W.Scheme,
    channel: W.Channel,
    sealed: bool = false,
    consumed: bool = false,
    owns_scheme: bool = true,
    pub fn init(backing: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, input: []const N.trace.Input, limits: Limits) !Worker {
        try validate(key, span, expected);
        if (input.len != span.calls) return error.OpTowerCallCount;
        const resources = try ResourcePlan.derive(key, span);
        try resources.admit(limits);
        const budget = try Budget.createRetainingParent(backing, limits.live_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var frontier = try SF.initWithoutFixed(a, input, span.first_id, key.frontier_log);
        errdefer frontier.deinit();
        var arithmetic = try SC.initWithoutFixed(a, input, span.first_id, key.arithmetic_log);
        errdefer arithmetic.deinit();
        var scheme = try W.Prover.init(a, key.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        return .{ .allocator = a, .parent_allocator = backing, .budget = budget, .resources = resources, .key = key, .span = span, .expected = expected, .frontier = frontier, .arithmetic = arithmetic, .scheme = scheme, .channel = Protocol.begin(key.profile, expected, key.identity, key.root) };
    }
    pub fn deinit(self: *Worker) void {
        self.frontier.deinit();
        self.arithmetic.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    fn takeColumns(self: *Worker, comptime tree: enum { main, interaction }) !Commit {
        const field = if (tree == .main) "main" else "interaction";
        const front = &@field(self.frontier, field);
        const arithmetic = &@field(self.arithmetic, field);
        if (front.len == 0 or arithmetic.len == 0) return error.OpTowerPhase;
        const left_width = if (tree == .main) LF.MAIN else LF.INTERACTION;
        const right_width = if (tree == .main) LC.MAIN else LC.INTERACTION;
        const a = self.allocator;
        const headers = try a.alloc(engine.pcs.ColumnEvaluation, left_width + right_width);
        errdefer a.free(headers);
        const backings = try a.alloc([]M31, 2);
        errdefer a.free(backings);
        columns(front.*, self.key.frontier_log, headers[0..left_width]);
        columns(arithmetic.*, self.key.arithmetic_log, headers[left_width..]);
        // Every fallible check/allocation precedes both ownership changes.
        backings[0] = front.*;
        backings[1] = arithmetic.*;
        front.* = &.{};
        arithmetic.* = &.{};
        return .{ .columns = headers, .backings = backings };
    }

    pub fn seal(self: *Worker) !Manifest.StageOne {
        if (self.sealed or self.consumed) return error.OpTowerPhase;
        self.consumed = true;
        try self.key.append(self.allocator, &self.scheme, &self.channel);
        const main = try self.takeColumns(.main);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        self.sealed = true;
        self.consumed = false;
        return .{ .main = self.scheme.trees.items[1].root(), .local = null };
    }
    pub fn complete(self: *Worker, pending: *const Manifest.Pending, index: usize) !Encoded {
        if (!self.sealed or self.consumed) return error.OpTowerPhase;
        try checkPending(self.key, self.span, self.expected, pending, index);
        try pending.checkPhysicalRoots(index, self.key.root, self.scheme.trees.items[1].root());
        self.consumed = true;
        const ch = drawLocal(&self.channel, pending.digest, pending.shared);
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "interaction_generation", "Miller SSA, range and global Wire interaction generation");
        defer generation.end();
        const fclaims = try self.frontier.generateInteraction(ch);
        const aclaims = try self.arithmetic.generateInteraction(ch);
        const claims = [4]O{ fclaims.ssa, fclaims.wire, aclaims.ssa, aclaims.wire };
        try checkClaims(claims);
        generation.end();
        Protocol.mixManifestAndClaims(&self.channel, pending.digest, &claims);
        const interaction = try self.takeColumns(.interaction);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, interaction.columns, interaction.backings, 64, self.native_recorder, &self.channel);
        try self.frontier.releaseAdvice();
        try self.arithmetic.releaseAdvice();
        const set = components(self.key, self.span, ch, claims);
        const handles = [_]engine.air.component_prover.ForField(O).ComponentProver{ set[0].asProverComponent(), set[1].asProverComponent() };
        const scheme = self.scheme;
        self.scheme = undefined;
        self.owns_scheme = false;
        var proof = try W.Prover.prove(self.allocator, &handles, &self.channel, scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(self.allocator);
        return .{ .bytes = try W.Wire.encodeProofBytesBinary(self.parent_allocator, proof.proof), .claims = claims };
    }
};
/// Only a freshly verified fragment claim. The caller must verify EVERY
/// admitted worker and close RAM/KIO/Wire before accepting an execution.
pub fn verify(a: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize, encoded: *const Encoded) !Manifest.Claims {
    return verifyWithCapture(a, key, span, expected, pending, index, encoded, null);
}
pub fn verifyWithCapture(a: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize, encoded: *const Encoded, output_capture: anytype) !Manifest.Claims {
    try checkPending(key, span, expected, pending, index);
    try checkClaims(encoded.claims);
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.root)) return error.OpTowerProofShape;
    try pending.checkPhysicalRoots(index, key.root, roots[1]);
    var channel = Protocol.begin(key.profile, expected, key.identity, key.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.profile.config());
    defer receiver.deinit(a);
    for (0..2) |tree| {
        const logs = try key.logs(a, tree);
        defer a.free(logs);
        try receiver.commit(a, roots[tree], logs, &channel);
    }
    const ch = drawLocal(&channel, pending.digest, pending.shared);
    Protocol.mixManifestAndClaims(&channel, pending.digest, &encoded.claims);
    const logs = try key.logs(a, 2);
    defer a.free(logs);
    try receiver.commit(a, roots[2], logs, &channel);
    const set = components(key, span, ch, encoded.claims);
    const handles = [_]core.air.components.ForField(O).Component{ set[0].asVerifierComponent(), set[1].asVerifierComponent() };
    if (comptime @TypeOf(output_capture) == @TypeOf(null)) {
        var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
        try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &receiver, &proof, &capture);
        capture.deinit(a);
    } else try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &receiver, &proof, output_capture);
    return .{ .ram = O.zero(), .kio = O.zero(), .wire = encoded.claims[1].add(encoded.claims[3]) };
}
