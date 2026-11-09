//! Explicit opt-in sealed-MAIN truth worker. Local tables use source-bound GKR;
//! global KIO/Wire keep their original classic obligations and manifest scope.
//! Existing catalog/CLI/root factories do not admit this authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const O = W.O;
const Manifest = @import("../pure_p2_manifest.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Old = @import("../../word16_global_execution/services/gkr_local/truth_worker.zig");
const Base = @import("../pure_p2_truth_worker.zig");
const Metadata = @import("../../word16_global_execution/services/gkr_local/truth_metadata.zig");
const Shapes = @import("authority.zig");
const N = @import("native.zig");
const Components = @import("components.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Limits = struct { live_bytes: usize, main_bytes: usize, interaction_bytes: usize, gkr_bytes: usize };
pub const Encoded = struct {
    bytes: []u8,
    local: []u8,
    receipt: [36]u8,
    claims: [2]O,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.local);
        self.* = undefined;
    }
};
fn kind(truth: R.Truth) @import("../../word16_global_execution/services/gkr_local/manifest.zig").Kind {
    return if (truth == .keccak) .keccak else if (truth.secp.setup.kind == .add) .secp_add else .secp_double;
}
pub fn logs(a: std.mem.Allocator, shapes: [3]Shapes.Shape, tree: usize) ![]u32 {
    if (tree > 2) return error.InvalidLocalGkrTruthShape;
    var count: usize = 0;
    for (shapes) |shape| count += shape.widths()[tree];
    const out = try a.alloc(u32, count);
    var at: usize = 0;
    for (shapes) |shape| {
        const width = shape.widths()[tree];
        @memset(out[at..][0..width], shape.original.log_size);
        at += width;
    }
    return out;
}
pub const Key = struct {
    base: Base.Key,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, truth: R.Truth, profile: Protocol.Profile) !Key {
        const shapes = try Shapes.shapes(truth);
        var base = try Base.Key.init(a, truth, profile);
        errdefer base.deinit();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(Shapes.DOMAIN);
        hash.update(&base.identity);
        for (shapes) |shape| {
            var words: [20]u8 = undefined;
            const values = [_]u32{ @intFromEnum(shape.original.kind), shape.original.log_size, @intCast(shape.widths()[0]), @intCast(shape.widths()[1]), @intCast(shape.widths()[2]) };
            for (values, 0..) |value, i| std.mem.writeInt(u32, words[i * 4 ..][0..4], value, .little);
            hash.update(&words);
        }
        return .{ .base = base, .identity = hash.finalResult() };
    }
    pub fn deinit(self: *Key) void {
        self.base.deinit();
        self.* = undefined;
    }
    pub fn require(self: *const Key, truth: R.Truth) !void {
        _ = try Shapes.shapes(truth);
        try self.base.require(truth);
    }
    pub fn statement(self: *const Key, truth: R.Truth) ![32]u8 {
        try self.require(truth);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(Shapes.DOMAIN);
        h.update(&self.identity);
        h.update(&try self.base.statement(truth));
        return h.finalResult();
    }
    pub fn expected(self: *const Key, truth: R.Truth, ordinal: u32) !Manifest.Expected {
        return .{ .kind = kind(truth), .ordinal = ordinal, .profile = self.base.profile, .fixed_identity = self.identity, .fixed = self.base.root, .statement = try self.statement(truth), .mass = try Old.truthMass(truth), .global_relations = .{ .ram = false, .kio = truth == .keccak, .wire = truth == .secp }, .local_instances = null };
    }
};
pub fn validateExpected(key: *const Key, truth: R.Truth, expected: Manifest.Expected) !void {
    if (!std.meta.eql(expected, try key.expected(truth, expected.ordinal))) return error.OpTruthLocalExpected;
}
fn checkPending(expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize) !void {
    if (index != expected.ordinal or index >= pending.entries.len) return error.GlobalGkrManifestOrdinal;
    if (!std.meta.eql(pending.shared, try Manifest.drawShared(pending.digest))) return error.OpTruthLocalManifest;
    const entry = pending.entries[index];
    if (!std.meta.eql(entry.authority, expected) or !std.meta.eql(entry.global_relations, expected.global_relations) or entry.local != null or entry.scope.ordinal != expected.ordinal or !std.mem.eql(u8, &entry.scope.fixed, &expected.fixed) or !std.mem.eql(u8, &entry.scope.statement, &expected.statement)) return error.OpTruthLocalManifest;
}
pub fn scopeFor(expected: Manifest.Expected, main: [36]u8, manifest: [36]u8) N.Scope {
    return .{ .statement = expected.statement, .fixed = expected.fixed, .main = main, .manifest = manifest, .ordinal = expected.ordinal };
}
pub fn mixClaims(channel: *W.Channel, manifest: [36]u8, receipt: [36]u8, claims: [2]O) void {
    channel.mixU32s(&.{ 0x4f505447, 2, 8, 9, 2 });
    channel.mixRoot(manifest);
    channel.mixRoot(receipt);
    channel.mixFelts(&claims);
}
pub const Worker = struct {
    allocator: std.mem.Allocator,
    parent_allocator: std.mem.Allocator,
    budget_owner: *Budget,
    key: *const Key,
    truth: R.Truth,
    source: ?R.TruthSource,
    expected: Manifest.Expected,
    limits: Limits,
    scheme: W.Scheme,
    channel: W.Channel,
    gkr_options: N.ProverOptions = .{},
    sealed: bool = false,
    consumed: bool = false,
    owns_scheme: bool = true,
    pub fn init(backing: std.mem.Allocator, key: *const Key, truth: R.Truth, builder: Base.SourceBuilder, expected: Manifest.Expected, limits: Limits) !Worker {
        return initWithGkrOptions(backing, key, truth, builder, expected, limits, .{});
    }
    /// Honest prover encoding policy; default construction preserves the
    /// trimmed control. The accepting protocol already admits lengths0..4.
    pub fn initWithGkrOptions(backing: std.mem.Allocator, key: *const Key, truth: R.Truth, builder: Base.SourceBuilder, expected: Manifest.Expected, limits: Limits, gkr_options: N.ProverOptions) !Worker {
        try validateExpected(key, truth, expected);
        const shapes = try Shapes.shapes(truth);
        if (limits.live_bytes == 0 or limits.gkr_bytes == 0) return error.OpTruthLocalBudget;
        var main_bytes: usize = 0;
        var interaction_bytes: usize = 0;
        for (shapes) |shape| {
            const rows = try shape.instance().rows();
            main_bytes = try std.math.add(usize, main_bytes, try std.math.mul(usize, 4 * shape.widths()[1], rows));
            interaction_bytes = try std.math.add(usize, interaction_bytes, try std.math.mul(usize, 4 * shape.widths()[2], rows));
        }
        if (main_bytes > limits.main_bytes or interaction_bytes > limits.interaction_bytes) return error.OpTruthLocalBudget;
        const owner = try Budget.createRetainingParent(backing, limits.live_bytes);
        errdefer owner.destroy();
        const a = owner.allocator();
        var source = try builder.build(builder.context, a, truth);
        errdefer source.deinit();
        try Base.validateAllocator(a, &source);
        _ = try Metadata.Provider.initClassic(&source, N.instances(shapes));
        var scheme = try W.Prover.init(a, key.base.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        return .{ .allocator = a, .parent_allocator = backing, .budget_owner = owner, .key = key, .truth = truth, .source = source, .expected = expected, .limits = limits, .gkr_options = gkr_options, .scheme = scheme, .channel = Protocol.begin(key.base.profile, expected, key.identity, key.base.root) };
    }
    pub fn deinit(self: *Worker) void {
        if (self.source) |*source| source.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.budget_owner.destroy();
        self.* = undefined;
    }
    pub fn seal(self: *Worker) !Manifest.StageOne {
        if (self.sealed or self.consumed) return error.OpTruthLocalPhase;
        self.consumed = true;
        try self.key.base.append(self.allocator, &self.scheme, &self.channel);
        const main = try self.source.?.takeMain();
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, main.columns, main.backings, 64, null, &self.channel);
        self.sealed = true;
        self.consumed = false;
        return .{ .main = self.scheme.trees.items[1].root(), .local = null };
    }
    pub fn complete(self: *Worker, pending: *const Manifest.Pending, index: usize) !Encoded {
        if (!self.sealed or self.consumed) return error.OpTruthLocalPhase;
        try checkPending(self.expected, pending, index);
        try pending.checkPhysicalRoots(index, self.key.base.root, self.scheme.trees.items[1].root());
        self.consumed = true;
        const a = self.allocator;
        const shapes = try Shapes.shapes(self.truth);
        const metadata = try Metadata.Provider.initClassic(&self.source.?, N.instances(shapes));
        const child_owner = try Budget.createRetainingParent(a, self.limits.gkr_bytes);
        defer child_owner.destroy();
        const child_a = child_owner.allocator();
        const scope = scopeFor(self.expected, self.scheme.trees.items[1].root(), pending.digest);
        var child = try N.proveUnboundWithOptions(child_a, scope, shapes, metadata, self.gkr_options);
        defer child.deinit(child_a);
        // The prover already has these exact terminal marginals. Re-verifying
        // its own GKR proof here adds no authority; the fresh receiver does so.
        const checked = child.terminal();
        const generated = try Components.generate(a, &self.source.?, shapes, metadata, checked, pending.shared, self.limits.interaction_bytes);
        var owns_inter = true;
        defer if (owns_inter) generated.commit.deinit(a);
        var components = try Components.Components.init(a, self.truth, checked, pending.shared, generated.claims);
        defer components.deinit();
        const handles = components.provers();
        mixClaims(&self.channel, pending.digest, child.digest, generated.claims);
        owns_inter = false;
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, generated.commit.columns, generated.commit.backings, 64, null, &self.channel);
        self.source.?.deinit();
        self.source = null;
        const local = try N.encode(self.parent_allocator, shapes, &child.result.proof);
        errdefer self.parent_allocator.free(local);
        self.owns_scheme = false;
        var proof = try W.Prover.prove(a, &handles, &self.channel, self.scheme, .{});
        defer proof.deinit(a);
        return .{ .bytes = try W.Wire.encodeProofBytesBinary(self.parent_allocator, proof.proof), .local = local, .receipt = child.digest, .claims = generated.claims };
    }
};
pub fn verify(a: std.mem.Allocator, key: *const Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize, encoded: *const Encoded) !Manifest.Claims {
    return verifyWithCapture(a, key, truth, expected, pending, index, encoded, null);
}
pub fn verifyWithCapture(a: std.mem.Allocator, key: *const Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize, encoded: *const Encoded, output_capture: anytype) !Manifest.Claims {
    try validateExpected(key, truth, expected);
    try checkPending(expected, pending, index);
    const shapes = try Shapes.shapes(truth);
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.base.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.base.root)) return error.OpTruthLocalProofShape;
    try pending.checkPhysicalRoots(index, key.base.root, roots[1]);
    var local = try N.decode(a, shapes, encoded.local);
    defer local.deinit();
    var checked = try N.verifyPending(a, scopeFor(expected, roots[1], pending.digest), shapes, &local.proof, encoded.receipt);
    defer checked.deinit(a);
    var components = try Components.Components.init(a, truth, checked.terminal(), pending.shared, encoded.claims);
    defer components.deinit();
    const handles = components.verifiers();
    var channel = Protocol.begin(key.base.profile, expected, key.identity, key.base.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.base.profile.config());
    defer receiver.deinit(a);
    for (0..2) |tree| {
        const tree_logs = try components.logs(a, tree);
        defer a.free(tree_logs);
        try receiver.commit(a, roots[tree], tree_logs, &channel);
    }
    mixClaims(&channel, pending.digest, encoded.receipt, encoded.claims);
    const inter_logs = try components.logs(a, 2);
    defer a.free(inter_logs);
    try receiver.commit(a, roots[2], inter_logs, &channel);
    if (comptime @TypeOf(output_capture) == @TypeOf(null)) {
        var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
        try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &receiver, &proof, &capture);
        capture.deinit(a);
    } else try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &receiver, &proof, output_capture);
    return .{ .ram = O.zero(), .kio = if (truth == .keccak) encoded.claims[0] else O.zero(), .wire = if (truth == .secp) encoded.claims[0].add(encoded.claims[1]) else O.zero() };
}
const MAGIC = "OPTLPCS1";
const HEADER = 124;
pub fn encode(a: std.mem.Allocator, value: *const Encoded) ![]u8 {
    _ = try core.crypto.poseidon2_m31_sponge.decode(value.receipt);
    if (value.local.len > N.Wire.MAX_BYTES or value.bytes.len == 0) return error.OpTruthLocalEnvelope;
    const size = try std.math.add(usize, HEADER, try std.math.add(usize, value.bytes.len, value.local.len));
    for (value.claims) |claim| for (claim.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.OpTruthLocalEnvelope;
    const out = try a.alloc(u8, size);
    @memcpy(out[0..8], MAGIC);
    std.mem.writeInt(u64, out[8..16], value.bytes.len, .little);
    std.mem.writeInt(u64, out[16..24], value.local.len, .little);
    @memcpy(out[24..60], &value.receipt);
    for (value.claims, 0..) |claim, j| for (claim.toM31Array(), 0..) |coordinate, i| std.mem.writeInt(u32, out[60 + 32 * j + 4 * i ..][0..4], coordinate.v, .little);
    @memcpy(out[HEADER..][0..value.bytes.len], value.bytes);
    @memcpy(out[HEADER + value.bytes.len ..], value.local);
    return out;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, max_bytes: usize) !Encoded {
    if (bytes.len < HEADER or bytes.len > max_bytes or !std.mem.eql(u8, bytes[0..8], MAGIC)) return error.OpTruthLocalEnvelope;
    const pcs = std.math.cast(usize, std.mem.readInt(u64, bytes[8..16], .little)) orelse return error.OpTruthLocalEnvelope;
    const local = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .little)) orelse return error.OpTruthLocalEnvelope;
    if (pcs == 0 or pcs > bytes.len - HEADER or local > N.Wire.MAX_BYTES or local != bytes.len - HEADER - pcs) return error.OpTruthLocalEnvelope;
    const receipt = bytes[24..60].*;
    _ = try core.crypto.poseidon2_m31_sponge.decode(receipt);
    var claims: [2]O = undefined;
    for (&claims, 0..) |*claim, j| {
        var coords: [8]core.fields.m31.M31 = undefined;
        for (&coords, 0..) |*coordinate, i| {
            const value = std.mem.readInt(u32, bytes[60 + 32 * j + 4 * i ..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.OpTruthLocalEnvelope;
            coordinate.* = core.fields.m31.M31.fromCanonical(value);
        }
        claim.* = O.fromM31Array(coords);
    }
    const proof = try a.dupe(u8, bytes[HEADER..][0..pcs]);
    errdefer a.free(proof);
    return .{ .bytes = proof, .local = try a.dupe(u8, bytes[HEADER + pcs ..]), .receipt = receipt, .claims = claims };
}
