//! Explicit opt-in pure-P2 Miller local GKR. Successful checks leave physical
//! source-terminal and global KIO/Wire obligations PENDING; never execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Authority = @import("authority.zig");
const Frame = Authority;
const A = @import("stwo_riscv_frontend").rv64_air;
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Input = @import("source_inputs.zig");
const Base = @import("../pure_p2_native.zig");
const Framing = @import("../pure_p2_framing.zig");
const S = core.crypto.poseidon2_m31_sponge;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
pub const Wire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const WIRE_MAGIC = "OPMLGKR1";
pub fn encode(a: std.mem.Allocator, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof) ![]u8 {
    _ = try geometry.instances();
    const frames = try geometry.instances();
    return Wire.encodeFor(a, &frames, proof, WIRE_MAGIC);
}
pub fn decode(a: std.mem.Allocator, geometry: Authority.Geometry, bytes: []const u8) !Wire.Owned {
    _ = try geometry.instances();
    const frames = try geometry.instances();
    return Wire.decodeFor(a, &frames, bytes, WIRE_MAGIC);
}
pub const Channel = Base.Channel;
pub const Challenges = Input.Challenges;
pub const Scope = struct { statement: [32]u8, fixed: S.Digest, main: S.Digest, manifest: S.Digest, ordinal: u32 };
pub const DOMAIN = [_]u32{ 0x4f504d47, 1, 8, 9 };
fn mixDigest32(channel: *Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn begin(scope: Scope, geometry: Authority.Geometry) !Channel {
    _ = try geometry.instances();
    _ = try S.decode(scope.fixed);
    _ = try S.decode(scope.main);
    _ = try S.decode(scope.manifest);
    var channel = Channel.init();
    channel.mixU32s(&DOMAIN);
    mixDigest32(&channel, scope.statement);
    channel.mixRoot(scope.fixed);
    channel.mixRoot(scope.main);
    channel.mixRoot(scope.manifest);
    channel.mixU32s(&.{ scope.ordinal, 4, geometry.calls, geometry.first_id, geometry.frontier_log, geometry.arithmetic_log });
    for (try geometry.instances()) |instance| {
        channel.mixU32s(&.{ @intFromEnum(instance.role), instance.row_log, instance.queries() });
    }
    return channel;
}
/// The scope and each source policy are typed independently of the CPU receipt;
/// only the canonical bounded proof payload is shared.
pub fn receipt(scope: Scope, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof, marginals: []const []const O) !S.Digest {
    var writer = Base.ReceiptWriter{};
    try emitReceipt(scope, geometry, proof, marginals, &writer);
    return writer.finish();
}
/// One typed receipt authority for native and in-circuit values.
pub fn emitReceipt(scope: anytype, geometry: Authority.Geometry, proof: anytype, marginals: anytype, writer: anytype) !void {
    _ = try geometry.instances();
    for (DOMAIN) |tag| writer.tag(tag);
    writer.rawDigest(scope.statement);
    writer.root(scope.fixed);
    writer.root(scope.main);
    writer.root(scope.manifest);
    writer.integer(scope.ordinal);
    writer.integer(4);
    writer.integer(if (@hasField(@TypeOf(scope), "calls")) scope.calls else geometry.calls);
    writer.integer(if (@hasField(@TypeOf(scope), "first_id")) scope.first_id else geometry.first_id);
    writer.integer(geometry.frontier_log);
    writer.integer(geometry.arithmetic_log);
    var variables: [4]u32 = undefined;
    for (try geometry.instances(), &variables) |instance, *n| {
        n.* = try instance.variables();
        writer.integer(@intFromEnum(instance.role));
        writer.integer(instance.row_log);
        writer.integer(instance.queries());
    }
    try Framing.emitPayload(proof, &variables, marginals, writer);
}
/// The common mixed-height verifier point uses suffix variables per instance.
pub fn splitPoint(instance: Frame.Instance, point: []const O, variables: usize) !struct { row: []const O, lane: []const O } {
    if (variables != try instance.variables() or point.len < variables or point.len > 30) return error.LocalGkrPointGeometryMismatch;
    const local = point[point.len - variables ..];
    return .{ .row = local[0..instance.row_log], .lane = local[instance.row_log..] };
}
/// Borrowed terminal data only. Even a verifier-derived view is pending its
/// authenticated source AIR; this handle grants no execution acceptance.
pub const Terminal = struct { artifact: *const GV.GkrArtifact, challenges: Challenges, eta: O };
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    challenges: Challenges,
    eta: O,
    digest: S.Digest,
    pub fn terminal(self: *const @This()) Terminal {
        return .{ .artifact = &self.artifact, .challenges = self.challenges, .eta = self.eta };
    }
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verifyPending(a: std.mem.Allocator, scope: Scope, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof, expected_digest: S.Digest) !Pending {
    var channel = try begin(scope, geometry);
    const challenges = draw(&channel);
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp, .LogUp }, proof, &channel);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != 4) return error.LocalGkrPointGeometryMismatch;
    for (try geometry.instances(), artifact.n_variables_by_instance) |instance, n| _ = try splitPoint(instance, artifact.ood_point, n);
    try close(a, proof.output_claims_by_instance);
    const digest = try receipt(scope, geometry, proof, artifact.claims_to_verify_by_instance);
    if (!std.mem.eql(u8, &digest, &expected_digest)) return error.LocalGkrReceiptMismatch;
    return .{ .artifact = artifact, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    challenges: Challenges,
    eta: O,
    digest: S.Digest,
    pub fn terminal(self: *const @This()) Terminal {
        return .{ .artifact = &self.result.artifact, .challenges = self.challenges, .eta = self.eta };
    }
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
/// Uses the bounded source/checkpointed engine. The caller must impose a numeric
/// allocator budget before entering; this API grants no production admission.
pub fn proveUnbound(a: std.mem.Allocator, scope: Scope, geometry: Authority.Geometry, provider: anytype) !Unbound {
    return proveUnboundWithOptions(a, scope, geometry, provider, .{});
}
pub const ProverOptions = GP.Options;
pub fn proveUnboundWithOptions(a: std.mem.Allocator, scope: Scope, geometry: Authority.Geometry, provider: anytype, options: ProverOptions) !Unbound {
    var channel = try begin(scope, geometry);
    const challenges = draw(&channel);
    var inputs = try Input.Batch(@TypeOf(provider)).init(a, geometry, challenges, provider);
    defer inputs.deinit();
    var result = try GP.proveBatchSourceCheckpointedWithOptions(a, &channel, inputs.sources, options);
    errdefer result.deinit(a);
    try close(a, result.proof.output_claims_by_instance);
    const digest = try receipt(scope, geometry, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}

/// One shared SSA draw for both components; range relations have distinct
/// transcript labels. The local child never draws the global Wire challenge.
pub fn draw(channel: *Channel) Challenges {
    return drawFor(O, channel);
}
pub fn drawFor(comptime Field: type, channel: anytype) A.crypto.bn254_tower.narrow.equations.ChallengesFor(Field) {
    channel.mixU32s(&.{0x42595445});
    const bytes = channel.drawSecureFelt();
    channel.mixU32s(&.{0x55313500});
    const carries = channel.drawSecureFelt();
    channel.mixU32s(&.{0x53534123});
    const ssa = A.crypto.curves.equations.WireFor(Field).draw(channel);
    return .{ .bytes = bytes, .carries = carries, .ssa = ssa, .wire = .{ .offset = Field.zero(), .coefficients = @splat(Field.zero()) } };
}
/// BYTE and U15 close independently; SSA closes exactly across the two
/// source-owned instances. This disallows cancellation between unrelated buses.
pub fn close(a: std.mem.Allocator, outputs: []const []const O) !void {
    if (outputs.len != 4) return error.LocalGkrOutputShape;
    try Closure.close(a, outputs[0..1]);
    try Closure.close(a, outputs[1..2]);
    try Closure.close(a, outputs[2..4]);
}
test "Miller local GKR independently closes ranges and cross-instance SSA" {
    const M = core.fields.m31.M31;
    const p = [_]O{ O.one(), O.one() };
    const n = [_]O{ O.one().neg(), O.one() };
    const z = [_]O{ O.zero(), O.one() };
    try close(std.testing.allocator, &.{ &z, &z, &p, &n });
    try std.testing.expectError(error.UnclosedLocalGkr, close(std.testing.allocator, &.{ &p, &n, &z, &z }));
    try std.testing.expectError(error.UnclosedLocalGkr, close(std.testing.allocator, &.{ &z, &z, &p, &z }));
    const pole = [_]O{ O.zero(), O.zero() };
    try std.testing.expectError(error.LocalGkrPole, close(std.testing.allocator, &.{ &z, &z, &pole, &z }));
    var ch = Channel.init();
    const challenges = draw(&ch);
    try std.testing.expect(!challenges.bytes.eql(challenges.carries));
    try std.testing.expect(!challenges.ssa.offset.eql(O.fromBase(M.zero())));
}

test "Miller local GKR actual source child proves and rejects changed manifest and receipt" {
    const allocator = std.testing.allocator;
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(allocator, 1 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const N = A.crypto.bn254_tower.narrow;
    const input = [_]N.trace.Input{@splat(1)};
    var frontier = try N.trace.SourceForField(.frontier, O).initWithoutFixed(a, &input, 7, 8);
    defer frontier.deinit();
    var arithmetic = try N.trace.SourceForField(.arithmetic, O).initWithoutFixed(a, &input, 7, 15);
    defer arithmetic.deinit();
    const g = Authority.Geometry{ .calls = 1, .first_id = 7, .frontier_log = 8, .arithmetic_log = 15 };
    const scope = Scope{ .statement = [_]u8{71} ** 32, .fixed = Base.hashWords(&.{1}), .main = Base.hashWords(&.{2}), .manifest = Base.hashWords(&.{3}), .ordinal = 7 };
    var proof = try proveUnboundWithOptions(a, scope, g, Input.Provider{ .frontier = &frontier, .arithmetic = &arithmetic }, .{ .coefficient_encoding = .fixed4 });
    defer proof.deinit(a);
    const encoded = try encode(a, g, &proof.result.proof);
    defer a.free(encoded);
    var decoded = try decode(a, g, encoded);
    defer decoded.deinit();
    var checked = try verifyPending(a, scope, g, &decoded.proof, proof.digest);
    defer checked.deinit(a);
    try std.testing.expect(checked.eta.eql(proof.eta));
    try std.testing.expectEqual(@as(usize, 4), checked.artifact.n_variables_by_instance.len);
    var binding = try @import("witness.zig").Witness.init(a, g, &checked.challenges, Input.Provider{ .frontier = &frontier, .arithmetic = &arithmetic }, &checked.artifact, checked.eta);
    defer binding.deinit();
    var physical_data = try @import("component.zig").Data(.arithmetic).init(a, g, checked.terminal());
    defer physical_data.deinit();
    const physical_component = @import("component.zig").Component(.arithmetic){ .log_size = 15, .public = .{ .calls = 1, .first_id = 7 }, .data = &physical_data, .challenges = checked.challenges, .global_claim = O.zero() };
    _ = physical_component.asProverComponent();
    _ = physical_component.asVerifierComponent();
    try physical_component.validate();
    const expected_rows = [_]usize{ 32768, 32768, 32768, 256 };
    for (binding.columns, expected_rows) |data, rows| try std.testing.expectEqual(16 * rows, data.len);
    // The source-bound binding prefix must refuse a forged terminal marginal,
    // even when the GKR mechanics alone have already returned pending data.
    const original = checked.artifact.claims_to_verify_by_instance[0][0];
    checked.artifact.claims_to_verify_by_instance[0][0] = original.add(O.one());
    try std.testing.expectError(error.UnboundLocalGkrInput, @import("witness.zig").Witness.init(a, g, &checked.challenges, Input.Provider{ .frontier = &frontier, .arithmetic = &arithmetic }, &checked.artifact, checked.eta));
    checked.artifact.claims_to_verify_by_instance[0][0] = original;
    // Coherently forge BOTH the physical MAIN provider multiplicity and its
    // retained metadata. A source-terminal prefix still cannot authenticate
    // that altered table debt against the already verified child marginal.
    const provider_row = A.witness.physical(0, 15);
    inline for (.{ N.source.BYTE_MULT, N.source.CARRY_MULT }) |column| {
        const at = column * arithmetic.size() + provider_row;
        const original_cell = arithmetic.main[at];
        arithmetic.main[at] = original_cell.add(core.fields.m31.M31.one());
        if (column == N.source.BYTE_MULT) arithmetic.byte_counts[0] += 1 else arithmetic.carry_counts[0] += 1;
        try std.testing.expectError(error.UnboundLocalGkrInput, @import("witness.zig").Witness.init(a, g, &checked.challenges, Input.Provider{ .frontier = &frontier, .arithmetic = &arithmetic }, &checked.artifact, checked.eta));
        arithmetic.main[at] = original_cell;
        if (column == N.source.BYTE_MULT) arithmetic.byte_counts[0] -= 1 else arithmetic.carry_counts[0] -= 1;
    }
    var wrong_receipt = proof.digest;
    wrong_receipt[0] ^= 1;
    try std.testing.expectError(error.LocalGkrReceiptMismatch, verifyPending(a, scope, g, &decoded.proof, wrong_receipt));
    var wrong_scope = scope;
    wrong_scope.manifest = Base.hashWords(&.{4});
    if (verifyPending(a, wrong_scope, g, &decoded.proof, proof.digest)) |bad| {
        var owned_bad = bad;
        owned_bad.deinit(a);
        return error.ChangedManifestAccepted;
    } else |_| {}
    try std.testing.expectError(error.LocalGkrWireProfile, @import("../truth_local_gkr/native.zig").Wire.decodeFor(a, &(try g.instances()), encoded, "OPTLGKR1"));
}
