//! Explicit opt-in pure-P2 truth-local GKR. Successful checks leave physical
//! source-terminal and global KIO/Wire obligations PENDING; never execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Authority = @import("authority.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
const TF = @import("../../word16_global_execution/services/gkr_local/truth_fractions.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Input = @import("source_inputs.zig");
const Base = @import("../pure_p2_native.zig");
const Framing = @import("../pure_p2_framing.zig");
const S = core.crypto.poseidon2_m31_sponge;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
pub const Wire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const WIRE_MAGIC = "OPTLGKR1";
pub fn encode(a: std.mem.Allocator, shapes: [3]Authority.Shape, proof: *const GV.GkrBatchProof) ![]u8 {
    try Authority.validate(shapes);
    const frames = instances(shapes);
    return Wire.encodeFor(a, &frames, proof, WIRE_MAGIC);
}
pub fn decode(a: std.mem.Allocator, shapes: [3]Authority.Shape, bytes: []const u8) !Wire.Owned {
    try Authority.validate(shapes);
    const frames = instances(shapes);
    return Wire.decodeFor(a, &frames, bytes, WIRE_MAGIC);
}
pub const Channel = Base.Channel;
pub const Challenges = TF.ChallengesFor(O);
pub const Scope = struct { statement: [32]u8, fixed: S.Digest, main: S.Digest, manifest: S.Digest, ordinal: u32 };
pub const DOMAIN = [_]u32{ 0x4f505447, 1, 8, 9 };
fn mixDigest32(channel: *Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn instances(shapes: [3]Authority.Shape) [3]Frame.Instance {
    var out: [3]Frame.Instance = undefined;
    for (shapes, &out) |shape, *value| value.* = shape.instance();
    return out;
}
pub fn begin(scope: Scope, shapes: [3]Authority.Shape) !Channel {
    try Authority.validate(shapes);
    _ = try S.decode(scope.fixed);
    _ = try S.decode(scope.main);
    _ = try S.decode(scope.manifest);
    var channel = Channel.init();
    channel.mixU32s(&DOMAIN);
    mixDigest32(&channel, scope.statement);
    channel.mixRoot(scope.fixed);
    channel.mixRoot(scope.main);
    channel.mixRoot(scope.manifest);
    channel.mixU32s(&.{ scope.ordinal, 3 });
    for (shapes) |shape| {
        const instance = shape.instance();
        channel.mixU32s(&.{ @intFromEnum(instance.role), instance.row_log, instance.queries, @intFromEnum(instance.keccak_policy), @intFromEnum(instance.byte_policy) });
    }
    return channel;
}
/// The scope and each source policy are typed independently of the CPU receipt;
/// only the canonical bounded proof payload is shared.
pub fn receipt(scope: Scope, shapes: [3]Authority.Shape, proof: *const GV.GkrBatchProof, marginals: []const []const O) !S.Digest {
    var writer = Base.ReceiptWriter{};
    try emitReceipt(scope, shapes, proof, marginals, &writer);
    return writer.finish();
}
/// One typed receipt authority for native and in-circuit values.
pub fn emitReceipt(scope: anytype, shapes: [3]Authority.Shape, proof: anytype, marginals: anytype, writer: anytype) !void {
    try Authority.validate(shapes);
    for (DOMAIN) |tag| writer.tag(tag);
    writer.rawDigest(scope.statement);
    writer.root(scope.fixed);
    writer.root(scope.main);
    writer.root(scope.manifest);
    writer.integer(scope.ordinal);
    writer.integer(3);
    var variables: [3]u32 = undefined;
    for (shapes, &variables) |shape, *n| {
        const instance = shape.instance();
        n.* = try instance.variables();
        writer.integer(@intFromEnum(instance.role));
        writer.integer(instance.row_log);
        writer.integer(instance.queries);
        writer.integer(@intFromEnum(instance.keccak_policy));
        writer.integer(@intFromEnum(instance.byte_policy));
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
pub fn verifyPending(a: std.mem.Allocator, scope: Scope, shapes: [3]Authority.Shape, proof: *const GV.GkrBatchProof, expected_digest: S.Digest) !Pending {
    var channel = try begin(scope, shapes);
    const challenges = Challenges.draw(&channel);
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp }, proof, &channel);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != 3) return error.LocalGkrPointGeometryMismatch;
    for (shapes, artifact.n_variables_by_instance) |shape, n| _ = try splitPoint(shape.instance(), artifact.ood_point, n);
    try Closure.close(a, proof.output_claims_by_instance);
    const digest = try receipt(scope, shapes, proof, artifact.claims_to_verify_by_instance);
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
pub fn proveUnbound(a: std.mem.Allocator, scope: Scope, shapes: [3]Authority.Shape, provider: anytype) !Unbound {
    var channel = try begin(scope, shapes);
    const challenges = Challenges.draw(&channel);
    const frames = instances(shapes);
    var inputs = try Input.Batch(@TypeOf(provider)).init(a, &frames, &challenges, provider);
    defer inputs.deinit();
    var result = try GP.proveBatchSourceCheckpointed(a, &channel, inputs.sources);
    errdefer result.deinit(a);
    try Closure.close(a, result.proof.output_claims_by_instance);
    const digest = try receipt(scope, shapes, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
test "OP truth local GKR native source proof binds manifest and ninth receipt coordinate" {
    const M = core.fields.m31.M31;
    const Provider = struct {
        pub fn emitRange(_: @This(), _: Frame.Instance, row: usize, first: usize, count: usize, sink: anytype) !void {
            for (first..first + count) |query| sink.emitBase(.byte, [1]M{M.fromCanonical(@intCast(row / 2 + query))}, if (row % 2 == 0) M.one() else M.one().neg());
        }
    };
    // Canonical secp catalog geometry, but a synthetic zero-sum provider tests
    // protocol mechanics only; it is NOT a source-terminal proof.
    const shapes = [_]Authority.Shape{ .{ .original = .{ .kind = .product, .log_size = 5 } }, .{ .original = .{ .kind = .linear, .log_size = 5 } }, .{ .original = .{ .kind = .bytes, .log_size = 8 } } };
    const scope = Scope{ .statement = [_]u8{71} ** 32, .fixed = Base.hashWords(&.{1}), .main = Base.hashWords(&.{2}), .manifest = Base.hashWords(&.{3}), .ordinal = 7 };
    const a = std.testing.allocator;
    var proof = try proveUnbound(a, scope, shapes, Provider{});
    defer proof.deinit(a);
    const bytes = try encode(a, shapes, &proof.result.proof);
    defer a.free(bytes);
    var decoded = try decode(a, shapes, bytes);
    defer decoded.deinit();
    var pending = try verifyPending(a, scope, shapes, &decoded.proof, proof.digest);
    defer pending.deinit(a);
    try std.testing.expect(proof.eta.eql(pending.eta));
    try std.testing.expectEqualSlices(O, proof.result.artifact.ood_point, pending.artifact.ood_point);
    var witness = try @import("witness.zig").Witness.init(a, shapes, &proof.challenges, Provider{}, &proof.result.artifact, proof.eta);
    defer witness.deinit();
    for (shapes, witness.columns) |shape, data| {
        const rows = try shape.instance().rows();
        const last = @import("stwo_riscv_frontend").rv64_air.witness.physical(rows - 1, shape.instance().row_log);
        for (0..8) |c| try std.testing.expect(data[(8 + c) * rows + last].isZero());
    }
    var changed = proof.digest;
    changed[32] ^= 1;
    try std.testing.expectError(error.LocalGkrReceiptMismatch, verifyPending(a, scope, shapes, &proof.result.proof, changed));
    var other = scope;
    other.manifest = Base.hashWords(&.{4});
    if (verifyPending(a, other, shapes, &proof.result.proof, proof.digest)) |value| {
        var own = value;
        own.deinit(a);
        return error.UnexpectedManifestAdmission;
    } else |err| try std.testing.expect(err != error.OutOfMemory);
}
