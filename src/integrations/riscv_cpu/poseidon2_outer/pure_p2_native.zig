//! Native numerical twin for the explicitly new OP pure-P2 local protocol.
//! A checked local child still returns a PENDING physical terminal binding:
//! this module cannot accept an execution, root, manifest or RAM claim.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const Receipt = @import("../word16_global_execution/services/gkr_local/receipt.zig");
const Closure = @import("../word16_global_execution/services/gkr_local/closure.zig");
const Input = @import("../word16_global_execution/services/gkr_local/source_inputs.zig");
const S = core.crypto.poseidon2_m31_sponge;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
pub const Channel = core.channel.poseidon2_m31.Om31ChannelV2;
pub const Challenges = @import("../word16_global_execution/services/gkr_local/challenges.zig").For(O);
pub const Digest = S.Digest;
/// Separates the OP candidate from the older unqualified AST and all raw
/// Blake/mixed native suites. Neither existing selector nor decoder admits it.
pub const LOCAL_DOMAIN = [_]u32{ 0x4f504c32, 1, 9 };
pub const Scope = struct { statement: [32]u8, fixed: Digest, main: Digest, ordinal: u32 };
fn mixDigest32(channel: *Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn begin(scope: Scope, instances: []const Frame.Instance) !Channel {
    if (instances.len == 0 or instances.len > Receipt.MAX_INSTANCES) return error.LocalGkrReceiptShape;
    _ = try S.decode(scope.fixed);
    _ = try S.decode(scope.main);
    var channel = Channel.init();
    channel.mixU32s(&LOCAL_DOMAIN);
    channel.mixU32s(&.{ if (Frame.v3Instances(instances)) @as(u32, 0x53474b33) else 0x53474b31, 8, scope.ordinal });
    mixDigest32(&channel, scope.statement);
    channel.mixRoot(scope.fixed);
    channel.mixRoot(scope.main);
    channel.mixU32s(&.{@intCast(instances.len)});
    for (instances) |instance| {
        _ = try instance.variables();
        channel.mixU32s(&Frame.originWords(instance.origin));
        channel.mixU32s(&.{ instance.row_log, instance.terms });
        channel.mixU64(instance.fixed_offset);
        channel.mixU64(instance.main_offset);
    }
    return channel;
}
pub fn hashWords(words: []const u32) Digest {
    var sponge = S.Sponge.init(.words);
    sponge.absorbU32(0x50324632);
    sponge.absorbU64(words.len);
    for (words) |word| sponge.absorbU32(word);
    return sponge.digest();
}
pub fn hashBytes(bytes: []const u8) Digest {
    var sponge = S.Sponge.init(.bytes);
    sponge.absorbU32(0x50325232);
    sponge.absorbU64(bytes.len);
    for (bytes) |byte| sponge.absorb(core.fields.m31.M31.fromCanonical(byte));
    return sponge.digest();
}
pub const ReceiptWriter = struct {
    sponge: S.Sponge = S.Sponge.init(.words),
    failure: ?anyerror = null,
    fields: usize = 0,
    pub fn tag(self: *@This(), value: u32) void {
        self.sponge.absorbU32(value);
    }
    pub fn integer(self: *@This(), value: u64) void {
        self.sponge.absorbU64(value);
    }
    pub fn rawDigest(self: *@This(), value: [32]u8) void {
        for (0..8) |i| self.sponge.absorbU32(std.mem.readInt(u32, value[4 * i ..][0..4], .little));
    }
    pub fn root(self: *@This(), value: Digest) void {
        const coordinates = S.decode(value) catch |err| {
            self.failure = err;
            return;
        };
        self.sponge.absorbFelts(&coordinates);
    }
    pub fn field(self: *@This(), value: O) !void {
        if (self.fields >= 1 << 20) return error.LocalGkrProofLimit;
        self.fields += 1;
        for (value.toM31Array()) |coordinate| {
            if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalLocalGkrCoordinate;
            self.sponge.absorb(coordinate);
        }
    }
    pub fn finish(self: *@This()) !Digest {
        if (self.failure) |err| return err;
        return self.sponge.digest();
    }
};
pub fn receipt(scope: Scope, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof, marginals: []const []const O) !Digest {
    var writer = ReceiptWriter{};
    try @import("pure_p2_framing.zig").emit(scope, instances, proof, marginals, &writer);
    return writer.finish();
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    challenges: Challenges,
    eta: O,
    digest: Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verifyPending(a: std.mem.Allocator, scope: Scope, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof, expected_digest: Digest) !Pending {
    var channel = try begin(scope, instances);
    const challenges = Challenges.drawForInstances(&channel, instances);
    const gates = try a.alloc(GV.Gate, instances.len);
    defer a.free(gates);
    @memset(gates, .LogUp);
    var artifact = try GV.partiallyVerifyBatch(a, gates, proof, &channel);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != instances.len) return error.LocalGkrPointGeometryMismatch;
    for (instances, artifact.n_variables_by_instance) |instance, variables| _ = try Frame.splitPoint(instance, artifact.ood_point, variables);
    try Closure.close(a, proof.output_claims_by_instance);
    const digest = try receipt(scope, instances, proof, artifact.claims_to_verify_by_instance);
    if (!std.mem.eql(u8, &digest, &expected_digest)) return error.LocalGkrReceiptMismatch;
    return .{ .artifact = artifact, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    challenges: Challenges,
    eta: O,
    digest: Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
/// Numerical source replay uses the existing checkpointed prover. Caller owns
/// resource admission; no retained MAIN or source provider escapes this call.
pub fn proveUnbound(a: std.mem.Allocator, scope: Scope, instances: []const Frame.Instance, provider: anytype) !Unbound {
    var channel = try begin(scope, instances);
    const challenges = Challenges.drawForInstances(&channel, instances);
    var inputs = try Input.Batch(@TypeOf(provider)).init(a, instances, &challenges, provider);
    defer inputs.deinit();
    var result = try GP.proveBatchSourceCheckpointed(a, &channel, inputs.sources);
    errdefer result.deinit(a);
    try Closure.close(a, result.proof.output_claims_by_instance);
    const digest = try receipt(scope, instances, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
