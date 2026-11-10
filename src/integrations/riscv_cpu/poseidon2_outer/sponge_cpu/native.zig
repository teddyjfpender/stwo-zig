//! New CPU source domain; common checkpoint, payload codec and closure engine.
//! A successful local check is still pending physical MAIN and shared claims.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Frame = @import("frame.zig");
const Provider = @import("provider.zig");
const Base = @import("../pure_p2_native.zig");
const Framing = @import("../pure_p2_framing.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const S = core.crypto.poseidon2_m31_sponge;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
const Profile = engine.lookups.gkr_profile;
pub const Wire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const WIRE_MAGIC = "OPSPCPU1";
pub const DOMAIN = [_]u32{ 0x53504350, 1, 8, 9 };
pub const Scope = struct { statement: [32]u8, fixed: S.Digest, main: S.Digest, ordinal: u32, epoch: u16, calls: u32 };
pub const Channel = Base.Channel;
pub fn encode(a: std.mem.Allocator, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof) ![]u8 {
    var wire_phase = try Profile.begin("gkr_wire_encoding", "Local GKR binary wire encoding");
    defer wire_phase.end();
    return Wire.encodeFor(a, instances, proof, WIRE_MAGIC);
}
pub fn decode(a: std.mem.Allocator, instances: []const Frame.Instance, bytes: []const u8) !Wire.Owned {
    return Wire.decodeFor(a, instances, bytes, WIRE_MAGIC);
}
fn validate(scope: Scope, instances: []const Frame.Instance) !void {
    if (instances.len < 2 or instances.len > 256) return error.SpongeCpuGeometry;
    for (instances[0 .. instances.len - 1]) |v| {
        if (v != .legacy or v.legacy.origin == .sponge) return error.SpongeCpuRequiresDetachedSetup;
    }
    const last = instances[instances.len - 1];
    if (last != .frontier) return error.SpongeCpuFrontierMissing;
    try @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge.serialized.frontier.validatePublic(scope.calls, last.rowLog(), scope.epoch, scope.ordinal);
    for (instances) |instance| _ = try instance.variables();
}
pub fn begin(scope: Scope, instances: []const Frame.Instance) !Channel {
    try validate(scope, instances);
    _ = try S.decode(scope.fixed);
    _ = try S.decode(scope.main);
    var channel = Channel.init();
    channel.mixU32s(&DOMAIN);
    var id: [8]u32 = undefined;
    for (&id, 0..) |*v, i| v.* = std.mem.readInt(u32, scope.statement[4 * i ..][0..4], .little);
    channel.mixU32s(&id);
    channel.mixRoot(scope.fixed);
    channel.mixRoot(scope.main);
    channel.mixU32s(&.{ scope.ordinal, scope.epoch, scope.calls, @intCast(instances.len) });
    for (instances) |instance| {
        channel.mixU32s(&instance.tag());
        channel.mixU32s(&.{ instance.rowLog(), instance.queries() });
        channel.mixU64(instance.fixedOffset());
        channel.mixU64(instance.mainOffset());
    }
    return channel;
}
/// One namespace choice derived from the ACTUAL legacy CPU row recipe.
fn draw(channel: *Channel, instances: []const Frame.Instance) Provider.Challenges {
    for (instances) |v| if (v == .legacy and v.legacy.origin == .core and v.legacy.origin.core == .cpu and v.legacy.terms == 14) return Provider.Challenges.drawV3(channel);
    return Provider.Challenges.draw(channel);
}
pub fn receipt(scope: Scope, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof, marginals: []const []const O) !S.Digest {
    var writer = Base.ReceiptWriter{};
    try emitReceipt(scope, instances, proof, marginals, &writer);
    return writer.finish();
}
pub fn emitReceipt(scope: anytype, instances: []const Frame.Instance, proof: anytype, marginals: anytype, writer: anytype) !void {
    for (DOMAIN) |tag| writer.tag(tag);
    writer.rawDigest(scope.statement);
    writer.root(scope.fixed);
    writer.root(scope.main);
    writer.integer(scope.ordinal);
    writer.integer(scope.epoch);
    writer.integer(scope.calls);
    writer.integer(instances.len);
    var variables: [256]u32 = undefined;
    if (instances.len < 2 or instances.len > variables.len) return error.SpongeCpuGeometry;
    for (instances, variables[0..instances.len]) |instance, *n| {
        for (instance.tag()) |tag| writer.integer(tag);
        writer.integer(instance.rowLog());
        writer.integer(instance.queries());
        writer.integer(instance.fixedOffset());
        writer.integer(instance.mainOffset());
        n.* = try instance.variables();
    }
    try Framing.emitPayload(proof, variables[0..instances.len], marginals, writer);
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    challenges: Provider.Challenges,
    eta: O,
    digest: S.Digest,
    pub fn checkedLegacy(self: *const Pending, count: usize, storage: *GV.GkrArtifact) !@import("../../word16_global_execution/services/gkr_local/terminal_view.zig").Checked {
        // Borrow the exact already-verified artifact prefix. Keep the global
        // common point; smaller instances take its suffix in the original AIR.
        if (count + 1 != self.artifact.n_variables_by_instance.len or self.artifact.claims_to_verify_by_instance.len != count + 1) return error.SpongeCpuGeometry;
        storage.* = self.artifact;
        storage.n_variables_by_instance = storage.n_variables_by_instance[0..count];
        storage.claims_to_verify_by_instance = storage.claims_to_verify_by_instance[0..count];
        return .{ .artifact = storage, .challenges = self.challenges, .eta = self.eta };
    }
    pub fn deinit(self: *Pending, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verifyPending(a: std.mem.Allocator, scope: Scope, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof, expected: S.Digest) !Pending {
    var channel = try begin(scope, instances);
    const challenges = draw(&channel, instances);
    const gates = try a.alloc(GV.Gate, instances.len);
    defer a.free(gates);
    @memset(gates, .LogUp);
    var artifact = try GV.partiallyVerifyBatch(a, gates, proof, &channel);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != instances.len) return error.SpongeCpuGeometry;
    for (instances, artifact.n_variables_by_instance) |instance, n| _ = try Frame.splitPoint(instance, artifact.ood_point, n);
    try Closure.close(a, proof.output_claims_by_instance);
    const digest = try receipt(scope, instances, proof, artifact.claims_to_verify_by_instance);
    if (!std.mem.eql(u8, &digest, &expected)) return error.LocalGkrReceiptMismatch;
    return .{ .artifact = artifact, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    challenges: Provider.Challenges,
    eta: O,
    digest: S.Digest,
    pub fn deinit(self: *Unbound, a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
/// Execution-only storage choice; neither proof framing nor transcript changes.
/// Callers selecting all_upper must separately admit the dense source-storage
/// planning reserve (80 B/fact plus metadata), not the checkpointed 52 B charge.
pub const SourceStorage = enum { checkpointed, all_upper };
pub fn proveUnbound(a: std.mem.Allocator, scope: Scope, instances: []const Frame.Instance, provider: Provider.Provider) !Unbound {
    return proveUnboundWithSourceStorage(a, scope, instances, provider, .checkpointed);
}
pub fn proveUnboundWithSourceStorage(a: std.mem.Allocator, scope: Scope, instances: []const Frame.Instance, provider: Provider.Provider, storage: SourceStorage) !Unbound {
    var channel = try begin(scope, instances);
    const challenges = draw(&channel, instances);
    var inputs = try @import("source_inputs.zig").Batch.init(a, instances, challenges, provider);
    defer inputs.deinit();
    var result = switch (storage) {
        .checkpointed => try GP.proveBatchSourceCheckpointed(a, &channel, inputs.sources),
        .all_upper => try GP.proveBatchSource(a, &channel, inputs.sources),
    };
    errdefer result.deinit(a);
    var terminal_phase = try Profile.begin("gkr_terminal_receipt", "Terminal closure and Poseidon receipt serialization");
    defer terminal_phase.end();
    try Closure.close(a, result.proof.output_claims_by_instance);
    const digest = try receipt(scope, instances, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
