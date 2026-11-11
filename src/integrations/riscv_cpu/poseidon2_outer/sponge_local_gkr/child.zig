//! Typed detached-sponge child. All eight source terminals remain pending
//! their physical MAIN/OODS binding; global RAM/KIO/Wire close externally.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const Shared = @import("../full_p2_child.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Authority = @import("authority.zig");
const Native = @import("native.zig");
const Fractions = @import("fractions.zig");
const B = circuit.builder;
pub const Scope = struct { statement: Public.Digest, fixed: C.Hash, main: C.Hash, manifest: C.Hash, ordinal: Public.Word, calls: Public.Word, permutations: Public.Word, first_id: Public.Word };
pub const Pending = struct {
    artifact: engine.lookups.verifier_kernel.Artifact(C.F),
    challenges: Fractions.ChallengesFor(C.F),
    eta: C.F,
    receipt: C.Hash,
    pub fn deinit(self: *Pending, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
fn begin(ctx: *C.Context, scope: Scope, geometry: Authority.Geometry) !Shared.Channel {
    if (!geometry.detached) return error.SpongeLocalScopeFlavor;
    const instances = try geometry.instances();
    var channel = try C.Channel.init(ctx);
    try channel.mixConstU32s(ctx, &Native.DETACHED_DOMAIN);
    try channel.mixU32s(ctx, &scope.statement);
    try channel.mixRoot(ctx, scope.fixed);
    try channel.mixRoot(ctx, scope.main);
    try channel.mixRoot(ctx, scope.manifest);
    try channel.mixU32s(ctx, &.{ scope.ordinal, try B.wrappers.constU32(C.Q, ctx, 8), scope.calls, scope.permutations, scope.first_id });
    for (instances) |instance| try channel.mixConstU32s(ctx, &.{ @intFromEnum(instance.role), instance.row_log, instance.queries() });
    return .{ .ctx = ctx, .channel = channel };
}
pub fn verify(ctx: *C.Context, scope: Scope, geometry: Authority.Geometry, proof: *const G.Proof) !Pending {
    var channel = try begin(ctx, scope, geometry);
    const challenges = Fractions.drawFor(C.F, &channel);
    const gates = [_]engine.lookups.gkr_verifier.ForField(C.O).Gate{.LogUp} ** 8;
    var artifact = try engine.lookups.verifier_kernel.partiallyVerifyBatch(C.F, ctx.gpa, &gates, proof, &channel, Shared.Checks{ .ctx = ctx });
    errdefer artifact.deinit(ctx.gpa);
    try channel.finish();
    if (artifact.n_variables_by_instance.len != 8) return error.SpongeLocalQueryShape;
    for (try geometry.instances(), artifact.n_variables_by_instance) |instance, n| if (n != try instance.variables() or artifact.ood_point.len < n) return error.LocalGkrPointGeometryMismatch;
    var inverses: [8]C.F = undefined;
    if (proof.output_claims_by_instance.len != 8) return error.SpongeLocalQueryShape;
    for (proof.output_claims_by_instance, &inverses) |pair, *inverse| {
        if (pair.len != 2) return error.LocalGkrOutputShape;
        inverse.* = pair[1].inv();
    }
    try Closure.closeFor(C.F, proof.output_claims_by_instance, &inverses, Shared.Checks{ .ctx = ctx });
    var writer = try Shared.ReceiptWriter.init(ctx);
    try Native.emitReceipt(scope, geometry, proof, artifact.claims_to_verify_by_instance, &writer);
    const receipt = try writer.finish();
    const eta = channel.drawSecureFelt();
    try channel.finish();
    return .{ .artifact = artifact, .challenges = challenges, .eta = eta, .receipt = receipt };
}
