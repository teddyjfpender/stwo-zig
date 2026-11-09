//! Constrained twin of the opt-in truth-local GKR child. All accepted terminal
//! marginals still require the original physical source binding component.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const Shared = @import("../full_p2_child.zig");
const Native = @import("native.zig");
const Authority = @import("authority.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
pub const Scope = struct { statement: Public.Digest, fixed: C.Hash, main: C.Hash, manifest: C.Hash, ordinal: Public.Word, calls: Public.Word, first_id: Public.Word };
pub const Pending = struct { artifact: engine.lookups.verifier_kernel.Artifact(C.F), challenges: A.crypto.bn254_tower.narrow.equations.ChallengesFor(C.F), eta: C.F, receipt: C.Hash };
pub fn begin(ctx: *C.Context, scope: Scope, geometry: Authority.Geometry) !Shared.Channel {
    const instances = try geometry.instances();
    var ch = try C.Channel.init(ctx);
    try ch.mixConstU32s(ctx, &Native.DOMAIN);
    try ch.mixU32s(ctx, &scope.statement);
    try ch.mixRoot(ctx, scope.fixed);
    try ch.mixRoot(ctx, scope.main);
    try ch.mixRoot(ctx, scope.manifest);
    try ch.mixU32s(ctx, &.{ scope.ordinal, try circuit.builder.wrappers.constU32(C.Q, ctx, 4), scope.calls, scope.first_id, try circuit.builder.wrappers.constU32(C.Q, ctx, geometry.frontier_log), try circuit.builder.wrappers.constU32(C.Q, ctx, geometry.arithmetic_log) });
    for (instances) |instance| {
        try ch.mixConstU32s(ctx, &.{ @intFromEnum(instance.role), instance.row_log, instance.queries() });
    }
    return .{ .ctx = ctx, .channel = ch };
}
pub fn verify(ctx: *C.Context, scope: Scope, geometry: Authority.Geometry, proof: *const G.Proof) !Pending {
    var channel = try begin(ctx, scope, geometry);
    const challenges = Native.drawFor(C.F, &channel);
    const gates = [_]engine.lookups.gkr_verifier.ForField(C.O).Gate{ .LogUp, .LogUp, .LogUp, .LogUp };
    var artifact = try engine.lookups.verifier_kernel.partiallyVerifyBatch(C.F, ctx.gpa, &gates, proof, &channel, Shared.Checks{ .ctx = ctx });
    errdefer artifact.deinit(ctx.gpa);
    try channel.finish();
    if (artifact.n_variables_by_instance.len != 4) return error.LocalGkrPointGeometryMismatch;
    for (try geometry.instances(), artifact.n_variables_by_instance) |instance, n| if (n != try instance.variables() or artifact.ood_point.len < n) return error.LocalGkrPointGeometryMismatch;
    const inverses = try ctx.scratch().alloc(C.F, proof.output_claims_by_instance.len);
    for (proof.output_claims_by_instance, inverses) |pair, *inverse| {
        if (pair.len != 2) return error.LocalGkrOutputShape;
        inverse.* = pair[1].inv();
    }
    try Closure.closeFor(C.F, proof.output_claims_by_instance[0..1], inverses[0..1], Shared.Checks{ .ctx = ctx });
    try Closure.closeFor(C.F, proof.output_claims_by_instance[1..2], inverses[1..2], Shared.Checks{ .ctx = ctx });
    try Closure.closeFor(C.F, proof.output_claims_by_instance[2..4], inverses[2..4], Shared.Checks{ .ctx = ctx });
    var writer = try Shared.ReceiptWriter.init(ctx);
    try Native.emitReceipt(scope, geometry, proof, artifact.claims_to_verify_by_instance, &writer);
    const receipt = try writer.finish();
    const eta = channel.drawSecureFelt();
    try channel.finish();
    return .{ .artifact = artifact, .challenges = challenges, .eta = eta, .receipt = receipt };
}
