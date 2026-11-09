//! In-circuit twin of the typed frontier CPU local transcript. This proves
//! neither MAIN binding nor an execution: every returned terminal is pending.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const Shared = @import("../full_p2_child.zig");
const Challenges = @import("../../word16_global_execution/services/gkr_local/challenges.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Frame = @import("frame.zig");
const Native = @import("native.zig");
const B = circuit.builder;
pub const Scope = struct { statement: Public.Digest, fixed: C.Hash, main: C.Hash, ordinal: Public.Word, epoch: Public.Word, calls: Public.Word };
pub const Terminal = struct { artifact: *const engine.lookups.verifier_kernel.Artifact(C.F), challenges: Challenges.For(C.F), eta: C.F };
pub const Pending = struct {
    artifact: engine.lookups.verifier_kernel.Artifact(C.F),
    challenges: Challenges.For(C.F),
    eta: C.F,
    receipt: C.Hash,
    /// Borrow a real verified prefix, preserve the SAME complete common point,
    /// and leave the complete receipt owned by this typed child. No legacy
    /// digest or fake Frame origin is ever constructed by this projection.
    pub fn legacy(self: *const Pending, count: usize, storage: *engine.lookups.verifier_kernel.Artifact(C.F)) !Terminal {
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
fn begin(ctx: *C.Context, scope: Scope, instances: []const Frame.Instance) !Shared.Channel {
    if (instances.len < 2 or instances.len > 256 or instances[instances.len - 1] != .frontier) return error.SpongeCpuGeometry;
    for (instances[0 .. instances.len - 1]) |v| if (v != .legacy or v.legacy.origin == .sponge) return error.SpongeCpuRequiresDetachedSetup;
    var channel = try C.Channel.init(ctx);
    try channel.mixConstU32s(ctx, &Native.DOMAIN);
    try channel.mixU32s(ctx, &scope.statement);
    try channel.mixRoot(ctx, scope.fixed);
    try channel.mixRoot(ctx, scope.main);
    try channel.mixU32s(ctx, &.{ scope.ordinal, scope.epoch, scope.calls, try B.wrappers.constU32(C.Q, ctx, @intCast(instances.len)) });
    for (instances) |instance| {
        _ = try instance.variables();
        try channel.mixConstU32s(ctx, &instance.tag());
        try channel.mixConstU32s(ctx, &.{ instance.rowLog(), instance.queries() });
        try channel.mixConstU32s(ctx, &.{ @truncate(instance.fixedOffset()), @intCast(instance.fixedOffset() >> 32) });
        try channel.mixConstU32s(ctx, &.{ @truncate(instance.mainOffset()), @intCast(instance.mainOffset() >> 32) });
    }
    return .{ .ctx = ctx, .channel = channel };
}
pub fn verify(ctx: *C.Context, scope: Scope, instances: []const Frame.Instance, proof: *const G.Proof) !Pending {
    var channel = try begin(ctx, scope, instances);
    var v3 = false;
    for (instances) |instance| if (instance == .legacy and instance.legacy.origin == .core and instance.legacy.origin.core == .cpu and instance.legacy.terms == 14) {
        v3 = true;
    };
    const challenges = Challenges.For(C.F).drawMode(&channel, v3);
    const gates = try ctx.scratch().alloc(engine.lookups.gkr_verifier.ForField(C.O).Gate, instances.len);
    @memset(gates, .LogUp);
    var artifact = try engine.lookups.verifier_kernel.partiallyVerifyBatch(C.F, ctx.gpa, gates, proof, &channel, Shared.Checks{ .ctx = ctx });
    errdefer artifact.deinit(ctx.gpa);
    try channel.finish();
    if (artifact.n_variables_by_instance.len != instances.len) return error.SpongeCpuGeometry;
    for (instances, artifact.n_variables_by_instance) |instance, n| if (n != try instance.variables() or artifact.ood_point.len < n) return error.SpongeCpuGeometry;
    const inverses = try ctx.scratch().alloc(C.F, proof.output_claims_by_instance.len);
    for (proof.output_claims_by_instance, inverses) |pair, *inverse| {
        if (pair.len != 2) return error.LocalGkrOutputShape;
        inverse.* = pair[1].inv();
    }
    try Closure.closeFor(C.F, proof.output_claims_by_instance, inverses, Shared.Checks{ .ctx = ctx });
    var writer = try Shared.ReceiptWriter.init(ctx);
    try Native.emitReceipt(scope, instances, proof, artifact.claims_to_verify_by_instance, &writer);
    const receipt = try writer.finish();
    const eta = channel.drawSecureFelt();
    try channel.finish();
    return .{ .artifact = artifact, .challenges = challenges, .eta = eta, .receipt = receipt };
}
