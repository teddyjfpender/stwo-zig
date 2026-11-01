//! Proof-local child lifecycle. Successful GKR verification returns a PENDING
//! terminal binding obligation; it is NEVER an accepting execution receiver.
//! All owned GKR allocations route through one stable bounded allocator owner.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
const Frame = @import("frame.zig");
const Receipt = @import("receipt.zig");
const Resource = @import("resource.zig");
const Inputs = @import("inputs.zig").Inputs;
const Challenges = @import("challenges.zig").For(O);
const Closure = @import("closure.zig");
const Budget = engine.host_budget_allocator.HostBudgetAllocator;
pub fn begin(scope: Receipt.Scope, instances: []const Frame.Instance) Channel {
    var ch = Channel.init();
    ch.mixU32s(&.{ 0x53474b31, 8, scope.ordinal });
    for ([_][32]u8{ scope.statement, scope.fixed, scope.main }) |bytes| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        ch.mixU32s(&words);
    }
    ch.mixU32s(&.{@intCast(instances.len)});
    for (instances) |instance| {
        switch (instance.origin) {
            .core => |role| ch.mixU32s(&.{ 0, @intFromEnum(role) }),
            .bridge => |family| ch.mixU32s(&.{ 1, @intFromEnum(family) }),
        }
        ch.mixU32s(&.{ instance.row_log, instance.terms });
        ch.mixU64(instance.fixed_offset);
        ch.mixU64(instance.main_offset);
    }
    return ch;
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    challenges: Challenges,
    eta: O,
    digest: [32]u8,
    pub fn deinit(self: *Pending, a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verifyPending(a: std.mem.Allocator, scope: Receipt.Scope, instances: []const Frame.Instance, proof: *const GV.GkrBatchProof, expected_digest: [32]u8) !Pending {
    if (instances.len == 0 or instances.len > Receipt.MAX_INSTANCES) return error.LocalGkrReceiptShape;
    var ch = begin(scope, instances);
    const challenges = Challenges.draw(&ch);
    const gates = try a.alloc(GV.Gate, instances.len);
    defer a.free(gates);
    @memset(gates, .LogUp);
    var artifact = try GV.partiallyVerifyBatch(a, gates, proof, &ch);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != instances.len) return error.LocalGkrPointGeometryMismatch;
    for (instances, artifact.n_variables_by_instance) |instance, variables| _ = try Frame.splitPoint(instance, artifact.ood_point, variables);
    try Closure.close(a, proof.output_claims_by_instance);
    const digest = try Receipt.digest(scope, instances, proof, artifact.claims_to_verify_by_instance);
    if (!std.mem.eql(u8, &digest, &expected_digest)) return error.LocalGkrReceiptMismatch;
    // Marginals are reconstructed by the checked child transcript, then eta
    // binds N+eta*D in each role's authenticated Eq/prefix constraints.
    const eta = ch.drawSecureFelt();
    return .{ .artifact = artifact, .challenges = challenges, .eta = eta, .digest = digest };
}
pub const Unbound = struct {
    parent_allocator: std.mem.Allocator,
    budget: Budget,
    plan: Resource.Plan,
    result: GP.ProveBatchResult,
    digest: [32]u8,
    peak_gkr_owned_bytes: usize,
    binding: @import("witness.zig").Witness,
    pub fn prove(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype) !*Unbound {
        const plan = try Resource.Plan.forInstances(instances, limit);
        // Owner address remains stable for every proof/result allocation.
        const self = try a.create(Unbound);
        errdefer a.destroy(self);
        self.* = .{ .parent_allocator = a, .budget = Budget.init(a, limit), .plan = plan, .result = undefined, .digest = undefined, .peak_gkr_owned_bytes = 0, .binding = undefined };
        const bounded = self.budget.allocator();
        var ch = begin(scope, instances);
        const challenges = Challenges.draw(&ch);
        var inputs = try Inputs.init(bounded, instances, &challenges, provider);
        defer inputs.deinit();
        var result = try GP.proveBatch(bounded, &ch, inputs.layers);
        errdefer result.deinit(bounded);
        try Closure.close(bounded, result.proof.output_claims_by_instance);
        self.digest = try Receipt.digest(scope, instances, &result.proof, result.artifact.claims_to_verify_by_instance);
        const eta = ch.drawSecureFelt();
        self.binding = try @import("witness.zig").Witness.init(bounded, instances, &inputs, &result.artifact, eta);
        self.result = result;
        self.peak_gkr_owned_bytes = self.budget.peak_live_bytes;
        return self;
    }
    pub fn deinit(self: *Unbound) void {
        const a = self.parent_allocator;
        self.binding.deinit();
        self.result.deinit(self.budget.allocator());
        std.debug.assert(self.budget.live_bytes == 0);
        a.destroy(self);
    }
};
