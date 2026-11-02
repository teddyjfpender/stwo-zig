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
/// Operational storage only: no transcript/profile/statement input changes.
pub fn parseTreeCheckpoints(value: ?[]const u8) !bool {
    const text = value orelse return false;
    if (text.len == 0) return false;
    if (std.mem.eql(u8, text, "2")) return true;
    return error.InvalidGkrTreeCheckpointPolicy;
}
pub fn treeCheckpoints(a: std.mem.Allocator) !bool {
    const value = std.process.getEnvVarOwned(a, "STWO_ZIG_GKR_TREE_CHECKPOINTS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer a.free(value);
    return parseTreeCheckpoints(value);
}
fn treeMetrics(a: std.mem.Allocator) !bool {
    const value = std.process.getEnvVarOwned(a, "STWO_ZIG_GKR_TREE_METRICS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer a.free(value);
    return std.mem.eql(u8, value, "1");
}

pub const TreePolicy = struct { checkpointed: bool = false, tight_admission: bool = false, stream_bottom: bool = false };
pub fn parseTightAdmission(value: ?[]const u8) !bool {
    const text = value orelse return false;
    if (text.len == 0 or std.mem.eql(u8, text, "0")) return false;
    if (std.mem.eql(u8, text, "1")) return true;
    return error.InvalidGkrTightAdmissionPolicy;
}
pub fn parseStreamBottom(value: ?[]const u8, _: bool) !bool {
    const text = value orelse return false;
    if (text.len == 0 or std.mem.eql(u8, text, "0")) return false;
    if (!std.mem.eql(u8, text, "1")) return error.InvalidGkrStreamBottomPolicy;
    return true;
}
pub fn readTreePolicy(a: std.mem.Allocator) !TreePolicy {
    const cp = try treeCheckpoints(a);
    const value: ?[]u8 = std.process.getEnvVarOwned(a, "STWO_ZIG_GKR_TIGHT_ADMISSION") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (value) |v| a.free(v);
    const tight = try parseTightAdmission(value);
    const stream: ?[]u8 = std.process.getEnvVarOwned(a, "STWO_ZIG_GKR_STREAM_BOTTOM") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (stream) |v| a.free(v);
    const streaming = try parseStreamBottom(stream, cp);
    return .{ .checkpointed = cp, .tight_admission = cp or tight or streaming, .stream_bottom = streaming };
}

pub const PhaseTiming = struct {
    inputs_ns: u64 = 0,
    numerical_ns: u64 = 0,
    binding_ns: u64 = 0,
    numerical_requested_peak_bytes: usize = 0,
    including_binding_requested_peak_bytes: usize = 0,
    admitted_gkr_peak_bytes: usize = 0,
    gkr_allocator_limit_bytes: usize = 0,
};
pub const Unbound = struct {
    parent_allocator: std.mem.Allocator,
    budget: Budget,
    plan: Resource.Plan,
    result: GP.ProveBatchResult,
    digest: [32]u8,
    peak_gkr_owned_bytes: usize,
    binding: @import("witness.zig").Witness,
    binding_reserved_bytes: usize,
    pub fn prove(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype) !*Unbound {
        return proveTimed(a, limit, scope, instances, provider, null);
    }
    pub fn proveTimed(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype, timing: ?*PhaseTiming) !*Unbound {
        return proveTimedWithPolicy(a, limit, scope, instances, provider, try readTreePolicy(a), timing);
    }
    pub fn proveTimedWithCheckpoints(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype, checkpointed: bool, timing: ?*PhaseTiming) !*Unbound {
        return proveTimedWithPolicy(a, limit, scope, instances, provider, .{ .checkpointed = checkpointed, .tight_admission = checkpointed }, timing);
    }
    pub fn proveTimedWithPolicy(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype, policy: TreePolicy, timing: ?*PhaseTiming) !*Unbound {
        const checkpointed = policy.checkpointed;
        if (policy.stream_bottom and !policy.tight_admission) return error.InvalidGkrStreamBottomPolicy;
        const metrics = try treeMetrics(a);
        const plan = if (policy.stream_bottom) try Resource.Plan.forInstancesWithSourceStorage(instances, limit, checkpointed) else try Resource.Plan.forInstancesWithTightAdmission(instances, limit, checkpointed, policy.tight_admission);
        // Owner address remains stable for every proof/result allocation.
        const self = try a.create(Unbound);
        errdefer a.destroy(self);
        self.* = .{ .parent_allocator = a, .budget = Budget.init(a, if (policy.tight_admission) plan.peak_bytes else limit), .plan = plan, .result = undefined, .digest = undefined, .peak_gkr_owned_bytes = 0, .binding = undefined, .binding_reserved_bytes = 0 };
        const bounded = self.budget.allocator();
        var ch = begin(scope, instances);
        const challenges = Challenges.draw(&ch);
        var clock: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
        if (timing) |output| output.* = .{};
        var inputs = if (policy.stream_bottom) Inputs{ .allocator = bounded, .layers = &.{} } else try Inputs.init(bounded, instances, &challenges, provider);
        defer inputs.deinit();
        var source_inputs = if (policy.stream_bottom) try @import("source_inputs.zig").Batch(@TypeOf(provider)).init(bounded, instances, &challenges, provider) else null;
        defer if (source_inputs) |*source| source.deinit();
        if (clock) |*timer| timing.?.inputs_ns = timer.lap();
        var result = if (source_inputs) |source| (if (checkpointed) try GP.proveBatchSourceCheckpointed(bounded, &ch, source.sources) else try GP.proveBatchSource(bounded, &ch, source.sources)) else if (checkpointed) try GP.proveBatchOwnedCheckpointed(bounded, &ch, inputs.takeLayers()) else try GP.proveBatch(bounded, &ch, inputs.layers);
        const numerical_peak_bytes = self.budget.peak_live_bytes;
        errdefer result.deinit(bounded);
        try Closure.close(bounded, result.proof.output_claims_by_instance);
        self.digest = try Receipt.digest(scope, instances, &result.proof, result.artifact.claims_to_verify_by_instance);
        const eta = ch.drawSecureFelt();
        if (clock) |*timer| timing.?.numerical_ns = timer.lap();
        const binding_bytes = try std.math.add(usize, plan.binding_bytes, try std.math.mul(usize, instances.len, @sizeOf([]@import("stwo_core").fields.m31.M31)));
        try Resource.reserveExternal(&self.budget, binding_bytes);
        errdefer Resource.releaseExternal(&self.budget, binding_bytes);
        // Parent-owned planes are explicitly charged while local, then adopted
        // by the existing worker/PCS allocator without a whole-witness copy.
        self.binding = if (checkpointed or policy.stream_bottom) try @import("witness.zig").Witness.initFromProvider(a, bounded, instances, &challenges, provider, &result.artifact, eta) else try @import("witness.zig").Witness.init(a, instances, &inputs, &result.artifact, eta);
        if (clock) |*timer| timing.?.binding_ns = timer.read();
        self.binding_reserved_bytes = binding_bytes;
        self.result = result;
        self.peak_gkr_owned_bytes = self.budget.peak_live_bytes;
        if (timing) |value| {
            value.numerical_requested_peak_bytes = numerical_peak_bytes;
            value.including_binding_requested_peak_bytes = self.peak_gkr_owned_bytes;
            value.admitted_gkr_peak_bytes = plan.peak_bytes;
            value.gkr_allocator_limit_bytes = self.budget.limit;
        }
        if (metrics) std.debug.print("GKR_TREE_POLICY stride={d} numerical_requested_peak={d} including_binding_peak={d} raw_input_bytes={d} tight_admission={any} admitted_peak_bytes={d} allocator_limit_bytes={d} streamed_bottom={any} planned_input_reserve_bytes={d}\n", .{ @as(u8, if (checkpointed) 2 else 1), numerical_peak_bytes, self.peak_gkr_owned_bytes, @as(usize, if (policy.stream_bottom) 0 else plan.input_bytes), policy.tight_admission, plan.peak_bytes, self.budget.limit, policy.stream_bottom, plan.input_bytes });
        return self;
    }
    pub fn takeBindingCommit(self: *Unbound, instances: []const Frame.Instance) !@import("../../../word16_execution/main_ownership.zig").Commit {
        const commit = try self.binding.takeCommit(instances);
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.binding_reserved_bytes = 0;
        // Storage remains live under its receiving worker's admission after this
        // explicit transfer; releasing the local reservation is not an RSS drop.
        return commit;
    }
    /// Caller allocates and validates its combined INTER descriptors first.
    /// This no-allocation transfer is the final ownership transition.
    pub fn takeBindingBackings(self: *Unbound) [][]core.fields.m31.M31 {
        const out = self.binding.columns;
        self.binding.columns = &.{};
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.binding_reserved_bytes = 0;
        return out;
    }
    pub fn deinit(self: *Unbound) void {
        const a = self.parent_allocator;
        self.binding.deinit();
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.result.deinit(self.budget.allocator());
        std.debug.assert(self.budget.live_bytes == 0);
        a.destroy(self);
    }
};

test "GKR operational tree policy fails closed without changing default protocol" {
    try std.testing.expect(!try parseTreeCheckpoints(null));
    try std.testing.expect(!try parseTreeCheckpoints(""));
    try std.testing.expect(try parseTreeCheckpoints("2"));
    for ([_][]const u8{ "1", "3", "false", "2 " }) |value| try std.testing.expectError(error.InvalidGkrTreeCheckpointPolicy, parseTreeCheckpoints(value));
}

test "tight admission operational flag is explicit and does not select a protocol" {
    try std.testing.expect(!try parseTightAdmission(null));
    try std.testing.expect(!try parseTightAdmission(""));
    try std.testing.expect(!try parseTightAdmission("0"));
    try std.testing.expect(try parseTightAdmission("1"));
    for ([_][]const u8{ "2", "true", "1 " }) |value| try std.testing.expectError(error.InvalidGkrTightAdmissionPolicy, parseTightAdmission(value));
}
