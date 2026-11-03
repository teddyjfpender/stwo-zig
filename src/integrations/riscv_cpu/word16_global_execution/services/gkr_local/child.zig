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
    ch.mixU32s(&.{ if (Frame.v3Instances(instances)) @as(u32, 0x53474b33) else 0x53474b31, 8, scope.ordinal });
    for ([_][32]u8{ scope.statement, scope.fixed, scope.main }) |bytes| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        ch.mixU32s(&words);
    }
    ch.mixU32s(&.{@intCast(instances.len)});
    for (instances) |instance| {
        ch.mixU32s(&Frame.originWords(instance.origin));
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
    const challenges = Challenges.drawForInstances(&ch, instances);
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
/// Unset/empty = policy default (null); "2" = stride-two checkpoints; "1" =
/// every upper layer retained (the pre-default dense-upper storage).
pub fn parseTreeCheckpoints(value: ?[]const u8) !?bool {
    const text = value orelse return null;
    if (text.len == 0) return null;
    if (std.mem.eql(u8, text, "2")) return true;
    if (std.mem.eql(u8, text, "1")) return false;
    return error.InvalidGkrTreeCheckpointPolicy;
}
pub fn treeCheckpoints(a: std.mem.Allocator) !?bool {
    const value = std.process.getEnvVarOwned(a, "STWO_ZIG_GKR_TREE_CHECKPOINTS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
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
/// Streamed bottom is the default (unset/empty/"1"); "0" selects the original
/// materialized N/D input planes. Storage only: proof bytes are identical.
pub fn parseStreamBottom(value: ?[]const u8) !bool {
    const text = value orelse return true;
    if (text.len == 0 or std.mem.eql(u8, text, "1")) return true;
    if (!std.mem.eql(u8, text, "0")) return error.InvalidGkrStreamBottomPolicy;
    return false;
}
/// Default storage: streamed bottom + stride-two checkpoints (source68 path).
/// Explicit opt-outs: STWO_ZIG_GKR_STREAM_BOTTOM=0 (materialized dense input)
/// or STWO_ZIG_GKR_TREE_CHECKPOINTS=1 (streamed bottom, dense upper layers).
pub fn readTreePolicy(a: std.mem.Allocator) !TreePolicy {
    return readTreePolicyFor(a, false);
}
/// `hybrid`: a nonzero checkpoint_above_gkr_bytes selector is configured. Its
/// base is source80, so the checkpoint default resolves to dense upper there;
/// an explicit "2" still conflicts and is rejected by tree_selection.validate.
pub fn readTreePolicyFor(a: std.mem.Allocator, hybrid: bool) !TreePolicy {
    const explicit_cp = try treeCheckpoints(a);
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
    const streaming = try parseStreamBottom(stream);
    return policyFrom(explicit_cp, tight, streaming, hybrid);
}
pub fn policyFrom(explicit_cp: ?bool, tight: bool, streaming: bool, hybrid: bool) TreePolicy {
    const cp = explicit_cp orelse (streaming and !hybrid);
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
/// Per-proof numerical backend seam. Sources are borrowed immutable readers;
/// a resident backend may instead project the same facts from native_source's
/// authenticated MAIN ownership. Neither sources nor native_source may escape
/// this synchronous call. Return a compact proof owned by the supplied bounded
/// allocator. Native partial verification reconstructs the terminal artifact and
/// transcript; a device never supplies an authoritative artifact or eta.
pub const DeviceBinding = @import("device_binding.zig");
pub const NativeColumns = struct {
    fixed: []const @import("stwo_prover_api").device_pcs.Column = &.{},
    main: []const @import("stwo_prover_api").device_pcs.Column = &.{},
};
pub const NumericalStage = struct {
    context: *anyopaque,
    prove: *const fn (*anyopaque, std.mem.Allocator, Request) anyerror!GV.GkrBatchProof,
    bind: ?*const fn (*anyopaque, std.mem.Allocator, DeviceBinding.Request) anyerror!DeviceBinding.Owner = null,
    abort: ?*const fn (*anyopaque, Receipt.Scope) void = null,
    pub const Request = struct {
        scope: Receipt.Scope,
        instances: []const Frame.Instance,
        challenges: *const Challenges,
        sources: []const GP.MultiplicitiesSource,
        native_source: ?*const @import("../roster.zig").Sources,
        native_fixed_columns: []const @import("stwo_prover_api").device_pcs.Column = &.{},
        native_main_columns: []const @import("stwo_prover_api").device_pcs.Column = &.{},
        /// Before the native relation draws; resident source projection replays
        /// these draws on device and must reach channel exactly.
        source_channel: Channel,
        channel: Channel,
        byte_cap: usize,
    };
};
fn proveNumericalStage(a: std.mem.Allocator, stage: NumericalStage, request: NumericalStage.Request, channel: *Channel) !GP.ProveBatchResult {
    var proof = try stage.prove(stage.context, a, request);
    errdefer proof.deinit(a);
    const gates = try a.alloc(GV.Gate, request.instances.len);
    defer a.free(gates);
    @memset(gates, .LogUp);
    var verified_channel = request.channel;
    var verification_timer = try std.time.Timer.start();
    var artifact = try GV.partiallyVerifyBatch(a, gates, &proof, &verified_channel);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != request.instances.len) return error.LocalGkrPointGeometryMismatch;
    for (request.instances, artifact.n_variables_by_instance) |instance, variables|
        _ = try Frame.splitPoint(instance, artifact.ood_point, variables);
    channel.* = verified_channel;
    std.debug.print("GPU_GKR_NATIVE_CHECK ordinal={} mandatory_partial_verify_ns={}\n", .{ request.scope.ordinal, verification_timer.read() });
    return .{ .proof = proof, .artifact = artifact };
}
pub const Unbound = struct {
    parent_allocator: std.mem.Allocator,
    budget: Budget,
    plan: Resource.Plan,
    result: GP.ProveBatchResult,
    digest: [32]u8,
    peak_gkr_owned_bytes: usize,
    binding: @import("witness.zig").Witness,
    device_binding: ?DeviceBinding.Owner = null,
    binding_reserved_bytes: usize,
    projection_pending: bool = false,
    projection_eta: O = O.zero(),
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
        return proveTimedWithBindingStorage(a, limit, scope, instances, provider, policy, false, timing);
    }
    pub fn proveTimedWithBindingStorage(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype, policy: TreePolicy, deferred: bool, timing: ?*PhaseTiming) !*Unbound {
        return proveTimedWithNumericalStage(a, limit, scope, instances, provider, policy, deferred, timing, null, .{});
    }
    pub fn proveTimedWithNumericalStage(a: std.mem.Allocator, limit: usize, scope: Receipt.Scope, instances: []const Frame.Instance, provider: anytype, policy: TreePolicy, deferred: bool, timing: ?*PhaseTiming, stage: ?NumericalStage, native_columns: NativeColumns) !*Unbound {
        var successful = false;
        var stage_attempted = false;
        var stage_disarmed = false;
        defer if (!successful and stage_attempted and !stage_disarmed) {
            if (stage) |backend| if (backend.abort) |abort| abort(backend.context, scope);
        };
        const checkpointed = policy.checkpointed;
        if (policy.stream_bottom and !policy.tight_admission) return error.InvalidGkrStreamBottomPolicy;
        const metrics = try treeMetrics(a);
        const original_plan = if (policy.stream_bottom) try Resource.Plan.forInstancesWithSourceStorage(instances, limit, checkpointed) else try Resource.Plan.forInstancesWithTightAdmission(instances, limit, checkpointed, policy.tight_admission);
        const plan = if (deferred) try original_plan.withDeferredBinding(instances.len, limit) else original_plan;
        // Owner address remains stable for every proof/result allocation.
        const self = try a.create(Unbound);
        errdefer a.destroy(self);
        self.* = .{ .parent_allocator = a, .budget = Budget.init(a, if (policy.tight_admission) plan.peak_bytes else limit), .plan = plan, .result = undefined, .digest = undefined, .peak_gkr_owned_bytes = 0, .binding = undefined, .binding_reserved_bytes = 0 };
        const bounded = self.budget.allocator();
        var ch = begin(scope, instances);
        const source_channel = ch;
        const challenges = Challenges.drawForInstances(&ch, instances);
        var clock: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
        if (timing) |output| output.* = .{};
        var inputs = if (policy.stream_bottom or stage != null) Inputs{ .allocator = bounded, .layers = &.{} } else try Inputs.init(bounded, instances, &challenges, provider);
        defer inputs.deinit();
        var source_inputs = if (policy.stream_bottom or stage != null) try @import("source_inputs.zig").Batch(@TypeOf(provider)).init(bounded, instances, &challenges, provider) else null;
        defer if (source_inputs) |*source| source.deinit();
        if (clock) |*timer| timing.?.inputs_ns = timer.lap();
        var result = if (stage) |backend| blk: {
            stage_attempted = true;
            break :blk try proveNumericalStage(bounded, backend, .{
                .scope = scope,
                .instances = instances,
                .challenges = &challenges,
                .sources = source_inputs.?.sources,
                .native_source = if (@TypeOf(provider) == @import("native_provider.zig").Provider) provider.source else null,
                .native_fixed_columns = native_columns.fixed,
                .native_main_columns = native_columns.main,
                .source_channel = source_channel,
                .channel = ch,
                .byte_cap = limit,
            }, &ch);
        } else if (source_inputs) |source| (if (checkpointed) try GP.proveBatchSourceCheckpointed(bounded, &ch, source.sources) else try GP.proveBatchSource(bounded, &ch, source.sources)) else if (checkpointed) try GP.proveBatchOwnedCheckpointed(bounded, &ch, inputs.takeLayers()) else try GP.proveBatch(bounded, &ch, inputs.layers);
        const numerical_peak_bytes = self.budget.peak_live_bytes;
        errdefer result.deinit(bounded);
        try Closure.close(bounded, result.proof.output_claims_by_instance);
        self.digest = try Receipt.digest(scope, instances, &result.proof, result.artifact.claims_to_verify_by_instance);
        const eta = ch.drawSecureFelt();
        if (clock) |*timer| timing.?.numerical_ns = timer.lap();
        const device_bind = if (stage) |backend| backend.bind else null;
        const binding_bytes = if (device_bind != null) @as(usize, 0) else try std.math.add(usize, if (deferred) plan.binding_bytes / 2 else plan.binding_bytes, try std.math.mul(usize, instances.len, @sizeOf([]@import("stwo_core").fields.m31.M31)));
        try Resource.reserveExternal(&self.budget, binding_bytes);
        errdefer Resource.releaseExternal(&self.budget, binding_bytes);
        // Parent-owned planes are explicitly charged while local, then adopted
        // by the existing worker/PCS allocator without a whole-witness copy.
        if (device_bind) |bind| {
            // bind consumes or cleans up the pending device job on failure;
            // abort is only for errors between numerical proof and this call.
            stage_disarmed = true;
            var owner = try bind(stage.?.context, a, .{ .scope = scope, .receipt_digest = self.digest, .instances = instances, .artifact = &result.artifact, .eta = eta, .deferred = deferred });
            errdefer owner.deinit(a);
            if (!std.meta.eql(owner.scope, scope) or !std.mem.eql(u8, &owner.receipt_digest, &self.digest)) return error.DeviceBindingScopeMismatch;
            if (!deferred) try owner.finalize(a, .{ .scope = scope, .receipt_digest = self.digest, .instances = instances, .artifact = &result.artifact, .eta = eta, .deferred = false });
            self.device_binding = owner;
        }
        self.binding = if (device_bind != null) .{ .allocator = a, .columns = &.{} } else if (deferred) try @import("witness.zig").Witness.initProjectionFromProvider(a, bounded, instances, &challenges, provider, &result.artifact, eta) else if (checkpointed or policy.stream_bottom or stage != null) try @import("witness.zig").Witness.initFromProvider(a, bounded, instances, &challenges, provider, &result.artifact, eta) else try @import("witness.zig").Witness.init(a, instances, &inputs, &result.artifact, eta);
        if (clock) |*timer| timing.?.binding_ns = timer.read();
        self.binding_reserved_bytes = binding_bytes;
        self.projection_pending = deferred;
        self.projection_eta = eta;
        self.result = result;
        self.peak_gkr_owned_bytes = self.budget.peak_live_bytes;
        if (timing) |value| {
            value.numerical_requested_peak_bytes = numerical_peak_bytes;
            value.including_binding_requested_peak_bytes = self.peak_gkr_owned_bytes;
            value.admitted_gkr_peak_bytes = plan.peak_bytes;
            value.gkr_allocator_limit_bytes = self.budget.limit;
        }
        if (metrics) std.debug.print("GKR_TREE_POLICY stride={d} numerical_requested_peak={d} including_binding_peak={d} raw_input_bytes={d} tight_admission={any} admitted_peak_bytes={d} allocator_limit_bytes={d} streamed_bottom={any} planned_input_reserve_bytes={d}\n", .{ @as(u8, if (checkpointed) 2 else 1), numerical_peak_bytes, self.peak_gkr_owned_bytes, @as(usize, if (policy.stream_bottom) 0 else plan.input_bytes), policy.tight_admission, plan.peak_bytes, self.budget.limit, policy.stream_bottom, plan.input_bytes });
        successful = true;
        return self;
    }
    /// All new allocations/validation precede the old-projection release. A
    /// failed completion leaves the projected owner intact and retryable.
    pub fn completeBinding(self: *Unbound, instances: []const Frame.Instance) !void {
        if (!self.projection_pending) return;
        if (self.device_binding) |*owner| {
            try owner.finalize(self.parent_allocator, .{ .scope = owner.scope, .receipt_digest = self.digest, .instances = instances, .artifact = &self.result.artifact, .eta = self.projection_eta, .deferred = false });
            self.projection_pending = false;
            return;
        }
        const final_bytes = try std.math.add(usize, self.plan.binding_bytes, try std.math.mul(usize, instances.len, @sizeOf([]core.fields.m31.M31)));
        try Resource.reserveExternal(&self.budget, final_bytes);
        errdefer Resource.releaseExternal(&self.budget, final_bytes);
        const completed = try self.binding.finalizeProjection(self.parent_allocator, instances, &self.result.artifact, self.projection_eta);
        self.binding.deinit();
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.binding = completed;
        self.binding_reserved_bytes = final_bytes;
        self.projection_pending = false;
        self.peak_gkr_owned_bytes = self.budget.peak_live_bytes;
    }
    pub fn takeBindingCommit(self: *Unbound, instances: []const Frame.Instance) !@import("../../../word16_execution/main_ownership.zig").Commit {
        if (self.projection_pending) return error.LocalGkrBindingUnavailable;
        const commit = try self.binding.takeCommit(instances);
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.binding_reserved_bytes = 0;
        // Storage remains live under its receiving worker's admission after this
        // explicit transfer; releasing the local reservation is not an RSS drop.
        return commit;
    }
    /// Caller allocates and validates its combined INTER descriptors first.
    /// This no-allocation transfer is the final ownership transition.
    pub fn takeBindingBackings(self: *Unbound) ![][]core.fields.m31.M31 {
        if (self.projection_pending) return error.LocalGkrBindingUnavailable;
        const out = self.binding.columns;
        self.binding.columns = &.{};
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.binding_reserved_bytes = 0;
        return out;
    }
    pub fn deviceBindingColumns(self: *const Unbound) ![]const @import("stwo_prover_api").device_pcs.Column {
        const owner = self.device_binding orelse return error.DeviceBindingUnavailable;
        if (!owner.finalized or self.projection_pending) return error.LocalGkrBindingUnavailable;
        return owner.columns;
    }
    pub fn deinit(self: *Unbound) void {
        const a = self.parent_allocator;
        if (self.device_binding) |*owner| owner.deinit(a);
        self.binding.deinit();
        Resource.releaseExternal(&self.budget, self.binding_reserved_bytes);
        self.result.deinit(self.budget.allocator());
        std.debug.assert(self.budget.live_bytes == 0);
        a.destroy(self);
    }
};

test "GKR operational tree policy fails closed without changing default protocol" {
    try std.testing.expectEqual(@as(?bool, null), try parseTreeCheckpoints(null));
    try std.testing.expectEqual(@as(?bool, null), try parseTreeCheckpoints(""));
    try std.testing.expectEqual(@as(?bool, true), try parseTreeCheckpoints("2"));
    try std.testing.expectEqual(@as(?bool, false), try parseTreeCheckpoints("1"));
    for ([_][]const u8{ "0", "3", "false", "2 " }) |value| try std.testing.expectError(error.InvalidGkrTreeCheckpointPolicy, parseTreeCheckpoints(value));
}

test "default GKR storage is streamed checkpoint68; explicit opt-outs keep the older storage" {
    try std.testing.expectEqualDeep(TreePolicy{ .checkpointed = true, .tight_admission = true, .stream_bottom = true }, policyFrom(null, false, true, false));
    // A hybrid selector keeps its source80 base unless "2" is explicit.
    try std.testing.expectEqualDeep(TreePolicy{ .checkpointed = false, .tight_admission = true, .stream_bottom = true }, policyFrom(null, false, true, true));
    try std.testing.expectEqualDeep(TreePolicy{ .checkpointed = false, .tight_admission = true, .stream_bottom = true }, policyFrom(false, false, true, false));
    // STREAM_BOTTOM=0 alone restores the original materialized dense default.
    try std.testing.expectEqualDeep(TreePolicy{}, policyFrom(null, false, false, false));
    try std.testing.expectEqualDeep(TreePolicy{ .checkpointed = true, .tight_admission = true }, policyFrom(true, false, false, false));
}

test "tight admission operational flag is explicit and does not select a protocol" {
    try std.testing.expect(!try parseTightAdmission(null));
    try std.testing.expect(!try parseTightAdmission(""));
    try std.testing.expect(!try parseTightAdmission("0"));
    try std.testing.expect(try parseTightAdmission("1"));
    for ([_][]const u8{ "2", "true", "1 " }) |value| try std.testing.expectError(error.InvalidGkrTightAdmissionPolicy, parseTightAdmission(value));
}

test "numerical stage proofs retain native transcript and reject changed claims" {
    const a = std.testing.allocator;
    const instances = [_]Frame.Instance{.{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 }};
    const zeroes: [32]O = @splat(O.zero());
    const ones: [32]O = @splat(O.one());
    const Callback = struct {
        layers: [1]GP.Layer,
        mutate: bool = false,
        fn run(ctx: *anyopaque, allocator: std.mem.Allocator, request: NumericalStage.Request) !GV.GkrBatchProof {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            var channel = request.channel;
            var result = try GP.proveBatch(allocator, &channel, &self.layers);
            result.artifact.deinit(allocator);
            if (self.mutate) result.proof.output_claims_by_instance[0][0] = O.one();
            return result.proof;
        }
    };
    var callback = Callback{ .layers = .{.{ .LogUpGeneric = .{
        .numerators = .{ .evals = @constCast(&zeroes), .owns_evals = false },
        .denominators = .{ .evals = @constCast(&ones), .owns_evals = false },
    } }} };
    const challenges: Challenges = undefined; // Numerical-only callback does not project rows.
    const initial = Channel.init();
    const request = NumericalStage.Request{ .scope = .{ .statement = @splat(0), .fixed = @splat(0), .main = @splat(0), .ordinal = 0 }, .instances = &instances, .challenges = &challenges, .sources = &.{}, .native_source = null, .source_channel = initial, .channel = initial, .byte_cap = 1 << 20 };
    var expected_channel = initial;
    var expected = try GP.proveBatch(a, &expected_channel, &callback.layers);
    defer expected.deinit(a);
    var channel = initial;
    var result = try proveNumericalStage(a, .{ .context = &callback, .prove = Callback.run }, request, &channel);
    defer result.deinit(a);
    try std.testing.expectEqual(expected_channel.inner.n_draws, channel.inner.n_draws);
    try std.testing.expectEqualSlices(u8, &expected_channel.inner.digest, &channel.inner.digest);
    try std.testing.expectEqualSlices(O, expected.artifact.ood_point, result.artifact.ood_point);
    callback.mutate = true;
    var rejected = false;
    var bad_channel = initial;
    if (proveNumericalStage(a, .{ .context = &callback, .prove = Callback.run }, request, &bad_channel)) |returned| {
        var unexpected = returned;
        unexpected.deinit(a);
    } else |_| {
        rejected = true;
    }
    try std.testing.expect(rejected);
    try std.testing.expectEqualSlices(u8, &initial.inner.digest, &bad_channel.inner.digest);
}
