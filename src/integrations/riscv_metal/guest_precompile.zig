//! Fail-closed Metal admission for the Poseidon2 guest-precompile profile.
//!
//! The current backend has authenticated resident kernels for the ordinary
//! RISC-V base-polynomial and lookup-polynomial component classes.  A guest
//! caller/provider component combines direct constraints and LogUp recurrences
//! in one protocol component, so neither single-class capability describes it
//! completely.  This integration therefore admits those two exact components
//! to the reviewed generic evaluator and audits their execution, while every
//! commitment and all backend-owned proof work remain on the authenticated
//! Metal engine.  A future combined resident capability changes this contract
//! and is rejected until it receives its own explicit admission path.

const std = @import("std");
const core = @import("stwo_core");
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine");
const metal = @import("stwo_metal_backend");
const riscv = @import("stwo_riscv_frontend");

const InnerEngine = metal.MetalProverEngine;
const ProverComponent = InnerEngine.Component;
const component_mod = prover_engine.air.component_prover;
const composition_work = prover_engine.air.composition_work;
const oods_work = prover_engine.air.oods_work;
const accumulation = prover_engine.air.accumulation;
const prepared_domain = prover_engine.air.prepared_domain;
const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;
const core_components = core.air.components;
const CirclePointQM31 = core.circle.CirclePointQM31;
const caller_component = riscv.air.guest_precompile.caller_component;
const provider_component = riscv.air.guest_precompile.provider_component;
const guest_statement = riscv.air.guest_precompile.statement;
const artifact_identity = riscv.air.guest_precompile.artifact_identity;
const prover = riscv.prover_mod;

pub const aot_bundle_admission = @import("aot_bundle_admission.zig");
pub const profile_identity = riscv.isa.execution_profile.poseidon2_name;
pub const capability_identity = riscv.isa.execution_profile.poseidon2_capability;
pub const profile_version: u16 = 1;
pub const caller_component_identity = "riscv_guest_poseidon2_caller_v1";
pub const provider_component_identity = "riscv_guest_poseidon2_provider_v1";
pub const execution_placement = "reviewed_generic_direct_plus_logup_v1";
pub const runtime_requirement = "authenticated_core_aot_v2";
pub const backend_fallback_allowed = false;

pub const Error = error{
    AuthenticatedRuntimeRequired,
    IncompleteAuthenticatedRuntimeIdentity,
    ProfileComponentSetTooSmall,
    CallerSemanticIdentityMismatch,
    ProviderSemanticIdentityMismatch,
    CallerConstraintGeometryMismatch,
    ProviderConstraintGeometryMismatch,
    ProfileLogDegreeMismatch,
    ProfileCompositionSplitMismatch,
    ProfilePreparedEvaluatorMissing,
    UnreviewedProfileDomainParallelism,
    UnreviewedProfileBackendCapability,
    ProfileCompositionOverrideUnsupported,
    ProfileCpuCompositionRequestUnsupported,
    CallerDomainEvaluationMissing,
    CallerDomainEvaluationRepeated,
    ProviderDomainEvaluationMissing,
    ProviderDomainEvaluationRepeated,
    CallerPointEvaluationMissing,
    CallerPointEvaluationRepeated,
    ProviderPointEvaluationMissing,
    ProviderPointEvaluationRepeated,
    NoResidentCommitmentEvidence,
    ResidentBasePolynomialDispatchMissing,
    ResidentLookupPolynomialDispatchMissing,
    UnexpectedBasePolynomialDispatch,
    UnexpectedLookupPolynomialDispatch,
    RuntimeIdentityChangedDuringProof,
};

/// The profile engine has byte-for-byte protocol types equal to the ordinary
/// Metal engine.  Only runtime admission, component auditing, and proof-release
/// policy differ.
pub const AuthenticatedProfileEngine = struct {
    pub const Backend = InnerEngine.Backend;
    pub const Hasher = InnerEngine.Hasher;
    pub const MerkleChannel = InnerEngine.MerkleChannel;
    pub const Channel = InnerEngine.Channel;
    pub const Component = InnerEngine.Component;
    pub const Scheme = InnerEngine.Scheme;
    pub const Session = InnerEngine.Session;
    pub const ExtendedProof = InnerEngine.ExtendedProof;
    pub const TelemetrySnapshot = InnerEngine.TelemetrySnapshot;
    pub const TelemetryError = InnerEngine.TelemetryError;
    pub const RuntimeInitializationPolicy = InnerEngine.RuntimeInitializationPolicy;
    pub const RuntimeLifecycleSnapshot = InnerEngine.RuntimeLifecycleSnapshot;

    pub const deinit = InnerEngine.deinit;
    pub const initSession = InnerEngine.initSession;
    pub const initWithSession = InnerEngine.initWithSession;
    pub const warmup = InnerEngine.warmup;
    pub const initializeRuntime = InnerEngine.initializeRuntime;
    pub const runtimeLifecycleSnapshot = InnerEngine.runtimeLifecycleSnapshot;
    pub const runtimePlatformIdentityAlloc = InnerEngine.runtimePlatformIdentityAlloc;
    pub const telemetrySnapshot = InnerEngine.telemetrySnapshot;
    pub const commit = InnerEngine.commit;
    pub const commitWithBacking = InnerEngine.commitWithBacking;
    pub const commitPreparedWithBacking = InnerEngine.commitPreparedWithBacking;
    pub const flushPendingCommit = InnerEngine.flushPendingCommit;

    pub fn init(
        allocator: std.mem.Allocator,
        config: core.pcs.PcsConfig,
    ) !Scheme {
        try validateRuntimeLifecycle(runtimeLifecycleSnapshot());
        return InnerEngine.init(allocator, config);
    }

    /// Consumes `scheme` on every path, exactly like `InnerEngine.prove`.
    pub fn prove(
        allocator: std.mem.Allocator,
        components: []const ProverComponent,
        channel: *Channel,
        scheme: Scheme,
        options: prover_api.ProveOptions,
    ) !ExtendedProof {
        var owned_scheme = scheme;
        var scheme_moved = false;
        defer if (!scheme_moved) InnerEngine.deinit(&owned_scheme, allocator);

        try validateRuntimeLifecycle(runtimeLifecycleSnapshot());
        try validateProfileComponents(components);
        if (options.composition_stage != null)
            return error.ProfileCompositionOverrideUnsupported;
        if (options.cpu_composition_execution != null)
            return error.ProfileCpuCompositionRequestUnsupported;

        const telemetry_before = try InnerEngine.telemetrySnapshot();
        const audited = try allocator.dupe(ProverComponent, components);
        defer allocator.free(audited);
        const caller_index = audited.len - 2;
        const provider_index = audited.len - 1;
        var audits = [2]ComponentAudit{
            .init(audited[caller_index]),
            .init(audited[provider_index]),
        };
        audited[caller_index] = audits[0].asComponent();
        audited[provider_index] = audits[1].asComponent();

        scheme_moved = true;
        var extended = try InnerEngine.prove(
            allocator,
            audited,
            channel,
            owned_scheme,
            options,
        );
        errdefer extended.deinit(allocator);

        try audits[0].requireEvidence(.caller);
        try audits[1].requireEvidence(.provider);
        const telemetry_after = try InnerEngine.telemetrySnapshot();
        try validateProofDelta(telemetry_after.delta(telemetry_before));
        return extended;
    }
};

pub fn provePoseidon2WithPublicData(
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.PcsConfig,
    exec_trace: *const riscv.runner.trace.Trace,
    calls: *const riscv.runner.guest_precompile.call_buffer.Frozen,
    execution_rows: *const riscv.runner.guest_precompile.poseidon2_v1.FrozenExecutionRows,
    opt_chain: ?*const riscv.runner.state_chain.StateChainTracker,
    opt_memory: ?*const riscv.runner.memory_state.Snapshot,
    recorder: ?*prover_api.stage_profile.Recorder,
    public_data: riscv.air.public_data.PublicData,
) !prover.Poseidon2ProveOutput {
    const lifecycle_before = AuthenticatedProfileEngine.runtimeLifecycleSnapshot();
    try validateRuntimeLifecycle(lifecycle_before);
    const telemetry_before = try AuthenticatedProfileEngine.telemetrySnapshot();

    var output = try prover.provePoseidon2WithEngineAndPublicData(
        AuthenticatedProfileEngine,
        allocator,
        pcs_config,
        exec_trace,
        calls,
        execution_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
    );
    errdefer output.deinit(allocator);

    const lifecycle_after = AuthenticatedProfileEngine.runtimeLifecycleSnapshot();
    try validateRuntimeLifecycle(lifecycle_after);
    if (!std.meta.eql(lifecycle_before.identity, lifecycle_after.identity))
        return error.RuntimeIdentityChangedDuringProof;
    const telemetry_after = try AuthenticatedProfileEngine.telemetrySnapshot();
    try validateTransactionDelta(telemetry_after.delta(telemetry_before));
    return output;
}

/// Independent verification consumes `proof` on every return path.  It uses
/// the ordinary Metal engine directly: the wrapper changes no transcript,
/// hasher, commitment, statement, proof, or verifier type.
pub fn verifyPoseidon2(
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.PcsConfig,
    statement: prover.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    proof: prover.Proof,
    claim: *const prover.Poseidon2InteractionClaim,
) !void {
    return prover.verifyPoseidon2WithEngine(
        InnerEngine,
        allocator,
        pcs_config,
        statement,
        extension,
        artifact,
        proof,
        claim,
    );
}

pub fn validateRuntimeLifecycle(
    lifecycle: InnerEngine.RuntimeLifecycleSnapshot,
) Error!void {
    if (!lifecycle.initialized or lifecycle.identity == null)
        return error.AuthenticatedRuntimeRequired;
    const identity = lifecycle.identity.?;
    if (identity.origin != .authenticated_core_aot)
        return error.AuthenticatedRuntimeRequired;
    if (identity.manifest_sha256 == null or identity.metallib_sha256 == null or
        identity.metallib_bytes == null or identity.metallib_bytes.? == 0)
    {
        return error.IncompleteAuthenticatedRuntimeIdentity;
    }
}

/// Admits exactly the canonical caller/provider tail to intentional generic
/// evaluation.  Any backend capability is rejected because the current union
/// can describe only one of their direct/LogUp halves, not the complete
/// protocol component.
pub fn validateProfileComponents(components: []const ProverComponent) Error!void {
    if (components.len < 2) return error.ProfileComponentSetTooSmall;
    const caller = components[components.len - 2];
    const provider = components[components.len - 1];
    if (caller.profile_identity != .riscv_guest_poseidon2_caller_v1)
        return error.CallerSemanticIdentityMismatch;
    if (provider.profile_identity != .riscv_guest_poseidon2_provider_v1)
        return error.ProviderSemanticIdentityMismatch;
    if (caller.nConstraints() != caller_component.constraint_count)
        return error.CallerConstraintGeometryMismatch;
    if (provider.nConstraints() != provider_component.constraint_count)
        return error.ProviderConstraintGeometryMismatch;
    if (caller.maxConstraintLogDegreeBound() != provider.maxConstraintLogDegreeBound())
        return error.ProfileLogDegreeMismatch;
    if (caller.compositionLogSplit() != provider.compositionLogSplit())
        return error.ProfileCompositionSplitMismatch;
    if (caller.prepare_domain_evaluator == null or provider.prepare_domain_evaluator == null)
        return error.ProfilePreparedEvaluatorMissing;
    if (caller.domain_parallel_evaluator != null or provider.domain_parallel_evaluator != null or
        caller.pool_exclusive_domain or provider.pool_exclusive_domain)
    {
        return error.UnreviewedProfileDomainParallelism;
    }
    if (caller.backend_composition_capability != null or
        provider.backend_composition_capability != null)
    {
        return error.UnreviewedProfileBackendCapability;
    }
}

pub fn validateProofDelta(delta: InnerEngine.Backend.TelemetryDelta) !void {
    const counters = delta.counters;
    if (counters.cpu_riscv_polynomial_composition_declines != 0)
        return error.ResidentPolynomialDeclineObserved;
    if (counters.riscv_base_polynomial_eligible_components != 0 and
        counters.metal_riscv_base_polynomial_batch_dispatches == 0)
    {
        return error.ResidentBasePolynomialDispatchMissing;
    }
    if (counters.riscv_lookup_polynomial_eligible_components != 0 and
        counters.metal_riscv_lookup_polynomial_batch_dispatches == 0)
    {
        return error.ResidentLookupPolynomialDispatchMissing;
    }
    if (counters.riscv_base_polynomial_eligible_components == 0 and
        counters.metal_riscv_base_polynomial_batch_dispatches != 0)
    {
        return error.UnexpectedBasePolynomialDispatch;
    }
    if (counters.riscv_lookup_polynomial_eligible_components == 0 and
        counters.metal_riscv_lookup_polynomial_batch_dispatches != 0)
    {
        return error.UnexpectedLookupPolynomialDispatch;
    }
    try delta.requireAcceleratedWithoutFallbacks();
}

pub fn validateTransactionDelta(delta: InnerEngine.Backend.TelemetryDelta) !void {
    try validateProofDelta(delta);
    const counters = delta.counters;
    if (counters.riscv_base_polynomial_eligible_components == 0 or
        counters.metal_riscv_base_polynomial_batch_dispatches == 0)
    {
        return error.ResidentBasePolynomialDispatchMissing;
    }
    if (counters.riscv_lookup_polynomial_eligible_components == 0 or
        counters.metal_riscv_lookup_polynomial_batch_dispatches == 0)
    {
        return error.ResidentLookupPolynomialDispatchMissing;
    }
    if (counters.resident_merkle_commits == 0)
        return error.NoResidentCommitmentEvidence;
}

const ProfileRole = enum { caller, provider };

const ComponentAudit = struct {
    original: ProverComponent,
    domain_evaluations: std.atomic.Value(u32) = .init(0),
    point_evaluations: std.atomic.Value(u32) = .init(0),

    fn init(original: ProverComponent) ComponentAudit {
        return .{ .original = original };
    }

    fn asComponent(self: *ComponentAudit) ProverComponent {
        return .{
            .ctx = self,
            .vtable = &audit_vtable,
            .profile_identity = self.original.profile_identity,
            .backend_composition_capability = self.original.backend_composition_capability,
            .composition_work_profile = if (self.original.composition_work_profile != null)
                compositionWorkProfile
            else
                null,
            .oods_work_profile = if (self.original.oods_work_profile != null)
                oodsWorkProfile
            else
                null,
            .prepare_domain_evaluator = prepareDomain,
            .domain_parallel_evaluator = if (self.original.domain_parallel_evaluator != null)
                evaluateDomainParallel
            else
                null,
            .pool_exclusive_domain = self.original.pool_exclusive_domain,
        };
    }

    fn requireEvidence(self: *const ComponentAudit, role: ProfileRole) Error!void {
        const domain = self.domain_evaluations.load(.acquire);
        const point = self.point_evaluations.load(.acquire);
        switch (role) {
            .caller => {
                if (domain == 0) return error.CallerDomainEvaluationMissing;
                if (domain != 1) return error.CallerDomainEvaluationRepeated;
                if (point == 0) return error.CallerPointEvaluationMissing;
                if (point != 1) return error.CallerPointEvaluationRepeated;
            },
            .provider => {
                if (domain == 0) return error.ProviderDomainEvaluationMissing;
                if (domain != 1) return error.ProviderDomainEvaluationRepeated;
                if (point == 0) return error.ProviderPointEvaluationMissing;
                if (point != 1) return error.ProviderPointEvaluationRepeated;
            },
        }
    }

    fn cast(context: *const anyopaque) *ComponentAudit {
        return @constCast(@as(*const ComponentAudit, @ptrCast(@alignCast(context))));
    }

    fn nConstraints(context: *const anyopaque) usize {
        return cast(context).original.nConstraints();
    }

    fn maxConstraintLogDegreeBound(context: *const anyopaque) u32 {
        return cast(context).original.maxConstraintLogDegreeBound();
    }

    fn compositionLogSplit(context: *const anyopaque) u32 {
        return cast(context).original.compositionLogSplit();
    }

    fn traceLogDegreeBounds(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!core_components.TraceLogDegreeBounds {
        return cast(context).original.traceLogDegreeBounds(allocator);
    }

    fn maskPoints(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_components.MaskPoints {
        return cast(context).original.maskPoints(
            allocator,
            point,
            max_log_degree_bound,
        );
    }

    fn preprocessedColumnIndices(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return cast(context).original.preprocessedColumnIndices(allocator);
    }

    fn evaluatePoint(
        context: *const anyopaque,
        point: CirclePointQM31,
        mask: *const core_components.MaskValues,
        accumulator: *core.air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void {
        const self = cast(context);
        _ = self.point_evaluations.fetchAdd(1, .monotonic);
        return self.original.evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }

    fn evaluateDomain(
        context: *const anyopaque,
        trace: *const component_mod.Trace,
        accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!void {
        const self = cast(context);
        _ = self.domain_evaluations.fetchAdd(1, .monotonic);
        return self.original.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }

    fn evaluateDomainParallel(
        context: *const anyopaque,
        trace: *const component_mod.Trace,
        accumulator: *accumulation.DomainEvaluationAccumulator,
        pool: *work_pool.WorkPool,
    ) anyerror!void {
        const self = cast(context);
        _ = self.domain_evaluations.fetchAdd(1, .monotonic);
        return self.original.evaluateConstraintQuotientsOnDomainParallel(
            trace,
            accumulator,
            pool,
        );
    }

    /// The audit changes the erased component context from the frontend owner
    /// to `ComponentAudit`. Forward cold work-authority callbacks explicitly
    /// so they still receive the original owner context; copying either raw
    /// callback into `asComponent` would reinterpret this audit as that owner.
    fn compositionWorkProfile(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work.ComponentProfile {
        const self = cast(context);
        const profile = self.original.composition_work_profile orelse
            return error.ProfileCompositionWorkAuthorityMissing;
        return profile(self.original.ctx, allocator);
    }

    fn oodsWorkProfile(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
        source: *const composition_work.ComponentProfile,
    ) anyerror!oods_work.ComponentProfile {
        const self = cast(context);
        const profile = self.original.oods_work_profile orelse
            return error.ProfileOodsWorkAuthorityMissing;
        return profile(
            self.original.ctx,
            allocator,
            max_log_degree_bound,
            source,
        );
    }

    fn prepareDomain(
        context: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const component_mod.Trace,
        accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self = cast(context);
        const prepare = self.original.prepare_domain_evaluator orelse
            return error.ProfilePreparedEvaluatorMissing;
        var inner = try prepare(self.original.ctx, allocator, trace, accumulator);
        errdefer inner.deinit();
        try inner.validate();
        const audited = try allocator.create(PreparedAudit);
        audited.* = .{
            .allocator = allocator,
            .owner = self,
            .inner = inner,
        };
        return .{
            .context = audited,
            .vtable = &prepared_audit_vtable,
            .task_class = inner.task_class,
            .resources = inner.resources,
        };
    }
};

const audit_vtable = component_mod.ComponentProverVTable{
    .nConstraints = ComponentAudit.nConstraints,
    .maxConstraintLogDegreeBound = ComponentAudit.maxConstraintLogDegreeBound,
    .compositionLogSplit = ComponentAudit.compositionLogSplit,
    .traceLogDegreeBounds = ComponentAudit.traceLogDegreeBounds,
    .maskPoints = ComponentAudit.maskPoints,
    .preprocessedColumnIndices = ComponentAudit.preprocessedColumnIndices,
    .evaluateConstraintQuotientsAtPoint = ComponentAudit.evaluatePoint,
    .evaluateConstraintQuotientsOnDomain = ComponentAudit.evaluateDomain,
};

const PreparedAudit = struct {
    allocator: std.mem.Allocator,
    owner: *ComponentAudit,
    inner: prepared_domain.PreparedDomainEvaluation,

    fn run(context: *anyopaque, execution: *task_graph.TaskContext) anyerror!void {
        const self: *PreparedAudit = @ptrCast(@alignCast(context));
        _ = self.owner.domain_evaluations.fetchAdd(1, .monotonic);
        return self.inner.run(execution);
    }

    fn deinit(context: *anyopaque) void {
        const self: *PreparedAudit = @ptrCast(@alignCast(context));
        const allocator = self.allocator;
        self.inner.deinit();
        allocator.destroy(self);
    }
};

const prepared_audit_vtable = prepared_domain.VTable{
    .run = PreparedAudit.run,
    .deinit = PreparedAudit.deinit,
};

test "component audit preserves work callbacks with their original context" {
    const Harness = struct {
        composition_calls: usize = 0,
        oods_calls: usize = 0,

        fn cast(context: *const anyopaque) *@This() {
            return @constCast(@as(*const @This(), @ptrCast(@alignCast(context))));
        }

        fn composition(
            context: *const anyopaque,
            _: std.mem.Allocator,
        ) anyerror!composition_work.ComponentProfile {
            cast(context).composition_calls += 1;
            return error.ExpectedCompositionForwarderCall;
        }

        fn oods(
            context: *const anyopaque,
            _: std.mem.Allocator,
            _: u32,
            _: *const composition_work.ComponentProfile,
        ) anyerror!oods_work.ComponentProfile {
            cast(context).oods_calls += 1;
            return error.ExpectedOodsForwarderCall;
        }
    };

    var harness = Harness{};
    const original = ProverComponent{
        .ctx = &harness,
        // This focused fixture invokes only the two optional cold callbacks;
        // the audit replaces the vtable before either callback is observed.
        .vtable = undefined,
        .composition_work_profile = Harness.composition,
        .oods_work_profile = Harness.oods,
    };
    var audit = ComponentAudit.init(original);
    const wrapped = audit.asComponent();
    try std.testing.expectEqual(@intFromPtr(&audit), @intFromPtr(wrapped.ctx));
    try std.testing.expect(wrapped.composition_work_profile != null);
    try std.testing.expect(wrapped.oods_work_profile != null);
    try std.testing.expect(wrapped.composition_work_profile != original.composition_work_profile);
    try std.testing.expect(wrapped.oods_work_profile != original.oods_work_profile);

    try std.testing.expectError(
        error.ExpectedCompositionForwarderCall,
        wrapped.composition_work_profile.?(wrapped.ctx, std.testing.allocator),
    );
    var source: composition_work.ComponentProfile = undefined;
    try std.testing.expectError(
        error.ExpectedOodsForwarderCall,
        wrapped.oods_work_profile.?(
            wrapped.ctx,
            std.testing.allocator,
            7,
            &source,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), harness.composition_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.oods_calls);

    var absent_audit = ComponentAudit.init(.{
        .ctx = &harness,
        .vtable = undefined,
    });
    const absent = absent_audit.asComponent();
    try std.testing.expect(absent.composition_work_profile == null);
    try std.testing.expect(absent.oods_work_profile == null);
}

comptime {
    prover_api.assertProverEngine(AuthenticatedProfileEngine);
    if (AuthenticatedProfileEngine.Backend != metal.MetalCommitBackend or
        AuthenticatedProfileEngine.Hasher != InnerEngine.Hasher or
        AuthenticatedProfileEngine.MerkleChannel != InnerEngine.MerkleChannel or
        AuthenticatedProfileEngine.Channel != InnerEngine.Channel or
        AuthenticatedProfileEngine.Scheme != InnerEngine.Scheme or
        AuthenticatedProfileEngine.ExtendedProof != InnerEngine.ExtendedProof)
    {
        @compileError("guest Metal admission changed the CPU-compatible proof protocol");
    }
}
