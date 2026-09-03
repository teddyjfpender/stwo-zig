//! Matched, non-production resource and closure policy for Ethereum leaves
//! whose canonical 445-column Poseidon provider is proved in d5 shards.
//!
//! The geometry input is the frontend-minted `GeometrySnapshot`; callers do
//! not supply column counts, log sizes, or byte estimates. Provider planning
//! is a separate step because reconstructing the exact ordered call authority
//! is materially more expensive than the request-independent geometry audit.
//! A fresh-closure admission can only be minted from the real d5 strategy and
//! independently verified zero-sum closure. None of these authorities enables
//! a production or recursive route by itself.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const aggregation_hash = @import("../../aggregation/hash.zig");
const component_d5 = @import("../../air/lang/typed_poseidon2_degree5_component.zig");
const public_data_v2 = @import("../../air/public_data_v2.zig");
const geometry_mod = @import("ethereum_segment_geometry.zig");
const matched_execution = @import("ethereum_leaf_matched_ab_execution_profile_v1.zig");
const provider_authority = @import("../memory_provider_shards/authority.zig");
const provider_order = @import("../memory_provider_shards/provider_order_component.zig");
const d5_authority = @import("../memory_provider_shards/degree5_ethereum_omit_provider_authority_v1.zig");
const omit_protocol = @import("../memory_provider_shards/ethereum_omit_protocol_v1.zig");
const policy_support = @import("ethereum_matched_ab_omitted_provider_policy_v1_support.zig");

const residency = prover_engine.pcs.residency_estimate;
const shard_planner = prover_engine.pcs.residency_shard_plan;

pub const format_version: u16 = 1;
pub const production_active = false;
pub const recursive_admissible = false;
pub const log_blowup_factor: u32 = 1;
pub const omitted_core_composition_log_split: u32 = 1;
pub const omitted_core_composition_columns: u64 = 8;
pub const legacy_provider_main_columns: u64 =
    provider_authority.main_column_count;
pub const provider_shard_log_size: u32 =
    provider_authority.maximum_shard_log_size;
pub const provider_preprocessed_columns: u64 = 2;
pub const provider_main_columns: u64 = component_d5.MAIN_COLUMNS;
pub const provider_interaction_columns: u64 =
    component_d5.INTERACTION_COLUMNS + provider_order.interaction_column_count;
pub const provider_composition_columns: u64 =
    4 * (@as(u64, 1) << @intCast(component_d5.COMPOSITION_LOG_SPLIT));
pub const provider_non_column_reserve_bytes: u64 =
    16 * 1024 * 1024 * 1024;
pub const host_byte_budget: u64 = matched_execution.leaf_host_byte_budget;
pub const provider_retention_policy: residency.RetentionPolicy = .always;
pub const omitted_core_retention_policy: residency.RetentionPolicy = .never;
pub const canonical_provider_execution =
    matched_execution.ProviderExecutionRequest{
        .concurrent_owners = 1,
        .engine_workers_per_owner = 1,
    };

pub const Digest = aggregation_hash.Digest;
pub const PublicDataWireId = public_data_v2.Digest;
pub const GeometrySnapshot = geometry_mod.GeometrySnapshot;
pub const ProviderCallAuthorityV1 = geometry_mod.ProviderCallAuthorityV1;
pub const ProviderShardPlanV1 = provider_authority.ProviderShardPlanV1;
pub const MatchedExecutionAuthorityV1 = matched_execution.Authority;
pub const StageEstimateV1 = policy_support.StageEstimateV1;

const omitted_core_domain =
    "stwo-zig/riscv/ethereum-matched-ab-omitted-core/v1\x00";
const geometry_domain =
    "stwo-zig/riscv/ethereum-matched-ab-geometry/v1\x00";
const call_authority_domain =
    "stwo-zig/riscv/ethereum-matched-ab-provider-calls/v1\x00";
const provider_resource_domain =
    "stwo-zig/riscv/ethereum-matched-ab-provider-resource/v1\x00";
const provider_plan_domain =
    "stwo-zig/riscv/ethereum-matched-ab-provider-plan/v1\x00";
const fresh_closure_domain =
    "stwo-zig/riscv/ethereum-matched-ab-fresh-closure/v1\x00";

comptime {
    if (legacy_provider_main_columns != 445 or
        provider_shard_log_size != 20 or
        provider_main_columns != 239 or
        provider_interaction_columns != 12 or
        component_d5.COMPOSITION_LOG_SPLIT != 2 or
        provider_composition_columns != 16 or
        omitted_core_composition_log_split != 1 or
        omitted_core_composition_columns != 8)
    {
        @compileError("matched omitted-provider geometry drifted");
    }
}

/// Geometry-only matched admission after removing exactly the typed legacy
/// provider span. This remains independently usable before provider calls are
/// reconstructed or a shard plan exists.
pub const OmittedCoreEstimateV1 = struct {
    format: u16,
    geometry_identity: Digest,
    execution_authority_identity: Digest,
    legacy_provider_log_size: u32,
    legacy_provider_rows: u32,
    tree0: StageEstimateV1,
    tree1_non_provider: StageEstimateV1,
    tree2: StageEstimateV1,
    composition: StageEstimateV1,
    composition_column_log_size: u32,
    retained_opening_lower_bound_bytes: u64,
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,
    host_byte_budget: u64,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: OmittedCoreEstimateV1) !void {
        if (self.format != format_version or self.production_eligible or
            aggregation_hash.isZero(self.geometry_identity) or
            aggregation_hash.isZero(self.execution_authority_identity) or
            self.legacy_provider_rows == 0 or
            self.legacy_provider_log_size != expectedLogSize(
                self.legacy_provider_rows,
            ) or self.composition.column_count !=
            omitted_core_composition_columns or
            self.composition_column_log_size !=
                self.composition.max_column_log_size or
            self.host_byte_budget != host_byte_budget)
        {
            return error.InvalidMatchedAbOmittedCoreEstimate;
        }
        inline for (.{
            self.tree0,
            self.tree1_non_provider,
            self.tree2,
            self.composition,
        }) |stage| {
            try stage.validate();
            if (stage.log_blowup_factor != log_blowup_factor or
                stage.retention_policy != omitted_core_retention_policy)
            {
                return error.InvalidMatchedAbOmittedCoreEstimate;
            }
        }
        const totals = try policy_support.stagedTotals(.{
            self.tree0,
            self.tree1_non_provider,
            self.tree2,
            self.composition,
        });
        if (self.retained_opening_lower_bound_bytes != totals.retained or
            self.commit_transient_lower_bound_bytes != totals.transient or
            self.staged_peak_lower_bound_bytes != totals.peak or
            !aggregation_hash.eql(self.identity, omittedCoreIdentity(self)))
        {
            return error.InvalidMatchedAbOmittedCoreEstimate;
        }
    }

    pub fn validateAgainst(
        self: OmittedCoreEstimateV1,
        snapshot: *const GeometrySnapshot,
        execution: MatchedExecutionAuthorityV1,
    ) !void {
        try self.validate();
        const expected = try estimateOmittedCoreV1(snapshot, execution);
        if (!std.meta.eql(self, expected))
            return error.MatchedAbOmittedCoreEstimateMismatch;
    }

    pub fn requireWithinMatchedBudget(
        self: OmittedCoreEstimateV1,
    ) !void {
        try self.validate();
        if (self.staged_peak_lower_bound_bytes > self.host_byte_budget)
            return error.PcsResidentBudgetExceeded;
    }
};

pub fn estimateOmittedCoreV1(
    snapshot: *const GeometrySnapshot,
    execution: MatchedExecutionAuthorityV1,
) !OmittedCoreEstimateV1 {
    try execution.validate();
    try validateSnapshot(snapshot);
    const tree0 = StageEstimateV1.fromResidency(try residency.estimate(
        snapshot.tree0_log_sizes,
        log_blowup_factor,
        omitted_core_retention_policy,
    ));
    const tree1 = StageEstimateV1.fromResidency(try residency.estimate(
        snapshot.tree1_non_candidate_log_sizes,
        log_blowup_factor,
        omitted_core_retention_policy,
    ));
    const tree2 = StageEstimateV1.fromResidency(try residency.estimate(
        snapshot.tree2_log_sizes,
        log_blowup_factor,
        omitted_core_retention_policy,
    ));
    const composition_log_size = @max(
        policy_support.maximumLogSize(snapshot.tree0_log_sizes),
        @max(
            policy_support.maximumLogSize(
                snapshot.tree1_non_candidate_log_sizes,
            ),
            policy_support.maximumLogSize(snapshot.tree2_log_sizes),
        ),
    );
    const composition = StageEstimateV1.fromResidency(
        try residency.estimateUniform(
            omitted_core_composition_columns,
            composition_log_size,
            log_blowup_factor,
            omitted_core_retention_policy,
        ),
    );
    const totals = try policy_support.stagedTotals(.{
        tree0,
        tree1,
        tree2,
        composition,
    });
    var result = OmittedCoreEstimateV1{
        .format = format_version,
        .geometry_identity = geometryIdentity(snapshot),
        .execution_authority_identity = execution.identity,
        .legacy_provider_log_size = snapshot.legacy_poseidon.log_size,
        .legacy_provider_rows = snapshot.legacy_poseidon.n_rows,
        .tree0 = tree0,
        .tree1_non_provider = tree1,
        .tree2 = tree2,
        .composition = composition,
        .composition_column_log_size = composition_log_size,
        .retained_opening_lower_bound_bytes = totals.retained,
        .commit_transient_lower_bound_bytes = totals.transient,
        .staged_peak_lower_bound_bytes = totals.peak,
        .host_byte_budget = host_byte_budget,
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = omittedCoreIdentity(result);
    try result.validate();
    return result;
}

/// Stable identity of the exact ordered call source. The commitment is
/// recomputed from calls; neither a count nor a digest is accepted from a
/// producer.
pub const CallAuthorityIdentityV1 = struct {
    format: u16,
    public_data_wire_id: PublicDataWireId,
    call_count: u64,
    ordered_call_list_commitment: Digest,
    identity: Digest,

    pub fn canonical(
        source: *const ProviderCallAuthorityV1,
    ) !CallAuthorityIdentityV1 {
        const count = std.math.cast(u64, source.calls.len) orelse
            return error.MatchedAbProviderCallCountOutOfRange;
        var result = CallAuthorityIdentityV1{
            .format = format_version,
            .public_data_wire_id = source.public_data_wire_id,
            .call_count = count,
            .ordered_call_list_commitment = try provider_authority.orderedCallListCommitment(source.calls),
            .identity = undefined,
        };
        result.identity = callAuthorityIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: CallAuthorityIdentityV1) !void {
        if (self.format != format_version or self.call_count == 0 or
            publicDataWireIdIsZero(self.public_data_wire_id) or
            aggregation_hash.isZero(self.ordered_call_list_commitment) or
            !aggregation_hash.eql(self.identity, callAuthorityIdentity(self)))
        {
            return error.InvalidMatchedAbProviderCallAuthority;
        }
    }

    pub fn validateAgainst(
        self: CallAuthorityIdentityV1,
        source: *const ProviderCallAuthorityV1,
    ) !void {
        try self.validate();
        const expected = try canonical(source);
        if (!std.meta.eql(self, expected))
            return error.MatchedAbProviderCallAuthorityMismatch;
    }
};

/// Exact lower-bound geometry of one log20 d5 provider owner. The canonical
/// call-partition plan remains 445 columns; this sibling records the actual
/// 2/239/12/16 d5 Tree0/1/2/composition geometry without changing plan bytes.
pub const ProviderResourceEstimateV1 = struct {
    tree0: StageEstimateV1,
    tree1: StageEstimateV1,
    tree2: StageEstimateV1,
    composition: StageEstimateV1,
    composition_column_log_size: u32,
    retained_opening_lower_bound_bytes: u64,
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,
    non_column_reserve_bytes: u64,
    admitted_peak_bytes: u64,
    identity: Digest,

    pub fn canonical() !ProviderResourceEstimateV1 {
        const tree0 = StageEstimateV1.fromResidency(
            try residency.estimateUniform(
                provider_preprocessed_columns,
                provider_shard_log_size,
                log_blowup_factor,
                provider_retention_policy,
            ),
        );
        const tree1 = StageEstimateV1.fromResidency(
            try residency.estimateUniform(
                provider_main_columns,
                provider_shard_log_size,
                log_blowup_factor,
                provider_retention_policy,
            ),
        );
        const tree2 = StageEstimateV1.fromResidency(
            try residency.estimateUniform(
                provider_interaction_columns,
                provider_shard_log_size,
                log_blowup_factor,
                provider_retention_policy,
            ),
        );
        const composition = StageEstimateV1.fromResidency(
            try residency.estimateUniform(
                provider_composition_columns,
                provider_shard_log_size,
                log_blowup_factor,
                provider_retention_policy,
            ),
        );
        const totals = try policy_support.stagedTotals(.{
            tree0,
            tree1,
            tree2,
            composition,
        });
        var result = ProviderResourceEstimateV1{
            .tree0 = tree0,
            .tree1 = tree1,
            .tree2 = tree2,
            .composition = composition,
            .composition_column_log_size = provider_shard_log_size,
            .retained_opening_lower_bound_bytes = totals.retained,
            .commit_transient_lower_bound_bytes = totals.transient,
            .staged_peak_lower_bound_bytes = totals.peak,
            .non_column_reserve_bytes = provider_non_column_reserve_bytes,
            .admitted_peak_bytes = try policy_support.add(
                totals.peak,
                provider_non_column_reserve_bytes,
            ),
            .identity = undefined,
        };
        result.identity = providerResourceIdentity(result);
        return result;
    }

    pub fn validate(self: ProviderResourceEstimateV1) !void {
        const expected = try canonical();
        if (!std.meta.eql(self, expected) or
            self.admitted_peak_bytes > host_byte_budget)
        {
            return error.InvalidMatchedAbProviderResourceEstimate;
        }
    }
};

pub const ProviderPlanAdmissionV1 = struct {
    format: u16,
    call_authority: CallAuthorityIdentityV1,
    execution_authority_identity: Digest,
    provider_execution: matched_execution.ProviderExecutionRequest,
    residency: provider_authority.ResidencyPlanningAuthorityV1,
    provider_plan_identity: Digest,
    call_list_commitment: Digest,
    shard_count: u32,
    resource: ProviderResourceEstimateV1,
    host_byte_budget: u64,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: ProviderPlanAdmissionV1) !void {
        try self.call_authority.validate();
        try self.residency.validate();
        const execution = matched_execution.Authority.canonical();
        try execution.validateProviderExecution(self.provider_execution);
        const request = self.residency.request;
        const plan = self.residency.result;
        if (self.format != format_version or self.production_eligible or
            !aggregation_hash.eql(
                self.execution_authority_identity,
                execution.identity,
            ) or !std.meta.eql(
            self.provider_execution,
            canonical_provider_execution,
        ) or request.logical_row_count != self.call_authority.call_count or
            request.column_count != legacy_provider_main_columns or
            request.min_shard_log_size != provider_shard_log_size or
            request.max_shard_log_size != provider_shard_log_size or
            request.log_blowup_factor != log_blowup_factor or
            request.retention_policy != provider_retention_policy or
            request.host_byte_budget != host_byte_budget or
            request.reserved_host_bytes != provider_non_column_reserve_bytes or
            request.requested_parallel_shards != 1 or
            plan.shard_log_size != provider_shard_log_size or
            plan.admitted_parallel_shards != 1 or
            plan.shard_count != self.shard_count or
            !aggregation_hash.eql(
                self.call_list_commitment,
                self.call_authority.ordered_call_list_commitment,
            ) or aggregation_hash.isZero(self.provider_plan_identity) or
            self.host_byte_budget != host_byte_budget)
        {
            return error.InvalidMatchedAbProviderPlanAdmission;
        }
        try self.resource.validate();
        if (!aggregation_hash.eql(self.identity, providerPlanIdentity(self)))
            return error.InvalidMatchedAbProviderPlanAdmission;
    }

    pub fn validateAgainst(
        self: ProviderPlanAdmissionV1,
        plan: *const ProviderShardPlanV1,
        calls: *const ProviderCallAuthorityV1,
        execution: MatchedExecutionAuthorityV1,
    ) !void {
        const expected = try providerPlanAdmission(plan, calls, execution);
        if (!std.meta.eql(self, expected))
            return error.MatchedAbProviderPlanAdmissionMismatch;
    }
};

pub const OwnedProviderPlanAdmissionV1 = struct {
    allocator: std.mem.Allocator,
    plan: ProviderShardPlanV1,
    admission: ProviderPlanAdmissionV1,

    pub fn create(
        allocator: std.mem.Allocator,
        session: Digest,
        calls: *const ProviderCallAuthorityV1,
        execution: MatchedExecutionAuthorityV1,
    ) !OwnedProviderPlanAdmissionV1 {
        try execution.validate();
        try execution.validateProviderExecution(canonical_provider_execution);
        const call_identity = try CallAuthorityIdentityV1.canonical(calls);
        var plan = try ProviderShardPlanV1.create(
            allocator,
            session,
            calls.calls,
            providerShardRequest(call_identity.call_count),
        );
        errdefer plan.deinit(allocator);
        const admission = try providerPlanAdmission(&plan, calls, execution);
        return .{
            .allocator = allocator,
            .plan = plan,
            .admission = admission,
        };
    }

    pub fn validateAgainst(
        self: *const OwnedProviderPlanAdmissionV1,
        calls: *const ProviderCallAuthorityV1,
        execution: MatchedExecutionAuthorityV1,
    ) !void {
        try self.admission.validateAgainst(&self.plan, calls, execution);
    }

    pub fn deinit(self: *OwnedProviderPlanAdmissionV1) void {
        self.plan.deinit(self.allocator);
        self.* = undefined;
    }
};

/// Proof-time leaf authority. It cannot be created from a provider plan or
/// detached claims: both the genuine d5 strategy and its fresh zero-sum joint
/// closure must validate and agree on every shared identity.
pub const FreshClosureAdmissionV1 = struct {
    format: u16,
    omitted_core_estimate_identity: Digest,
    provider_plan_admission_identity: Digest,
    call_authority_identity: Digest,
    strategy: d5_authority.FreshStrategyV1,
    closure: omit_protocol.VerifiedJointClosureV1,
    production_eligible: bool,
    recursive_admissible: bool,
    identity: Digest,

    pub fn canonical(
        core: *const OmittedCoreEstimateV1,
        plan: *const ProviderPlanAdmissionV1,
        strategy: d5_authority.FreshStrategyV1,
        closure: omit_protocol.VerifiedJointClosureV1,
    ) !FreshClosureAdmissionV1 {
        try core.validate();
        try plan.validate();
        try strategy.validate();
        try closure.validate();
        var result = FreshClosureAdmissionV1{
            .format = format_version,
            .omitted_core_estimate_identity = core.identity,
            .provider_plan_admission_identity = plan.identity,
            .call_authority_identity = plan.call_authority.identity,
            .strategy = strategy,
            .closure = closure,
            .production_eligible = false,
            .recursive_admissible = false,
            .identity = undefined,
        };
        result.identity = freshClosureIdentity(result);
        try result.validateAgainst(core, plan);
        return result;
    }

    pub fn validate(self: FreshClosureAdmissionV1) !void {
        try self.strategy.validate();
        try self.closure.validate();
        if (self.format != format_version or self.production_eligible or
            self.recursive_admissible or
            !aggregation_hash.eql(
                self.strategy.plan_identity,
                self.closure.plan_identity,
            ) or !aggregation_hash.eql(
            self.strategy.manifest_identity,
            self.closure.manifest_identity,
        ) or !aggregation_hash.eql(
            self.strategy.relation_context_identity,
            self.closure.relation_context_identity,
        ) or !aggregation_hash.eql(
            self.strategy.closure_identity,
            self.closure.identity,
        ) or !aggregation_hash.eql(
            self.strategy.ordered_provider_claims_identity,
            self.closure.ordered_provider_claims_identity,
        ) or self.strategy.shard_count != self.closure.shard_count or
            !aggregation_hash.eql(self.identity, freshClosureIdentity(self)))
        {
            return error.InvalidMatchedAbFreshClosureAdmission;
        }
    }

    pub fn validateAgainst(
        self: FreshClosureAdmissionV1,
        core: *const OmittedCoreEstimateV1,
        plan: *const ProviderPlanAdmissionV1,
    ) !void {
        try core.validate();
        try plan.validate();
        try self.validate();
        if (!aggregation_hash.eql(
            self.omitted_core_estimate_identity,
            core.identity,
        ) or !aggregation_hash.eql(
            self.provider_plan_admission_identity,
            plan.identity,
        ) or !aggregation_hash.eql(
            self.call_authority_identity,
            plan.call_authority.identity,
        ) or !aggregation_hash.eql(
            self.strategy.plan_identity,
            plan.provider_plan_identity,
        ) or !aggregation_hash.eql(
            self.strategy.plan_identity,
            self.closure.plan_identity,
        ) or self.strategy.shard_count != plan.shard_count) {
            return error.MatchedAbFreshClosureAuthorityMismatch;
        }
    }
};

fn providerPlanAdmission(
    plan: *const ProviderShardPlanV1,
    calls: *const ProviderCallAuthorityV1,
    execution: MatchedExecutionAuthorityV1,
) !ProviderPlanAdmissionV1 {
    try execution.validate();
    try execution.validateProviderExecution(canonical_provider_execution);
    try plan.validate(calls.calls);
    const call_identity = try CallAuthorityIdentityV1.canonical(calls);
    if (!aggregation_hash.eql(
        plan.call_list_commitment,
        call_identity.ordered_call_list_commitment,
    )) return error.MatchedAbProviderCallAuthorityMismatch;
    var result = ProviderPlanAdmissionV1{
        .format = format_version,
        .call_authority = call_identity,
        .execution_authority_identity = execution.identity,
        .provider_execution = canonical_provider_execution,
        .residency = plan.residency,
        .provider_plan_identity = plan.identity,
        .call_list_commitment = plan.call_list_commitment,
        .shard_count = plan.shard_count,
        .resource = try ProviderResourceEstimateV1.canonical(),
        .host_byte_budget = host_byte_budget,
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = providerPlanIdentity(result);
    try result.validate();
    return result;
}

fn providerShardRequest(call_count: u64) shard_planner.Request {
    return .{
        .logical_row_count = call_count,
        .column_count = legacy_provider_main_columns,
        .min_shard_log_size = provider_shard_log_size,
        .max_shard_log_size = provider_shard_log_size,
        .log_blowup_factor = log_blowup_factor,
        .retention_policy = provider_retention_policy,
        .host_byte_budget = host_byte_budget,
        .reserved_host_bytes = provider_non_column_reserve_bytes,
        .requested_parallel_shards = 1,
    };
}

fn validateSnapshot(snapshot: *const GeometrySnapshot) !void {
    if (snapshot.tree0_log_sizes.len == 0 or
        snapshot.tree1_non_candidate_log_sizes.len == 0 or
        snapshot.tree2_log_sizes.len == 0 or
        snapshot.legacy_poseidon.main_column_count !=
            legacy_provider_main_columns or
        snapshot.legacy_poseidon.n_rows == 0 or
        snapshot.legacy_poseidon.log_size != expectedLogSize(
            snapshot.legacy_poseidon.n_rows,
        ))
    {
        return error.InvalidMatchedAbOmittedCoreGeometry;
    }
}

pub fn geometryIdentity(snapshot: *const GeometrySnapshot) Digest {
    var sink = aggregation_hash.HashSink.init(geometry_domain);
    aggregation_hash.writeU16(&sink, format_version) catch unreachable;
    policy_support.hashLogSizes(&sink, snapshot.tree0_log_sizes);
    policy_support.hashLogSizes(
        &sink,
        snapshot.tree1_non_candidate_log_sizes,
    );
    policy_support.hashLogSizes(&sink, snapshot.tree2_log_sizes);
    aggregation_hash.writeU32(
        &sink,
        snapshot.legacy_poseidon.infra_index,
    ) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        snapshot.legacy_poseidon.main_column_offset,
    ) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        snapshot.legacy_poseidon.main_column_count,
    ) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        snapshot.legacy_poseidon.log_size,
    ) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        snapshot.legacy_poseidon.n_rows,
    ) catch unreachable;
    return sink.finalize();
}

fn omittedCoreIdentity(value: OmittedCoreEstimateV1) Digest {
    var sink = aggregation_hash.HashSink.init(omitted_core_domain);
    aggregation_hash.writeU16(&sink, value.format) catch unreachable;
    sink.writeAll(&value.geometry_identity) catch unreachable;
    sink.writeAll(&value.execution_authority_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.legacy_provider_log_size) catch unreachable;
    aggregation_hash.writeU32(&sink, value.legacy_provider_rows) catch unreachable;
    inline for (.{
        value.tree0,
        value.tree1_non_provider,
        value.tree2,
        value.composition,
    }) |stage| policy_support.hashStage(&sink, stage);
    aggregation_hash.writeU32(
        &sink,
        value.composition_column_log_size,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.retained_opening_lower_bound_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.commit_transient_lower_bound_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.staged_peak_lower_bound_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(&sink, value.host_byte_budget) catch unreachable;
    sink.writeAll(&.{@intFromBool(value.production_eligible)}) catch unreachable;
    return sink.finalize();
}

fn callAuthorityIdentity(value: CallAuthorityIdentityV1) Digest {
    var sink = aggregation_hash.HashSink.init(call_authority_domain);
    aggregation_hash.writeU16(&sink, value.format) catch unreachable;
    for (value.public_data_wire_id) |word|
        aggregation_hash.writeU32(&sink, word) catch unreachable;
    aggregation_hash.writeU64(&sink, value.call_count) catch unreachable;
    sink.writeAll(&value.ordered_call_list_commitment) catch unreachable;
    return sink.finalize();
}

fn providerResourceIdentity(value: ProviderResourceEstimateV1) Digest {
    var sink = aggregation_hash.HashSink.init(provider_resource_domain);
    inline for (.{ value.tree0, value.tree1, value.tree2, value.composition }) |stage|
        policy_support.hashStage(&sink, stage);
    aggregation_hash.writeU32(
        &sink,
        value.composition_column_log_size,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.retained_opening_lower_bound_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.commit_transient_lower_bound_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.staged_peak_lower_bound_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.non_column_reserve_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(&sink, value.admitted_peak_bytes) catch unreachable;
    return sink.finalize();
}

fn providerPlanIdentity(value: ProviderPlanAdmissionV1) Digest {
    var sink = aggregation_hash.HashSink.init(provider_plan_domain);
    aggregation_hash.writeU16(&sink, value.format) catch unreachable;
    sink.writeAll(&value.call_authority.identity) catch unreachable;
    sink.writeAll(&value.execution_authority_identity) catch unreachable;
    aggregation_hash.writeU16(
        &sink,
        value.provider_execution.concurrent_owners,
    ) catch unreachable;
    aggregation_hash.writeU16(
        &sink,
        value.provider_execution.engine_workers_per_owner,
    ) catch unreachable;
    sink.writeAll(&value.residency.result.request_identity) catch unreachable;
    sink.writeAll(&value.residency.result.plan_identity) catch unreachable;
    sink.writeAll(&value.provider_plan_identity) catch unreachable;
    sink.writeAll(&value.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    sink.writeAll(&value.resource.identity) catch unreachable;
    aggregation_hash.writeU64(&sink, value.host_byte_budget) catch unreachable;
    sink.writeAll(&.{@intFromBool(value.production_eligible)}) catch unreachable;
    return sink.finalize();
}

fn freshClosureIdentity(value: FreshClosureAdmissionV1) Digest {
    var sink = aggregation_hash.HashSink.init(fresh_closure_domain);
    aggregation_hash.writeU16(&sink, value.format) catch unreachable;
    sink.writeAll(&value.omitted_core_estimate_identity) catch unreachable;
    sink.writeAll(&value.provider_plan_admission_identity) catch unreachable;
    sink.writeAll(&value.call_authority_identity) catch unreachable;
    sink.writeAll(&value.strategy.identity) catch unreachable;
    sink.writeAll(&value.closure.identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.production_eligible),
        @intFromBool(value.recursive_admissible),
    }) catch unreachable;
    return sink.finalize();
}

fn expectedLogSize(rows: u32) u32 {
    return std.math.log2_int_ceil(u32, rows);
}

fn publicDataWireIdIsZero(value: PublicDataWireId) bool {
    var combined: u32 = 0;
    for (value) |word| combined |= word;
    return combined == 0;
}
