//! Ordered-call V2 provider proof for the nonproduction d5 Poseidon program.
//!
//! This sibling preserves the pinned V1 proof and adds four Tree-2 columns
//! whose component borrows only compiler-selected d5 main columns. The
//! 445-column provider plan remains call-partition custody, never AIR geometry.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const aggregation_hash = @import("../../aggregation/hash.zig");
const candidate_mod = @import("../../air/lang/typed_poseidon2_degree_bounded_candidate.zig");
const component_backend = @import("../../air/lang/typed_poseidon2_degree5_backend.zig");
const component_mod = @import("../../air/lang/typed_poseidon2_degree5_component.zig");
const trace_mod = @import("../../air/lang/typed_poseidon2_degree5_trace.zig");
const relations_mod = @import("../../air/relation_challenges.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const v1 = @import("degree5_provider_proof_v1.zig");
const harness = @import("proof_harness.zig");
const proof_authority = @import("joint_proof_authority.zig");
const provider_order = @import("provider_order_component.zig");

pub const format_version: u32 = 2;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const SOURCE_PLAN_IS_CALL_PARTITION_ONLY = true;
pub const ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = true;
pub const SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED = false;
pub const FRESH_VERIFIER_IMPLEMENTED = true;
pub const coefficient_retention = harness.CoefficientRetention.always;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;
pub const tree2_columns: usize = component_mod.INTERACTION_COLUMNS +
    provider_order.interaction_column_count;
pub const Digest = authority.Digest;
pub const ExecutionProfileV1 = v1.ExecutionProfileV1;
pub const ExecutionProfileV2 = v1.ExecutionProfileV2;

pub const VerifierProgramAuthorityV2 = struct {
    format: u32,
    base: v1.VerifierProgramAuthorityV1,
    selected_main_columns: provider_order.SelectedMainColumns,
    order_interaction_columns: u16,
    order_constraints: u16,
    order_composition_log_split: u32,
    tree2_columns: u16,
    air_program_identity: Digest,

    pub fn coldCompile(
        allocator: std.mem.Allocator,
    ) !VerifierProgramAuthorityV2 {
        var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
        defer candidate.deinit();
        const base = try v1.VerifierProgramAuthorityV1.coldCompile(allocator);
        return canonicalProgram(base, &candidate);
    }

    pub fn validateCold(
        self: VerifierProgramAuthorityV2,
        allocator: std.mem.Allocator,
    ) !void {
        var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
        defer candidate.deinit();
        try self.validateCandidate(&candidate);
    }

    pub fn validateCandidate(
        self: VerifierProgramAuthorityV2,
        candidate: *const candidate_mod.Candidate,
    ) !void {
        try self.base.validate(candidate);
        const canonical = try canonicalProgram(self.base, candidate);
        if (!std.meta.eql(self, canonical))
            return error.InvalidDegree5ProviderOrderProgram;
    }
};

pub const StatementV2 = struct {
    format: u32,
    air_program_identity: Digest,
    source_plan_identity: Digest,
    source_descriptor_identity: Digest,
    global_call_list_commitment: Digest,
    shard_call_list_commitment: Digest,
    shard_index: u32,
    first_call: u64,
    call_count: u32,
    log_size: u32,
    claims: poseidon2_air.Claims,
    ordered_call_claim: provider_order.ClaimV1,
    identity: Digest,
};

pub fn ProveOutput(comptime Engine: type) type {
    return struct {
        statement: StatementV2,
        execution_profile_identity: Digest,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub const FreshVerifiedShardV2 = struct {
    format: u32,
    air_program_identity: Digest,
    execution_profile_identity: Digest,
    source_plan_identity: Digest,
    source_descriptor_identity: Digest,
    statement_identity: Digest,
    proof_commitments_identity: Digest,
    fresh_stark_verified: bool,
    ordered_call_air_verified: bool,
    ordered_call_claim_recomputed: bool,
    shared_core_relation_context_verified: bool,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: FreshVerifiedShardV2) !void {
        if (self.format != format_version or
            !self.fresh_stark_verified or
            !self.ordered_call_air_verified or
            !self.ordered_call_claim_recomputed or
            self.shared_core_relation_context_verified or
            self.production_eligible or
            !aggregation_hash.eql(self.identity, freshIdentity(self)))
        {
            return error.InvalidFreshDegree5ProviderOrder;
        }
    }
};

pub fn proveShard(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) !ProveOutput(Engine) {
    return proveShardInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        plan,
        calls,
        shard_index,
        null,
        null,
    );
}

pub fn proveShardV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) !ProveOutput(Engine) {
    return proveShardInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        plan,
        calls,
        shard_index,
        null,
        null,
    );
}

/// Moves a verifier-checked, coefficient-bearing Stage-A transaction into the
/// standalone ordered provider proof. The transaction type stays structural
/// here because its nominal owner imports this module through the shared
/// Ethereum binding; its methods recheck the exact plan/call pointers, roots,
/// program identity, and one-shot ownership before the move.
pub fn proveShardPreparedV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
    prepared: anytype,
) !ProveOutput(Engine) {
    return proveShardInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        plan,
        calls,
        shard_index,
        null,
        prepared,
    );
}

pub fn proveShardPreparedValidatedV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: *const authority.OwnedValidatedPlanCallAuthorityV1,
    shard_index: u32,
    prepared: anytype,
) !ProveOutput(Engine) {
    return proveShardInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        plan,
        calls,
        shard_index,
        validated_calls,
        prepared,
    );
}

fn proveShardInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: anytype,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
    validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
    prepared: anytype,
) !ProveOutput(Engine) {
    var local_candidate: candidate_mod.Candidate = undefined;
    var local_candidate_live = false;
    defer if (local_candidate_live) local_candidate.deinit();
    const candidate: *candidate_mod.Candidate = if (comptime @TypeOf(prepared) == @TypeOf(null)) blk: {
        local_candidate = try candidate_mod.Candidate.init(allocator, .degree5);
        local_candidate_live = true;
        try expected_program.validateCandidate(&local_candidate);
        break :blk &local_candidate;
    } else blk: {
        const roots = try prepared.roots();
        if (validated_calls) |validated|
            try prepared.validateBorrowedValidated(
                expected_program,
                plan,
                calls,
                validated,
                shard_index,
                roots.preprocessed_root,
                roots.main_root,
            )
        else
            try prepared.validateBorrowed(
                expected_program,
                plan,
                calls,
                shard_index,
                roots.preprocessed_root,
                roots.main_root,
            );
        break :blk &prepared.candidate;
    };
    try execution_profile.validate(expected_program.base);
    const shard_calls = if (validated_calls) |validated|
        try harness.admittedShardValidated(validated, plan, calls, shard_index)
    else
        try harness.admittedShard(plan, calls, shard_index);
    const descriptor = plan.shards[shard_index];
    const log_size = descriptor.expected_log_size;

    var channel = Engine.Channel{};
    mixPrefix(&channel, pcs_config, expected_program, plan, descriptor);
    var scheme = if (comptime @TypeOf(prepared) == @TypeOf(null))
        try Engine.init(allocator, pcs_config)
    else blk: {
        const roots = try prepared.roots();
        break :blk if (validated_calls) |validated|
            try prepared.takeSchemeValidated(
                expected_program,
                plan,
                calls,
                validated,
                shard_index,
                roots.preprocessed_root,
                roots.main_root,
            )
        else
            try prepared.takeScheme(
                expected_program,
                plan,
                calls,
                shard_index,
                roots.preprocessed_root,
                roots.main_root,
            );
    };
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    if (comptime @TypeOf(prepared) == @TypeOf(null)) {
        scheme.setCoefficientRetentionPolicy(.always);
        try Engine.commit(
            &scheme,
            allocator,
            try harness.generateSelectors(
                allocator,
                log_size,
                descriptor.call_count,
            ),
            null,
            &channel,
        );
        var main = try trace_mod.generateMain(
            allocator,
            candidate,
            shard_calls,
            log_size,
        );
        var main_owned = true;
        defer if (main_owned) main.deinit(allocator);
        const main_columns = try wrapColumns(allocator, main.values, log_size);
        allocator.free(main.values);
        main_owned = false;
        try Engine.commit(&scheme, allocator, main_columns, null, &channel);
    } else {
        const roots = try prepared.roots();
        Engine.MerkleChannel.mixRoot(&channel, roots.preprocessed_root);
        Engine.MerkleChannel.mixRoot(&channel, roots.main_root);
    }

    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        shard_calls,
        log_size,
        &relations,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    var ordered = try provider_order.generateInteraction(
        allocator,
        descriptor.first_call,
        shard_calls,
        log_size,
        &relations,
    );
    var ordered_owned = true;
    defer if (ordered_owned) ordered.deinit(allocator);
    var statement = StatementV2{
        .format = format_version,
        .air_program_identity = expected_program.air_program_identity,
        .source_plan_identity = plan.identity,
        .source_descriptor_identity = descriptor.identity,
        .global_call_list_commitment = plan.call_list_commitment,
        .shard_call_list_commitment = descriptor.shard_call_list_commitment,
        .shard_index = shard_index,
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = log_size,
        .claims = interaction.claims,
        .ordered_call_claim = ordered.claim,
        .identity = undefined,
    };
    statement.identity = statementIdentity(statement);
    mixStatement(&channel, statement);
    const interaction_columns = try mergeInteractionColumns(
        allocator,
        log_size,
        &interaction,
        &ordered,
    );
    interaction_owned = false;
    ordered_owned = false;
    try Engine.commit(
        &scheme,
        allocator,
        interaction_columns,
        null,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const component = try component_mod.Component.init(
        candidate,
        log_size,
        descriptor.call_count,
        0,
        1,
        0,
        0,
        &relations,
        statement.claims.sums,
    );
    const order_component = try provider_order.ProviderOrderComponent.initProjected(
        log_size,
        descriptor.call_count,
        descriptor.first_call,
        0,
        1,
        0,
        component_mod.MAIN_COLUMNS,
        expected_program.selected_main_columns,
        expected_program.order_composition_log_split,
        component_mod.INTERACTION_COLUMNS,
        &relations,
        statement.ordered_call_claim,
    );
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        component_backend.asProverComponent(&component),
        order_component.asProverComponent(),
    };
    const workers = std.math.cast(
        usize,
        execution_profile.composition_workers_per_provider,
    ) orelse return error.InvalidDegree5ExecutionProfile;
    const host_budget = std.math.cast(
        usize,
        execution_profile.composition_host_byte_budget,
    ) orelse return error.InvalidDegree5ExecutionProfile;
    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        &components,
        &channel,
        scheme,
        .{ .cpu_composition_execution = .{
            .worker_count = workers,
            .host_byte_budget = host_budget,
            .contention_policy = .strict,
        } },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return .{
        .statement = statement,
        .execution_profile_identity = execution_profile.identity,
        .proof = proof,
    };
}

pub fn verifyShardFresh(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    statement: StatementV2,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshVerifiedShardV2 {
    return verifyShardFreshInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        plan,
        calls,
        statement,
        proof_in,
        null,
    );
}

pub fn verifyShardFreshV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV2,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    statement: StatementV2,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshVerifiedShardV2 {
    return verifyShardFreshInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        plan,
        calls,
        statement,
        proof_in,
        null,
    );
}

pub fn verifyShardFreshValidatedV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV2,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: *const authority.OwnedValidatedPlanCallAuthorityV1,
    statement: StatementV2,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshVerifiedShardV2 {
    return verifyShardFreshInternal(
        Engine,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        plan,
        calls,
        statement,
        proof_in,
        validated_calls,
    );
}

fn verifyShardFreshInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: anytype,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    statement: StatementV2,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
) !FreshVerifiedShardV2 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    try expected_program.validateCandidate(&candidate);
    try expected_execution_profile.validate(expected_program.base);
    const shard_calls = if (validated_calls) |validated|
        try harness.admittedShardValidated(
            validated,
            plan,
            calls,
            statement.shard_index,
        )
    else
        try harness.admittedShard(plan, calls, statement.shard_index);
    const descriptor = plan.shards[statement.shard_index];
    try validateStatement(expected_program, plan, descriptor, statement);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != proof_commitment_count)
        return core_verifier.VerificationError.InvalidStructure;
    const commitments_identity = proof_authority.commitmentsIdentity(
        Engine,
        commitments,
    );
    try harness.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement.log_size,
        statement.call_count,
        commitments[0],
    );

    var channel = Engine.Channel{};
    mixPrefix(&channel, pcs_config, expected_program, plan, descriptor);
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    try scheme.commit(
        allocator,
        commitments[0],
        &[_]u32{ statement.log_size, statement.log_size },
        &channel,
    );
    try scheme.commit(
        allocator,
        commitments[1],
        &([_]u32{statement.log_size} ** component_mod.MAIN_COLUMNS),
        &channel,
    );
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    const expected_order = try provider_order.expectedClaim(
        descriptor.first_call,
        shard_calls,
        &relations,
    );
    if (!std.meta.eql(expected_order, statement.ordered_call_claim))
        return error.ProviderOrderClaimMismatch;
    mixStatement(&channel, statement);
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** tree2_columns),
        &channel,
    );
    const component = try component_mod.Component.init(
        &candidate,
        statement.log_size,
        statement.call_count,
        0,
        1,
        0,
        0,
        &relations,
        statement.claims.sums,
    );
    const order_component = try provider_order.ProviderOrderComponent.initProjected(
        statement.log_size,
        statement.call_count,
        statement.first_call,
        0,
        1,
        0,
        component_mod.MAIN_COLUMNS,
        expected_program.selected_main_columns,
        expected_program.order_composition_log_split,
        component_mod.INTERACTION_COLUMNS,
        &relations,
        statement.ordered_call_claim,
    );
    const components = [_]core_air.components.Component{
        component.asVerifierComponent(),
        order_component.asVerifierComponent(),
    };
    proof_moved = true;
    try core_verifier.verify(
        Engine.Hasher,
        Engine.MerkleChannel,
        allocator,
        &components,
        &channel,
        &scheme,
        proof,
    );
    var result = FreshVerifiedShardV2{
        .format = format_version,
        .air_program_identity = expected_program.air_program_identity,
        .execution_profile_identity = expected_execution_profile.identity,
        .source_plan_identity = statement.source_plan_identity,
        .source_descriptor_identity = statement.source_descriptor_identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_stark_verified = true,
        .ordered_call_air_verified = true,
        .ordered_call_claim_recomputed = true,
        .shared_core_relation_context_verified = false,
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = freshIdentity(result);
    try result.validate();
    return result;
}

fn canonicalProgram(
    base: v1.VerifierProgramAuthorityV1,
    candidate: *const candidate_mod.Candidate,
) !VerifierProgramAuthorityV2 {
    try base.validate(candidate);
    var result = VerifierProgramAuthorityV2{
        .format = format_version,
        .base = base,
        .selected_main_columns = try candidate.narrowProviderOrderColumns(),
        .order_interaction_columns = provider_order.interaction_column_count,
        .order_constraints = provider_order.constraint_count,
        .order_composition_log_split = component_mod.COMPOSITION_LOG_SPLIT,
        .tree2_columns = tree2_columns,
        .air_program_identity = undefined,
    };
    result.air_program_identity = airProgramIdentity(result);
    return result;
}

fn validateStatement(
    program: VerifierProgramAuthorityV2,
    plan: *const authority.ProviderShardPlanV1,
    descriptor: authority.ProviderShardDescriptorV1,
    statement: StatementV2,
) !void {
    if (statement.format != format_version or
        !aggregation_hash.eql(
            statement.air_program_identity,
            program.air_program_identity,
        ) or !aggregation_hash.eql(statement.source_plan_identity, plan.identity) or
        !aggregation_hash.eql(
            statement.source_descriptor_identity,
            descriptor.identity,
        ) or !aggregation_hash.eql(
        statement.global_call_list_commitment,
        plan.call_list_commitment,
    ) or !aggregation_hash.eql(
        statement.shard_call_list_commitment,
        descriptor.shard_call_list_commitment,
    ) or statement.shard_index != descriptor.shard_index or
        statement.first_call != descriptor.first_call or
        statement.call_count != descriptor.call_count or
        statement.log_size != descriptor.expected_log_size or
        statement.ordered_call_claim.format != provider_order.format_version or
        statement.ordered_call_claim.first_call != descriptor.first_call or
        statement.ordered_call_claim.call_count != descriptor.call_count or
        !aggregation_hash.eql(statement.identity, statementIdentity(statement)))
    {
        return error.InvalidDegree5ProviderOrderStatement;
    }
}

fn airProgramIdentity(value: VerifierProgramAuthorityV2) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-order-air-program/v2\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.base.air_program_identity) catch unreachable;
    aggregation_hash.writeU16(&sink, value.base.main_columns) catch unreachable;
    for (value.selected_main_columns) |column|
        aggregation_hash.writeU16(&sink, column) catch unreachable;
    aggregation_hash.writeU16(&sink, value.order_interaction_columns) catch unreachable;
    aggregation_hash.writeU16(&sink, value.order_constraints) catch unreachable;
    aggregation_hash.writeU32(&sink, value.order_composition_log_split) catch unreachable;
    aggregation_hash.writeU16(&sink, value.tree2_columns) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(ACTIVATES_PRODUCTION_PROOF),
        @intFromBool(ORDERED_CALL_COMMITMENT_IS_AIR_PROVED),
        @intFromBool(SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED),
    }) catch unreachable;
    return sink.finalize();
}

fn statementIdentity(value: StatementV2) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-order-statement/v2\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&value.source_plan_identity) catch unreachable;
    sink.writeAll(&value.source_descriptor_identity) catch unreachable;
    sink.writeAll(&value.global_call_list_commitment) catch unreachable;
    sink.writeAll(&value.shard_call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_index) catch unreachable;
    aggregation_hash.writeU64(&sink, value.first_call) catch unreachable;
    aggregation_hash.writeU32(&sink, value.call_count) catch unreachable;
    aggregation_hash.writeU32(&sink, value.log_size) catch unreachable;
    writeClaims(&sink, value.claims);
    writeOrderClaim(&sink, value.ordered_call_claim);
    return sink.finalize();
}

fn freshIdentity(value: FreshVerifiedShardV2) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-order-fresh/v2\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&value.execution_profile_identity) catch unreachable;
    sink.writeAll(&value.source_plan_identity) catch unreachable;
    sink.writeAll(&value.source_descriptor_identity) catch unreachable;
    sink.writeAll(&value.statement_identity) catch unreachable;
    sink.writeAll(&value.proof_commitments_identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.fresh_stark_verified),
        @intFromBool(value.ordered_call_air_verified),
        @intFromBool(value.ordered_call_claim_recomputed),
        @intFromBool(value.shared_core_relation_context_verified),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

fn mixPrefix(
    channel: anytype,
    pcs_config: core_pcs.PcsConfig,
    program: VerifierProgramAuthorityV2,
    plan: *const authority.ProviderShardPlanV1,
    descriptor: authority.ProviderShardDescriptorV1,
) void {
    pcs_config.mixInto(channel);
    channel.mixU32s(&prefix_domain);
    mixDigest(channel, program.air_program_identity);
    mixDigest(channel, plan.identity);
    mixDigest(channel, descriptor.identity);
    mixDigest(channel, plan.call_list_commitment);
    mixDigest(channel, descriptor.shard_call_list_commitment);
    channel.mixU64(descriptor.shard_index);
    channel.mixU64(descriptor.first_call);
    channel.mixU64(descriptor.call_count);
    channel.mixU64(descriptor.expected_log_size);
}

fn mixStatement(channel: anytype, statement: StatementV2) void {
    channel.mixU32s(&statement_domain);
    mixDigest(channel, statement.identity);
    channel.mixFelts(&statement.claims.sums);
    channel.mixFelts(&.{statement.ordered_call_claim.terminal});
}

fn mixDigest(channel: anytype, value: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

fn writeClaims(sink: anytype, claims: poseidon2_air.Claims) void {
    for (claims.sums) |claim| for (claim.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

fn writeOrderClaim(sink: anytype, claim: provider_order.ClaimV1) void {
    aggregation_hash.writeU32(sink, claim.format) catch unreachable;
    aggregation_hash.writeU64(sink, claim.first_call) catch unreachable;
    aggregation_hash.writeU32(sink, claim.call_count) catch unreachable;
    for (claim.terminal.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

fn wrapColumns(
    allocator: std.mem.Allocator,
    values: [][]@import("stwo_core").fields.m31.M31,
    log_size: u32,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, values.len);
    for (columns, values) |*column, source|
        column.* = .{ .log_size = log_size, .values = source };
    return columns;
}

fn mergeInteractionColumns(
    allocator: std.mem.Allocator,
    log_size: u32,
    poseidon: *poseidon2_air.Interaction,
    ordered: *provider_order.Interaction,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, tree2_columns);
    for (poseidon.columns, 0..) |values, index| columns[index] = .{
        .log_size = log_size,
        .values = values,
    };
    for (ordered.columns, 0..) |values, index| {
        columns[component_mod.INTERACTION_COLUMNS + index] = .{
            .log_size = log_size,
            .values = values,
        };
    }
    return columns;
}

const prefix_domain = [8]u32{
    0x5354_5742, // STWB
    0x4435_4f52, // D5OR
    format_version,
    component_mod.MAIN_COLUMNS,
    tree2_columns,
    component_mod.DIRECT_CONSTRAINTS,
    provider_order.constraint_count,
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};

const statement_domain = [5]u32{
    0x5354_5742, // STWB
    0x4435_5332, // D5S2
    format_version,
    poseidon2_air.N_SUMS,
    provider_order.constraint_count,
};

comptime {
    if (component_mod.MAIN_COLUMNS != 239 or tree2_columns != 12 or
        provider_order.selected_main_count != 17 or
        provider_order.constraint_count != 4 or
        component_mod.COMPOSITION_LOG_SPLIT != 2 or
        coefficient_retention != .always or
        ACTIVATES_PRODUCTION_PROOF or
        !ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED)
    {
        @compileError("degree-five ordered provider authority drifted");
    }
}
