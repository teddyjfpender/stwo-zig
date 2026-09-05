//! Nonproduction retained-coefficient provider proof for the degree-five
//! Poseidon2-M31 program.
//!
//! The existing provider plan is consumed only as ordered call-partition
//! custody. Its legacy 445-column geometry is never relabelled as this proof's
//! 239-column verifier program. A cold compiler reconstructs the exact d5 AIR
//! authority on both sides, while the execution profile keeps `.always`
//! coefficient retention and scheduler concurrency outside the transcript.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const aggregation_hash = @import("../../aggregation/hash.zig");
const candidate_mod = @import("../../air/lang/typed_poseidon2_degree_bounded_candidate.zig");
const component_mod = @import("../../air/lang/typed_poseidon2_degree5_component.zig");
const trace_mod = @import("../../air/lang/typed_poseidon2_degree5_trace.zig");
const relations_mod = @import("../../air/relation_challenges.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const harness = @import("proof_harness.zig");
const proof_authority = @import("joint_proof_authority.zig");

pub const format_version: u32 = 1;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const SOURCE_PLAN_IS_CALL_PARTITION_ONLY = true;
pub const ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED = false;
pub const FRESH_VERIFIER_IMPLEMENTED = true;
pub const coefficient_retention = harness.CoefficientRetention.always;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;
pub const Digest = authority.Digest;

pub const VerifierProgramAuthorityV1 = struct {
    format: u32,
    candidate_profile: candidate_mod.Profile,
    candidate_compiler_identity: Digest,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    logup_constraints: u16,
    maximum_constraint_degree: u8,
    quotient_expansion_bits: u8,
    composition_log_split: u8,
    air_program_identity: Digest,

    pub fn coldCompile(
        allocator: std.mem.Allocator,
    ) !VerifierProgramAuthorityV1 {
        var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
        defer candidate.deinit();
        return canonicalProgram(&candidate);
    }

    pub fn validate(
        self: VerifierProgramAuthorityV1,
        candidate: *const candidate_mod.Candidate,
    ) !void {
        const canonical = try canonicalProgram(candidate);
        if (!std.meta.eql(self, canonical))
            return error.InvalidDegree5VerifierProgram;
    }

    pub fn validateCold(
        self: VerifierProgramAuthorityV1,
        allocator: std.mem.Allocator,
    ) !void {
        var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
        defer candidate.deinit();
        try self.validate(&candidate);
    }
};

/// Physical execution policy, deliberately excluded from the proof statement.
/// Four providers may run concurrently while each proof owns one composition
/// worker, avoiding nested oversubscription in Halley's N=4 scheduler.
pub const ExecutionProfileV1 = struct {
    format: u32,
    air_program_identity: Digest,
    retention: harness.CoefficientRetention,
    concurrent_provider_limit: u16,
    composition_workers_per_provider: u16,
    composition_host_byte_budget: u64,
    identity: Digest,

    pub fn n4(
        program: VerifierProgramAuthorityV1,
    ) ExecutionProfileV1 {
        var result = ExecutionProfileV1{
            .format = format_version,
            .air_program_identity = program.air_program_identity,
            .retention = .always,
            .concurrent_provider_limit = 4,
            .composition_workers_per_provider = 1,
            .composition_host_byte_budget = 1024 * 1024 * 1024,
            .identity = undefined,
        };
        result.identity = executionProfileIdentity(result);
        return result;
    }

    pub fn validate(
        self: ExecutionProfileV1,
        program: VerifierProgramAuthorityV1,
    ) !void {
        if (self.format != format_version or
            !aggregation_hash.eql(
                self.air_program_identity,
                program.air_program_identity,
            ) or self.retention != .always or
            self.concurrent_provider_limit != 4 or
            self.composition_workers_per_provider != 1 or
            self.composition_host_byte_budget != 1024 * 1024 * 1024 or
            !aggregation_hash.eql(self.identity, executionProfileIdentity(self)))
        {
            return error.InvalidDegree5ExecutionProfile;
        }
    }
};

/// Runtime-scalable sibling for candidate/provider throughput experiments.
/// Unlike V1's historical N=4 fixture, this profile does not choose the outer
/// concurrency. A process-local host/RSS admission owner must separately bind
/// `concurrent_provider_limit` before any batch starts.
pub const ExecutionProfileV2 = struct {
    format: u32 = 2,
    air_program_identity: Digest,
    retention: harness.CoefficientRetention = .always,
    concurrent_provider_limit: u16,
    composition_workers_per_provider: u16,
    composition_host_byte_budget: u64,
    identity: Digest,

    pub fn runtime(
        program: VerifierProgramAuthorityV1,
        concurrent_provider_limit: u16,
        composition_workers_per_provider: u16,
        composition_host_byte_budget: u64,
    ) !ExecutionProfileV2 {
        var result = ExecutionProfileV2{
            .air_program_identity = program.air_program_identity,
            .concurrent_provider_limit = concurrent_provider_limit,
            .composition_workers_per_provider = composition_workers_per_provider,
            .composition_host_byte_budget = composition_host_byte_budget,
            .identity = undefined,
        };
        result.identity = executionProfileV2Identity(result);
        try result.validate(program);
        return result;
    }

    pub fn validate(
        self: ExecutionProfileV2,
        program: VerifierProgramAuthorityV1,
    ) !void {
        if (self.format != 2 or
            !aggregation_hash.eql(
                self.air_program_identity,
                program.air_program_identity,
            ) or self.retention != .always or
            self.concurrent_provider_limit == 0 or
            self.concurrent_provider_limit > work_pool.MAX_WORKERS or
            self.composition_workers_per_provider == 0 or
            self.composition_workers_per_provider > work_pool.MAX_WORKERS or
            self.composition_workers_per_provider > self.concurrent_provider_limit or
            self.composition_host_byte_budget == 0 or
            self.composition_host_byte_budget == std.math.maxInt(u64) or
            !aggregation_hash.eql(
                self.identity,
                executionProfileV2Identity(self),
            ))
        {
            return error.InvalidDegree5ExecutionProfile;
        }
    }
};

pub const StatementV1 = struct {
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
    identity: Digest,
};

pub fn ProveOutput(comptime Engine: type) type {
    return struct {
        statement: StatementV1,
        execution_profile_identity: Digest,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub const FreshVerifiedShardV1 = struct {
    format: u32,
    air_program_identity: Digest,
    execution_profile_identity: Digest,
    source_plan_identity: Digest,
    source_descriptor_identity: Digest,
    statement_identity: Digest,
    proof_commitments_identity: Digest,
    fresh_stark_verified: bool,
    ordered_call_air_verified: bool,
    shared_core_relation_context_verified: bool,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: FreshVerifiedShardV1) !void {
        if (self.format != format_version or
            !self.fresh_stark_verified or
            self.ordered_call_air_verified or
            self.shared_core_relation_context_verified or
            self.production_eligible or
            !aggregation_hash.eql(self.identity, freshIdentity(self)))
        {
            return error.InvalidFreshDegree5Provider;
        }
    }
};

pub fn proveShard(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV1,
    execution_profile: ExecutionProfileV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) !ProveOutput(Engine) {
    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    try expected_program.validate(&candidate);
    try execution_profile.validate(expected_program);
    const shard_calls = try harness.admittedShard(plan, calls, shard_index);
    const descriptor = plan.shards[shard_index];
    const log_size = descriptor.expected_log_size;

    var channel = Engine.Channel{};
    mixPrefix(
        &channel,
        pcs_config,
        expected_program,
        plan,
        descriptor,
    );
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
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
        &candidate,
        shard_calls,
        log_size,
    );
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const main_columns = try wrapColumns(allocator, main.values, log_size);
    allocator.free(main.values);
    main_owned = false;
    try Engine.commit(&scheme, allocator, main_columns, null, &channel);

    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        shard_calls,
        log_size,
        &relations,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    var statement = StatementV1{
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
        .identity = undefined,
    };
    statement.identity = statementIdentity(statement);
    mixStatement(&channel, statement);
    const interaction_columns = try harness.takeColumns(
        poseidon2_air.N_INTERACTION_COLUMNS,
        allocator,
        &interaction.columns,
        log_size,
    );
    interaction_owned = false;
    try Engine.commit(
        &scheme,
        allocator,
        interaction_columns,
        null,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const component = try component_mod.Component.init(
        &candidate,
        log_size,
        descriptor.call_count,
        0,
        1,
        0,
        0,
        &relations,
        statement.claims.sums,
    );
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        component.asProverComponent(),
    };
    const composition_workers = std.math.cast(
        usize,
        execution_profile.composition_workers_per_provider,
    ) orelse return error.InvalidDegree5ExecutionProfile;
    const composition_host_byte_budget = std.math.cast(
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
            .worker_count = composition_workers,
            .host_byte_budget = composition_host_byte_budget,
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
    expected_program: VerifierProgramAuthorityV1,
    expected_execution_profile: ExecutionProfileV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    statement: StatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshVerifiedShardV1 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    try expected_program.validate(&candidate);
    try expected_execution_profile.validate(expected_program);
    const shard_calls = try harness.admittedShard(
        plan,
        calls,
        statement.shard_index,
    );
    _ = shard_calls;
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
    mixPrefix(
        &channel,
        pcs_config,
        expected_program,
        plan,
        descriptor,
    );
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
    mixStatement(&channel, statement);
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** component_mod.INTERACTION_COLUMNS),
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
    const components = [_]core_air.components.Component{
        component.asVerifierComponent(),
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
    var result = FreshVerifiedShardV1{
        .format = format_version,
        .air_program_identity = expected_program.air_program_identity,
        .execution_profile_identity = expected_execution_profile.identity,
        .source_plan_identity = statement.source_plan_identity,
        .source_descriptor_identity = statement.source_descriptor_identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_stark_verified = true,
        .ordered_call_air_verified = false,
        .shared_core_relation_context_verified = false,
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = freshIdentity(result);
    try result.validate();
    return result;
}

fn canonicalProgram(
    candidate: *const candidate_mod.Candidate,
) !VerifierProgramAuthorityV1 {
    try candidate.validateRetained();
    if (candidate.profile != .degree5)
        return error.InvalidDegree5VerifierProgram;
    var result = VerifierProgramAuthorityV1{
        .format = format_version,
        .candidate_profile = .degree5,
        .candidate_compiler_identity = candidate.identity,
        .main_columns = component_mod.MAIN_COLUMNS,
        .interaction_columns = component_mod.INTERACTION_COLUMNS,
        .direct_constraints = component_mod.DIRECT_CONSTRAINTS,
        .logup_constraints = component_mod.LOGUP_CONSTRAINTS,
        .maximum_constraint_degree = candidate.profile.maximumConstraintDegree(),
        .quotient_expansion_bits = component_mod.QUOTIENT_EXPANSION_BITS,
        .composition_log_split = component_mod.COMPOSITION_LOG_SPLIT,
        .air_program_identity = undefined,
    };
    result.air_program_identity = airProgramIdentity(result);
    return result;
}

fn validateStatement(
    program: VerifierProgramAuthorityV1,
    plan: *const authority.ProviderShardPlanV1,
    descriptor: authority.ProviderShardDescriptorV1,
    statement: StatementV1,
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
        !aggregation_hash.eql(statement.identity, statementIdentity(statement)))
    {
        return error.InvalidDegree5ProviderStatement;
    }
}

fn airProgramIdentity(value: VerifierProgramAuthorityV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-air-program/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&.{@intFromEnum(value.candidate_profile)}) catch unreachable;
    sink.writeAll(&value.candidate_compiler_identity) catch unreachable;
    aggregation_hash.writeU16(&sink, value.main_columns) catch unreachable;
    aggregation_hash.writeU16(&sink, value.interaction_columns) catch unreachable;
    aggregation_hash.writeU16(&sink, value.direct_constraints) catch unreachable;
    aggregation_hash.writeU16(&sink, value.logup_constraints) catch unreachable;
    sink.writeAll(&.{
        value.maximum_constraint_degree,
        value.quotient_expansion_bits,
        value.composition_log_split,
        @intFromBool(ACTIVATES_PRODUCTION_PROOF),
        @intFromBool(ORDERED_CALL_COMMITMENT_IS_AIR_PROVED),
        @intFromBool(SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED),
    }) catch unreachable;
    return sink.finalize();
}

fn executionProfileIdentity(value: ExecutionProfileV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-execution-profile/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&.{@intFromEnum(value.retention)}) catch unreachable;
    aggregation_hash.writeU16(&sink, value.concurrent_provider_limit) catch unreachable;
    aggregation_hash.writeU16(
        &sink,
        value.composition_workers_per_provider,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.composition_host_byte_budget,
    ) catch unreachable;
    return sink.finalize();
}

fn executionProfileV2Identity(value: ExecutionProfileV2) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-execution-profile/v2\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&.{@intFromEnum(value.retention)}) catch unreachable;
    aggregation_hash.writeU16(&sink, value.concurrent_provider_limit) catch unreachable;
    aggregation_hash.writeU16(
        &sink,
        value.composition_workers_per_provider,
    ) catch unreachable;
    aggregation_hash.writeU64(
        &sink,
        value.composition_host_byte_budget,
    ) catch unreachable;
    return sink.finalize();
}

fn statementIdentity(value: StatementV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-statement/v1\x00",
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
    return sink.finalize();
}

fn freshIdentity(value: FreshVerifiedShardV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/narrow-memory-provider/d5-fresh-verified/v1\x00",
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
        @intFromBool(value.shared_core_relation_context_verified),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

fn mixPrefix(
    channel: anytype,
    pcs_config: core_pcs.PcsConfig,
    program: VerifierProgramAuthorityV1,
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

fn mixStatement(channel: anytype, statement: StatementV1) void {
    channel.mixU32s(&statement_domain);
    mixDigest(channel, statement.identity);
    channel.mixFelts(&statement.claims.sums);
}

fn mixDigest(channel: anytype, value: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

fn writeClaims(sink: anytype, claims: poseidon2_air.Claims) void {
    for (claims.sums) |claim| {
        for (claim.toM31Array()) |limb|
            aggregation_hash.writeU32(sink, limb.v) catch unreachable;
    }
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

const prefix_domain = [8]u32{
    0x5354_5742, // STWB
    0x4435_5056, // D5PV
    format_version,
    component_mod.MAIN_COLUMNS,
    component_mod.INTERACTION_COLUMNS,
    component_mod.DIRECT_CONSTRAINTS,
    component_mod.QUOTIENT_EXPANSION_BITS,
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};

const statement_domain = [4]u32{
    0x5354_5742, // STWB
    0x4435_5354, // D5ST
    format_version,
    poseidon2_air.N_SUMS,
};

comptime {
    if (component_mod.MAIN_COLUMNS != 239 or
        component_mod.INTERACTION_COLUMNS != 8 or
        component_mod.DIRECT_CONSTRAINTS != 227 or
        component_mod.LOGUP_CONSTRAINTS != 2 or
        component_mod.QUOTIENT_EXPANSION_BITS != 2 or
        component_mod.COMPOSITION_LOG_SPLIT != 2 or
        coefficient_retention != .always or
        ACTIVATES_PRODUCTION_PROOF or
        ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED)
    {
        @compileError("degree-five retained provider authority drifted");
    }
}
