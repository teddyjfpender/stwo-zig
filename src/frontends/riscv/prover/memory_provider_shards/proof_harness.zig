//! Research-only standalone STARK for one base narrow-memory Poseidon shard.
//!
//! This proves the real 445-column `poseidon2_air` main trace and its exact
//! two-QM31/eight-column LogUp trace under the base relation registry.  It is
//! intentionally not an R-008 guest-I/O proof and is not a production split:
//! the ordered call digest is transcript-bound but not AIR-proved, there is no
//! caller+N manifest or joint interaction PoW, and recursion admits no shard.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const aggregation_hash = @import("../../aggregation/hash.zig");
const relations_mod = @import("../../air/relation_challenges.zig");
const hash_component = @import("../../air/memory_commitment/hash_component.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const opcode_trace = @import("../opcode_trace.zig");
const authority = @import("authority.zig");
const standalone_component = @import("standalone_component.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const PRODUCES_REAL_BASE_PROVIDER_STARK = true;
pub const FRESH_VERIFIER_IMPLEMENTED = true;
pub const EXACT_TWO_QM31_CLAIMS = true;
pub const ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const CALLER_N_MANIFEST_IMPLEMENTED = false;
pub const JOINT_INTERACTION_POW_IMPLEMENTED = false;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;
pub const BOUNDED_TWO_PASS_PCS_IMPLEMENTED = false;

pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;

pub const CoefficientRetention = enum {
    always,
    never,
};

pub const StatementV1 = struct {
    plan_identity: authority.Digest,
    descriptor_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    shard_index: u32,
    log_size: u32,
    n_rows: u32,
    claims: poseidon2_air.Claims,
};

pub const OwnerTeardownTelemetryV1 = struct {
    retention: CoefficientRetention,
    tree_count_before_consume: u32,
    committed_column_count: u32,
    retained_coefficient_columns: u32,
    scheme_consumed_by_engine: bool,
    extended_aux_released: bool,

    pub fn validate(self: @This()) !void {
        if (self.tree_count_before_consume != tree_count or
            self.committed_column_count !=
                2 + poseidon2_air.N_MAIN_COLUMNS + poseidon2_air.N_INTERACTION_COLUMNS or
            !self.scheme_consumed_by_engine or
            !self.extended_aux_released)
        {
            return error.InvalidProviderOwnerTelemetry;
        }
        const expected: u32 = switch (self.retention) {
            .always => self.committed_column_count,
            .never => 0,
        };
        if (self.retained_coefficient_columns != expected)
            return error.InvalidProviderOwnerTelemetry;
    }
};

pub fn ProveOutput(comptime Engine: type) type {
    return struct {
        statement: StatementV1,
        roots: [tree_count]Engine.Hasher.Hash,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
        owner_telemetry: OwnerTeardownTelemetryV1,
    };
}

/// Backend-neutral Stage-A commitment pair used by the research joint
/// caller+N transcript.  It contains no relation challenge or interaction
/// claim: every shard must publish this pair before the one shared draw.
pub fn StageACommitment(comptime Engine: type) type {
    return struct {
        preprocessed_root: Engine.Hasher.Hash,
        main_root: Engine.Hasher.Hash,
    };
}

/// Materializes and commits the real selector and 445-column main traces for
/// exactly one shard, then tears the PCS owner down.  The roots are independent
/// of the scratch channel used by commitment publication; the joint protocol
/// replays them later in canonical plan order before drawing relations.
pub fn commitStageA(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) !StageACommitment(Engine) {
    const shard_calls = try admittedShard(plan, calls, shard_index);
    const descriptor = plan.shards[shard_index];
    var channel = Engine.Channel{};
    pcs_config.mixInto(&channel);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);

    const preprocessed = try generateSelectors(
        allocator,
        descriptor.expected_log_size,
        descriptor.call_count,
    );
    try Engine.commit(&scheme, allocator, preprocessed, null, &channel);

    var main = try poseidon2_air.generateMain(
        allocator,
        shard_calls,
        descriptor.expected_log_size,
    );
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const main_columns = try takeColumns(
        poseidon2_air.N_MAIN_COLUMNS,
        allocator,
        &main.values,
        descriptor.expected_log_size,
    );
    main_owned = false;
    try Engine.commit(&scheme, allocator, main_columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 2) return error.InvalidProviderStageATreeCount;
    return .{
        .preprocessed_root = roots.items[0],
        .main_root = roots.items[1],
    };
}

/// Proves exactly one canonical descriptor.  `retention` is physical owner
/// policy and is deliberately absent from the statement: changing whether a
/// duplicate coefficient form is retained must not change roots or proof.
pub fn proveShard(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
    retention: CoefficientRetention,
    recorder: ?*stage_profile.Recorder,
) !ProveOutput(Engine) {
    const shard_calls = try admittedShard(plan, calls, shard_index);
    const descriptor = plan.shards[shard_index];
    const log_size = descriptor.expected_log_size;

    var channel = Engine.Channel{};
    mixPrefix(&channel, pcs_config, plan, descriptor);
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(switch (retention) {
        .always => .always,
        .never => .never,
    });

    const preprocessed = try generateSelectors(
        allocator,
        log_size,
        descriptor.call_count,
    );
    try Engine.commit(&scheme, allocator, preprocessed, recorder, &channel);

    var main = try poseidon2_air.generateMain(allocator, shard_calls, log_size);
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const main_columns = try takeColumns(
        poseidon2_air.N_MAIN_COLUMNS,
        allocator,
        &main.values,
        log_size,
    );
    main_owned = false;
    try Engine.commit(&scheme, allocator, main_columns, recorder, &channel);

    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        shard_calls,
        log_size,
        &relations,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    const relation_context = try authority.PoseidonRelationContextV1.canonical(
        plan.session,
        relations.poseidon2.z,
        relations.poseidon2.alpha,
    );
    const statement = StatementV1{
        .plan_identity = plan.identity,
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = relation_context.identity,
        .shard_index = shard_index,
        .log_size = log_size,
        .n_rows = descriptor.call_count,
        .claims = interaction.claims,
    };
    mixInteractionStatement(&channel, statement);
    const interaction_columns = try takeColumns(
        poseidon2_air.N_INTERACTION_COLUMNS,
        allocator,
        &interaction.columns,
        log_size,
    );
    interaction_owned = false;
    try Engine.commit(&scheme, allocator, interaction_columns, recorder, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    var roots_value = try scheme.roots(allocator);
    defer roots_value.deinit(allocator);
    if (roots_value.items.len != tree_count)
        return error.InvalidProviderTreeCount;
    const roots = [tree_count]Engine.Hasher.Hash{
        roots_value.items[0],
        roots_value.items[1],
        roots_value.items[2],
    };
    const telemetry_prefix = try ownerTelemetry(&scheme, retention);

    const component = hash_component.HashComponent{
        .kind = .poseidon2,
        .log_size = log_size,
        .n_rows = descriptor.call_count,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = &relations,
        .poseidon_shell = .narrow_memory,
        .poseidon_claims = interaction.claims.sums,
    };
    var standalone = standalone_component.Prover{
        .inner = component.asProverComponent(),
    };
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        standalone.asComponent(),
    };

    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        &components,
        &channel,
        scheme,
        .{ .recorder = recorder },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    var telemetry = telemetry_prefix;
    telemetry.scheme_consumed_by_engine = true;
    telemetry.extended_aux_released = true;
    try telemetry.validate();
    return .{
        .statement = statement,
        .roots = roots,
        .proof = proof,
        .owner_telemetry = telemetry,
    };
}

/// Fresh verification consumes `proof_in` on success and failure.  The
/// deterministic selector tree is recomputed independently before its proof
/// root is admitted; the remaining roots are authenticated by the STARK.
pub fn verifyShard(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    statement: StatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    const shard_calls = try admittedShard(plan, calls, statement.shard_index);
    _ = shard_calls;
    const descriptor = plan.shards[statement.shard_index];
    try validateStatement(plan, descriptor, statement);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != proof_commitment_count)
        return core_verifier.VerificationError.InvalidStructure;
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement.log_size,
        statement.n_rows,
        commitments[0],
    );

    var channel = Engine.Channel{};
    mixPrefix(&channel, pcs_config, plan, descriptor);
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
        &([_]u32{statement.log_size} ** poseidon2_air.N_MAIN_COLUMNS),
        &channel,
    );
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    const relation_context = try authority.PoseidonRelationContextV1.canonical(
        plan.session,
        relations.poseidon2.z,
        relations.poseidon2.alpha,
    );
    if (!aggregation_hash.eql(
        relation_context.identity,
        statement.relation_context_identity,
    )) return error.RelationContextMismatch;
    mixInteractionStatement(&channel, statement);
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** poseidon2_air.N_INTERACTION_COLUMNS),
        &channel,
    );

    const component = hash_component.HashComponent{
        .kind = .poseidon2,
        .log_size = statement.log_size,
        .n_rows = statement.n_rows,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = &relations,
        .poseidon_shell = .narrow_memory,
        .poseidon_claims = statement.claims.sums,
    };
    var standalone = standalone_component.Verifier{
        .inner = component.asVerifierComponent(),
    };
    const components = [_]core_air.components.Component{
        standalone.asComponent(),
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
}

pub fn admittedShard(
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) ![]const poseidon2_air.Call {
    try plan.validate(calls);
    if (shard_index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[shard_index];
    const first = std.math.cast(usize, descriptor.first_call) orelse
        return error.CallCountOutOfRange;
    const count = std.math.cast(usize, descriptor.call_count) orelse
        return error.CallCountOutOfRange;
    const end = std.math.add(usize, first, count) catch
        return error.CallCountOutOfRange;
    if (end > calls.len) return error.CallCountOutOfRange;
    return calls[first..end];
}

pub fn admittedShardValidated(
    validated: *const authority.OwnedValidatedPlanCallAuthorityV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) ![]const poseidon2_air.Call {
    return validated.admittedShard(plan, calls, shard_index);
}

fn validateStatement(
    plan: *const authority.ProviderShardPlanV1,
    descriptor: authority.ProviderShardDescriptorV1,
    statement: StatementV1,
) !void {
    if (!aggregation_hash.eql(statement.plan_identity, plan.identity))
        return error.PlanIdentityMismatch;
    if (!aggregation_hash.eql(statement.descriptor_identity, descriptor.identity))
        return error.ShardIdentityMismatch;
    if (statement.shard_index != descriptor.shard_index or
        statement.log_size != descriptor.expected_log_size or
        statement.n_rows != descriptor.call_count)
    {
        return error.ProviderGeometryMismatch;
    }
}

pub fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    log_size: u32,
    n_rows: u32,
    expected: Engine.Hasher.Hash,
) !void {
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    const columns = try generateSelectors(allocator, log_size, n_rows);
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], expected))
        return error.InvalidProviderPreprocessedRoot;
}

pub fn generateSelectors(
    allocator: std.mem.Allocator,
    log_size: u32,
    n_rows: u32,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, 2);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    columns[0] = .{
        .log_size = log_size,
        .values = try opcode_trace.generateIsFirst(allocator, log_size),
    };
    initialized = 1;
    columns[1] = .{
        .log_size = log_size,
        .values = try opcode_trace.generateIsActive(allocator, log_size, n_rows),
    };
    return columns;
}

pub fn takeColumns(
    comptime count: usize,
    allocator: std.mem.Allocator,
    values: *[count][]M31,
    log_size: u32,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, count);
    for (columns, values.*) |*column, source| {
        column.* = .{ .log_size = log_size, .values = source };
    }
    return columns;
}

fn ownerTelemetry(
    scheme: anytype,
    retention: CoefficientRetention,
) !OwnerTeardownTelemetryV1 {
    var columns: usize = 0;
    var retained: usize = 0;
    for (scheme.trees.items) |tree| {
        columns = std.math.add(usize, columns, tree.columns.len) catch
            return error.ProviderOwnerTelemetryOverflow;
        if (tree.coefficients) |coefficients| {
            retained = std.math.add(usize, retained, coefficients.len) catch
                return error.ProviderOwnerTelemetryOverflow;
        }
    }
    return .{
        .retention = retention,
        .tree_count_before_consume = std.math.cast(u32, scheme.trees.items.len) orelse
            return error.ProviderOwnerTelemetryOverflow,
        .committed_column_count = std.math.cast(u32, columns) orelse
            return error.ProviderOwnerTelemetryOverflow,
        .retained_coefficient_columns = std.math.cast(u32, retained) orelse
            return error.ProviderOwnerTelemetryOverflow,
        .scheme_consumed_by_engine = false,
        .extended_aux_released = false,
    };
}

fn mixPrefix(
    channel: anytype,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    descriptor: authority.ProviderShardDescriptorV1,
) void {
    pcs_config.mixInto(channel);
    channel.mixU32s(&prefix_domain_words);
    channel.mixU64(authority.format_version);
    mixDigest(channel, plan.session);
    mixDigest(channel, plan.identity);
    mixDigest(channel, descriptor.identity);
    mixDigest(channel, plan.call_list_commitment);
    mixDigest(channel, descriptor.shard_call_list_commitment);
    channel.mixU64(descriptor.shard_index);
    channel.mixU64(descriptor.shard_count);
    channel.mixU64(descriptor.first_call);
    channel.mixU64(descriptor.call_count);
    channel.mixU64(descriptor.expected_log_size);
    channel.mixU64(descriptor.main_columns);
    channel.mixU64(descriptor.interaction_columns);
}

fn mixInteractionStatement(channel: anytype, statement: StatementV1) void {
    channel.mixU32s(&claim_domain_words);
    mixDigest(channel, statement.relation_context_identity);
    channel.mixFelts(&statement.claims.sums);
}

fn mixDigest(channel: anytype, digest: authority.Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    }
    channel.mixU32s(&words);
}

const prefix_domain_words = [8]u32{
    0x5354_5742, // STWB
    0x4e4d_5050, // NMPP
    0x5354_4b31, // STK1
    1,
    @intFromBool(RESEARCH_ONLY),
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
    poseidon2_air.N_MAIN_COLUMNS,
    poseidon2_air.N_INTERACTION_COLUMNS,
};

const claim_domain_words = [5]u32{
    0x5354_5742, // STWB
    0x4e4d_5043, // NMPC
    1,
    poseidon2_air.N_SUMS,
    poseidon2_air.N_INTERACTION_COLUMNS,
};

comptime {
    if (poseidon2_air.N_SUMS != 2 or
        poseidon2_air.N_MAIN_COLUMNS != authority.main_column_count or
        poseidon2_air.N_INTERACTION_COLUMNS != authority.interaction_column_count)
    {
        @compileError("standalone narrow-memory provider geometry drifted");
    }
}
