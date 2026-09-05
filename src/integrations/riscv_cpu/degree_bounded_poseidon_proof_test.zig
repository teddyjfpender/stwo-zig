//! Proof-level acceptance for the degree-six Poseidon2 materialization.
//!
//! This target is intentionally separate from the production 445-column
//! narrow-memory provider.  It proves that the append-only 161-column AIR can
//! traverse the complete PCS/FRI path with its genuine `log_n + 3` quotient
//! bound and be reconstructed by an independent verifier.

const std = @import("std");
const builtin = @import("builtin");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");

const candidate_mod = frontend.air.typed_poseidon2_degree_bounded_candidate;
const component_mod = frontend.air.typed_poseidon2_degree_bounded_component;
const trace_mod = frontend.air.typed_poseidon2_degree_bounded_trace;
const relations_mod = frontend.air.relation_challenges;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const poseidon2 = frontend.air.memory_commitment.poseidon2;
const provider_harness = frontend.testing.narrow_memory_provider_proof_harness;
const provider_authority = frontend.testing.narrow_memory_provider_shard_authority;
const Engine = riscv_cpu.CpuProverEngine;

const CONFIG = core_pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = core_pcsConfig(),
};

fn core_pcsConfig() @import("stwo_core").fri.FriConfig {
    return @import("stwo_core").fri.FriConfig.init(0, 1, 3) catch unreachable;
}

const Statement = struct {
    candidate_identity: [32]u8,
    log_size: u32,
    n_rows: u32,
    claims: poseidon2_air.Claims,
};

fn ProveOutput(comptime ProverEngine: type) type {
    return struct {
        statement: Statement,
        proof: @import("stwo_core").proof.StarkProof(ProverEngine.Hasher),
    };
}

test "degree-six Poseidon candidate proves and cold fresh-verifies at quotient plus three" {
    const allocator = std.testing.allocator;
    const calls = try callsFixture(allocator, 13);
    defer allocator.free(calls);

    var prover_candidate = try candidate_mod.Candidate.init(allocator, .degree6);
    defer prover_candidate.deinit();
    var output = try prove(
        Engine,
        allocator,
        &prover_candidate,
        calls,
        4,
        .always,
        null,
    );
    defer output.proof.deinit(allocator);

    var encoded: std.ArrayList(u8) = .{};
    defer encoded.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        encoded.writer(allocator),
        output.proof,
    );
    try std.testing.expect(encoded.items.len > 0);

    var verifier_candidate = try candidate_mod.Candidate.init(allocator, .degree6);
    defer verifier_candidate.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &prover_candidate.identity,
        &verifier_candidate.identity,
    );
    var stream = std.io.fixedBufferStream(encoded.items);
    try verify(
        Engine,
        allocator,
        &verifier_candidate,
        output.statement,
        try postcard.deserializeProof(
            Engine.Hasher,
            allocator,
            stream.reader(),
        ),
    );

    try std.testing.expectEqual(@as(u32, 7), 4 + component_mod.QUOTIENT_EXPANSION_BITS);
    try std.testing.expectEqual(@as(usize, 161), component_mod.MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 8), component_mod.INTERACTION_COLUMNS);
    try std.testing.expectEqual(@as(usize, 149), component_mod.DIRECT_CONSTRAINTS);
    try std.testing.expect(!component_mod.PRODUCTION_ACTIVATION);
}

test "degree-six Poseidon candidate recomputes discarded coefficients with exact proof parity" {
    const allocator = std.testing.allocator;
    const calls = try callsFixture(allocator, 13);
    defer allocator.free(calls);

    var candidate = try candidate_mod.Candidate.init(allocator, .degree6);
    defer candidate.deinit();
    var retained = try prove(
        Engine,
        allocator,
        &candidate,
        calls,
        4,
        .always,
        null,
    );
    defer retained.proof.deinit(allocator);
    var recomputed = try prove(
        Engine,
        allocator,
        &candidate,
        calls,
        4,
        .never,
        null,
    );
    defer recomputed.proof.deinit(allocator);

    try std.testing.expect(std.meta.eql(retained.statement, recomputed.statement));
    var retained_bytes: std.ArrayList(u8) = .{};
    defer retained_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        retained_bytes.writer(allocator),
        retained.proof,
    );
    var recomputed_bytes: std.ArrayList(u8) = .{};
    defer recomputed_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        recomputed_bytes.writer(allocator),
        recomputed.proof,
    );
    try std.testing.expectEqualSlices(
        u8,
        retained_bytes.items,
        recomputed_bytes.items,
    );

    var stream = std.io.fixedBufferStream(recomputed_bytes.items);
    try verify(
        Engine,
        allocator,
        &candidate,
        recomputed.statement,
        try postcard.deserializeProof(
            Engine.Hasher,
            allocator,
            stream.reader(),
        ),
    );
}

test "degree-six Poseidon log16 retained-call A B benchmark" {
    if (builtin.mode != .ReleaseFast) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const log_size: u32 = 16;
    const call_count: usize = @as(usize, 1) << @intCast(log_size);
    const engine_workers: usize = 4;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = engine_workers });
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const calls = try callsFixture(allocator, call_count);
    defer allocator.free(calls);

    var plan = try provider_authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0xd6} ** 32,
        calls,
        .{
            .logical_row_count = call_count,
            .column_count = provider_authority.main_column_count,
            .min_shard_log_size = log_size,
            .max_shard_log_size = log_size,
            .log_blowup_factor = CONFIG.fri_config.log_blowup_factor,
            .retention_policy = .never,
            .host_byte_budget = 4 * 1024 * 1024 * 1024,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        },
    );
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), plan.shard_count);

    var candidate = try candidate_mod.Candidate.init(allocator, .degree6);
    defer candidate.deinit();
    const legacy_a = try benchmarkLegacyArm(allocator, &plan, calls);
    const degree6_a = try benchmarkDegree6Arm(allocator, &candidate, calls, log_size);
    const degree6_b = try benchmarkDegree6Arm(allocator, &candidate, calls, log_size);
    const legacy_b = try benchmarkLegacyArm(allocator, &plan, calls);
    const legacy_retained = try benchmarkLegacyArmWithRetention(
        allocator,
        &plan,
        calls,
        .always,
    );
    const degree6_retained = try benchmarkDegree6ArmWithRetention(
        allocator,
        &candidate,
        calls,
        log_size,
        .always,
    );
    try std.testing.expectEqualSlices(u8, &legacy_a.proof_sha256, &legacy_b.proof_sha256);
    try std.testing.expectEqualSlices(u8, &degree6_a.proof_sha256, &degree6_b.proof_sha256);

    std.debug.print(
        "{{\"schema\":\"stwo.riscv.poseidon-degree6-ab.v1\",\"production\":false,\"log_size\":{d},\"call_count\":{d},\"engine_workers\":{d},\"legacy_main_columns\":445,\"degree6_main_columns\":161,\"legacy_never\":[{{\"prove_ns\":{d},\"verify_ns\":{d},\"proof_bytes\":{d}}},{{\"prove_ns\":{d},\"verify_ns\":{d},\"proof_bytes\":{d}}}],\"degree6_never\":[{{\"prove_ns\":{d},\"verify_ns\":{d},\"proof_bytes\":{d}}},{{\"prove_ns\":{d},\"verify_ns\":{d},\"proof_bytes\":{d}}}],\"legacy_always\":{{\"prove_ns\":{d},\"verify_ns\":{d},\"proof_bytes\":{d}}},\"degree6_always\":{{\"prove_ns\":{d},\"verify_ns\":{d},\"proof_bytes\":{d}}}}}\n",
        .{
            log_size,
            call_count,
            engine_workers,
            legacy_a.prove_ns,
            legacy_a.verify_ns,
            legacy_a.proof_bytes,
            legacy_b.prove_ns,
            legacy_b.verify_ns,
            legacy_b.proof_bytes,
            degree6_a.prove_ns,
            degree6_a.verify_ns,
            degree6_a.proof_bytes,
            degree6_b.prove_ns,
            degree6_b.verify_ns,
            degree6_b.proof_bytes,
            legacy_retained.prove_ns,
            legacy_retained.verify_ns,
            legacy_retained.proof_bytes,
            degree6_retained.prove_ns,
            degree6_retained.verify_ns,
            degree6_retained.proof_bytes,
        },
    );
}

const BenchmarkSample = struct {
    prove_ns: u64,
    verify_ns: u64,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

fn benchmarkLegacyArm(
    allocator: std.mem.Allocator,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
) !BenchmarkSample {
    return benchmarkLegacyArmWithRetention(allocator, plan, calls, .never);
}

fn benchmarkLegacyArmWithRetention(
    allocator: std.mem.Allocator,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    retention: provider_harness.CoefficientRetention,
) !BenchmarkSample {
    var timer = try std.time.Timer.start();
    var output = try provider_harness.proveShard(
        Engine,
        allocator,
        CONFIG,
        plan,
        calls,
        0,
        retention,
        null,
    );
    defer output.proof.deinit(allocator);
    const prove_ns = timer.read();
    var encoded: std.ArrayList(u8) = .{};
    defer encoded.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, encoded.writer(allocator), output.proof);
    var proof_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded.items, &proof_sha256, .{});
    timer.reset();
    var stream = std.io.fixedBufferStream(encoded.items);
    try provider_harness.verifyShard(
        Engine,
        allocator,
        CONFIG,
        plan,
        calls,
        output.statement,
        try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader()),
    );
    return .{
        .prove_ns = prove_ns,
        .verify_ns = timer.read(),
        .proof_bytes = encoded.items.len,
        .proof_sha256 = proof_sha256,
    };
}

fn benchmarkDegree6Arm(
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    calls: []const poseidon2_air.Call,
    log_size: u32,
) !BenchmarkSample {
    return benchmarkDegree6ArmWithRetention(
        allocator,
        candidate,
        calls,
        log_size,
        .never,
    );
}

fn benchmarkDegree6ArmWithRetention(
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    calls: []const poseidon2_air.Call,
    log_size: u32,
    retention: provider_harness.CoefficientRetention,
) !BenchmarkSample {
    var timer = try std.time.Timer.start();
    var output = try prove(
        Engine,
        allocator,
        candidate,
        calls,
        log_size,
        retention,
        4,
    );
    defer output.proof.deinit(allocator);
    const prove_ns = timer.read();
    var encoded: std.ArrayList(u8) = .{};
    defer encoded.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, encoded.writer(allocator), output.proof);
    var proof_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded.items, &proof_sha256, .{});
    timer.reset();
    var stream = std.io.fixedBufferStream(encoded.items);
    try verify(
        Engine,
        allocator,
        candidate,
        output.statement,
        try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader()),
    );
    return .{
        .prove_ns = prove_ns,
        .verify_ns = timer.read(),
        .proof_bytes = encoded.items.len,
        .proof_sha256 = proof_sha256,
    };
}

fn prove(
    comptime ProverEngine: type,
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    calls: []const poseidon2_air.Call,
    log_size: u32,
    retention: provider_harness.CoefficientRetention,
    composition_workers: ?usize,
) !ProveOutput(ProverEngine) {
    try candidate.validate();
    const n_rows = std.math.cast(u32, calls.len) orelse
        return error.InvalidDegreeBoundedFixture;
    var channel = ProverEngine.Channel{};
    mixPrefix(&channel, candidate, log_size, n_rows);
    var scheme = try ProverEngine.init(allocator, CONFIG);
    var scheme_owned = true;
    errdefer if (scheme_owned) ProverEngine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(switch (retention) {
        .always => .always,
        .never => .never,
    });

    try ProverEngine.commit(
        &scheme,
        allocator,
        try provider_harness.generateSelectors(allocator, log_size, n_rows),
        null,
        &channel,
    );

    var main = try trace_mod.generateMain(allocator, candidate, calls, log_size);
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const main_columns = try wrapColumns(allocator, main.values, log_size);
    allocator.free(main.values);
    main_owned = false;
    try ProverEngine.commit(&scheme, allocator, main_columns, null, &channel);

    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        calls,
        log_size,
        &relations,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    const statement = Statement{
        .candidate_identity = candidate.identity,
        .log_size = log_size,
        .n_rows = n_rows,
        .claims = interaction.claims,
    };
    mixClaims(&channel, statement);
    const interaction_columns = try provider_harness.takeColumns(
        poseidon2_air.N_INTERACTION_COLUMNS,
        allocator,
        &interaction.columns,
        log_size,
    );
    interaction_owned = false;
    try ProverEngine.commit(
        &scheme,
        allocator,
        interaction_columns,
        null,
        &channel,
    );
    try ProverEngine.flushPendingCommit(&scheme, allocator, &channel);

    const component = try component_mod.Component.init(
        candidate,
        log_size,
        n_rows,
        0,
        1,
        0,
        0,
        &relations,
        interaction.claims.sums,
    );
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        component.asProverComponent(),
    };
    scheme_owned = false;
    var extended = try ProverEngine.prove(
        allocator,
        &components,
        &channel,
        scheme,
        .{ .cpu_composition_execution = if (composition_workers) |workers| .{
            .worker_count = workers,
            .host_byte_budget = 1024 * 1024 * 1024,
            .contention_policy = .strict,
        } else null },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return .{ .statement = statement, .proof = proof };
}

fn verify(
    comptime ProverEngine: type,
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    statement: Statement,
    proof_in: @import("stwo_core").proof.StarkProof(ProverEngine.Hasher),
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try candidate.validate();
    if (!std.mem.eql(u8, &statement.candidate_identity, &candidate.identity) or
        statement.log_size == 0 or
        @as(u64, statement.n_rows) > (@as(u64, 1) << @intCast(statement.log_size)))
    {
        return error.InvalidDegreeBoundedStatement;
    }
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != 4)
        return core_verifier.VerificationError.InvalidStructure;
    try provider_harness.verifyPreprocessedRoot(
        ProverEngine,
        allocator,
        CONFIG,
        statement.log_size,
        statement.n_rows,
        commitments[0],
    );

    var channel = ProverEngine.Channel{};
    mixPrefix(&channel, candidate, statement.log_size, statement.n_rows);
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        ProverEngine.Hasher,
        ProverEngine.MerkleChannel,
    ).init(allocator, CONFIG);
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
    mixClaims(&channel, statement);
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** component_mod.INTERACTION_COLUMNS),
        &channel,
    );

    const component = try component_mod.Component.init(
        candidate,
        statement.log_size,
        statement.n_rows,
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
        ProverEngine.Hasher,
        ProverEngine.MerkleChannel,
        allocator,
        &components,
        &channel,
        &scheme,
        proof,
    );
}

fn wrapColumns(
    allocator: std.mem.Allocator,
    values: [][]@import("stwo_core").fields.m31.M31,
    log_size: u32,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, values.len);
    for (columns, values) |*column, source| {
        column.* = .{ .log_size = log_size, .values = source };
    }
    return columns;
}

fn mixPrefix(channel: anytype, candidate: *const candidate_mod.Candidate, log_size: u32, n_rows: u32) void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&prefix_domain);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(
            u32,
            candidate.identity[index * 4 ..][0..4],
            .little,
        );
    }
    channel.mixU32s(&words);
    channel.mixU64(log_size);
    channel.mixU64(n_rows);
    channel.mixU64(component_mod.MAIN_COLUMNS);
    channel.mixU64(component_mod.INTERACTION_COLUMNS);
    channel.mixU64(component_mod.QUOTIENT_EXPANSION_BITS);
}

fn mixClaims(channel: anytype, statement: Statement) void {
    channel.mixU32s(&claim_domain);
    channel.mixFelts(&statement.claims.sums);
}

fn callsFixture(allocator: std.mem.Allocator, count: usize) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        const left: u32 = @intCast(5 * index + 3);
        const right: u32 = @intCast(7 * index + 11);
        call.* = poseidon2_air.Call.narrowWithOutput(
            left,
            right,
            poseidon2.hashPair(left, right),
        );
    }
    return calls;
}

const prefix_domain = [8]u32{
    0x5354_5742, // STWB
    0x4436_5052, // D6PR
    1,
    component_mod.MAIN_COLUMNS,
    component_mod.INTERACTION_COLUMNS,
    component_mod.DIRECT_CONSTRAINTS,
    component_mod.QUOTIENT_EXPANSION_BITS,
    @intFromBool(component_mod.PRODUCTION_ACTIVATION),
};

const claim_domain = [4]u32{
    0x5354_5742, // STWB
    0x4436_434c, // D6CL
    1,
    poseidon2_air.N_SUMS,
};

comptime {
    if (component_mod.MAIN_COLUMNS != 161 or
        component_mod.INTERACTION_COLUMNS != 8 or
        component_mod.DIRECT_CONSTRAINTS != 149 or
        component_mod.QUOTIENT_EXPANSION_BITS != 3)
    {
        @compileError("degree-six proof test geometry drifted");
    }
}
