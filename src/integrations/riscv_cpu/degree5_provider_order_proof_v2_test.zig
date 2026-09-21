//! Focused acceptance for the ordered-call d5 provider proof sibling.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_pcs = @import("stwo_core").pcs;
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");

const provider = frontend.testing.narrow_memory_provider_degree5_order_proof_v2;
const provider_v1 = frontend.testing.narrow_memory_provider_degree5_proof_v1;
const provider_order = frontend.testing.narrow_memory_provider_order_component;
const authority = frontend.testing.narrow_memory_provider_shard_authority;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const poseidon2 = frontend.air.memory_commitment.poseidon2;
const relation_challenges = frontend.air.relation_challenges;
const Engine = riscv_cpu.CpuProverEngine;

const CONFIG = core_pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = @import("stwo_core").fri.FriConfig.init(0, 1, 3) catch
        unreachable,
};

test "degree-five ordered provider program binds its compiler projection" {
    const allocator = std.testing.allocator;
    const program = try provider.VerifierProgramAuthorityV2.coldCompile(
        allocator,
    );
    try program.validateCold(allocator);
    const execution = provider.ExecutionProfileV1.n4(program.base);
    try execution.validate(program.base);

    try std.testing.expectEqual(@as(u16, 239), program.base.main_columns);
    try std.testing.expectEqual(@as(u16, 4), program.order_interaction_columns);
    try std.testing.expectEqual(@as(u16, 4), program.order_constraints);
    try std.testing.expectEqual(@as(u32, 2), program.order_composition_log_split);
    try std.testing.expectEqual(@as(u16, 12), program.tree2_columns);
    for (program.selected_main_columns[0..poseidon2_air.WIDTH], 0..) |
        column,
        lane,
    | try std.testing.expectEqual(@as(u16, @intCast(1 + lane)), column);
    const output_column = program.selected_main_columns[poseidon2_air.WIDTH];
    try std.testing.expect(output_column < program.base.main_columns);
    try std.testing.expect(output_column != 1 + poseidon2_air.N_TEMPORARIES);
    for (program.selected_main_columns, 0..) |column, index| {
        for (program.selected_main_columns[0..index]) |previous|
            try std.testing.expect(column != previous);
    }

    const legacy = try provider_v1.VerifierProgramAuthorityV1.coldCompile(
        allocator,
    );
    try std.testing.expectEqualSlices(
        u8,
        &legacy.air_program_identity,
        &program.base.air_program_identity,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &program.air_program_identity,
        &program.base.air_program_identity,
    ));
    try std.testing.expect(provider.SOURCE_PLAN_IS_CALL_PARTITION_ONLY);
    try std.testing.expect(provider.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!provider.SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED);
    try std.testing.expect(!provider.ACTIVATES_PRODUCTION_PROOF);
    try expectProviderOrderDomainParity(program);

    var malformed = program;
    malformed.selected_main_columns[poseidon2_air.WIDTH] =
        malformed.selected_main_columns[0];
    try std.testing.expectError(
        error.InvalidDegree5ProviderOrderProgram,
        malformed.validateCold(allocator),
    );
}

fn expectProviderOrderDomainParity(
    program: provider.VerifierProgramAuthorityV2,
) !void {
    const log_size: u32 = 4;
    const first_call: u64 = 7;
    const relations = relation_challenges.Relations.dummy();
    const claim = provider_order.ClaimV1{
        .format = provider_order.format_version,
        .first_call = first_call,
        .call_count = 1,
        .terminal = stwo_core.fields.qm31.QM31.fromU32Unchecked(3, 5, 7, 11),
    };
    var legacy_columns: provider_order.SelectedMainColumns = undefined;
    for (legacy_columns[0..poseidon2_air.WIDTH], 0..) |*column, lane|
        column.* = @intCast(1 + lane);
    legacy_columns[poseidon2_air.WIDTH] = 1 + poseidon2_air.N_TEMPORARIES;
    const legacy = try provider_order.ProviderOrderComponent.init(
        log_size,
        1,
        first_call,
        0,
        1,
        0,
        0,
        &relations,
        claim,
    );
    const explicit_split_one = try provider_order.ProviderOrderComponent.initProjected(
        log_size,
        1,
        first_call,
        0,
        1,
        0,
        poseidon2_air.N_MAIN_COLUMNS,
        legacy_columns,
        1,
        0,
        &relations,
        claim,
    );
    try std.testing.expect(std.meta.eql(legacy, explicit_split_one));
    try std.testing.expectEqual(log_size + 1, legacy.maxConstraintLogDegreeBound());

    const projected = try provider_order.ProviderOrderComponent.initProjected(
        log_size,
        1,
        first_call,
        0,
        1,
        0,
        program.base.main_columns,
        program.selected_main_columns,
        program.order_composition_log_split,
        0,
        &relations,
        claim,
    );
    const global_log_size = log_size + program.order_composition_log_split;
    try std.testing.expectEqual(global_log_size, projected.maxConstraintLogDegreeBound());

    const M31 = stwo_core.fields.m31.M31;
    const QM31 = stwo_core.fields.qm31.QM31;
    const canonic = stwo_core.poly.circle.canonic;
    const row: usize = 21;
    const domain = canonic.CanonicCoset.new(global_log_size).circleDomain();
    const point_m31 = domain.at(stwo_core.utils.bitReverseIndex(row, global_log_size));
    const point = stwo_core.circle.CirclePointQM31{
        .x = QM31.fromBase(point_m31.x),
        .y = QM31.fromBase(point_m31.y),
    };
    try std.testing.expect(!point.eql(point.repeatedDouble(1)));
    const trace_coset = canonic.CanonicCoset.new(log_size).coset();
    const denominator_class = row >> @intCast(log_size);
    const prepared_point = domain.at(stwo_core.utils.bitReverseIndex(
        denominator_class,
        program.order_composition_log_split,
    ));
    const prepared_denominator = try stwo_core.constraints.cosetVanishing(
        M31,
        trace_coset,
        prepared_point,
    ).inv();
    const oods_denominator = try stwo_core.constraints.cosetVanishing(
        QM31,
        trace_coset,
        point,
    ).inv();
    try std.testing.expect(QM31.fromBase(prepared_denominator).eql(oods_denominator));

    var selected: [provider_order.selected_main_count]QM31 = undefined;
    for (&selected, 0..) |*value, index|
        value.* = QM31.fromBase(M31.fromCanonical(@intCast(17 + index)));
    const constraints = provider_order.evaluateSelectedGeneric(
        QM31,
        selected,
        QM31.fromU32Unchecked(101, 103, 107, 109),
        QM31.fromU32Unchecked(113, 127, 131, 137),
        QM31.fromBase(M31.fromCanonical(139)),
        QM31.fromBase(M31.fromCanonical(149)),
        projected.challenges.row_power,
        projected.challenges.accumulator_power,
        first_call,
        claim.call_count,
        claim.terminal,
    );
    for (constraints) |constraint| {
        const prepared = constraint.mulM31(prepared_denominator);
        const oods = constraint.mul(oods_denominator);
        try std.testing.expect(prepared.eql(oods));
    }
}

test "degree-five ordered provider log16 postcard cold fresh verifies" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 16;
    const call_count: usize = @as(usize, 1) << @intCast(log_size);
    const calls = try callsFixture(allocator, call_count);
    defer allocator.free(calls);
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0xd5} ** 32,
        calls,
        .{
            .logical_row_count = call_count,
            .column_count = authority.main_column_count,
            .min_shard_log_size = log_size,
            .max_shard_log_size = log_size,
            .log_blowup_factor = CONFIG.fri_config.log_blowup_factor,
            .retention_policy = .always,
            .host_byte_budget = 4 * 1024 * 1024 * 1024,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        },
    );
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), plan.shard_count);

    const producer_program =
        try provider.VerifierProgramAuthorityV2.coldCompile(allocator);
    const execution = provider.ExecutionProfileV1.n4(producer_program.base);
    var output = try provider.proveShard(
        Engine,
        allocator,
        CONFIG,
        producer_program,
        execution,
        &plan,
        calls,
        0,
    );
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);
    const statement = output.statement;
    try std.testing.expectEqualSlices(
        u8,
        &execution.identity,
        &output.execution_profile_identity,
    );

    var encoded: std.ArrayList(u8) = .{};
    defer encoded.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        encoded.writer(allocator),
        output.proof,
    );
    try std.testing.expect(encoded.items.len > 0);
    output.proof.deinit(allocator);
    proof_owned = false;

    var parity_stream = std.io.fixedBufferStream(encoded.items);
    var parity_proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        parity_stream.reader(),
    );
    defer parity_proof.deinit(allocator);
    var parity: std.ArrayList(u8) = .{};
    defer parity.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        parity.writer(allocator),
        parity_proof,
    );
    try std.testing.expectEqualSlices(u8, encoded.items, parity.items);

    const verifier_program =
        try provider.VerifierProgramAuthorityV2.coldCompile(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &producer_program.air_program_identity,
        &verifier_program.air_program_identity,
    );
    const verifier_execution = provider.ExecutionProfileV1.n4(
        verifier_program.base,
    );
    var verify_stream = std.io.fixedBufferStream(encoded.items);
    const fresh = try provider.verifyShardFresh(
        Engine,
        allocator,
        CONFIG,
        verifier_program,
        verifier_execution,
        &plan,
        calls,
        statement,
        try postcard.deserializeProof(
            Engine.Hasher,
            allocator,
            verify_stream.reader(),
        ),
    );
    try fresh.validate();
    try std.testing.expect(fresh.fresh_stark_verified);
    try std.testing.expect(fresh.ordered_call_air_verified);
    try std.testing.expect(fresh.ordered_call_claim_recomputed);
    try std.testing.expect(!fresh.shared_core_relation_context_verified);
    try std.testing.expect(!fresh.production_eligible);
    try std.testing.expectEqualSlices(
        u8,
        &statement.identity,
        &fresh.statement_identity,
    );

    var malformed_statement = statement;
    malformed_statement.ordered_call_claim.call_count -= 1;
    var reject_stream = std.io.fixedBufferStream(encoded.items);
    try std.testing.expectError(
        error.InvalidDegree5ProviderOrderStatement,
        provider.verifyShardFresh(
            Engine,
            allocator,
            CONFIG,
            verifier_program,
            verifier_execution,
            &plan,
            calls,
            malformed_statement,
            try postcard.deserializeProof(
                Engine.Hasher,
                allocator,
                reject_stream.reader(),
            ),
        ),
    );
}

fn callsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
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
