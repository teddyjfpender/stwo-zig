//! Focused acceptance for the additive retained d5 provider proof path.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");

const provider = frontend.testing.narrow_memory_provider_degree5_proof_v1;
const authority = frontend.testing.narrow_memory_provider_shard_authority;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const poseidon2 = frontend.air.memory_commitment.poseidon2;
const Engine = riscv_cpu.CpuProverEngine;

const CONFIG = core_pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = @import("stwo_core").fri.FriConfig.init(0, 1, 3) catch
        unreachable,
};

const expected_proof_bytes: usize = 25_988;
const expected_proof_sha256 = digest(
    "de0edc727c67c4e622b3cc6565df289454ab02d34f36cb4ef834b85b798c0d8b",
);
const expected_receipt_identity = digest(
    "e471d7a8e7d1eec260749359b795975636bb320f929cfc851418b3f681c2f766",
);
const expected_statement_identity = digest(
    "9f1797ebfd0087b21a1dc98f8e092b8776bd9bf697e6bcae9e53e28ab3c3f6bc",
);
const expected_air_program_identity = digest(
    "e7cab88eac99a3929ec8b89c27667b100e05f7a2bce232e2d3ac765fc67bd0ee",
);

test "degree-five retained provider program and N4 profile are cold and fail closed" {
    const allocator = std.testing.allocator;
    const program = try provider.VerifierProgramAuthorityV1.coldCompile(
        allocator,
    );
    try program.validateCold(allocator);
    const execution = provider.ExecutionProfileV1.n4(program);
    try execution.validate(program);

    try std.testing.expectEqual(
        @as(u16, 239),
        program.main_columns,
    );
    try std.testing.expectEqual(@as(u16, 4), execution.concurrent_provider_limit);
    try std.testing.expectEqual(
        authority.main_column_count,
        @as(u16, 445),
    );
    try std.testing.expect(provider.SOURCE_PLAN_IS_CALL_PARTITION_ONLY);
    try std.testing.expect(!provider.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!provider.SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED);
    try std.testing.expect(!provider.ACTIVATES_PRODUCTION_PROOF);

    var malformed_program = program;
    malformed_program.main_columns += 1;
    try std.testing.expectError(
        error.InvalidDegree5VerifierProgram,
        malformed_program.validateCold(allocator),
    );
    var malformed_execution = execution;
    malformed_execution.concurrent_provider_limit -= 1;
    try std.testing.expectError(
        error.InvalidDegree5ExecutionProfile,
        malformed_execution.validate(program),
    );
}

test "degree-five retained provider log16 postcard cold fresh verifies" {
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

    const producer_program = try provider.VerifierProgramAuthorityV1.coldCompile(
        allocator,
    );
    const execution = provider.ExecutionProfileV1.n4(producer_program);
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
    var proof_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded.items, &proof_sha256, .{});
    output.proof.deinit(allocator);
    proof_owned = false;

    // The transport itself is canonical before a cold verifier consumes it.
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

    const verifier_program = try provider.VerifierProgramAuthorityV1.coldCompile(
        allocator,
    );
    try std.testing.expectEqualSlices(
        u8,
        &producer_program.air_program_identity,
        &verifier_program.air_program_identity,
    );
    const verifier_execution = provider.ExecutionProfileV1.n4(verifier_program);
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
    try std.testing.expect(!fresh.ordered_call_air_verified);
    try std.testing.expect(!fresh.shared_core_relation_context_verified);
    try std.testing.expect(!fresh.production_eligible);
    try std.testing.expectEqualSlices(
        u8,
        &statement.identity,
        &fresh.statement_identity,
    );
    try std.testing.expectEqual(expected_proof_bytes, encoded.items.len);
    try std.testing.expectEqualSlices(
        u8,
        &expected_proof_sha256,
        &proof_sha256,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_receipt_identity,
        &fresh.identity,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_statement_identity,
        &statement.identity,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_air_program_identity,
        &verifier_program.air_program_identity,
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

fn digest(comptime encoded: *const [64:0]u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}
