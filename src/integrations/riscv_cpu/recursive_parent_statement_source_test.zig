//! Exact-type and fail-atomic gate for the CPU parent-statement adapter.

const std = @import("std");
const integration = @import("stwo_riscv_cpu_integration");
const frontend = @import("stwo_riscv_frontend");

const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const fixed_wire = recursion.fixed_wire;
const pair_node = recursion.pair_node;
const protocol = recursion.protocol;
const source = recursion.outer_parent_statement_source;
const adapter = integration.recursive_parent_statement_source;
const air_adapter = integration.recursive_parent_statement_air_source;
const air_source = recursion.outer_parent_statement_air_source;
const segment_source = recursion.segment_statement_outer_source;
const outer = integration.recursive_fri_outer;

const Dimensions = fixed_wire.Dimensions{
    .commitment_count = admission.TREE_COUNT,
    .claimed_sum_count = admission.CLAIMED_SUM_COUNT,
    .sampled_value_count = admission.TREE_COUNT,
    .queried_value_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .trace_path_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .fri_layer_count = 5,
    .query_count = admission.QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 6,
};
const Prepared = source.Prepared(Dimensions);
const Wire = admission.FixedOuterProofWireV1(Dimensions);

test "CPU parent statement adapter consumes exact VerifiedOuterProofV1 and fails atomically" {
    try std.testing.expect(!adapter.COMPLETE_PARENT_STARK_VERIFIED);
    try std.testing.expectEqual(@as(usize, 0), adapter.HEAP_ALLOCATIONS_PER_PREPARE);

    var invalid_verified: outer.VerifiedOuterProofV1 = undefined;
    @memset(std.mem.asBytes(&invalid_verified), 0);
    var invalid_wire: Wire = undefined;
    @memset(std.mem.asBytes(&invalid_wire), 0);
    var invalid_candidate: admission.BinaryPairCandidateV1 = undefined;
    @memset(std.mem.asBytes(&invalid_candidate), 0);

    const context = pair_node.VerifierContextV1{
        .session_id = digest(11),
        .job_id = digest(31),
        .execution_statement_id = digest(51),
        .public_call_commitment = protocol.emptyCallCommitment(),
        .event_count = 0,
        .session_leaf_count = 2,
        .pair_index = 0,
        .aggregator_vk_id = digest(71),
    };
    try context.validate();
    var invalid_authority: pair_node.VerifierAuthorityV1 = undefined;
    @memset(std.mem.asBytes(&invalid_authority), 0);
    invalid_authority.context = context;
    const suite = try pair_node.prepareProtocolSuite();
    const authority = source.AuthorityInputsV1{
        .pair = .{
            .context = context,
            .root_pin = .{ .expected_aggregator_vk_id = context.aggregator_vk_id },
        },
        .verified = &invalid_authority,
        .suite = &suite,
    };
    var invalid_binding: admission.PairChildInputsV1 = undefined;
    @memset(std.mem.asBytes(&invalid_binding), 0);
    const child = adapter.VerifiedChildInput(Dimensions){
        .verified = &invalid_verified,
        .wire = &invalid_wire,
        .candidate = &invalid_candidate,
        .binding = invalid_binding,
    };
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(Dimensions),
    );
    defer std.testing.allocator.free(scratch);
    var destination: Prepared = undefined;
    @memset(std.mem.asBytes(&destination), 0xd7);
    const snapshot = std.mem.asBytes(&destination)[0..@sizeOf(Prepared)].*;

    try std.testing.expectError(
        error.InvalidReceipt,
        adapter.prepareInto(
            Dimensions,
            &destination,
            scratch,
            authority,
            .{ child, child },
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &snapshot,
        std.mem.asBytes(&destination),
    );
}

test "CPU fused parent AIR adapter preserves custody-first failure and performance budget" {
    try std.testing.expect(!air_adapter.COMPLETE_PARENT_STARK_VERIFIED);
    try std.testing.expect(air_adapter.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS);
    try std.testing.expect(!air_adapter.EXTERNAL_STATEMENT_PREIMAGE_BINDING);
    try std.testing.expectEqual(@as(usize, 1), air_adapter.PAIR_AUTHENTICATIONS_PER_PREPARE);
    try std.testing.expectEqual(@as(usize, 55), air_adapter.PAIR_PERMUTATIONS_PER_AUTHENTICATION);
    try std.testing.expectEqual(@as(usize, 229), air_adapter.PRIOR_STATIC_PAIR_PERMUTATION_ESTIMATE);
    try std.testing.expectEqual(@as(usize, 165), air_adapter.PAIR_PERMUTATIONS_AVOIDED);
    try std.testing.expectEqual(@as(usize, 0), air_adapter.HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL);
    try std.testing.expectEqual(@as(usize, 0), air_adapter.HOT_TRACE_HEAP_ALLOCATIONS);

    var invalid_verified: outer.VerifiedOuterProofV1 = undefined;
    @memset(std.mem.asBytes(&invalid_verified), 0);
    var invalid_wire: Wire = undefined;
    @memset(std.mem.asBytes(&invalid_wire), 0);
    var invalid_candidate: admission.BinaryPairCandidateV1 = undefined;
    @memset(std.mem.asBytes(&invalid_candidate), 0);
    var invalid_binding: admission.PairChildInputsV1 = undefined;
    @memset(std.mem.asBytes(&invalid_binding), 0);

    const context = pair_node.VerifierContextV1{
        .session_id = digest(11),
        .job_id = digest(31),
        .execution_statement_id = digest(51),
        .public_call_commitment = protocol.emptyCallCommitment(),
        .event_count = 0,
        .session_leaf_count = 2,
        .pair_index = 0,
        .aggregator_vk_id = digest(71),
    };
    try context.validate();
    var invalid_authority: pair_node.VerifierAuthorityV1 = undefined;
    @memset(std.mem.asBytes(&invalid_authority), 0);
    invalid_authority.context = context;
    const suite = try pair_node.prepareProtocolSuite();
    const parent_inputs = source.AuthorityInputsV1{
        .pair = .{
            .context = context,
            .root_pin = .{ .expected_aggregator_vk_id = context.aggregator_vk_id },
        },
        .verified = &invalid_authority,
        .suite = &suite,
    };
    const child = adapter.VerifiedChildInput(Dimensions){
        .verified = &invalid_verified,
        .wire = &invalid_wire,
        .candidate = &invalid_candidate,
        .binding = invalid_binding,
    };
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(Dimensions),
    );
    defer std.testing.allocator.free(scratch);
    var unused_authority: segment_source.Authority = undefined;
    @memset(std.mem.asBytes(&unused_authority), 0);
    var unused_workspace: air_source.Workspace = undefined;
    @memset(std.mem.asBytes(&unused_workspace), 0);
    try std.testing.expectError(
        error.InvalidReceipt,
        air_adapter.prepare(
            Dimensions,
            std.testing.allocator,
            &unused_authority,
            &unused_workspace,
            scratch,
            parent_inputs,
            .{ child, child },
        ),
    );
}

fn digest(seed: u32) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index * 2));
    return result;
}
