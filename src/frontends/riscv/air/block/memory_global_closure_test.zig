const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const closure = @import("memory_global_closure.zig");
const memory = @import("memory_component.zig");
const memory_proof = @import("../../prover/block_memory_proof_v2.zig");
const execution_proof = @import("../../prover/block_memory_execution_proof_v2.zig");
const source_seal = @import("../../prover/block_memory_source_seal_v2.zig");
const manifest = @import("../../prover/block_commitment_manifest.zig");

test "verified block-memory closure structurally rejects missing reordered or mismatched receipts" {
    // These test values exercise admission after verification; the separate
    // PCS tests are the authority for constructing genuine receipts.
    const Transition = @import("memory_transition.zig").Transition;
    const first = Transition{ .space = 1, .address = 4096, .clock = 1, .before = 0, .after = 1 };
    const second = Transition{ .space = 1, .address = 4096, .clock = 5, .before = 1, .after = 2 };
    const third = Transition{ .space = 1, .address = 4096, .clock = 9, .before = 2, .after = 3 };
    const seal = try source_seal.SourceSeal.init(manifest.Sealed{ .digest = @splat(19), .instance_count = 2 }, 0, @splat(23));
    var channel = seal.sharedChannel();
    const digest = channel.digestBytes();
    const claims = [_]memory.Claim{
        try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = first, .last = second }, 3, 1, null),
        try memory.Claim.fromSummary(.{ .first_row = 2, .rows = 1, .first = third, .last = third }, 3, 1, second),
    };
    const memory_receipts = [_]memory_proof.VerifiedMemoryReceipt{
        .{ .claim = claims[0], .relation = .{ .instance_index = 0, .transition_sum = Q.fromBase(core.fields.m31.M31.fromCanonical(7)), .link_sum = Q.one() }, .first_round_roots = .{ @splat(1), @splat(2) }, .sealed_channel_digest = digest },
        .{ .claim = claims[1], .relation = .{ .instance_index = 1, .transition_sum = Q.fromBase(core.fields.m31.M31.fromCanonical(11)), .link_sum = Q.one().neg() }, .first_round_roots = .{ @splat(3), @splat(4) }, .sealed_channel_digest = digest },
    };
    const execution_receipts = [_]execution_proof.VerifiedExecutionReceipt{
        .{ .instance_index = 0, .transition_sum = Q.fromBase(core.fields.m31.M31.fromCanonical(7)).neg(), .first_round_roots = .{ @splat(5), @splat(6) }, .sealed_channel_digest = digest, .event_count = 2 },
        .{ .instance_index = 1, .transition_sum = Q.fromBase(core.fields.m31.M31.fromCanonical(11)).neg(), .first_round_roots = .{ @splat(7), @splat(8) }, .sealed_channel_digest = digest, .event_count = 1 },
    };
    try closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, &execution_receipts, 3);
    try std.testing.expectError(error.InvalidMemoryReceiptCensus, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, memory_receipts[0..1], &execution_receipts, 3));
    try std.testing.expectError(error.InvalidBlockExecutionReceiptCensus, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, execution_receipts[0..1], 3));
    const reversed = [_]execution_proof.VerifiedExecutionReceipt{ execution_receipts[1], execution_receipts[0] };
    try std.testing.expectError(error.InvalidBlockExecutionReceiptCensus, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, &reversed, 3));
    var changed = execution_receipts;
    changed[0].sealed_channel_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidBlockExecutionReceiptCensus, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, &changed, 3));
    changed = execution_receipts;
    changed[0].event_count += 1;
    try std.testing.expectError(error.InvalidBlockExecutionEventCensus, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, &changed, 3));
    changed = execution_receipts;
    changed[0].event_count = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidBlockExecutionReceiptCensus, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, &changed, 3));
    changed = execution_receipts;
    changed[0].transition_sum = changed[0].transition_sum.add(Q.one());
    try std.testing.expectError(error.UnclosedBlockMemoryTransition, closure.checkStructuralBlockMemoryClosure(std.testing.allocator, seal, &memory_receipts, &changed, 3));

    // Memory instances are independently sized and may outnumber execution
    // instances; the source seal binds both cardinalities separately.
    const wider_memory = try source_seal.SourceSeal.initWithMemoryCount(
        manifest.Sealed{ .digest = @splat(19), .instance_count = 1 },
        0,
        @splat(23),
        2,
    );
    var wider_channel = wider_memory.sharedChannel();
    const wider_digest = wider_channel.digestBytes();
    var wider_memory_receipts = memory_receipts;
    for (&wider_memory_receipts) |*receipt| receipt.sealed_channel_digest = wider_digest;
    const one_execution = [_]execution_proof.VerifiedExecutionReceipt{.{
        .instance_index = 0,
        .transition_sum = Q.fromBase(core.fields.m31.M31.fromCanonical(18)).neg(),
        .first_round_roots = .{ @splat(5), @splat(6) },
        .sealed_channel_digest = wider_digest,
        .event_count = 3,
    }};
    try closure.checkStructuralBlockMemoryClosure(std.testing.allocator, wider_memory, &wider_memory_receipts, &one_execution, 3);
}
