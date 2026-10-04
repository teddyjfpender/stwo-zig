//! Two real precompile leaves close under one canonical recursive block root.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const protocol = @import("../../recursion/blake3_execution_parent_protocol.zig");
const fixture = @import("block_v4_multi_core_fixture_test.zig");
const recursive = @import("block_v4_multi_recursion_fixture_test.zig");
const receiver = @import("../block_memory_complete_receiver_v3.zig");
const batch = @import("../block_memory_batch_verify_v2.zig");
const execution_receiver = @import("../block_execution_batch_receiver_v2.zig").ForEthereumShaBackend(Cpu);

fn verifyTwo(a: std.mem.Allocator, view: fixture.View, comptime unpadded: bool) !void {
    // This guest has an empty public input/output payload. Their
    // boundary digests still belong only to the first/last leaf.
    const first_span = view.execution_pins[0].statement.body.executed;
    const last_span = view.execution_pins[1].statement.body.executed;
    try std.testing.expect(first_span.input.digest != null);
    try std.testing.expect(first_span.output.digest == null);
    try std.testing.expect(last_span.input.digest == null);
    try std.testing.expect(last_span.output.digest != null);
    try std.testing.expect(!view.segments[0].base.isComplete());
    try std.testing.expect(view.segments[1].base.isComplete());
    try std.testing.expect(view.statement.execution_extension_active_counts[0] > 0);
    try std.testing.expect(view.statement.execution_extension_active_counts[1] > 0);
    if (unpadded) {
        try std.testing.expectEqual(@as(u64, 0), view.statement.execution_active_counts[1]);
        const prepared = view.executions[1].prepared;
        const leaf = view.execution_pins[1];
        var wrong_root = view.receipts[1].witness_root;
        wrong_root[0] ^= 1;
        try std.testing.expectError(error.InvalidEmptyExecutionSidecar, execution_receiver.verify(a, view.wire.execution[1], prepared, leaf.expected_key_id, leaf.statement, view.statement.seal, 1, wrong_root, view.config));
        var wrong_bytes = view.wire.execution[1];
        wrong_bytes.sidecar_stark = &.{1};
        try std.testing.expectError(error.InvalidEmptyExecutionSidecar, execution_receiver.verify(a, wrong_bytes, prepared, leaf.expected_key_id, leaf.statement, view.statement.seal, 1, view.receipts[1].witness_root, view.config));
        var wrong_claims = view.wire.execution[1];
        wrong_claims.sidecar_claims = view.wire.execution[0].sidecar_claims[0..1];
        try std.testing.expectError(error.InvalidExecutionSlotClaims, execution_receiver.verify(a, wrong_claims, prepared, leaf.expected_key_id, leaf.statement, view.statement.seal, 1, view.receipts[1].witness_root, view.config));
    }

    var proofs = try recursive.prove(a, view);
    defer proofs.deinit(a);
    var statement = view.statement;
    var complete = statement.complete_pins.?;
    complete.outer_recursive_key_id = proofs.outer_admission.expected_id;
    complete.forest_roster_digest = proofs.forest_digest;
    statement.complete_pins = complete;
    const leaves = [_]receiver.ProofPin{
        .{ .admission = proofs.leaf_admissions[0], .expected_key_id = proofs.leaf_admissions[0].expected_id },
        .{ .admission = proofs.leaf_admissions[1], .expected_key_id = proofs.leaf_admissions[1].expected_id },
    };
    const parent_pin = [_]receiver.DyadicPin{.{
        .left_index = 0,
        .right_index = 1,
        .proof = .{ .admission = proofs.dyadic_admission, .expected_key_id = proofs.dyadic_admission.expected_id },
    }};
    const leaf_bytes = [_][]const u8{ proofs.leaf_bytes[0], proofs.leaf_bytes[1] };
    const dyadic_bytes = [_][]const u8{proofs.dyadic_bytes};
    const roots = [_]u32{2};
    const pins = receiver.RecursionPins{
        .leaf = &leaves,
        .dyadic = &parent_pin,
        .root_indices = &roots,
        .outer = .{ .admission = proofs.outer_admission, .expected_key_id = proofs.outer_admission.expected_id },
    };
    const bytes = receiver.RecursionBytes{
        .leaf = &leaf_bytes,
        .dyadic = &dyadic_bytes,
        .outer = proofs.outer_bytes,
    };
    const result = try receiver.verifyCanonicalEthereumShaWithExtension(
        Cpu,
        a,
        statement,
        view.wire,
        view.execution_pins,
        view.public_initial,
        pins,
        bytes,
        view.config,
    );
    try std.testing.expectEqual(batch.CompleteBlock.complete_block_verified, result);

    var wrong = statement;
    var wrong_complete = wrong.complete_pins.?;
    wrong_complete.outer_recursive_key_id[0] ^= 1;
    wrong.complete_pins = wrong_complete;
    try std.testing.expectError(error.UntrustedBlockOuterKey, receiver.verifyCanonicalEthereumShaWithExtension(Cpu, a, wrong, view.wire, view.execution_pins, view.public_initial, pins, bytes, view.config));
    std.debug.print(
        "BLOCK_V4_MULTI_COMPLETE verified=true unpadded={} segments=2 events={d} external={d}+{d} leaf_bytes={d}+{d} dyadic_bytes={d} outer_bytes={d} recursion_peak_bytes={d} core_ns={d} leaf_ns={d}+{d} dyadic_ns={d} outer_ns={d} recursion_ns={d}\n",
        .{ unpadded, view.verified.event_count, view.statement.execution_extension_active_counts[0], view.statement.execution_extension_active_counts[1], proofs.leaf_bytes[0].len, proofs.leaf_bytes[1].len, proofs.dyadic_bytes.len, proofs.outer_bytes.len, proofs.peak_live_bytes, view.core_elapsed_ns, proofs.leaf_prove_ns[0], proofs.leaf_prove_ns[1], proofs.dyadic_prove_ns, proofs.outer_prove_ns, proofs.elapsed_ns },
    );
}

test "block-v4 canonical two-segment SHA Keccak complete receiver" {
    const callback = struct {
        fn run(a: std.mem.Allocator, view: fixture.View) !void {
            try verifyTwo(a, view, false);
        }
    };
    try fixture.withFixture(protocol.CSP_CONFIG, callback.run);
}

test "block-v4 canonical unpadded two-segment SHA Keccak complete receiver" {
    const callback = struct {
        fn run(a: std.mem.Allocator, view: fixture.View) !void {
            try verifyTwo(a, view, true);
        }
    };
    try fixture.withUnpaddedFixture(protocol.CSP_CONFIG, callback.run);
}
