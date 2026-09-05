const std = @import("std");

const subject =
    @import("ethereum_incremental_full_leaf_prepared_proof_transaction_v4.zig");

test "prepared transaction pins one construction of every expensive owner" {
    std.testing.refAllDecls(subject.PreparedProofTransactionV4);
    std.testing.refAllDecls(subject.ProofViewV4);
    try std.testing.expect(!subject.SERIALIZABLE);
    try std.testing.expect(!subject.DIGEST_IS_ADMISSION);
    try std.testing.expect(!subject.DEFAULT_PRODUCER_CHANGED);
    try std.testing.expect(subject.PREPARED_ORCHESTRATION_AVAILABLE);

    const expected = subject.ConstructionReceiptV1.onePass();
    try expected.validate();
    inline for (std.meta.fields(subject.ConstructionReceiptV1)) |field| {
        var changed = expected;
        @field(changed, field.name) +%= 1;
        try std.testing.expectError(
            error.InvalidIncrementalPreparedConstructionReceiptV4,
            changed.validate(),
        );
    }

    var counters = subject.CountersV1{};
    counters.recordValidation();
    counters.recordValidation();
    counters.recordBorrow();
    const timing = subject.PhaseTimingV1{
        .witness_prepare_ns = 1,
        .statement_profile_prepare_ns = 2,
    };
    try timing.validate();
    const snapshot = counters.snapshot(expected, timing, null);
    try std.testing.expectEqual(@as(u64, 2), snapshot.owner_validations);
    try std.testing.expectEqual(@as(u64, 1), snapshot.proof_view_borrows);
    try std.testing.expectEqualDeep(expected, snapshot.construction);
    try std.testing.expectEqualDeep(timing, snapshot.phase_timing);
    try std.testing.expect(snapshot.prepared_program_work == null);

    const program_work = @import("stwo_riscv_frontend").testing
        .commitment_witness.PreparedProgramWorkReceiptV1{
        .execution_fetch_rows_scanned = 3,
        .completion_fetch_rows_scanned = 1,
        .fixed_declared_rows = 5,
        .fixed_committed_rows = 4,
        .fixed_sparse_leaves = 16,
        .fixed_sparse_nodes = 7,
        .sparse_tree_builds_elided = 1,
        .sparse_tree_validation_rebuilds_elided = 1,
        .declared_row_decodes_elided = 4,
        .node_poseidon_call_derivations_elided = 7,
    };
    try program_work.validate();
    const prepared_snapshot = counters.snapshot(expected, timing, program_work);
    try std.testing.expectEqualDeep(
        program_work,
        prepared_snapshot.prepared_program_work.?,
    );
}

test "prepared transaction token rejects pointer identity and seal drift" {
    const original = pointerFixture();
    var token = try subject.ProcessTokenV1.init(original);
    try token.validateAgainst(original);

    var changed = original;
    changed.owner_anchor_ptr +%= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        token.validateAgainst(changed),
    );
    changed = original;
    changed.trace_rows_len +%= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        token.validateAgainst(changed),
    );
    changed = original;
    changed.public_wire_id[3] +%= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        token.validateAgainst(changed),
    );
    changed = original;
    changed.profile_identity_sha256[7] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        token.validateAgainst(changed),
    );

    token.snapshot.workspace_ptr +%= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        token.validateAgainst(original),
    );
    token.snapshot = original;
    token.seal_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        token.validateAgainst(original),
    );

    changed = original;
    changed.recovery_records_ptr = 0;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedPointerSnapshotV4,
        subject.ProcessTokenV1.init(changed),
    );

    changed = original;
    changed.prepared_program_owner_ptr = 0x11_000;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedPointerSnapshotV4,
        subject.ProcessTokenV1.init(changed),
    );

    changed.prepared_program_token_ptr = 0x12_000;
    changed.prepared_program_identity_sha256 = .{23} ** 32;
    var prepared_token = try subject.ProcessTokenV1.init(changed);
    try prepared_token.validateAgainst(changed);
    changed.prepared_program_identity_sha256[5] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalPreparedProcessTokenV4,
        prepared_token.validateAgainst(changed),
    );
}

test "prepared process token allocation releases every partial owner" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseTokenAllocation,
        .{pointerFixture()},
    );
}

test "prepared transaction explicit program constructor has no legacy fallback" {
    var inputs: subject.InputsV4 = undefined;
    inputs.prepared_program = null;
    try std.testing.expectError(
        error.MissingPreparedProgramCommitmentV4,
        subject.PreparedProofTransactionV4.initOwnedWithPreparedProgram(
            std.testing.allocator,
            inputs,
        ),
    );
}

fn exerciseTokenAllocation(
    allocator: std.mem.Allocator,
    snapshot: subject.LivePointerSnapshotV1,
) !void {
    const token = try allocator.create(subject.ProcessTokenV1);
    errdefer allocator.destroy(token);
    token.* = try subject.ProcessTokenV1.init(snapshot);
    const receipt = try allocator.create(subject.ConstructionReceiptV1);
    errdefer allocator.destroy(receipt);
    receipt.* = subject.ConstructionReceiptV1.onePass();
    try receipt.validate();
    allocator.destroy(receipt);
    allocator.destroy(token);
}

fn pointerFixture() subject.LivePointerSnapshotV1 {
    return .{
        .owner_anchor_ptr = 0x1000,
        .replay_ptr = 0x2000,
        .memory_snapshot_ptr = 0x3000,
        .boundary_artifact_ptr = 0x4000,
        .public_wire_ptr = 0x5000,
        .role_public_ptr = 0x6000,
        .workspace_ptr = 0x7000,
        .prepared_witness_ptr = 0x8000,
        .ethereum_witness_ptr = 0x9000,
        .statement_ptr = 0xa000,
        .extension_ptr = 0xb000,
        .profile_ptr = 0xc000,
        .trace_rows_ptr = 0xd000,
        .trace_rows_len = 17,
        .keccak_records_ptr = 0xe000,
        .keccak_records_len = 2,
        .recovery_records_ptr = 0xf000,
        .recovery_records_len = 1,
        .public_wire_id = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .boundary_content_sha256 = .{9} ** 32,
        .statement_authority_id = .{ 10, 11, 12, 13, 14, 15, 16, 17 },
        .profile_identity_sha256 = .{18} ** 32,
        .program_source_identity_sha256 = .{19} ** 32,
        .prepared_program_owner_ptr = 0,
        .prepared_program_token_ptr = 0,
        .prepared_program_identity_sha256 = .{0} ** 32,
    };
}
