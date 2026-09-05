const std = @import("std");

const prepared =
    @import("ethereum_incremental_prepared_program_commitment_v1.zig");
const frontend = @import("stwo_riscv_frontend");
const elf_fixture = frontend.testing.guest_precompile_test_elf;

fn buildEthereumElf(allocator: std.mem.Allocator) ![]u8 {
    const bytes = elf_fixture.buildEthereum();
    return allocator.dupe(u8, &bytes);
}

test "prepared program commitment deep owns exact ELF and validates borrowed prefix" {
    const allocator = std.testing.allocator;
    const source = try buildEthereumElf(allocator);
    defer allocator.free(source);
    var original_source_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &original_source_sha256, .{});

    const owner = try prepared.PreparedProgramCommitmentV1.create(
        allocator,
        source,
    );
    defer owner.deinit();

    source[0] ^= 0xff;
    const borrowed = try owner.borrow();
    try borrowed.validate();
    try owner.validateColdContent();
    try std.testing.expect(borrowed.source_bytes.ptr != source.ptr);
    try std.testing.expectEqualSlices(
        u8,
        &original_source_sha256,
        &borrowed.inventory.source_bytes_sha256,
    );
    try std.testing.expectEqual(
        borrowed.commitment.tree.nodes.len,
        borrowed.ordered_poseidon_calls.len,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(borrowed.declared_rows.len)),
        borrowed.inventory.declared_row_count,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(borrowed.commitment.rows.len)),
        borrowed.inventory.committed_row_count,
    );
    try std.testing.expectEqual(
        borrowed.commitment.tree.root,
        borrowed.inventory.sparse_tree_root,
    );
    try std.testing.expect(!prepared.SERIALIZABLE);
    try std.testing.expect(!prepared.PROOF_AUTHORITY);
    try std.testing.expect(!prepared.TRANSCRIPT_REUSE_ALLOWED);
    try std.testing.expect(prepared.PREPARED_WITNESS_INTEGRATED);
}

test "prepared program leaf rows retain only multiplicities and exact work receipt" {
    const allocator = std.testing.allocator;
    const source = try buildEthereumElf(allocator);
    defer allocator.free(source);
    const owner = try prepared.PreparedProgramCommitmentV1.create(
        allocator,
        source,
    );
    defer owner.deinit();
    const borrowed = try owner.borrow();

    const fixed_row = borrowed.commitment.rows[0];
    var raw_word: ?u32 = null;
    for (borrowed.declared_rows) |declared| {
        if (declared.addr == fixed_row.addr) {
            raw_word = declared.initial_word;
            break;
        }
    }
    const word = raw_word orelse return error.MissingPreparedProgramTestWord;
    const ExecutionRow = struct { pc: u32, inst_word: u32 };
    const executions = [_]ExecutionRow{
        .{ .pc = fixed_row.addr, .inst_word = word },
        .{ .pc = fixed_row.addr, .inst_word = word },
    };
    var leaf = try borrowed.prepareLeafRows(
        allocator,
        .{executions[0..]},
        .{ .pc = fixed_row.addr, .word = word },
    );
    defer leaf.deinit();
    try leaf.validate();
    const receipt = leaf.workReceipt();
    try receipt.validate();
    try std.testing.expectEqual(@as(u64, 2), receipt.execution_fetch_rows_scanned);
    try std.testing.expectEqual(@as(u8, 1), receipt.completion_fetch_rows_scanned);
    try std.testing.expectEqual(
        borrowed.inventory.committed_row_count,
        receipt.declared_row_decodes_elided,
    );
    try std.testing.expectEqual(
        borrowed.inventory.sparse_node_count,
        receipt.node_poseidon_call_derivations_elided,
    );

    var matched = false;
    for (leaf.rows) |row| {
        if (row.addr != fixed_row.addr) continue;
        try std.testing.expectEqual(@as(u32, 3), row.multiplicity);
        matched = true;
    }
    try std.testing.expect(matched);
    try owner.validateBorrowed();
}

test "prepared program leaf rows reject address and instruction drift" {
    const allocator = std.testing.allocator;
    const source = try buildEthereumElf(allocator);
    defer allocator.free(source);
    const owner = try prepared.PreparedProgramCommitmentV1.create(
        allocator,
        source,
    );
    defer owner.deinit();
    const borrowed = try owner.borrow();
    const fixed_row = borrowed.commitment.rows[0];
    var raw_word: ?u32 = null;
    for (borrowed.declared_rows) |declared| {
        if (declared.addr == fixed_row.addr) {
            raw_word = declared.initial_word;
            break;
        }
    }
    const word = raw_word orelse return error.MissingPreparedProgramTestWord;
    const ExecutionRow = struct { pc: u32, inst_word: u32 };

    const changed = [_]ExecutionRow{.{
        .pc = fixed_row.addr,
        .inst_word = word ^ 0x0000_0080,
    }};
    try std.testing.expectError(
        error.ProgramWordChanged,
        borrowed.prepareLeafRows(allocator, .{changed[0..]}, null),
    );

    const missing = [_]ExecutionRow{.{
        .pc = borrowed.layout.program_end,
        .inst_word = word,
    }};
    try std.testing.expectError(
        error.FetchedProgramWordMissing,
        borrowed.prepareLeafRows(allocator, .{missing[0..]}, null),
    );
}

test "prepared commitment witness builder preserves table order and work receipt" {
    const allocator = std.testing.allocator;
    const source = try buildEthereumElf(allocator);
    defer allocator.free(source);
    const owner = try prepared.PreparedProgramCommitmentV1.create(
        allocator,
        source,
    );
    defer owner.deinit();
    const borrowed = try owner.borrow();

    const fixed_row = borrowed.commitment.rows[0];
    var raw_word: ?u32 = null;
    for (borrowed.declared_rows) |declared| {
        if (declared.addr == fixed_row.addr) {
            raw_word = declared.initial_word;
            break;
        }
    }
    const word = raw_word orelse return error.MissingPreparedProgramTestWord;
    const ExecutionRow = struct { pc: u32, inst_word: u32 };
    const executions = [_]ExecutionRow{.{
        .pc = fixed_row.addr,
        .inst_word = word,
    }};
    const program_words = try allocator.dupe(
        frontend.runner.memory_state.WordState,
        borrowed.declared_rows,
    );
    defer allocator.free(program_words);
    const snapshot = frontend.runner.memory_state.Snapshot{
        .layout = borrowed.layout.*,
        .segment_role = .single(),
        .words = &.{},
        .program_words = program_words,
    };
    const roots = frontend.testing.commitment_witness.IncrementalRootsV3{
        .entry = 0x1234,
        .exit = 0x5678,
    };
    const boundary_rows = [_]frontend.air.memory_commitment.boundary.Row{.{
        .addr = 0,
        .clock = 0,
        .value = .{ 0, 0, 0, 0 },
        .multiplicity = .zero(),
        .root = roots.entry,
    }};
    const incremental_merkle_rows =
        [_]frontend.air.memory_commitment.merkle_node.NodeRow{.{
            .index = 0,
            .depth = 0,
            .lhs = 1,
            .rhs = 2,
            .cur = 3,
            .lhs_mult = 0,
            .rhs_mult = 0,
            .cur_mult = 0,
            .root = roots.entry,
        }};
    const incremental_calls =
        [_]frontend.air.memory_commitment.poseidon2_air.Call{
            .narrowWithOutput(1, 2, 3),
        };
    var witness = try frontend.testing.commitment_witness.CommitmentWitness
        .buildExternalProfileWithPreparedProgramAndIncrementalBoundaryV3(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{executions[0..]},
        &snapshot,
        frontend.air.public_data.Completion.unretiredProgramFetch(
            fixed_row.addr,
            word,
        ),
        borrowed,
        &boundary_rows,
        &incremental_merkle_rows,
        &incremental_calls,
        roots,
    );
    defer witness.deinit(allocator);

    const receipt = witness.preparedProgramWorkReceipt() orelse
        return error.MissingPreparedProgramWorkReceipt;
    try receipt.validate();
    try std.testing.expectEqual(@as(u64, 1), receipt.execution_fetch_rows_scanned);
    try std.testing.expectEqual(@as(u8, 1), receipt.completion_fetch_rows_scanned);
    try std.testing.expectEqual(
        borrowed.commitment.tree.root,
        witness.program.tree.root,
    );
    try std.testing.expectEqual(
        borrowed.ordered_poseidon_calls.len + incremental_calls.len,
        witness.poseidonCalls().len,
    );
    try std.testing.expectEqualDeep(
        borrowed.ordered_poseidon_calls[0],
        witness.poseidonCalls()[0],
    );
    try std.testing.expectEqualDeep(
        incremental_calls[0],
        witness.poseidonCalls()[borrowed.ordered_poseidon_calls.len],
    );
    try std.testing.expectEqualDeep(
        incremental_merkle_rows[0],
        witness.merkleRows()[0],
    );
    try owner.validateBorrowed();
}

test "prepared program commitment rejects copied owner and borrowed pointer drift" {
    const allocator = std.testing.allocator;
    const source = try buildEthereumElf(allocator);
    defer allocator.free(source);
    const owner = try prepared.PreparedProgramCommitmentV1.create(
        allocator,
        source,
    );
    defer owner.deinit();

    var copied_owner = owner.*;
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentTokenV1,
        copied_owner.validateBorrowed(),
    );

    const borrowed = try owner.borrow();
    try std.testing.expect(borrowed.ordered_poseidon_calls.len != 0);
    const copied_source = try allocator.dupe(u8, borrowed.source_bytes);
    defer allocator.free(copied_source);
    var source_drift = borrowed;
    source_drift.source_bytes = copied_source;
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentBorrowV1,
        source_drift.validate(),
    );

    var layout_copy = borrowed.layout.*;
    var layout_drift = borrowed;
    layout_drift.layout = &layout_copy;
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentBorrowV1,
        layout_drift.validate(),
    );

    var inventory_drift = borrowed;
    inventory_drift.inventory.sparse_tree_root +%= 1;
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentBorrowV1,
        inventory_drift.validate(),
    );

    var call_slice_drift = borrowed;
    call_slice_drift.ordered_poseidon_calls =
        borrowed.ordered_poseidon_calls[1..];
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentBorrowV1,
        call_slice_drift.validate(),
    );
}

test "prepared program commitment cold validation rejects retained root and call mutation" {
    const allocator = std.testing.allocator;
    const source = try buildEthereumElf(allocator);
    defer allocator.free(source);
    const owner = try prepared.PreparedProgramCommitmentV1.create(
        allocator,
        source,
    );
    defer owner.deinit();
    const borrowed = try owner.borrow();
    try std.testing.expect(borrowed.ordered_poseidon_calls.len != 0);

    const commitment = @constCast(borrowed.commitment);
    const original_root = commitment.tree.root;
    commitment.tree.root +%= 1;
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentContentV1,
        owner.validateBorrowed(),
    );
    commitment.tree.root = original_root;
    try owner.validateBorrowed();

    const calls = @constCast(borrowed.ordered_poseidon_calls);
    const original_input = calls[0].input[0];
    calls[0].input[0] +%= 1;
    try std.testing.expectError(
        error.InvalidPreparedProgramCommitmentContentV1,
        owner.validateColdContent(),
    );
    calls[0].input[0] = original_input;
    try owner.validateColdContent();
}
