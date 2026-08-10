//! Exact and adversarial program-authority evidence for C-009.

const std = @import("std");
const subject = @import("program_commitment.zig");
const component_registry = @import("component_registry.zig");
const base_commitment = @import("../program/commitment.zig");
const program_decode = @import("../program/decode.zig");
const program_table = @import("../program/table.zig");
const sparse_merkle = @import("../memory_commitment/sparse_merkle.zig");
const custom0 = @import("../../isa/custom0.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const memory_state = @import("../../runner/memory_state.zig");
const trace = @import("../../runner/trace.zig");

const addi_x1_x0_1: u32 = 0x0010_0093;
const addi_x2_x0_2: u32 = 0x0020_0113;

test "guest program decoder binds exact opcode 46 tuple and delegates RV32IM" {
    try std.testing.expectEqual(
        @as(u32, component_registry.guest_opcode_id),
        program_decode.poseidon2_v1_program_opcode_id,
    );
    for (0..32) |register_index| {
        const rs1: u5 = @intCast(register_index);
        try std.testing.expectEqual(
            program_decode.ProgramValues{ 46, 0, rs1, 0 },
            try subject.decodeProgramWord(custom0.encodePoseidon2(rs1)),
        );
    }
    try std.testing.expectEqual(
        try program_decode.decodeProgramWord(addi_x1_x0_1),
        try subject.decodeProgramWord(addi_x1_x0_1),
    );
}

test "guest program commitment counts repeated custom retirements at one PC" {
    const custom = custom0.encodePoseidon2(5);
    const guest_rows = [_]guest_runner.ExecutionRow{
        guestRow(1, 0x1000, custom, 0),
        guestRow(2, 0x1000, custom, 1),
        guestRow(3, 0x1000, custom, 2),
    };
    var frozen = try freezeRows(std.testing.allocator, &guest_rows);
    defer frozen.deinit();
    const words = [_]memory_state.WordState{declaredWord(0x1000, custom)};

    var commitment = try subject.buildDeclared(
        std.testing.allocator,
        &.{},
        &frozen,
        &words,
        null,
    );
    defer commitment.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), commitment.rows.len);
    try std.testing.expectEqual(@as(u32, 0x1000), commitment.rows[0].addr);
    try std.testing.expectEqual(
        program_decode.ProgramValues{ 46, 0, 5, 0 },
        commitment.rows[0].values,
    );
    try std.testing.expectEqual(@as(u32, 3), commitment.rows[0].multiplicity);
    try commitment.validate(std.testing.allocator);
}

test "guest program commitment counts mixed streams and completion without union allocation" {
    const custom = custom0.encodePoseidon2(9);
    const base_rows = [_]trace.TraceRow{
        baseRow(1, 0x1000, addi_x1_x0_1),
        baseRow(2, 0x1000, addi_x1_x0_1),
    };
    const guest_rows = [_]guest_runner.ExecutionRow{
        guestRow(3, 0x1004, custom, 0),
        guestRow(4, 0x1004, custom, 1),
    };
    var frozen = try freezeRows(std.testing.allocator, &guest_rows);
    defer frozen.deinit();
    // Deliberately unsorted, with one zero ROM gap that must remain omitted.
    const words = [_]memory_state.WordState{
        declaredWord(0x1008, addi_x2_x0_2),
        declaredWord(0x1004, custom),
        declaredWord(0x100c, 0),
        declaredWord(0x1000, addi_x1_x0_1),
    };

    var commitment = try subject.buildDeclared(
        std.testing.allocator,
        &base_rows,
        &frozen,
        &words,
        .{ .pc = 0x1008, .word = addi_x2_x0_2 },
    );
    defer commitment.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), commitment.rows.len);
    try expectRow(commitment.rows[0], 0x1000, .{ 10, 1, 0, 1 }, 2);
    try expectRow(commitment.rows[1], 0x1004, .{ 46, 0, 9, 0 }, 2);
    try expectRow(commitment.rows[2], 0x1008, .{ 10, 2, 0, 2 }, 1);
    try commitment.validate(std.testing.allocator);
}

test "guest program authority rejects reserved CUSTOM-0 and base path stays closed" {
    const canonical = custom0.encodePoseidon2(17);
    const reserved_rd = canonical | (@as(u32, 1) << 7);
    try std.testing.expectError(
        error.InvalidPrecompileEncoding,
        subject.decodeProgramWord(reserved_rd),
    );
    try std.testing.expectError(
        error.InvalidInstruction,
        program_decode.decodeProgramWord(canonical),
    );

    var empty_guest = try freezeRows(std.testing.allocator, &.{});
    defer empty_guest.deinit();
    const malformed_words = [_]memory_state.WordState{declaredWord(0x1000, reserved_rd)};
    try std.testing.expectError(
        error.InvalidPrecompileEncoding,
        subject.buildDeclared(
            std.testing.allocator,
            &.{},
            &empty_guest,
            &malformed_words,
            null,
        ),
    );

    const custom_fetches = [_]struct { pc: u32, inst_word: u32 }{
        .{ .pc = 0x1000, .inst_word = canonical },
    };
    const custom_words = [_]memory_state.WordState{declaredWord(0x1000, canonical)};
    try std.testing.expectError(
        error.InvalidInstruction,
        base_commitment.buildDeclared(
            std.testing.allocator,
            &custom_fetches,
            &custom_words,
            null,
        ),
    );
}

test "guest program commitment rejects changed and undeclared fetches from every stream" {
    const declared_custom = custom0.encodePoseidon2(5);
    const changed_custom = custom0.encodePoseidon2(6);
    const words = [_]memory_state.WordState{declaredWord(0x1000, declared_custom)};

    var changed = try freezeRows(std.testing.allocator, &.{
        guestRow(1, 0x1000, changed_custom, 0),
    });
    defer changed.deinit();
    try std.testing.expectError(
        error.ProgramWordChanged,
        subject.buildDeclared(std.testing.allocator, &.{}, &changed, &words, null),
    );

    var missing = try freezeRows(std.testing.allocator, &.{
        guestRow(1, 0x1004, declared_custom, 0),
    });
    defer missing.deinit();
    try std.testing.expectError(
        error.FetchedProgramWordMissing,
        subject.buildDeclared(std.testing.allocator, &.{}, &missing, &words, null),
    );

    var empty = try freezeRows(std.testing.allocator, &.{});
    defer empty.deinit();
    try std.testing.expectError(
        error.FetchedProgramWordMissing,
        subject.buildDeclared(
            std.testing.allocator,
            &.{},
            &empty,
            &words,
            .{ .pc = 0x1004, .word = addi_x1_x0_1 },
        ),
    );
    try std.testing.expectError(
        error.ProgramWordChanged,
        subject.buildDeclared(
            std.testing.allocator,
            &.{},
            &empty,
            &words,
            .{ .pc = 0x1000, .word = changed_custom },
        ),
    );
}

test "ordinary base commitment and extension delegation are tree-exact" {
    const base_rows = [_]trace.TraceRow{
        baseRow(1, 0x1000, addi_x1_x0_1),
        baseRow(2, 0x1000, addi_x1_x0_1),
    };
    const words = [_]memory_state.WordState{
        declaredWord(0x1004, addi_x2_x0_2),
        declaredWord(0x1000, addi_x1_x0_1),
    };
    const completion = program_table.Fetch{ .pc = 0x1004, .word = addi_x2_x0_2 };
    const fetches = [_]program_table.Fetch{
        .{ .pc = 0x1000, .word = addi_x1_x0_1 },
        .{ .pc = 0x1000, .word = addi_x1_x0_1 },
        completion,
    };
    var empty_guest = try freezeRows(std.testing.allocator, &.{});
    defer empty_guest.deinit();

    // `build` is the independent fetch-table path that predates the dense
    // declared-word accumulator. All three routes must remain byte-exact.
    var legacy = try base_commitment.build(std.testing.allocator, &fetches, &words);
    defer legacy.deinit(std.testing.allocator);
    var base = try base_commitment.buildDeclared(
        std.testing.allocator,
        &base_rows,
        &words,
        completion,
    );
    defer base.deinit(std.testing.allocator);
    var extension = try subject.buildDeclared(
        std.testing.allocator,
        &base_rows,
        &empty_guest,
        &words,
        completion,
    );
    defer extension.deinit(std.testing.allocator);

    try expectCommitmentEqual(legacy, base);
    try expectCommitmentEqual(base, extension);
}

test "guest retirement volume does not allocate a concatenated fetch stream" {
    const custom = custom0.encodePoseidon2(5);
    const words = [_]memory_state.WordState{declaredWord(0x1000, custom)};
    var empty = try freezeRows(std.testing.allocator, &.{});
    defer empty.deinit();

    var repeated_rows: [1024]guest_runner.ExecutionRow = undefined;
    for (&repeated_rows, 0..) |*row, index| {
        row.* = guestRow(
            @intCast(index + 1),
            0x1000,
            custom,
            @intCast(index),
        );
    }
    var repeated = try freezeRows(std.testing.allocator, &repeated_rows);
    defer repeated.deinit();

    var empty_counter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var empty_commitment = try subject.buildDeclared(
        empty_counter.allocator(),
        &.{},
        &empty,
        &words,
        null,
    );
    empty_commitment.deinit(empty_counter.allocator());

    var repeated_counter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var repeated_commitment = try subject.buildDeclared(
        repeated_counter.allocator(),
        &.{},
        &repeated,
        &words,
        null,
    );
    repeated_commitment.deinit(repeated_counter.allocator());

    try std.testing.expectEqual(empty_counter.allocations, repeated_counter.allocations);
    try std.testing.expectEqual(empty_counter.allocated_bytes, repeated_counter.allocated_bytes);
    try std.testing.expectEqual(empty_counter.allocated_bytes, empty_counter.freed_bytes);
    try std.testing.expectEqual(repeated_counter.allocated_bytes, repeated_counter.freed_bytes);
}

fn exerciseAllocationFailures(
    allocator: std.mem.Allocator,
    base_rows: []const trace.TraceRow,
    guest_rows: *const subject.FrozenExecutionRows,
) !void {
    const custom = custom0.encodePoseidon2(5);
    const words = [_]memory_state.WordState{
        declaredWord(0x1000, addi_x1_x0_1),
        declaredWord(0x1004, custom),
        declaredWord(0x1008, addi_x2_x0_2),
    };
    var commitment = try subject.buildDeclared(
        allocator,
        base_rows,
        guest_rows,
        &words,
        .{ .pc = 0x1008, .word = addi_x2_x0_2 },
    );
    defer commitment.deinit(allocator);
}

test "guest program commitment releases every partial allocation" {
    const base_rows = [_]trace.TraceRow{
        baseRow(1, 0x1000, addi_x1_x0_1),
    };
    var guest_rows = try freezeRows(std.testing.allocator, &.{
        guestRow(2, 0x1004, custom0.encodePoseidon2(5), 0),
    });
    defer guest_rows.deinit();

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAllocationFailures,
        .{ base_rows[0..], &guest_rows },
    );
}

fn declaredWord(addr: u32, word: u32) memory_state.WordState {
    return .{
        .addr = addr,
        .initial_word = word,
        .final_word = word,
        .final_clock = 0,
    };
}

fn baseRow(clock: u32, pc: u32, word: u32) trace.TraceRow {
    // Program construction intentionally consumes only `pc` and `inst_word`.
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = .ADDI,
        .rd = 0,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 0,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = word,
    };
}

fn guestRow(
    execution_clock: u32,
    pc: u32,
    word: u32,
    call_index: u32,
) guest_runner.ExecutionRow {
    return .{
        .execution_clock = execution_clock,
        .pc = pc,
        .inst_word = word,
        .call_index = call_index,
    };
}

fn freezeRows(
    allocator: std.mem.Allocator,
    rows: []const guest_runner.ExecutionRow,
) !subject.FrozenExecutionRows {
    var storage: std.ArrayList(guest_runner.ExecutionRow) = .empty;
    errdefer storage.deinit(allocator);
    try storage.appendSlice(allocator, rows);
    return .{ .storage = storage, .allocator = allocator };
}

fn expectRow(
    actual: base_commitment.Row,
    addr: u32,
    values: program_decode.ProgramValues,
    multiplicity: u32,
) !void {
    try std.testing.expectEqual(addr, actual.addr);
    try std.testing.expectEqual(values, actual.values);
    try std.testing.expectEqual(multiplicity, actual.multiplicity);
}

fn expectCommitmentEqual(
    expected: base_commitment.Commitment,
    actual: base_commitment.Commitment,
) !void {
    try std.testing.expectEqualSlices(base_commitment.Row, expected.rows, actual.rows);
    try std.testing.expectEqual(expected.tree.root, actual.tree.root);
    try std.testing.expectEqualSlices(
        sparse_merkle.Leaf,
        expected.tree.leaves,
        actual.tree.leaves,
    );
    try std.testing.expectEqualSlices(
        sparse_merkle.Node,
        expected.tree.nodes,
        actual.tree.nodes,
    );
}
