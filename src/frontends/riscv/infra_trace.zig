//! Infrastructure trace generation for the RISC-V STARK.
//!
//! Provides column generators for infrastructure (non-opcode) components:
//! Program ROM, Memory check, Clock updates (mem + reg), Merkle tree,
//! Poseidon2 permutation, and preprocessed multiplicity tables.
//!
//! Each generator produces padded, bit-reversed column arrays suitable
//! for commitment via the stwo STARK backend.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const poseidon2 = @import("common/poseidon2.zig");
const trace_mod = @import("runner/trace.zig");
const state_chain = @import("runner/state_chain.zig");
const clock_update = @import("infra_trace/clock_update.zig");
const hash = @import("infra_trace/hash.zig");
const multiplicity = @import("infra_trace/multiplicity.zig");
const permutation = @import("infra_trace/permutation.zig");
const program_memory = @import("infra_trace/program_memory.zig");

const M31 = m31.M31;
const StateChainTracker = state_chain.StateChainTracker;

pub const PROGRAM_TRACE_COLS = program_memory.PROGRAM_TRACE_COLS;
pub const MEMORY_TRACE_COLS = program_memory.MEMORY_TRACE_COLS;
pub const MEM_CLOCK_UPDATE_COLS = clock_update.MEM_CLOCK_UPDATE_COLS;
pub const REG_CLOCK_UPDATE_COLS = clock_update.REG_CLOCK_UPDATE_COLS;
pub const CLOCK_UPDATE_COLS = clock_update.CLOCK_UPDATE_COLS;
pub const POSEIDON2_TRACE_COLS = hash.POSEIDON2_TRACE_COLS;
pub const MERKLE_TRACE_COLS = hash.MERKLE_TRACE_COLS;
pub const N_MULTIPLICITY_TABLES = multiplicity.N_MULTIPLICITY_TABLES;

pub const BitReversalTable = permutation.BitReversalTable;
pub const MemoryColumnsResult = program_memory.MemoryColumnsResult;
pub const genProgramColumns = program_memory.genProgramColumns;
pub const freeProgramColumns = program_memory.freeProgramColumns;
pub const genMemoryColumns = program_memory.genMemoryColumns;
pub const genMemoryColumnsRange = program_memory.genMemoryColumnsRange;
pub const freeMemoryColumns = program_memory.freeMemoryColumns;
pub const genMemClockUpdateColumns = clock_update.genMemClockUpdateColumns;
pub const freeMemClockUpdateColumns = clock_update.freeMemClockUpdateColumns;
pub const genRegClockUpdateColumns = clock_update.genRegClockUpdateColumns;
pub const freeRegClockUpdateColumns = clock_update.freeRegClockUpdateColumns;
pub const genClockUpdateColumns = clock_update.genClockUpdateColumns;
pub const freeClockUpdateColumns = clock_update.freeClockUpdateColumns;
pub const genPreprocessedMultiplicityColumns = multiplicity.genPreprocessedMultiplicityColumns;
pub const freeMultiplicityColumns = multiplicity.freeMultiplicityColumns;
pub const multiplicityLogSize = multiplicity.multiplicityLogSize;
pub const genPoseidon2Columns = hash.genPoseidon2Columns;
pub const freePoseidon2Columns = hash.freePoseidon2Columns;
pub const genMerkleColumns = hash.genMerkleColumns;
pub const freeMerkleColumns = hash.freeMerkleColumns;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "infra_trace: genPoseidon2Columns basic" {
    const allocator = std.testing.allocator;

    // Create two traced permutations
    var state1: poseidon2.State = [_]M31{M31.zero()} ** poseidon2.STATE_WIDTH;
    state1[0] = M31.fromCanonical(1);
    const trace1 = poseidon2.permuteTraced(&state1);

    var state2: poseidon2.State = [_]M31{M31.zero()} ** poseidon2.STATE_WIDTH;
    state2[0] = M31.fromCanonical(2);
    const trace2 = poseidon2.permuteTraced(&state2);

    const traces = [_]poseidon2.PermuteTrace{ trace1, trace2 };
    const log_size: u32 = 2; // domain_size = 4

    var result = try genPoseidon2Columns(allocator, &traces, log_size);
    defer freePoseidon2Columns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 2), result.n_real_rows);

    // Enabler column (col 0): exactly 2 rows should be M31.one()
    var ones_count: usize = 0;
    for (result.columns[0]) |v| {
        if (v.eql(M31.one())) ones_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), ones_count);
}

test "infra_trace: genPoseidon2Columns empty traces" {
    const allocator = std.testing.allocator;
    const traces = [_]poseidon2.PermuteTrace{};
    const log_size: u32 = 1; // domain_size = 2

    var result = try genPoseidon2Columns(allocator, &traces, log_size);
    defer freePoseidon2Columns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 0), result.n_real_rows);

    // All values should be zero
    for (result.columns[0]) |v| {
        try std.testing.expect(v.isZero());
    }
}

test "infra_trace: genMerkleColumns basic" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 3; // domain_size = 8
    const n_nodes: usize = 5;

    var result = try genMerkleColumns(allocator, n_nodes, log_size);
    defer freeMerkleColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 5), result.n_real_rows);

    // Enabler column: exactly 5 rows should be M31.one()
    var ones_count: usize = 0;
    for (result.columns[0]) |v| {
        if (v.eql(M31.one())) ones_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), ones_count);
}

test "infra_trace: genMerkleColumns empty" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 2; // domain_size = 4
    const n_nodes: usize = 0;

    var result = try genMerkleColumns(allocator, n_nodes, log_size);
    defer freeMerkleColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 0), result.n_real_rows);

    // All values should be zero
    for (0..MERKLE_TRACE_COLS) |col| {
        for (result.columns[col]) |v| {
            try std.testing.expect(v.isZero());
        }
    }
}

test "infra_trace: genMerkleColumns clamps to domain_size" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 2; // domain_size = 4
    const n_nodes: usize = 100; // more than domain_size

    var result = try genMerkleColumns(allocator, n_nodes, log_size);
    defer freeMerkleColumns(allocator, &result.columns);

    // n_real_rows reports the requested count, not the clamped count
    try std.testing.expectEqual(@as(usize, 100), result.n_real_rows);

    // But only 4 rows should actually have enabler=1
    var ones_count: usize = 0;
    for (result.columns[0]) |v| {
        if (v.eql(M31.one())) ones_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), ones_count);
}

test "infra_trace: genProgramColumns basic" {
    const allocator = std.testing.allocator;
    var exec_trace = trace_mod.Trace.init(allocator);
    defer exec_trace.deinit();

    try exec_trace.append(.{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x00100093,
    });
    try exec_trace.append(.{
        .clk = 2,
        .pc = 0x1004,
        .opcode = .ADD,
        .rd = 2,
        .rs1 = 1,
        .rs2 = 0,
        .imm = 0,
        .rs1_val = 1,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1008,
        .inst_word = 0x00008133,
    });

    var result = try genProgramColumns(allocator, &exec_trace, 4);
    defer freeProgramColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, PROGRAM_TRACE_COLS), result.columns.len);
    try std.testing.expectEqual(@as(usize, 2), result.n_real_rows);
    try std.testing.expectEqual(@as(usize, 16), result.columns[0].len);
}

test "infra_trace: genPreprocessedMultiplicityColumns basic" {
    const allocator = std.testing.allocator;
    var exec_trace = trace_mod.Trace.init(allocator);
    defer exec_trace.deinit();

    for (0..32) |i| {
        try exec_trace.append(.{
            .clk = @intCast(i + 1),
            .pc = @intCast(0x1000 + i * 4),
            .opcode = .ADDI,
            .rd = 1,
            .rs1 = 0,
            .rs2 = 0,
            .imm = 1,
            .rs1_val = 0,
            .rs2_val = 0,
            .rd_val = 1,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1004 + i * 4),
        });
    }

    var result = try genPreprocessedMultiplicityColumns(allocator, &exec_trace);
    defer freeMultiplicityColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, N_MULTIPLICITY_TABLES), result.columns.len);
    try std.testing.expectEqual(@as(u32, 5), result.log_size); // log2(32) = 5
}

// ---------------------------------------------------------------------------
// Program ROM tests
// ---------------------------------------------------------------------------

/// Helper: build a small execution trace for testing infrastructure columns.
fn makeSmallExecTrace(allocator: std.mem.Allocator) !trace_mod.Trace {
    var t = trace_mod.Trace.init(allocator);
    errdefer t.deinit();
    // Row 0: pc=0x100
    try t.append(.{
        .clk = 1,
        .pc = 0x100,
        .opcode = .ADD,
        .rd = 1,
        .rs1 = 2,
        .rs2 = 3,
        .imm = 0,
        .rs1_val = 10,
        .rs2_val = 20,
        .rd_val = 30,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x104,
        .inst_word = 0x003100b3,
    });
    // Row 1: pc=0x104
    try t.append(.{
        .clk = 2,
        .pc = 0x104,
        .opcode = .SUB,
        .rd = 4,
        .rs1 = 1,
        .rs2 = 5,
        .imm = 0,
        .rs1_val = 30,
        .rs2_val = 5,
        .rd_val = 25,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x108,
        .inst_word = 0x40508233,
    });
    // Row 2: repeat pc=0x100 (multiplicity test)
    try t.append(.{
        .clk = 3,
        .pc = 0x100,
        .opcode = .ADD,
        .rd = 1,
        .rs1 = 2,
        .rs2 = 3,
        .imm = 0,
        .rs1_val = 10,
        .rs2_val = 20,
        .rd_val = 30,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x104,
        .inst_word = 0x003100b3,
    });
    return t;
}

test "infra_trace: genProgramColumns row count with duplicates" {
    const allocator = std.testing.allocator;
    var exec_trace = try makeSmallExecTrace(allocator);
    defer exec_trace.deinit();

    const log_size: u32 = 2; // domain_size = 4
    var result = try genProgramColumns(allocator, &exec_trace, log_size);
    defer freeProgramColumns(allocator, &result.columns);

    // 3 rows but only 2 unique PCs (0x100 appears twice).
    try std.testing.expectEqual(@as(usize, 2), result.n_real_rows);
}

test "infra_trace: genProgramColumns enabler count and multiplicity sum" {
    const allocator = std.testing.allocator;
    var exec_trace = try makeSmallExecTrace(allocator);
    defer exec_trace.deinit();

    const log_size: u32 = 2;
    var result = try genProgramColumns(allocator, &exec_trace, log_size);
    defer freeProgramColumns(allocator, &result.columns);

    const domain_size: usize = 1 << log_size;
    var enabler_count: usize = 0;
    var mult_sum: u64 = 0;
    for (0..domain_size) |i| {
        if (result.columns[0][i].eql(M31.one())) {
            enabler_count += 1;
            mult_sum += result.columns[6][i].v;
        }
    }
    // Exactly 2 unique PCs => 2 enablers.
    try std.testing.expectEqual(@as(usize, 2), enabler_count);
    // Total multiplicity = 3 (pc 0x100 x2 + pc 0x104 x1).
    try std.testing.expectEqual(@as(u64, 3), mult_sum);
}

test "infra_trace: genProgramColumns all columns have domain_size length" {
    const allocator = std.testing.allocator;
    var exec_trace = try makeSmallExecTrace(allocator);
    defer exec_trace.deinit();

    const log_size: u32 = 3; // domain_size = 8
    const domain_size: usize = 1 << log_size;
    var result = try genProgramColumns(allocator, &exec_trace, log_size);
    defer freeProgramColumns(allocator, &result.columns);

    for (result.columns) |col| {
        try std.testing.expectEqual(domain_size, col.len);
    }
}

test "infra_trace: genProgramColumns empty trace" {
    const allocator = std.testing.allocator;
    var exec_trace = trace_mod.Trace.init(allocator);
    defer exec_trace.deinit();

    const log_size: u32 = 2;
    var result = try genProgramColumns(allocator, &exec_trace, log_size);
    defer freeProgramColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 0), result.n_real_rows);
    // All enabler values should be zero.
    const domain_size: usize = 1 << log_size;
    for (0..domain_size) |i| {
        try std.testing.expect(result.columns[0][i].isZero());
    }
}

// ---------------------------------------------------------------------------
// Memory column tests
// ---------------------------------------------------------------------------

/// Helper: build a StateChainTracker with register + memory accesses.
fn makeSmallChain(allocator: std.mem.Allocator) !StateChainTracker {
    var chain = StateChainTracker.init(allocator);
    errdefer chain.deinit();
    try chain.recordRegAccess(1, 0, 42);
    try chain.recordRegAccess(2, 2, 100);
    try chain.recordMemAccess(0x1000, 4, 0xDEADBEEF);
    try chain.recordMemAccess(0x2000, 6, 0xCAFEBABE);
    try chain.recordMemAccess(0x1000, 8, 0x12345678);
    return chain;
}

test "infra_trace: genMemoryColumns row count" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 3; // domain_size = 8
    var result = try genMemoryColumns(allocator, &chain, log_size);
    defer freeMemoryColumns(allocator, &result.columns);

    // Unified memory (stark-v): one row per access — 2 register + 3 memory.
    try std.testing.expectEqual(@as(usize, 5), result.n_real_rows);
}

test "infra_trace: genMemoryColumns value decomposition" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 2;
    var result = try genMemoryColumns(allocator, &chain, log_size);
    defer freeMemoryColumns(allocator, &result.columns);

    // Find the row for addr=0x1000, clk=4 (value=0xDEADBEEF).
    const domain_size: usize = 1 << log_size;
    var found = false;
    for (0..domain_size) |i| {
        if (result.columns[1][i].eql(M31.fromCanonical(0x1000)) and
            result.columns[2][i].eql(M31.fromCanonical(4)))
        {
            // 0xDEADBEEF => limbs: 0xEF, 0xBE, 0xAD, 0xDE
            try std.testing.expectEqual(@as(u32, 0xEF), result.columns[3][i].v);
            try std.testing.expectEqual(@as(u32, 0xBE), result.columns[4][i].v);
            try std.testing.expectEqual(@as(u32, 0xAD), result.columns[5][i].v);
            try std.testing.expectEqual(@as(u32, 0xDE), result.columns[6][i].v);
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "infra_trace: genMemoryColumns all columns have domain_size length" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 3;
    const domain_size: usize = 1 << log_size;
    var result = try genMemoryColumns(allocator, &chain, log_size);
    defer freeMemoryColumns(allocator, &result.columns);

    for (result.columns) |col| {
        try std.testing.expectEqual(domain_size, col.len);
    }
}

test "infra_trace: genMemoryColumns includes register accesses" {
    const allocator = std.testing.allocator;
    var chain = StateChainTracker.init(allocator);
    defer chain.deinit();

    // Register accesses are address space 0 of the unified memory argument.
    try chain.recordRegAccess(1, 0, 42);
    try chain.recordRegAccess(2, 2, 100);

    const log_size: u32 = 2;
    var result = try genMemoryColumns(allocator, &chain, log_size);
    defer freeMemoryColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 2), result.n_real_rows);
}

// ---------------------------------------------------------------------------
// Memory clock update tests
// ---------------------------------------------------------------------------

test "infra_trace: genMemClockUpdateColumns empty when no gaps" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 2;
    var result = try genMemClockUpdateColumns(allocator, &chain, log_size);
    defer freeMemClockUpdateColumns(allocator, &result.columns);

    // No clock gaps in makeSmallChain (all clocks are small/close).
    try std.testing.expectEqual(@as(usize, 0), result.n_real_rows);
}

test "infra_trace: genMemClockUpdateColumns with gap filling" {
    const allocator = std.testing.allocator;
    var chain = StateChainTracker.init(allocator);
    defer chain.deinit();

    // Create a large clock gap (> MAX_CLOCK_DIFF) to trigger gap-filling.
    try chain.recordMemAccess(0x3000, 0, 0xFF);
    try chain.recordMemAccess(0x3000, 2_000_000, 0xAB);

    // Gap-filling should produce records.
    try std.testing.expect(chain.clock_updates_mem.items.len > 0);

    const log_size: u32 = 2;
    var result = try genMemClockUpdateColumns(allocator, &chain, log_size);
    defer freeMemClockUpdateColumns(allocator, &result.columns);

    try std.testing.expect(result.n_real_rows > 0);

    // Every filled row should have enabler = 1.
    const domain_size: usize = 1 << log_size;
    var enabler_count: usize = 0;
    for (0..domain_size) |i| {
        if (result.columns[0][i].eql(M31.one())) enabler_count += 1;
    }
    // n_real_rows may be clamped to domain_size.
    try std.testing.expectEqual(@min(result.n_real_rows, domain_size), enabler_count);
}

test "infra_trace: genMemClockUpdateColumns all columns have domain_size length" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 3;
    const domain_size: usize = 1 << log_size;
    var result = try genMemClockUpdateColumns(allocator, &chain, log_size);
    defer freeMemClockUpdateColumns(allocator, &result.columns);

    for (result.columns) |col| {
        try std.testing.expectEqual(domain_size, col.len);
    }
}

// ---------------------------------------------------------------------------
// Register clock update tests
// ---------------------------------------------------------------------------

test "infra_trace: genRegClockUpdateColumns empty when no gaps" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 2;
    var result = try genRegClockUpdateColumns(allocator, &chain, log_size);
    defer freeRegClockUpdateColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 0), result.n_real_rows);
}

test "infra_trace: genRegClockUpdateColumns with gap filling" {
    const allocator = std.testing.allocator;
    var chain = StateChainTracker.init(allocator);
    defer chain.deinit();

    // Large register clock gap.
    try chain.recordRegAccess(5, 0, 99);
    try chain.recordRegAccess(5, 2_000_000, 100);

    try std.testing.expect(chain.clock_updates_reg.items.len > 0);

    const log_size: u32 = 2;
    var result = try genRegClockUpdateColumns(allocator, &chain, log_size);
    defer freeRegClockUpdateColumns(allocator, &result.columns);

    try std.testing.expect(result.n_real_rows > 0);
}

test "infra_trace: genRegClockUpdateColumns all columns have domain_size length" {
    const allocator = std.testing.allocator;
    var chain = try makeSmallChain(allocator);
    defer chain.deinit();

    const log_size: u32 = 3;
    const domain_size: usize = 1 << log_size;
    var result = try genRegClockUpdateColumns(allocator, &chain, log_size);
    defer freeRegClockUpdateColumns(allocator, &result.columns);

    for (result.columns) |col| {
        try std.testing.expectEqual(domain_size, col.len);
    }
}

test "infra_trace: unified clock updates preserve address spaces" {
    const allocator = std.testing.allocator;
    var chain = StateChainTracker.init(allocator);
    defer chain.deinit();

    try chain.recordRegAccess(5, 2_000_000, 0x01020304);
    try chain.recordMemAccess(0x3000, 2_000_000, 0xA0B0C0D0);

    var result = try genClockUpdateColumns(allocator, &chain, 2);
    defer freeClockUpdateColumns(allocator, &result.columns);

    try std.testing.expectEqual(@as(usize, 2), result.n_real_rows);
    var register_rows: usize = 0;
    var memory_rows: usize = 0;
    for (result.columns[0], result.columns[1]) |enabled, addr_space| {
        if (!enabled.eql(M31.one())) continue;
        if (addr_space.eql(M31.zero())) register_rows += 1;
        if (addr_space.eql(M31.one())) memory_rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), register_rows);
    try std.testing.expectEqual(@as(usize, 1), memory_rows);
}

// ---------------------------------------------------------------------------
// Preprocessed multiplicity additional tests
// ---------------------------------------------------------------------------

test "infra_trace: genPreprocessedMultiplicityColumns empty trace" {
    const allocator = std.testing.allocator;
    var exec_trace = trace_mod.Trace.init(allocator);
    defer exec_trace.deinit();

    var result = try genPreprocessedMultiplicityColumns(allocator, &exec_trace);
    defer freeMultiplicityColumns(allocator, &result.columns);

    // step_count=0 => @max(0,16) = 16 => log_size=4 => domain_size=16
    try std.testing.expectEqual(@as(u32, 4), result.log_size);
    try std.testing.expectEqual(@as(usize, 16), result.columns[0].len);

    // All should be zero (placeholder).
    for (result.columns[0]) |v| try std.testing.expect(v.isZero());
}

test "infra_trace: genPreprocessedMultiplicityColumns all tables same size" {
    const allocator = std.testing.allocator;
    var exec_trace = try makeSmallExecTrace(allocator);
    defer exec_trace.deinit();

    var result = try genPreprocessedMultiplicityColumns(allocator, &exec_trace);
    defer freeMultiplicityColumns(allocator, &result.columns);

    const expected_size = result.columns[0].len;
    for (result.columns) |col| {
        try std.testing.expectEqual(expected_size, col.len);
    }
}

test "infra_trace: multiplicityLogSize consistency" {
    const allocator = std.testing.allocator;
    var exec_trace = try makeSmallExecTrace(allocator);
    defer exec_trace.deinit();
    var result = try genPreprocessedMultiplicityColumns(allocator, &exec_trace);
    defer freeMultiplicityColumns(allocator, &result.columns);
    try std.testing.expectEqual(result.log_size, multiplicityLogSize(&exec_trace));
}
