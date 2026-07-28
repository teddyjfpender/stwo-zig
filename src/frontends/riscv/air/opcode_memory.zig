//! Opcode-side `memory_access` LogUp columns and constraints.
//!
//! Every Stark-V RV32IM family has at most three register/RW-memory accesses
//! per row. Fixed slots keep the proof shape independent of opcode counts;
//! unused slots are zero recurrences with zero claims. The verifier rebuilds
//! every tuple from the committed family columns through `accessFromMain`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const memory_logup = @import("memory_logup.zig");
const relation_challenges = @import("relation_challenges.zig");
const trace_mod = @import("../runner/trace.zig");
const access_clock = @import("../access_clock.zig");

pub const N_ACCESSES: usize = 3;
pub const N_COLUMNS: usize = N_ACCESSES * 4;
pub const Previous = [N_ACCESSES][4][]M31;

pub const RegisterBoundary = struct {
    initial: [32]u32 = .{0} ** 32,
    final: [32]u32 = .{0} ** 32,
    last_clock: [32]u32 = .{0} ** 32,
};

pub const Generated = struct {
    columns: [N_COLUMNS][]M31,
    previous: Previous,
    claims: [N_ACCESSES]QM31,

    pub fn deinit(self: *Generated, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        for (&self.previous) |*set| freeColumns(allocator, set);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    rows: []const trace_mod.TraceRow,
    family: trace_mod.OpcodeFamily,
    log_size: u32,
    relation: *const relation_challenges.RelationElements(7),
) !Generated {
    var result: Generated = undefined;
    var initialized: usize = 0;
    errdefer {
        freeColumns(allocator, result.columns[0 .. initialized * 4]);
        for (result.previous[0..initialized]) |*set| freeColumns(allocator, set);
    }

    for (0..N_ACCESSES) |slot| {
        const has_access = slot < accessCount(family);
        var accesses: []memory_logup.AccessWitness = &.{};
        if (has_access) accesses = try allocator.alloc(memory_logup.AccessWitness, rows.len);
        defer if (has_access) allocator.free(accesses);
        if (has_access) {
            for (rows, accesses) |row, *access| access.* = accessFromTrace(row, family, slot);
        }

        const generated = try memory_logup.generate(allocator, accesses, log_size, relation);
        for (generated.columns, 0..) |column, coordinate| {
            result.columns[slot * 4 + coordinate] = column;
        }
        result.previous[slot] = generated.previous_columns;
        result.claims[slot] = generated.claimed;
        initialized += 1;
    }
    return result;
}

/// Reconstruct one access from the committed main row. This is the sole
/// verifier-side family layout map for the memory-access relation.
pub fn accessFromMain(
    family: trace_mod.OpcodeFamily,
    main: []const QM31,
    slot: usize,
    is_active: QM31,
) !memory_logup.AccessWitness {
    if (main.len < trace_mod.nColumnsForFamily(family)) return error.InvalidOracleTraceShape;
    if (slot >= accessCount(family)) return disabledAccess();
    const instruction_clock = main[clockColumn(family)];

    if (family == .load_store) {
        const is_load = main[42].add(main[43]).add(main[44]).add(main[45]).add(main[46]);
        const is_store = main[47].add(main[48]).add(main[49]);
        const first = derivedClock(instruction_clock, .first);
        const second = derivedClock(instruction_clock, .second);
        return switch (slot) {
            0 => fromMainAccess(
                main,
                2,
                is_store,
                main[37],
                second.add(is_store),
                is_active,
            ),
            1 => fromMainAccess(main, 12, QM31.zero(), main[12], first, is_active),
            2 => fromMainAccess(
                main,
                22,
                is_load,
                main[36],
                second.add(is_load),
                is_active,
            ),
            else => unreachable,
        };
    }

    return fromMainAccess(
        main,
        accessOffset(family, slot),
        QM31.zero(),
        main[accessOffset(family, slot)],
        derivedClock(instruction_clock, accessOrdinal(family, slot)),
        is_active,
    );
}

pub fn constraints(
    family: trace_mod.OpcodeFamily,
    main: []const QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_ACCESSES]QM31,
    previous: [N_ACCESSES]QM31,
    claims: [N_ACCESSES]QM31,
    relation: *const relation_challenges.RelationElements(7),
) ![N_ACCESSES]QM31 {
    var result: [N_ACCESSES]QM31 = undefined;
    for (&result, 0..) |*constraint, slot| {
        const access = try accessFromMain(family, main, slot, is_active);
        constraint.* = memory_logup.pairConstraint(
            sums[slot],
            previous[slot],
            is_first,
            claims[slot],
            memory_logup.rowPair(relation, access),
        );
    }
    return result;
}

/// Derive the register boundary used by the convenience trace-only proving
/// API while validating the exact source-before-destination access chain.
/// Production ELF proving supplies the runner's full initial/final state.
pub fn deriveRegisterBoundary(rows: []const trace_mod.TraceRow) !RegisterBoundary {
    var result = RegisterBoundary{};
    var seen = [_]bool{false} ** 32;
    for (rows) |row| {
        const family = trace_mod.opcodeFamily(row.opcode);
        switch (family) {
            .base_alu_reg, .shifts_reg, .lt_reg, .mul, .mulh, .div => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rs2Trace(row, .second));
                try observe(&result, &seen, rdTrace(row, .third));
            },
            .base_alu_imm, .shifts_imm, .lt_imm => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rdTrace(row, .second));
            },
            .branch_eq, .branch_lt => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rs2Trace(row, .second));
            },
            .lui, .auipc, .jal => try observe(&result, &seen, rdTrace(row, .first)),
            .jalr => {
                try observe(&result, &seen, rs1Trace(row, .first));
                try observe(&result, &seen, rdTrace(row, .second));
            },
            .load_store => {
                try observe(&result, &seen, rs1Trace(row, .first));
                if (row.is_load) {
                    try observe(&result, &seen, rdTrace(row, .second));
                } else {
                    try observe(&result, &seen, rs2Trace(row, .second));
                }
            },
            .fence => {},
        }
    }
    return result;
}

pub fn accessCount(family: trace_mod.OpcodeFamily) usize {
    return switch (family) {
        .base_alu_reg, .shifts_reg, .lt_reg, .load_store, .mul, .mulh, .div => 3,
        .base_alu_imm, .shifts_imm, .lt_imm, .branch_eq, .branch_lt, .jalr => 2,
        .lui, .auipc, .jal => 1,
        .fence => 0,
    };
}

pub fn clockColumn(family: trace_mod.OpcodeFamily) usize {
    return switch (family) {
        .lui, .auipc, .jalr, .jal, .mul, .fence => 1,
        else => 0,
    };
}

fn accessOffset(family: trace_mod.OpcodeFamily, slot: usize) usize {
    return switch (family) {
        .lui, .auipc, .jal => 3,
        .jalr, .mul => 3 + slot * 10,
        .fence => unreachable,
        else => 2 + slot * 10,
    };
}

fn accessFromTrace(
    row: trace_mod.TraceRow,
    family: trace_mod.OpcodeFamily,
    slot: usize,
) memory_logup.AccessWitness {
    if (family == .load_store) return switch (slot) {
        0 => if (row.is_store)
            memoryAccess(row, .third)
        else
            rdAccess(row, .second),
        1 => rs1Access(row, .first),
        2 => if (row.is_load)
            memoryAccess(row, .third)
        else
            rs2Access(row, .second),
        else => unreachable,
    };
    const ordinal = accessOrdinal(family, slot);
    return switch (accessKind(family, slot)) {
        .rd => rdAccess(row, ordinal),
        .rs1 => rs1Access(row, ordinal),
        .rs2 => rs2Access(row, ordinal),
    };
}

const AccessKind = enum { rd, rs1, rs2 };

const TraceAccess = struct {
    addr: u5,
    previous_clock: u32,
    previous: u32,
    clock: u32,
    next: u32,
};

fn accessKind(family: trace_mod.OpcodeFamily, slot: usize) AccessKind {
    return switch (family) {
        .branch_eq, .branch_lt => if (slot == 0) .rs1 else .rs2,
        .lui, .auipc, .jal => .rd,
        .jalr => if (slot == 0) .rd else .rs1,
        .fence => unreachable,
        else => @enumFromInt(slot),
    };
}

fn accessOrdinal(
    family: trace_mod.OpcodeFamily,
    slot: usize,
) access_clock.Ordinal {
    return switch (accessKind(family, slot)) {
        .rs1 => .first,
        .rs2 => .second,
        .rd => switch (family) {
            .base_alu_reg, .shifts_reg, .lt_reg, .mul, .mulh, .div => .third,
            .base_alu_imm, .shifts_imm, .lt_imm, .jalr => .second,
            .lui, .auipc, .jal => .first,
            .branch_eq, .branch_lt, .load_store, .fence => unreachable,
        },
    };
}

fn rdAccess(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        0,
        row.rd,
        row.rd_prev_clk,
        row.rd_prev_val,
        access_clock.encode(row.clk, ordinal),
        row.rd_val,
    );
}

fn rdTrace(row: trace_mod.TraceRow, ordinal: access_clock.Ordinal) TraceAccess {
    return .{
        .addr = row.rd,
        .previous_clock = row.rd_prev_clk,
        .previous = row.rd_prev_val,
        .clock = access_clock.encode(row.clk, ordinal),
        .next = row.rd_val,
    };
}

fn rs1Access(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        0,
        row.rs1,
        row.rs1_prev_clk,
        row.rs1_val,
        access_clock.encode(row.clk, ordinal),
        row.rs1_val,
    );
}

fn rs1Trace(row: trace_mod.TraceRow, ordinal: access_clock.Ordinal) TraceAccess {
    return .{
        .addr = row.rs1,
        .previous_clock = row.rs1_prev_clk,
        .previous = row.rs1_val,
        .clock = access_clock.encode(row.clk, ordinal),
        .next = row.rs1_val,
    };
}

fn rs2Access(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        0,
        row.rs2,
        row.rs2_prev_clk,
        row.rs2_val,
        access_clock.encode(row.clk, ordinal),
        row.rs2_val,
    );
}

fn rs2Trace(row: trace_mod.TraceRow, ordinal: access_clock.Ordinal) TraceAccess {
    return .{
        .addr = row.rs2,
        .previous_clock = row.rs2_prev_clk,
        .previous = row.rs2_val,
        .clock = access_clock.encode(row.clk, ordinal),
        .next = row.rs2_val,
    };
}

fn observe(boundary: *RegisterBoundary, seen: *[32]bool, access: TraceAccess) !void {
    const index = @as(usize, access.addr);
    if (!seen[index]) {
        if (access.previous_clock != 0) return error.InvalidRegisterAccessChain;
        boundary.initial[index] = access.previous;
        boundary.final[index] = access.previous;
        seen[index] = true;
    }
    if (boundary.last_clock[index] != access.previous_clock or
        boundary.final[index] != access.previous)
        return error.InvalidRegisterAccessChain;
    boundary.last_clock[index] = access.clock;
    boundary.final[index] = access.next;
}

fn memoryAccess(
    row: trace_mod.TraceRow,
    ordinal: access_clock.Ordinal,
) memory_logup.AccessWitness {
    return witness(
        1,
        row.mem_addr & ~@as(u32, 3),
        row.mem_prev_clk,
        row.mem_prev_word,
        access_clock.encode(row.clk, ordinal),
        row.mem_next_word,
    );
}

fn witness(
    addr_space: u1,
    addr: u32,
    previous_clock: u32,
    previous_value: u32,
    clock: u32,
    next_value: u32,
) memory_logup.AccessWitness {
    return .{
        .addr_space = base(addr_space),
        .addr = base(addr),
        .previous_clock = base(previous_clock),
        .previous = limbs(previous_value),
        .clock = base(clock),
        .next = limbs(next_value),
        .enabler = QM31.one(),
    };
}

fn fromMainAccess(
    main: []const QM31,
    offset: usize,
    addr_space: QM31,
    addr: QM31,
    clock: QM31,
    enabler: QM31,
) memory_logup.AccessWitness {
    return .{
        .addr_space = addr_space,
        .addr = addr,
        .previous_clock = main[offset + 5],
        .previous = .{ main[offset + 1], main[offset + 2], main[offset + 3], main[offset + 4] },
        .clock = clock,
        .next = .{ main[offset + 6], main[offset + 7], main[offset + 8], main[offset + 9] },
        .enabler = enabler,
    };
}

fn derivedClock(
    instruction_clock: QM31,
    ordinal: access_clock.Ordinal,
) QM31 {
    return instruction_clock.sub(QM31.one())
        .mul(base(access_clock.STRIDE))
        .add(base(@intFromEnum(ordinal) + 1));
}

fn disabledAccess() memory_logup.AccessWitness {
    return .{
        .addr_space = QM31.zero(),
        .addr = QM31.zero(),
        .previous_clock = QM31.zero(),
        .previous = .{QM31.zero()} ** 4,
        .clock = QM31.zero(),
        .next = .{QM31.zero()} ** 4,
        .enabler = QM31.zero(),
    };
}

fn limbs(value: u32) [4]QM31 {
    return .{
        base(@as(u8, @truncate(value))),
        base(@as(u8, @truncate(value >> 8))),
        base(@as(u8, @truncate(value >> 16))),
        base(@as(u8, @truncate(value >> 24))),
    };
}

fn base(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

test "opcode memory: committed load/store selectors choose address spaces" {
    var main = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
    main[0] = base(9);
    main[12] = base(3);
    main[22] = base(0x1000);
    main[36] = base(0x1000);
    main[37] = base(4);
    main[46] = QM31.one();

    const dst = try accessFromMain(.load_store, &main, 0, QM31.one());
    const source = try accessFromMain(.load_store, &main, 2, QM31.one());
    try std.testing.expect(dst.addr_space.isZero());
    try std.testing.expect(dst.addr.eql(base(4)));
    try std.testing.expect(source.addr_space.eql(QM31.one()));
    try std.testing.expect(source.addr.eql(base(0x1000)));
}

test "opcode memory: absent family slots are disabled" {
    var main = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
    const absent = try accessFromMain(.lui, &main, 1, QM31.one());
    try std.testing.expect(absent.enabler.isZero());
    try std.testing.expectEqual(@as(usize, 1), accessCount(.lui));
    try std.testing.expectEqual(@as(usize, 3), accessCount(.div));
}
