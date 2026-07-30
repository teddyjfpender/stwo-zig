//! Exact relation-entry sequences for all proof-bearing RV32IM families.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constraint_program = @import("../constraint_program.zig");
const entry = @import("entry.zig");
const trace = @import("../../runner/trace.zig");

pub const List = entry.List;

pub fn entryCount(family: trace.OpcodeFamily) usize {
    return constraint_program.entryCount(family);
}

pub fn batchSize(family: trace.OpcodeFamily) usize {
    return constraint_program.batchSize(family);
}

pub fn batchCount(family: trace.OpcodeFamily) usize {
    return (entryCount(family) + batchSize(family) - 1) / batchSize(family);
}

pub fn interactionColumnCount(family: trace.OpcodeFamily) usize {
    return batchCount(family) * 4;
}

/// Reconstruct the exact committed family row from a runner row. This is used
/// only by witness generation; AIR evaluation calls `fromMain` directly.
pub fn fromTraceRow(row: trace.TraceRow, family: trace.OpcodeFamily) !List {
    var values: [trace.MAX_FAMILY_COLUMNS]M31 = .{M31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var columns: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (0..trace.MAX_FAMILY_COLUMNS) |index| columns[index] = values[index .. index + 1];
    trace.fillFamilyColumns(&columns, 0, row, family);
    const count = trace.nColumnsForFamily(family);
    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (values[0..count], secure[0..count]) |value, *dst| dst.* = QM31.fromBase(value);
    return fromMain(family, secure[0..count]);
}

pub fn Entries(comptime S: type) type {
    return struct {
        const program = constraint_program.Builder(S);
        const e = entry.Builder(S);

        pub fn fromMain(
            family: trace.OpcodeFamily,
            columns: []const S,
        ) !e.List {
            return (try program.buildLookups(family, columns)).lookup_entries;
        }
    };
}

const shipped = Entries(QM31);

pub const fromMain = shipped.fromMain;

test "opcode lookup matrix preserves reviewed family geometry" {
    const expected_entries = [_]usize{ 18, 16, 20, 16, 14, 11, 9, 11, 7, 12, 18, 8, 16, 16, 22, 25, 3 };
    const expected_batches = [_]usize{ 9, 8, 10, 8, 7, 6, 5, 6, 4, 6, 9, 4, 8, 16, 22, 25, 2 };
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        try std.testing.expectEqual(expected_entries[index], entryCount(family));
        try std.testing.expectEqual(expected_batches[index], batchCount(family));
    }
}

test "opcode lookup vectors preserve exact domain order and batching" {
    const D = entry.Domain;
    const expected = [_][]const D{
        // base_alu_reg
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .bitwise, .bitwise, .bitwise, .bitwise, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20 },
        // base_alu_imm
        &.{ .program_access, .range_check_8_11, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .bitwise, .bitwise, .bitwise, .bitwise, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20 },
        // shifts_reg
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20, .range_check_m31 },
        // shifts_imm
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20, .range_check_m31 },
        // lt_reg
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_20, .memory_access, .memory_access, .range_check_20 },
        // lt_imm
        &.{ .program_access, .range_check_8_8_4, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .range_check_20, .memory_access, .memory_access, .range_check_20 },
        // branch_eq
        &.{ .program_access, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .registers_state, .registers_state },
        // branch_lt
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_20 },
        // lui
        &.{ .program_access, .registers_state, .registers_state, .range_check_8_8_4, .memory_access, .memory_access, .range_check_20 },
        // auipc
        &.{ .program_access, .registers_state, .registers_state, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_m31, .range_check_8_8, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // jalr
        &.{ .program_access, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_m31, .range_check_8_8_4, .registers_state, .registers_state, .range_check_8_8, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // jal
        &.{ .program_access, .registers_state, .registers_state, .range_check_8_8, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // load_store
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .range_check_20, .range_check_m31, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_m31, .range_check_m31 },
        // mul
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .memory_access, .memory_access, .range_check_20 },
        // mulh
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_m31, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // div
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_m31, .range_check_8_8, .range_check_20, .memory_access, .memory_access, .range_check_20 },
        // fence
        &.{ .program_access, .registers_state, .registers_state },
    };

    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const list = try fromMain(family, columns[0..trace.nColumnsForFamily(family)]);
        try std.testing.expectEqual(expected[index].len, list.len);
        for (expected[index], list.entries[0..list.len]) |want, actual| {
            try std.testing.expectEqual(want, actual.domain);
        }
        try std.testing.expectEqual(batchSize(family), list.batch_size);
        try std.testing.expectEqual(batchCount(family), list.batchCount());
        for (0..list.batchCount()) |batch| {
            const first = batch * list.batch_size;
            const entries_in_batch = @min(list.batch_size, list.len - first);
            try std.testing.expect(entries_in_batch == 1 or entries_in_batch == 2);
            if (family == .mul or family == .mulh or family == .div) {
                try std.testing.expectEqual(@as(usize, 1), entries_in_batch);
            }
        }
    }
}
