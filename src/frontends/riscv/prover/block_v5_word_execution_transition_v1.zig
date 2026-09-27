//! Explicit packed-word transition projection from the same authenticated
//! native opcode/precompile pair and byte witness. Existing9 columns and
//! exact event count remain; no independent packed witness is introduced.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const bus = @import("block_memory_relation_v2.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const framework = @import("../recursion/air/framework_interaction.zig");

const old = @import("block_execution_transition_interaction_v2.zig");
pub const COLUMN_COUNT = old.COLUMN_COUNT;
pub const Row = old.Row;
pub const Point = old.Point;

pub fn constraints(challenges: *const protocol.Challenges, point: Point, claimed_sum: Q, claimed_count: u64, trace_size: u32) ![3]Q {
    if (trace_size == 0) return error.InvalidExecutionTransitionDomain;
    if (claimed_count > trace_size) return error.InvalidExecutionEventCount;
    const raw = challenges.transition.combineSecure(protocol.fromByteTransition(Q, point.tuple));
    const shift = try claimed_sum.divM31(M.fromCanonical(trace_size));
    const count_shift = try Q.fromBase(M.fromU64(claimed_count)).divM31(M.fromCanonical(trace_size));
    return @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).transitionConstraints(point.active, raw, point.term, point.prefix, point.previous_prefix, point.count_prefix, point.previous_count_prefix, shift, count_shift);
}

pub const Result = old.Result;

pub fn generate(a: std.mem.Allocator, challenges: *const protocol.Challenges, rows: []const Row, log_size: u32) !Result {
    if (log_size == 0 or log_size > 30 or rows.len != @as(usize, 1) << @intCast(log_size))
        return error.InvalidExecutionTransitionDomain;
    const size = rows.len;
    const storage = try a.alloc(M, size * COLUMN_COUNT);
    errdefer a.free(storage);
    var columns: [COLUMN_COUNT][]M = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
    var total = Q.zero();
    var count: u64 = 0;
    for (rows, 0..) |row, logical| {
        const term = if (row.active) blk: {
            _ = try bus.decodeTransitionTuple(row.tuple);
            break :blk try challenges.transition.combineBase(protocol.fromByteTransition(M, row.tuple)).inv();
        } else Q.zero();
        total = total.add(term);
        count += @intFromBool(row.active);
        write(&columns, 0, framework.committedRow(logical, log_size), term);
    }
    const shift = try total.divM31(M.fromU64(size));
    var prefix = Q.zero();
    var count_prefix = M.zero();
    const count_shift = try M.fromU64(count).div(M.fromU64(size));
    for (0..size) |logical| {
        const physical = framework.committedRow(logical, log_size);
        prefix = prefix.add(read(&columns, 0, physical)).sub(shift);
        write(&columns, 1, physical, prefix);
        count_prefix = count_prefix.add(if (rows[logical].active) M.one() else M.zero()).sub(count_shift);
        columns[8][physical] = count_prefix;
    }
    if (!prefix.isZero()) return error.InvalidExecutionTransitionPrefix;
    if (!count_prefix.isZero()) return error.InvalidExecutionCountPrefix;
    return .{ .columns = columns, .storage = storage, .claim = total, .count = count };
}

fn write(columns: *[COLUMN_COUNT][]M, secure_index: usize, row: usize, value: Q) void {
    const limbs = value.toM31Array();
    for (limbs, 0..) |limb, index| columns[secure_index * 4 + index][row] = limb;
}
pub fn read(columns: *const [COLUMN_COUNT][]M, secure_index: usize, row: usize) Q {
    return Q.fromM31Array(.{
        columns[secure_index * 4][row],     columns[secure_index * 4 + 1][row],
        columns[secure_index * 4 + 2][row], columns[secure_index * 4 + 3][row],
    });
}
