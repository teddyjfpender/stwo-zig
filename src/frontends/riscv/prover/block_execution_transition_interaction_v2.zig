//! Block-v2 execution-side transition LogUp. Each opcode access slot gets a
//! cyclic prefix over its native component domain; the typed main columns and
//! sidecar byte witness supply the tuple in the quotient adapter.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const bus = @import("block_memory_relation_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");

pub const COLUMN_COUNT: usize = 9;
pub const Row = struct { active: bool, tuple: bus.TransitionTuple };
pub const Point = struct {
    active: Q,
    tuple: [bus.TRANSITION_ARITY]Q,
    term: Q,
    prefix: Q,
    previous_prefix: Q,
    count_prefix: Q,
    previous_count_prefix: Q,
};

pub fn constraints(challenges: *const bus.Challenges, point: Point, claimed_sum: Q, claimed_count: u64, trace_size: u32) ![3]Q {
    if (trace_size == 0) return error.InvalidExecutionTransitionDomain;
    if (claimed_count > trace_size) return error.InvalidExecutionEventCount;
    const one = Q.one();
    const raw = challenges.transition.combineSecure(point.tuple);
    const denominator = point.active.mul(raw).add(one.sub(point.active));
    const shift = try claimed_sum.divM31(M.fromCanonical(trace_size));
    return .{
        denominator.mul(point.term).sub(point.active),
        point.prefix.sub(point.previous_prefix).add(shift).sub(point.term),
        point.count_prefix.sub(point.previous_count_prefix)
            .add(try Q.fromBase(M.fromU64(claimed_count)).divM31(M.fromCanonical(trace_size)))
            .sub(point.active),
    };
}

pub const Result = struct {
    columns: [COLUMN_COUNT][]M,
    storage: []M,
    claim: Q,
    count: u64,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};

pub fn generate(a: std.mem.Allocator, challenges: *const bus.Challenges, rows: []const Row, log_size: u32) !Result {
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
            break :blk try challenges.transition.combineBase(row.tuple).inv();
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
        columns[secure_index * 4][row], columns[secure_index * 4 + 1][row],
        columns[secure_index * 4 + 2][row], columns[secure_index * 4 + 3][row],
    });
}

test "block-v2 execution transition recurrence binds typed event sum" {
    const a = std.testing.allocator;
    const sealed = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(10), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(a, sealed);
    const tuple = bus.transitionTuple(.{ .space = 1, .address = 4096, .clock = 17, .before = 7, .after = 8 });
    var generated = try generate(a, &challenges, &.{ .{ .active = true, .tuple = tuple }, .{ .active = false, .tuple = @splat(M.zero()) } }, 1);
    defer generated.deinit(a);
    for (0..2) |logical| {
        const physical = framework.committedRow(logical, 1);
        const previous = framework.committedRow((logical + 1) % 2, 1);
        const row = Point{
            .active = if (logical == 0) Q.one() else Q.zero(),
            .tuple = if (logical == 0) baseTuple(tuple) else @splat(Q.zero()),
            .term = read(&generated.columns, 0, physical),
            .prefix = read(&generated.columns, 1, physical),
            .previous_prefix = read(&generated.columns, 1, previous),
            .count_prefix = Q.fromBase(generated.columns[8][physical]),
            .previous_count_prefix = Q.fromBase(generated.columns[8][previous]),
        };
        const residuals = try constraints(&challenges, row, generated.claim, generated.count, 2);
        for (residuals) |residual| try std.testing.expect(residual.isZero());
        try std.testing.expect(!(try constraints(&challenges, row, generated.claim, generated.count + 1, 2))[2].isZero());
    }
}

fn baseTuple(tuple: bus.TransitionTuple) [bus.TRANSITION_ARITY]Q {
    var result: [bus.TRANSITION_ARITY]Q = undefined;
    for (tuple, &result) |limb, *out| out.* = Q.fromBase(limb);
    return result;
}
