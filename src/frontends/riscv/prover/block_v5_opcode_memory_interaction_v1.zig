//! Opposite universal memory-access claim for an ordinary typed opcode slot.
//! The PCS adapter must evaluate `pointFromPair` on the same opened native
//! main columns used for the block transition and byte-range constraints.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const bridge = @import("block_execution_access_bridge_v2.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const framework = @import("../recursion/air/framework_interaction.zig");

pub const COLUMN_COUNT: usize = 12;
pub const CONSTRAINT_COUNT: usize = 3;
pub const Tuple = [7]M;
pub const Point = struct {
    active: Q,
    consumed: [7]Q,
    emitted: [7]Q,
    consume_term: Q,
    emit_term: Q,
    prefix: Q,
    previous_prefix: Q,
};
pub const Row = struct { active: bool, consumed: Tuple, emitted: Tuple };

/// Native opcode entries use `-active` for consume and `+active` for emit.
/// This component proves their exact opposite, including the *distinct*
/// consumed clock. Address unit remains the native entry's own unit here;
/// only the separate block transition bridge converts word indices to bytes.
pub fn pointFromPair(pair: bridge.Pair(Q)) !struct { active: Q, consumed: [7]Q, emitted: [7]Q } {
    const prior_clock = pair.consume_clock orelse return error.MissingNativeConsumeClock;
    return .{
        .active = pair.active,
        .consumed = .{ pair.space, pair.source_address, prior_clock } ++ pair.before,
        .emitted = .{ pair.space, pair.source_address, pair.local_clock } ++ pair.after,
    };
}

pub fn rowFromPair(pair: bridge.Pair(Q)) !Row {
    const decoded = try bridge.decodePair(pair);
    if (!decoded.active) return .{ .active = false, .consumed = @splat(M.zero()), .emitted = @splat(M.zero()) };
    const point = try pointFromPair(pair);
    var consumed: Tuple = undefined;
    var emitted: Tuple = undefined;
    for (point.consumed, &consumed) |value, *out| out.* = try base(value);
    for (point.emitted, &emitted) |value, *out| out.* = try base(value);
    return .{ .active = true, .consumed = consumed, .emitted = emitted };
}

pub fn constraints(elements: *const universal.Elements, point: Point, claimed_sum: Q, trace_size: u32) ![CONSTRAINT_COUNT]Q {
    if (trace_size == 0 or elements.arity != 7) return error.InvalidUniversalMemoryDomain;
    const shift = try claimed_sum.divM31(M.fromCanonical(trace_size));
    return @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).universalPointConstraints(elements, point.active, point.consumed, point.emitted, point.consume_term, point.emit_term, point.prefix, point.previous_prefix, shift);
}

pub const Generated = struct {
    storage: []M,
    columns: [COLUMN_COUNT][]M,
    claim: Q,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};

pub fn generate(a: std.mem.Allocator, elements: *const universal.Elements, rows: []const Row, log_size: u32) !Generated {
    if (elements.arity != 7 or log_size == 0 or log_size > 24 or rows.len != @as(usize, 1) << @intCast(log_size))
        return error.InvalidUniversalMemoryDomain;
    const size = rows.len;
    const storage = try a.alloc(M, COLUMN_COUNT * size);
    errdefer a.free(storage);
    var columns: [COLUMN_COUNT][]M = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
    var total = Q.zero();
    for (rows, 0..) |row, logical| {
        const physical = framework.committedRow(logical, log_size);
        const consumed = if (row.active) try (try elements.combineBase(&row.consumed)).inv() else Q.zero();
        const emitted = if (row.active) try (try elements.combineBase(&row.emitted)).inv() else Q.zero();
        total = total.add(consumed).sub(emitted);
        write(&columns, 0, physical, consumed);
        write(&columns, 1, physical, emitted);
    }
    const shift = try total.divM31(M.fromCanonical(@intCast(size)));
    var prefix = Q.zero();
    for (0..size) |logical| {
        const physical = framework.committedRow(logical, log_size);
        prefix = prefix.add(read(&columns, 0, physical)).sub(read(&columns, 1, physical)).sub(shift);
        write(&columns, 2, physical, prefix);
    }
    if (!prefix.isZero()) return error.InvalidUniversalMemoryPrefix;
    return .{ .storage = storage, .columns = columns, .claim = total };
}

pub fn read(columns: *const [COLUMN_COUNT][]M, secure_index: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[secure_index * 4][row], columns[secure_index * 4 + 1][row], columns[secure_index * 4 + 2][row], columns[secure_index * 4 + 3][row] });
}
fn write(columns: *[COLUMN_COUNT][]M, secure_index: usize, row: usize, value: Q) void {
    const limbs = value.toM31Array();
    for (limbs, 0..) |limb, index| columns[secure_index * 4 + index][row] = limb;
}
fn base(value: Q) !M {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseNativeMemoryTuple;
    return limbs[0];
}

test "v5 opcode memory opposite claim keeps native consume and emit clocks distinct" {
    const a = std.testing.allocator;
    const relations = universal.UniversalRelations.dummy();
    const elements = relations.get(.memory_access);
    const before: Tuple = .{ M.zero(), M.fromCanonical(4), M.fromCanonical(3), M.fromCanonical(7), M.zero(), M.zero(), M.zero() };
    const after: Tuple = .{ M.zero(), M.fromCanonical(4), M.fromCanonical(9), M.fromCanonical(8), M.zero(), M.zero(), M.zero() };
    const rows = [_]Row{ .{ .active = true, .consumed = before, .emitted = after }, .{ .active = false, .consumed = @splat(M.zero()), .emitted = @splat(M.zero()) } };
    var generated = try generate(a, elements, &rows, 1);
    defer generated.deinit(a);
    const expected = (try (try elements.combineBase(&before)).inv()).sub(try (try elements.combineBase(&after)).inv());
    try std.testing.expect(generated.claim.eql(expected));
    for (rows, 0..) |row, logical| {
        const physical = framework.committedRow(logical, 1);
        const previous = framework.committedRow((logical + 1) % 2, 1);
        var consumed: [7]Q = undefined;
        var emitted: [7]Q = undefined;
        for (row.consumed, &consumed) |value, *out| out.* = Q.fromBase(value);
        for (row.emitted, &emitted) |value, *out| out.* = Q.fromBase(value);
        const point = Point{ .active = if (row.active) Q.one() else Q.zero(), .consumed = consumed, .emitted = emitted, .consume_term = read(&generated.columns, 0, physical), .emit_term = read(&generated.columns, 1, physical), .prefix = read(&generated.columns, 2, physical), .previous_prefix = read(&generated.columns, 2, previous) };
        for (try constraints(elements, point, generated.claim, 2)) |residual| try std.testing.expect(residual.isZero());
        try std.testing.expect(!(try constraints(elements, point, generated.claim.add(Q.one()), 2))[2].isZero());
    }
}

test "v5 opcode memory source uses both exact typed clocks" {
    const q = Q.fromBase;
    var pair = bridge.Pair(Q){
        .active = Q.one(),
        .space = Q.zero(),
        .source_address = q(M.fromCanonical(5)),
        .local_clock = q(M.fromCanonical(17)),
        .consume_clock = q(M.fromCanonical(11)),
        .before = .{ q(M.fromCanonical(42)), Q.zero(), Q.zero(), Q.zero() },
        .after = .{ q(M.fromCanonical(43)), Q.zero(), Q.zero(), Q.zero() },
        .pair_residuals = @splat(Q.zero()),
        .access_ordinal = 0,
    };
    const row = try rowFromPair(pair);
    try std.testing.expectEqual(@as(u32, 11), row.consumed[2].toU32());
    try std.testing.expectEqual(@as(u32, 17), row.emitted[2].toU32());
    pair.consume_clock = null;
    try std.testing.expectError(error.MissingNativeConsumeClock, rowFromPair(pair));
}
