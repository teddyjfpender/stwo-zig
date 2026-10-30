const std = @import("std");
const core = @import("stwo_core");
const R = @import("../block_v7_memory_relations_v1.zig");
const K = @import("../block_v8_compact_ram_kernel_v1.zig");
const C = @import("../block_v8_compact_ram_component_v1.zig");
const T = @import("../block_v7_memory_trace_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
fn q(v: u32) R.Q {
    return R.Q.fromBase(R.M.fromCanonical(v));
}
fn ch() !C.Challenges(R.Q) {
    const pin = try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)});
    var counts: E.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try E.Epoch.init(@splat(3), @import("../../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG, counts, &.{pin}, 1);
    return C.fromEpoch(try epoch.draw(std.testing.allocator));
}
const Context = struct {
    challenges: C.Challenges(R.Q),
    pub fn termsAt(self: Context, matrix: T.Matrix, logical: usize) ![C.PLANES]R.Term(R.Q) {
        const previous = (logical + matrix.size() - 1) % matrix.size();
        return C.terms(R.Q, self.challenges, matrix.row(3, 0, logical), matrix.row(12, 3, logical), matrix.row(12, 3, previous));
    }
};
fn pack(comptime n: usize, matrix: T.Matrix, offset: usize, start: usize) [n]R.P {
    var out: [n]R.P = undefined;
    for (&out, 0..) |*cell, column| {
        var lanes: [core.fields.m31.PACK_WIDTH]R.Q = undefined;
        for (&lanes, 0..) |*lane, index| lane.* = R.Q.fromBase(matrix.get(column + offset, (start + index) % matrix.size()));
        cell.* = R.P.fromLanes(lanes);
    }
    return out;
}
test "compact RAM scalar packed and cyclic source rows agree with exact boundary fractions" {
    const a = std.testing.allocator;
    const transitions = [_]K.Transition{
        .{ .space = 1, .address = 16, .clock = 3, .before = 10, .after = 11 },
        .{ .space = 1, .address = 16, .clock = 7, .before = 11, .after = 12 },
        .{ .space = 1, .address = 20, .clock = 3, .before = 20, .after = 21 },
        .{ .space = 1, .address = (1 << 30) - 4, .clock = 11, .before = 30, .after = 30 },
    };
    var matrix = try T.Matrix.init(a, 4, 15, 1 << 20);
    defer matrix.deinit();
    for (transitions, 0..) |transition, i| {
        matrix.set(0, i, R.M.one());
        matrix.set(1, i, if (i == 0) R.M.one() else R.M.zero());
        matrix.set(2, i, if (i + 1 == transitions.len) R.M.one() else R.M.zero());
        const row = try K.construct(.{ .cohort_count = 4 }, transition, if (i == 0) null else transitions[i - 1]);
        try K.checkRanges(row);
        for (row, 0..) |value, column| matrix.set(column + 3, i, value);
    }
    const challenges = try ch();
    var generated = try T.interactions(C.PLANES, a, matrix, Context{ .challenges = challenges }, 1 << 20);
    defer generated.deinit();
    const spec = C.Spec{ .challenges = challenges, .sums = generated.sums };
    var domain = try spec.prepareDomain(16);
    for (0..matrix.size()) |i| {
        const previous = (i + matrix.size() - 1) % matrix.size();
        for (try domain.evaluate(matrix.row(3, 0, i), matrix.row(12, 3, i), matrix.row(12, 3, previous), generated.matrix.row(24, 0, i), generated.matrix.row(24, 0, previous), 16)) |value| try std.testing.expect(value.isZero());
    }
    const W = core.fields.m31.PACK_WIDTH;
    var i: usize = 0;
    while (i < matrix.size()) : (i += W) {
        const previous = (i + matrix.size() - 1) % matrix.size();
        for (domain.evaluatePacked(pack(3, matrix, 0, i), pack(12, matrix, 3, i), pack(12, matrix, 3, previous), pack(24, generated.matrix, 0, i), pack(24, generated.matrix, 0, previous))) |value| for (0..W) |lane| try std.testing.expect(value.lane(lane).isZero());
    }
    var expected_transition = R.Q.zero();
    for (0..transitions.len) |index| expected_transition = expected_transition.sub(try challenges.transition.combineSecure(K.transitionTuple(R.Q, matrix.row(12, 3, index))).inv());
    try std.testing.expectEqualDeep(expected_transition, generated.sums[0]);
    var expected_initial = R.Q.zero();
    for ([_]usize{ 0, 2, 3 }) |index| expected_initial = expected_initial.add(try challenges.boundary.combineSecure(K.initialTuple(R.Q, matrix.row(12, 3, index))).inv());
    var expected_final = R.Q.zero();
    for ([_]usize{ 1, 2, 3 }) |index| expected_final = expected_final.add(try challenges.boundary.combineSecure(K.finalTuple(R.Q, matrix.row(12, 3, index))).inv());
    try std.testing.expectEqualDeep(expected_initial, generated.sums[1]);
    try std.testing.expectEqualDeep(expected_final, generated.sums[2]);
    try std.testing.expectEqualDeep(q(7), generated.sums[5]);
}
test "compact ordering rejects decreasing keys clocks and modular range substitutes" {
    const policy = K.Policy{ .cohort_count = 4096 };
    const previous = K.Transition{ .space = 1, .address = 65536, .clock = 7, .before = 1, .after = 2 };
    var current = previous;
    current.address = 16;
    try std.testing.expectError(error.UnorderedCompactRam, K.construct(policy, current, previous));
    current = previous;
    current.clock = 3;
    try std.testing.expectError(error.UnorderedCompactRam, K.construct(policy, current, previous));
    current.clock = 11;
    current.before = 9;
    try std.testing.expectError(error.UnorderedCompactRam, K.construct(policy, current, previous));
    // Solving the field equation for a negative address gap produces a high
    // limb outside12bits. Both high and high*16 requests are indispensable.
    const negative_gap = R.M.zero().sub(R.M.fromCanonical(16384)).sub(R.M.one());
    var row: [12]R.M = @splat(R.M.zero());
    row[K.Col.gap_low] = R.M.fromCanonical(negative_gap.toU32() & 65535);
    row[K.Col.gap_high] = R.M.fromCanonical(negative_gap.toU32() >> 16);
    try std.testing.expectError(error.InvalidCompactRamRange, K.checkRanges(row));
}
test "separate initial and final planes reject an unchanged uninitialized read" {
    const challenges = try ch();
    const row_m = try K.construct(.{ .cohort_count = 1 }, .{ .space = 1, .address = 16, .clock = 3, .before = 99, .after = 99 }, null);
    var row: [12]R.Q = undefined;
    for (&row, row_m) |*cell, value| cell.* = R.Q.fromBase(value);
    const terms = C.terms(R.Q, challenges, .{ R.Q.one(), R.Q.one(), R.Q.one() }, row, @splat(R.Q.zero()));
    const source_initial = try terms[1].fraction();
    const source_final = try terms[2].fraction();
    const table = C.BoundarySpec.termsFor(R.Q, challenges.boundary, .{ q(1), q(16), q(0), q(10), q(0), q(10), q(0), q(0) }, .{q(1)});
    const initial = source_initial.add(try table[0].fraction());
    const final = source_final.add(try table[1].fraction());
    try std.testing.expect(!initial.isZero());
    try std.testing.expect(!final.isZero());
    // A delta-only check would cancel exactly and accept the wrong value.
    try std.testing.expect(initial.sub(final).isZero());
    const zero = R.Q.zero();
    const altered_changed = C.BoundarySpec.equationsFor(R.Q, challenges.boundary, .{ q(1), q(16), q(0), q(10), q(0), q(11), q(0), q(1) }, .{zero}, @splat(zero), @splat(zero), .{ zero, zero });
    try std.testing.expect(!altered_changed[2].isZero());
}
