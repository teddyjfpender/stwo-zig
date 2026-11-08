const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const P = @import("protocol.zig");
const W = @import("witness.zig");
const O = P.O;
const Q = P.Q;
const M = P.M;
const LO = prover.air.logup_columns.ForField(O);
const LQ = prover.air.logup_columns;
const Rows = struct {
    fn q(_: @This(), row: usize, out: []LQ.Fraction) !void {
        for (out, 0..) |*v, i| v.* = .{ .numerator = Q.fromBase(M.fromU64(row + i + 1)), .denominator = Q.fromU32Unchecked(@intCast(row + 17), 2, 3, @intCast(i + 4)) };
    }
    fn o(self: @This(), row: usize, out: []LO.Fraction) !void {
        var qvalues: [2]LQ.Fraction = undefined;
        try self.q(row, &qvalues);
        for (out, qvalues) |*v, qv| v.* = .{ .numerator = O.fromInner(qv.numerator), .denominator = O.fromInner(qv.denominator) };
    }
};
fn free(a: std.mem.Allocator, columns: []prover.pcs.ColumnEvaluation) void {
    circuit.witness.trace.freeColumns(a, columns);
}
test "om31 outer LogUp shared builder preserves legacy quartic coordinates" {
    const a = std.testing.allocator;
    const q = try LQ.build(a, 5, 2, Rows{}, Rows.q);
    defer free(a, q.columns);
    const o = try LO.build(a, 5, 2, Rows{}, Rows.o);
    defer free(a, o.columns);
    try std.testing.expect(o.claimed_sum.eql(O.fromInner(q.claimed_sum)));
    try std.testing.expectEqual(q.columns.len * 2, o.columns.len);
    for (0..2) |batch| for (0..4) |coordinate| {
        try std.testing.expectEqualSlices(M, q.columns[4 * batch + coordinate].values, o.columns[8 * batch + coordinate].values);
        for (o.columns[8 * batch + coordinate + 4].values) |value| try std.testing.expect(value.isZero());
    };
}
test "om31 outer lookup denominator uses upper challenge coordinates" {
    const tuples = [_]circuit.witness.components.Lookup{.{ .numerator = M.one(), .tuple = .{ M.one(), M.fromCanonical(7), M.zero(), M.zero(), M.zero(), M.zero() }, .len = 2 }};
    const z = O{ .c0 = Q.fromU32Unchecked(11, 2, 3, 4), .c1 = Q.fromU32Unchecked(5, 6, 7, 8) };
    const alpha = O{ .c0 = Q.fromU32Unchecked(13, 2, 3, 4), .c1 = Q.fromU32Unchecked(17, 6, 7, 8) };
    const elements = W.Elements.init(z, alpha);
    var fractions: [1]LO.Fraction = undefined;
    try W.pairFractions(&elements, &tuples, &fractions);
    const expected = O.one().add(alpha.mulM31(M.fromCanonical(7))).sub(z);
    try std.testing.expect(fractions[0].denominator.eql(expected));
    try std.testing.expect(!fractions[0].denominator.c1.isZero());
}
test "om31 sparse tuple combine matches dense reference for every tuple width" {
    var random = std.Random.DefaultPrng.init(0x5350415253454f38);
    const rng = random.random();
    const elements = W.Elements.init(O.fromM31Array(.{ M.one(), M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(4), M.fromCanonical(5), M.fromCanonical(6), M.fromCanonical(7), M.fromCanonical(8) }), O.fromM31Array(.{ M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17), M.fromCanonical(19), M.fromCanonical(23), M.fromCanonical(29), M.fromCanonical(31), M.fromCanonical(37) }));
    for (0..128) |iteration| {
        var tuple: [6]M = undefined;
        for (&tuple, 0..) |*value, j| value.* = if ((iteration >> @intCast(j)) & 1 == 0) M.zero() else M.fromU64(rng.int(u32));
        for (0..7) |width| {
            var reference = O.zero();
            for (tuple[0..width], elements.powers[0..width]) |value, power| reference = reference.add(power.mulM31(value));
            try std.testing.expect(reference.sub(elements.z).eql(elements.combine(tuple[0..width])));
        }
    }
}
test "om31 outer witness instantiates full source path and rejects malformed MAIN" {
    var base = circuit.witness.trace.BaseTrace{ .allocator = std.testing.allocator, .columns = &.{}, .log_sizes = circuit.common.component_list.PerComponent(u32).fromArray(@splat(5)), .output_values = &.{} };
    defer base.deinit();
    var pp: circuit.common.preprocessed.PreprocessedCircuit = undefined;
    try std.testing.expectError(error.InvalidTraceShape, W.writeReleasing(std.testing.allocator, &base, &pp, O.one(), O.basis()));
}
