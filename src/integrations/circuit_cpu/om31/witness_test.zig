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
test "om31 outer witness instantiates full source path and rejects malformed MAIN" {
    var base = circuit.witness.trace.BaseTrace{ .allocator = std.testing.allocator, .columns = &.{}, .log_sizes = circuit.common.component_list.PerComponent(u32).fromArray(@splat(5)), .output_values = &.{} };
    defer base.deinit();
    var pp: circuit.common.preprocessed.PreprocessedCircuit = undefined;
    try std.testing.expectError(error.InvalidTraceShape, W.writeReleasing(std.testing.allocator, &base, &pp, O.one(), O.basis()));
}

test "om31 output term matches independent Horner tuple and typed lookup fault closure" {
    const t = std.testing;
    const trace = circuit.witness.trace;
    const relation = circuit.common.component_list.GATE_RELATION_ID;
    // Bind the independent RV64 job fixture constants to the canonical authority.
    try t.expectEqual(@as(u32, 378353459), relation);
    try t.expectEqual(@as(usize, 2), trace.U_VAR_IDX);
    try t.expect(trace.U_VALUE.eql(Q.fromU32Unchecked(0, 0, 1, 0)));
    const z = O.fromBase(M.fromCanonical(1009));
    const alpha = O.fromBase(M.fromCanonical(17));
    const elements = W.Elements.init(z, alpha);
    const values = [_]Q{ trace.U_VALUE, Q.fromU32Unchecked(1, 2, 3, 4), Q.fromU32Unchecked(1, 0, 1, 0) };
    var terms: [values.len]O = undefined;
    for (values, 0..) |value, i| {
        const address = trace.U_VAR_IDX + @as(usize, @intFromBool(i == 1));
        const limbs = value.toM31Array();
        const tuple = [_]M{ M.fromCanonical(relation), M.fromU64(address), limbs[0], limbs[1], limbs[2], limbs[3] };
        var denominator = O.zero();
        var remaining: usize = tuple.len;
        while (remaining != 0) {
            remaining -= 1;
            denominator = denominator.mul(alpha).add(O.fromBase(tuple[remaining]));
        }
        const independent = try denominator.sub(z).inv();
        terms[i] = try W.outputTerm(&elements, address, value);
        try t.expect(independent.eql(terms[i]));
    }
    const claim = terms[0].add(terms[1]).neg();
    try t.expect(claim.add(terms[1]).add(terms[0]).isZero());
    try t.expect(!claim.add(terms[1]).add(terms[2]).isZero());
}
