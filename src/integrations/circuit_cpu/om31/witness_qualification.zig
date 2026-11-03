//! Actual finalized builder circuit, native fixed tables and unchanged MAIN.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const P = @import("protocol.zig");
const W = @import("witness.zig");
const Q = P.Q;
const O = P.O;
test "om31 outer actual circuit MAIN and native lookup multiset parity" {
    const a = std.testing.allocator;
    var ctx = try circuit.builder.Context(Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(Q.fromU32Unchecked(3, 1, 2, 4));
    const y = try ctx.guess(Q.fromU32Unchecked(7, 2, 3, 5));
    const z = try ctx.mul(x, y);
    try ctx.setOutputs(&.{z});
    try ctx.finalize(true);
    const sizes = circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
    try circuit.common.finalize.padToTargets(Q, &ctx, sizes);
    try std.testing.expect(try ctx.isCircuitValid());
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var base = try circuit.witness.trace.writeTrace(a, ctx.values(), &pp);
    defer base.deinit();
    const qz = Q.fromU32Unchecked(17, 2, 3, 4);
    const qa = Q.fromU32Unchecked(11, 5, 7, 9);
    var legacy = try circuit.witness.trace.writeInteractionTrace(a, base.columns, base.log_sizes, &pp, qz, qa);
    defer legacy.deinit();
    try std.testing.expect((try circuit.witness.trace.lookupSum(base.output_values, legacy.claimed_sums, qz, qa)).isZero());
    var embedded = try W.write(a, &base, &pp, O.fromInner(qz), O.fromInner(qa));
    const widths = circuit.witness.trace.interactionWidths();
    var qi: usize = 0;
    var oi: usize = 0;
    for (widths) |width| {
        for (0..width / 4) |group| for (0..4) |coordinate| {
            try std.testing.expectEqualSlices(P.M, legacy.columns[qi + 4 * group + coordinate].values, embedded.columns[oi + 8 * group + coordinate].values);
            for (embedded.columns[oi + 8 * group + 4 + coordinate].values) |v| try std.testing.expect(v.isZero());
        };
        qi += width;
        oi += 2 * width;
    }
    for (legacy.claimed_sums.toArray(), embedded.claimed_sums.toArray()) |q, o| try std.testing.expect(o.eql(O.fromInner(q)));
    embedded.deinit();
    const oz = O{ .c0 = qz, .c1 = Q.fromU32Unchecked(19, 23, 29, 31) };
    const oa = O{ .c0 = qa, .c1 = Q.fromU32Unchecked(37, 41, 43, 47) };
    var wide = try W.writeReleasing(a, &base, &pp, oz, oa);
    defer wide.deinit();
    try std.testing.expectEqual(@as(usize, 0), base.columns.len);
    const elements = W.Elements.init(oz, oa);
    try std.testing.expect((try W.lookupSum(base.output_values, wide.claimed_sums, &elements)).isZero());
    std.debug.print("OM31_CIRCUIT_WITNESS native_MAIN_once=true lookup_multiset_parity=true full_upper_challenges_closed=true columns={}\n", .{wide.columns.len});
}
