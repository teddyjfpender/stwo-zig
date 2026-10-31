//! One mixed-lane authority for the explicit native2n permutation.
const E = @import("../equations.zig");
const K = @import("../layout.zig");
const L = @import("layout.zig");
const V = @import("../../../evaluation.zig");
pub fn RowFor(comptime F: type) type {
    return struct { base: E.RowFor(F), round_enable: F, io_enable: F };
}
pub fn emitFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), previous: V.SecureFor(F), claim: V.ConstFor(F), ch: E.ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    E.emitDirectFor(F, row.base, public, sink, false);
    sink.emit(row.round_enable.sub(E.roundActiveFor(F, row.base)));
    sink.emit(row.io_enable.sub(E.ioActiveFor(F, row.base)));
    sink.emit(row.round_enable.mul(row.round_enable.sub(F.one())));
    sink.emit(row.io_enable.mul(row.io_enable.sub(F.one())));
    var term = V.SecureFor(F).zero();
    for (0..L.PAIRS) |pair| {
        var d: [2]V.SecureFor(F) = @splat(V.SecureFor(F).one());
        const round = pair < L.ROUND_PAIRS;
        const enable = if (round) row.round_enable else row.io_enable;
        const local = if (round) pair else pair - L.ROUND_PAIRS;
        for (0..2) |side| {
            const event = 2 * local + side;
            if (round) d[side] = E.lookupDenominatorFor(F, row.base, ch, event) else if (event < K.IO_LANES) d[side] = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &E.ioTupleFor(F, row.base, event), true);
        }
        const inverse = interaction[pair];
        sink.emit(inverse.mul(d[0]).mul(d[1]).sub(V.liftFor(F, enable)));
        sink.emit(V.mulBaseFor(F, inverse, F.one().sub(enable)));
        const numerator = if (!round and 2 * local + 1 >= K.IO_LANES) d[1] else d[0].add(d[1]);
        const contribution = inverse.mul(numerator);
        term = if (round) term.sub(contribution) else term.add(contribution);
    }
    const delta = interaction[L.PAIRS].sub(previous).add(V.mulBaseFor(F, V.splatFor(F, claim), row.base.fixed[K.FIRST]));
    sink.emit(delta.sub(term));
}
