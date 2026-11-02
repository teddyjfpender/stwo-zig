//! Active-prefix authority for RAM caller tables over any secure lane. Shape
//! values are verifier-owned; the fixed row index never comes from witness advice.
const E = @import("../evaluation.zig");
const Q = E.Q;
/// Row publics as lane values: the active row count, the derived `count != 0`
/// Boolean and the (geometry-constant) total row count.
pub fn RowsFor(comptime F: type) type {
    return struct { active: F, nonempty: F, total: F };
}
pub fn rows(active_rows: u32, total_rows: u32) RowsFor(Q) {
    return .{ .active = E.q(active_rows), .nonempty = E.q(@intFromBool(active_rows != 0)), .total = E.q(total_rows) };
}
/// Active-row publics as a component lane stores them: nothing natively (the
/// shape's counts are authoritative), optional lane wires for an external lane.
pub fn ActiveFor(comptime Lane: type) type {
    E.assertConstLane(Lane);
    return if (E.isExternalLane(Lane)) ?struct { rows: Lane, nonempty: Lane } else void;
}
pub fn activeDefault(comptime Lane: type) ActiveFor(Lane) {
    return if (E.isExternalLane(Lane)) null else {};
}
pub fn evaluate(active: Q, previous: Q, first: Q, last: Q, index: Q, active_rows: u32, total_rows: u32, out: *E.Sink) void {
    return evaluateFor(Q, active, previous, first, last, index, rows(active_rows, total_rows), out);
}
pub fn evaluateFor(comptime F: type, active: F, previous: F, first: F, last: F, index: F, public: RowsFor(F), out: *E.SinkFor(F)) void {
    out.emit(active.mul(active.sub(F.one())));
    out.emit(first.mul(active.sub(public.nonempty)));
    const nonfirst = F.one().sub(first);
    out.emit(nonfirst.mul(active).mul(F.one().sub(previous)));
    out.emit(nonfirst.mul(previous.sub(active)).mul(index.sub(public.active)));
    out.emit(last.mul(active).mul(public.active.sub(public.total)));
}
