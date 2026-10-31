//! Concrete QM31 active-prefix authority for RAM caller tables. Shape values
//! are verifier-owned; the fixed row index never comes from witness advice.
const E = @import("../evaluation.zig");
const Q = E.Q;
pub fn evaluate(active: Q, previous: Q, first: Q, last: Q, index: Q, active_rows: u32, total_rows: u32, out: *E.Sink) void {
    out.emit(active.mul(active.sub(Q.one())));
    out.emit(first.mul(active.sub(E.q(@intFromBool(active_rows != 0)))));
    const nonfirst = Q.one().sub(first);
    out.emit(nonfirst.mul(active).mul(Q.one().sub(previous)));
    out.emit(nonfirst.mul(previous.sub(active)).mul(index.sub(E.q(active_rows))));
    out.emit(last.mul(active).mul(E.q(active_rows).sub(E.q(total_rows))));
}
