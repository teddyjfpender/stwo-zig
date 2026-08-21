//! Executable entry points for the focused profile clock-authority mutations.

const support = @import("trace_clock_authority_test_support.zig");
const Trace = @import("trace.zig").Trace;

test "profile clock authority rejects gaps order and count forgery" {
    try support.rejectGapOrderAndCountForgery(Trace);
}

test "profile clock authority carries an exact continuation origin" {
    try support.carryExactContinuationOrigin(Trace);
}
