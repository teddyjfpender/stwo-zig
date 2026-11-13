//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/lang/tests/materialization_direct_program_test.zig");
    _ = @import("cases/air/lang/tests/materialization_fixed_direct_test.zig");
    _ = @import("cases/air/lang/tests/materialization_fixed_cost_test.zig");
}
