//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/lang/tests/lookup_batch_execution_test.zig");
    _ = @import("cases/air/lang/tests/lookup_batch_performance_test.zig");
    _ = @import("cases/air/lang/tests/lookup_batch_planner_test.zig");
    _ = @import("cases/air/lang/tests/row_window_test.zig");
    _ = @import("cases/air/lang/tests/access_transaction_test.zig");
}
