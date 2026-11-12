//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("compat/tests/testing/cases/recursion/tests/segment_statement_test.zig");
    _ = @import("compat/tests/testing/cases/recursion/tests/segment_statement_runner_e2e_test.zig");
    _ = @import("compat/tests/testing/cases/recursion/tests/segment_leaf_local_authority_test.zig");
    _ = @import("compat/tests/recursion/tests/segment_leaf_authority_v2_test.zig");
    _ = @import("compat/tests/testing/cases/air/tests/public_data_test.zig");
    _ = @import("compat/tests/testing/cases/air/tests/public_logup_test.zig");
}
