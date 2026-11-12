//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/lang/tests/typed_branch_eq_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_branch_lt_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_div_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_fence_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_load_store_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_lt_imm_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_lt_reg_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_imm_witness_performance_test.zig");
}
