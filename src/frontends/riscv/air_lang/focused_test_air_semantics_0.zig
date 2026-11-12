//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("shared/air/semantics/common.zig");
    _ = @import("shared/air/semantics/control_common.zig");
    _ = @import("tests/direct_witness_executor_test.zig");
    _ = @import("tests/hint_recipe_test.zig");
    _ = @import("tests/range_refinement_test.zig");
}
