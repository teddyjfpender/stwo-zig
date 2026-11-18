//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("../../shared/air/semantics/common.zig");
    _ = @import("../../shared/air/semantics/control_common.zig");
    _ = @import("../direct_witness_executor_test.zig");
    _ = @import("../hint_recipe_test.zig");
    _ = @import("../range_refinement_test.zig");
}
