//! CPU-only local stage-1 model/capacity/guard acceptance and refusal cases.
test "local stage1 dependency suites" {
    _ = @import("native_stage1_capacity.zig");
    _ = @import("native_stage1_allocations.zig");
}
