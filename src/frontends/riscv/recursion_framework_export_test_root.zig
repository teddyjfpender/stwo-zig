//! Focused authenticated backend-export loop, independent of proof producers.
test {
    _ = @import("air/lookups/tables/schema.zig");
    _ = @import("recursion/air/framework_polynomial_export_v1_test.zig");
    _ = @import("recursion/air/range_check_8_8_bridge_test.zig");
}
