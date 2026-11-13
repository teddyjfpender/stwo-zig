//! Test discovery and compatibility exports for the independently owned case groups.
const Support = @import("relation_adapter_test_support.zig");

test {
    _ = @import("relation_adapter_test_admission.zig");
    _ = @import("relation_adapter_test_projection.zig");
}
