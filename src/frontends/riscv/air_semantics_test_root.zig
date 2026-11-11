//! Complete focused test root; every compilation partition remains mandatory.

test {
    _ = @import("air_semantics_partition_0_test_root.zig");
    _ = @import("air_semantics_partition_1_test_root.zig");
    _ = @import("air_semantics_partition_2_test_root.zig");
    _ = @import("air_semantics_partition_3_test_root.zig");
}
