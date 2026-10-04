//! Nonproving original arithmetic/fusion/fixed-schedule parity and ownership.
comptime {
    _ = @import("recursion/air/tests/arithmetic_fusion_direct_columns_test.zig");
    _ = @import("recursion/air/tests/qm31_mul_add_v1_test.zig");
    _ = @import("recursion/air/tests/detached_opening_accumulate4_v1_test.zig");
}
