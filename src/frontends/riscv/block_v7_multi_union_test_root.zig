test {
    const std = @import("std");
    std.testing.refAllDecls(@import("prover/block_v7_fixed_column_census_v1.zig"));
    std.testing.refAllDecls(@import("prover/tests/block_v7_multi_union_test.zig"));
    std.testing.refAllDecls(@import("prover/tests/block_v7_native_caller_union_test.zig"));
}
