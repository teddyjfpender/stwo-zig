const subject = @import("stwo_riscv_recursion").modules.segment_public_outer_source_v2;

test "V2 public-spine source instantiates" {
    try subject.CAPABILITY_LEDGER.validate();
}

comptime {
    _ = @import("stwo_riscv_recursion").modules.tests_segment_public_outer_source_test;
}
