const subject = @import("recursion/segment_public_outer_source_v2.zig");

test "V2 public-spine source instantiates" {
    try subject.CAPABILITY_LEDGER.validate();
}

comptime {
    _ = @import("recursion/segment_public_outer_source_v2_test.zig");
}
