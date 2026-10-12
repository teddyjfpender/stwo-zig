const extra = @import("recursion/segment_leaf_wrapper_extra_rows_v3.zig");
test "V3 extra row exact tuple gate" {
    try extra.testLocalClosure();
}
