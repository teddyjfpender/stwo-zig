//! Direct test root for the isolated native/non-recursive R-007 reference.

test {
    _ = @import("manifest_test.zig");
    _ = @import("summary_test.zig");
}
