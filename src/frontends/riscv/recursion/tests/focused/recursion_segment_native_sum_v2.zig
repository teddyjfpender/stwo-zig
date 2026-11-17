//! Owner-local focused collection; selected by the maintained catalog.
const subject = @import("segment_public_native_sum_authority.zig");

test {
    _ = subject;
    _ = @import("tests/segment_public_native_sum_authority_test.zig");
}
