//! Focused unit-test root for the reusable C-013 corpus authority.

test {
    _ = @import("calibration_protocol_test.zig");
    _ = @import("capture_protocol_test.zig");
    _ = @import("capture_schedule_test.zig");
    _ = @import("corpus.zig");
}
