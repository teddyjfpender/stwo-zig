const raw_transport_tests =
    @import("ethereum_incremental_capture_raw_transport_v4_test.zig");
const postprocess_tests =
    @import("ethereum_incremental_capture_postprocess_v4_test.zig");

comptime {
    _ = raw_transport_tests;
    _ = postprocess_tests;
}
