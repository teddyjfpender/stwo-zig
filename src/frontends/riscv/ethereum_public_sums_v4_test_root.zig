//! Focused V4 public-sum equivalence and arithmetic measurements. Keep the
//! module root at the frontend boundary so native AIR/runner imports compose.
comptime {
    _ = @import("air/incremental_public_logup_v4.zig");
    _ = @import("air/incremental_public_logup_v4_bench_test.zig");
}
