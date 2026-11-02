//! Experimental WGKR-LS-RANGE-v0 driver (not part of any default protocol).
pub fn main() !void {
    try @import("logup_gkr/main.zig").main();
}
