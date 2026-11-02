//! Measurement-only LogUp / LogUp-GKR CPU kernel benchmark (no protocol).
pub fn main() !void {
    try @import("logup_gkr/kernel_bench.zig").main();
}
