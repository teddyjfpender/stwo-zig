//! Actual installed entry bodies compiled without invoking any main or proof.
const std = @import("std");
export fn stwo_capacity_cpu_product_body_gate() void {
    inline for (.{ &@import("ethereum_block_v5_cpu_produce.zig").main, &@import("ethereum_block_v5_cpu_verify.zig").main }) |entry| std.mem.doNotOptimizeAway(entry);
}
