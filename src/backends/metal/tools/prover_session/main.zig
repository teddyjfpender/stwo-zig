//! Persistent Metal prover-session executable.

pub const stwo = @import("stwo");
pub const one_shot = @import("one_shot");

pub fn main() !void {
    return @import("app.zig").main();
}

test {
    _ = @import("startup.zig");
    _ = @import("protocol_tests.zig");
    _ = @import("cache_tests.zig");
}
