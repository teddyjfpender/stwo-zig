//! Focused Sail RV32IM CPU/SIMD proof command root.

const std = @import("std");

/// Production commands reserve stdout for the machine-readable result and
/// stderr for actionable failures. Proof-stage diagnostics remain available
/// from test and benchmark-tool roots that opt into informational logging.
pub const std_options: std.Options = .{ .log_level = .warn };

pub fn main() !void {
    return @import("app.zig").main();
}
