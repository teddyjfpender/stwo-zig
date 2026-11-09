//! Installed entry point for the focused Native CPU/SIMD product.

pub const stwo = @import("stwo_native_cpu");

pub fn main() !void {
    return @import("app.zig").main();
}

test {
    _ = @import("app.zig");
    _ = @import("cli.zig");
    _ = @import("identity.zig");
    _ = @import("registry.zig");
    const std = @import("std");
    const required = .{
        "bounded proving report carries the exact focused product identity",
        "focused parser admits Native CPU workloads and rejects foreign capabilities",
        "help contains only compiled capabilities",
        "generated Native CPU identity is internally consistent",
        "registry exposes only Native examples and CPU",
    };
    // Anonymous tests survive filtering: a dropped product suite must fail.
    inline for (required) |suffix| {
        var found = false;
        for (@import("builtin").test_functions) |entry| {
            if (std.mem.endsWith(u8, entry.name, suffix)) found = true;
        }
        try std.testing.expect(found);
    }
}
