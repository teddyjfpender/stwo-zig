//! Sail-facing RV32IM ISA boundary.

pub const authority = @import("authority.zig");
pub const custom0 = @import("custom0.zig");
pub const profile = @import("profile.zig");
pub const decode = @import("decode.zig");
pub const execution_profile = @import("execution_profile.zig");

test {
    _ = authority;
    _ = custom0;
    _ = profile;
    _ = decode;
    _ = execution_profile;
}
