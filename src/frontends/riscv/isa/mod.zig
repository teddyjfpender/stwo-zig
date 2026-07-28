//! Sail-facing RV32IM ISA boundary.

pub const authority = @import("authority.zig");
pub const profile = @import("profile.zig");
pub const decode = @import("decode.zig");

test {
    _ = authority;
    _ = profile;
    _ = decode;
}
