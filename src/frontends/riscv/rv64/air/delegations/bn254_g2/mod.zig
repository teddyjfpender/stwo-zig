//! Closed homogeneous transition research. No VM tag or profile admission.
pub const spec = @import("spec.zig");
pub const witness = @import("witness.zig");
pub const vectors = @import("vectors.zig");
pub const fixture = @import("fixture.zig");
pub fn sourceDigest() [32]u8 {
    const std = @import("std");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("witness.zig"));
    h.update(@embedFile("fixture.zig"));
    return h.finalResult();
}
pub const preparation = @import("preparation/mod.zig");
