//! Closed dense tower arithmetic research; no execution tag/admission.
pub const spec = @import("spec.zig");
pub const row = @import("row.zig");
pub const air = @import("air.zig");
pub const chain = @import("chain.zig");

pub const fixture_component = @import("fixture_component.zig");
pub const fixture_trace = @import("fixture_trace.zig");
pub const reference = @import("tests.zig").reference;
/// Explicit candidate authority fingerprint; no existing profile consumes it.
pub fn sourceDigest() [32]u8 {
    const std = @import("std");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("row.zig"));
    h.update(@embedFile("air.zig"));
    return h.finalResult();
}
