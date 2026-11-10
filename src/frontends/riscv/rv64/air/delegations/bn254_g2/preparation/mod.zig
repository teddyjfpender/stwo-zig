//! Complete conditional preparation source, no production/service admission.
pub const spec = @import("spec.zig");
pub const witness = @import("witness.zig");
pub const fixture = @import("fixture.zig");
pub const vectors = @import("vectors.zig");
pub const export_vector = @import("export_vector.zig");
pub fn sourceDigest() [32]u8 {
    const std = @import("std");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("../spec.zig"));
    h.update(@embedFile("../../curves/spec.zig"));
    h.update(@embedFile("witness.zig"));
    h.update(@embedFile("fixture.zig"));
    return h.finalResult();
}
