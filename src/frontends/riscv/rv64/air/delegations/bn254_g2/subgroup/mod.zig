const std = @import("std");
pub const spec = @import("spec.zig");
pub const witness = @import("witness.zig");
pub const fixture = @import("fixture.zig");
pub const hint = @import("../../bn254_hint/source.zig");
pub const hint_witness = @import("../../bn254_hint/witness.zig");
pub const vectors = @import("vectors.zig");
pub fn sourceDigest() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("conditional-exact-r-subgroup-fixture/v1");
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("witness.zig"));
    h.update(@embedFile("fixture.zig"));
    h.update(&hint.sourceDigest());
    return h.finalResult();
}
