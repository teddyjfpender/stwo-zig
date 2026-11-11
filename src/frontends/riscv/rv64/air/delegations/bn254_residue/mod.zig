//! Conditional positive-residue source, no VM/production admission.
pub const spec = @import("spec.zig");
pub const witness = @import("witness.zig");
pub const vectors = @import("vectors.zig");
pub const physical_spec = @import("physical_spec.zig");
pub const physical_witness = @import("physical_witness.zig");
pub const fixture = @import("fixture.zig");
pub const hint_source = @import("../bn254_hint/source.zig");
pub fn sourceDigest() [32]u8 {
    const std = @import("std");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("frobenius.zig"));
    h.update(@embedFile("witness.zig"));
    h.update(@embedFile("physical_spec.zig"));
    h.update(@embedFile("physical_witness.zig"));
    h.update(@embedFile("fixture.zig"));
    h.update(@embedFile("../curves/spec.zig"));
    h.update(&hint_source.sourceDigest());
    return h.finalResult();
}
