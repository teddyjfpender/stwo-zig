//! Conditional complete shared Miller source; not an admitted VM service.
pub const spec = @import("spec.zig");
pub const witness = @import("witness.zig");
pub const vectors = @import("vectors.zig");
pub fn sourceDigest() [32]u8 {
    const std = @import("std");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("shared-four-pair-miller-source/v1");
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("witness.zig"));
    h.update(@embedFile("../bn254_g2/preparation/spec.zig"));
    h.update(@embedFile("../bn254_g2/spec.zig"));
    h.update(@embedFile("../bn254_dense/spec.zig"));
    h.update(@embedFile("../curves/spec.zig"));
    return h.finalResult();
}

/// Candidate public framing for later physical joins. SHA source identity binds
/// the whole DAG; all initial P/Q/literals and independently expected z are bound.
/// No current production transcript consumes this unadmitted source format.
pub fn statement(input: spec.Input, expected_z: [12]u256) ![32]u8 {
    const std = @import("std");
    const initial = try spec.initialValues(input);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("shared-four-pair-miller-statement/v1");
    h.update(&sourceDigest());
    for (initial) |v| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);
        h.update(&bytes);
    }
    for (expected_z) |v| {
        if (v >= spec.B.BN254_P) return error.NonCanonicalMillerOutput;
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
