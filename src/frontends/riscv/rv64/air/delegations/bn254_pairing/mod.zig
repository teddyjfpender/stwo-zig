//! Complete finite four-pair positive source, no physical/VM admission.
pub const spec = @import("spec.zig");
pub const witness = @import("witness.zig");
pub fn sourceDigest() [32]u8 {
    const std = @import("std");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("complete-finite-four-pair-positive-source/v1");
    h.update(@embedFile("spec.zig"));
    h.update(@embedFile("witness.zig"));
    h.update(&@import("../bn254_miller/mod.zig").sourceDigest());
    h.update(&@import("../bn254_residue/mod.zig").sourceDigest());
    h.update(@embedFile("../bn254_g2/subgroup/spec.zig"));
    h.update(@embedFile("../bn254_hint/source.zig"));
    return h.finalResult();
}
pub fn statement(input: spec.M.Input) ![32]u8 {
    const std = @import("std");
    const initial = try spec.initialValues(input);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("complete-finite-four-pair-positive-statement/v1");
    h.update(&sourceDigest());
    for (initial) |v| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);
        h.update(&bytes);
    }
    h.update("result=ONE;no-independent-z-claim");
    return h.finalResult();
}
