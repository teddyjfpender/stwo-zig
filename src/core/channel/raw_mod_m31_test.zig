const std = @import("std");
const R = @import("raw_mod_m31.zig");
const M = @import("../fields/m31.zig");
const B = @import("blake2s.zig");
test "raw-mod profile boundaries are canonical including both legacy rejected raw words" {
    const p = M.Modulus;
    const raw = [8]u32{ p - 1, p, p + 1, 2 * p - 1, 2 * p, 2 * p + 1, 0, 1 };
    const expected = [8]u32{ p - 1, 0, 1, p - 1, 0, 1, 0, 1 };
    for (R.reduceWords(raw), expected) |value, want| try std.testing.expectEqual(want, value.v);
    // Residues0/1 have exactly three32-bit preimages; all others have two.
    for ([_]u64{ 0, 1, 2, p - 1 }) |residue| {
        var preimages: u32 = 0;
        for (0..3) |multiple| if (residue + multiple * @as(u64, p) < R.RAW_ORDER) {
            preimages += 1;
        };
        try std.testing.expectEqual(if (residue <= 1) @as(u32, 3) else 2, preimages);
    }
}
test "raw-mod channels separate trusted degree and packing profiles and consume exact raw counters" {
    var q = R.Qm31Channel.init();
    var o = R.Om31Channel.init();
    const legacy: B.Blake2sChannel = .{};
    try std.testing.expect(!std.mem.eql(u8, &q.digestBytes(), &legacy.digestBytes()));
    try std.testing.expect(!std.mem.eql(u8, &q.digestBytes(), &o.digestBytes()));
    try std.testing.expect(!std.mem.eql(u8, &R.qm31_profile.identity(), &R.om31_profile.identity()));
    var oracle = q.inner;
    const words = R.reduceWords(oracle.drawU32s());
    try std.testing.expect(q.drawSecureFelt().eql(@import("../fields/qm31.zig").QM31.fromM31Array(words[0..4].*)));
    const many = try q.drawSecureFelts(std.testing.allocator, 3);
    defer std.testing.allocator.free(many);
    try std.testing.expectEqual(@as(u32, 3), q.inner.n_draws);
    const empty = try q.drawSecureFelts(std.testing.allocator, 0);
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(u32, 3), q.inner.n_draws);
    const wide = try o.drawSecureFelts(std.testing.allocator, 3);
    defer std.testing.allocator.free(wide);
    try std.testing.expectEqual(@as(u32, 3), o.inner.n_draws);
    o.inner.n_draws = std.math.maxInt(u32);
    _ = o.drawSecureFelt();
    try std.testing.expectEqual(@as(u32, 0), o.inner.n_draws);
    q.mixU64(7);
    o.mixU64(7);
    try std.testing.expectEqual(@as(u32, 0), q.inner.n_draws);
    try std.testing.expectEqual(@as(u32, 0), o.inner.n_draws);
}
