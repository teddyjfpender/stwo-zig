// Real canonical polynomial tables; kept in the native test root so the
// lightweight outer job tests do not import the host prover engine.
const std = @import("std");
const S = @import("outer_staged.zig");
const Image = S.Image;
const Twiddles = S.Twiddles;
const Statics = S.Statics;
const Staged = S.Staged;
const Region = S.Region;

test "twiddle tower shares real canonical suffixes across different height subsets" {
    const a = std.testing.allocator;
    const Tw = @import("stwo_prover_engine").poly.twiddles;
    const core = @import("stwo_core");
    const logs = [_]u32{ 3, 5, 7, 8, 9, 10 };
    var trees: [logs.len]Tw.TwiddleTree([]core.fields.m31.M31) = undefined;
    var made: usize = 0;
    defer for (trees[0..made]) |*tree| Tw.deinitM31(a, tree);
    var all: [29]?Twiddles = @splat(null);
    for (logs, &trees) |log, *tree| {
        tree.* = try Tw.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        made += 1;
        all[log] = .{ .twiddles = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.twiddles)), .itwiddles = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)) };
    }
    var tables_a = all;
    tables_a[9] = null;
    var tables_b = all;
    tables_b[8] = null;
    var image_a = Image{};
    var image_b = Image{};
    for (tables_a, tables_b) |ta, tb| {
        if (ta) |t| {
            _ = image_a.take(.twiddles, t.twiddles.len);
            _ = image_a.take(.twiddles, t.itwiddles.len);
        }
        if (tb) |t| {
            _ = image_b.take(.twiddles, t.twiddles.len);
            _ = image_b.take(.twiddles, t.itwiddles.len);
        }
    }
    const original = image_a;
    const max_a = try image_a.shareTwiddleTower(tables_a);
    const max_b = try image_b.shareTwiddleTower(tables_b);
    try std.testing.expectEqual(@as(?u32, 10), max_a);
    try std.testing.expectEqual(max_a, max_b);
    const region = @intFromEnum(Region.twiddles);
    try std.testing.expect(image_a.words[region] < original.words[region]);
    try std.testing.expectEqual(image_a.words[region], image_b.words[region]);
    const image_words = try a.alloc(u32, @intCast(image_a.words[region]));
    defer a.free(image_words);
    @memset(image_words, 0);
    for (tables_a, 0..) |table, log| if (table) |t| {
        const f = image_a.twiddles[log];
        const inv = image_a.itwiddles[log];
        try std.testing.expectEqual(@as(u64, 0), f.offset % 64);
        try std.testing.expectEqual(@as(u64, 0), inv.offset % 64);
        @memcpy(image_words[@intCast(f.offset)..][0..t.twiddles.len], t.twiddles);
        @memcpy(image_words[@intCast(inv.offset)..][0..t.itwiddles.len], t.itwiddles);
    };
    for (tables_a, 0..) |table, log| if (table) |t| {
        try std.testing.expectEqualSlices(u32, t.twiddles, image_words[@intCast(image_a.twiddles[log].offset)..][0..t.twiddles.len]);
        try std.testing.expectEqualSlices(u32, t.itwiddles, image_words[@intCast(image_a.itwiddles[log].offset)..][0..t.itwiddles.len]);
    };
    var statics_a: Statics = undefined;
    statics_a.tables = tables_a;
    var statics_b: Statics = undefined;
    statics_b.tables = tables_b;
    var staged_a: Staged = undefined;
    staged_a.statics = &statics_a;
    staged_a.image = image_a;
    staged_a.shared_twiddle_log = max_a;
    var staged_b: Staged = undefined;
    staged_b.statics = &statics_b;
    staged_b.image = image_b;
    staged_b.shared_twiddle_log = max_b;
    try std.testing.expectEqualSlices(u8, &staged_a.twiddleRegionKey(), &staged_b.twiddleRegionKey());
    staged_b.shared_twiddle_log = null;
    try std.testing.expect(!std.mem.eql(u8, &staged_a.twiddleRegionKey(), &staged_b.twiddleRegionKey()));
    // A shifted or corrupt table is refused before any image is changed.
    const bad = try a.dupe(u32, all[7].?.twiddles);
    defer a.free(bad);
    bad[0] ^= 1;
    tables_a[7] = .{ .twiddles = bad, .itwiddles = all[7].?.itwiddles };
    var untouched = original;
    try std.testing.expectError(error.InvalidOuterTwiddleTower, untouched.shareTwiddleTower(tables_a));
    try std.testing.expectEqual(original.words, untouched.words);
}
