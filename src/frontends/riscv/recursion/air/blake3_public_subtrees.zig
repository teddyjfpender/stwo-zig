//! Canonical dyadic cover of independently admitted public word replacements.
//! Every covered word has an explicit old/new public value. No gap, untouched
//! word, or private sibling is absorbed into a public subtree digest.
const std = @import("std");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
pub const Edit = @import("blake3_memory_update_chain.zig").Edit;
pub const Range = struct {
    address: u32,
    height: u5,
    first_edit: usize,
    count: usize,
    before: tree.Digest,
    after: tree.Digest,
};
pub fn cover(a: std.mem.Allocator, edits: []const Edit) ![]Range {
    for (edits, 0..) |edit, i| {
        if (edit.address >= tree.MEMORY_WORD_LIMIT or (i != 0 and edits[i - 1].address >= edit.address))
            return error.InvalidPublicSubtreeEdits;
    }
    var result: std.ArrayList(Range) = .empty;
    errdefer result.deinit(a);
    const hasher = tree.TreeHasher.init(.memory);
    var first: usize = 0;
    while (first < edits.len) {
        var end = first + 1;
        while (end < edits.len and edits[end].address == edits[end - 1].address + 1) : (end += 1) {}
        while (first < end) {
            const address = edits[first].address;
            const aligned: u32 = if (address == 0) 28 else @min(28, @ctz(address));
            const height: u5 = @intCast(@min(aligned, std.math.log2_int(usize, end - first)));
            const count = @as(usize, 1) << height;
            const values = edits[first..][0..count];
            try result.append(a, .{
                .address = address,
                .height = height,
                .first_edit = first,
                .count = count,
                .before = digest(&hasher, values, false),
                .after = digest(&hasher, values, true),
            });
            first += count;
        }
    }
    return result.toOwnedSlice(a);
}
fn digest(hasher: *const tree.TreeHasher, edits: []const Edit, comptime after: bool) tree.Digest {
    if (edits.len == 1) return hasher.leaf(if (after) edits[0].after else edits[0].before);
    const half = edits.len / 2;
    return hasher.pair(digest(hasher, edits[0..half], after), digest(hasher, edits[half..], after));
}
/// Independent admission: all range geometry and both digests are recomputed
/// from the authenticated public words, never from a received range hash.
pub fn admit(a: std.mem.Allocator, edits: []const Edit, ranges: []const Range) !void {
    const expected = try cover(a, edits);
    defer a.free(expected);
    if (expected.len != ranges.len) return error.UntrustedPublicSubtrees;
    for (expected, ranges) |wanted, actual| if (!std.meta.eql(wanted, actual)) return error.UntrustedPublicSubtrees;
}

test "public subtree cover matches sparse tree hashes without absorbing gaps" {
    const a = std.testing.allocator;
    const edits = [_]Edit{
        .{ .address = 4, .before = 0, .after = 10 },
        .{ .address = 5, .before = 0, .after = 11 },
        .{ .address = 6, .before = 0, .after = 0 },
        .{ .address = 7, .before = 0, .after = 13 },
        .{ .address = 9, .before = 19, .after = 20 },
    };
    const ranges = try cover(a, &edits);
    defer a.free(ranges);
    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try std.testing.expectEqual(@as(u5, 2), ranges[0].height);
    var leaves: [edits.len]tree.Leaf = undefined;
    for (edits, &leaves) |edit, *leaf| leaf.* = .{ .index = edit.address, .value = edit.after };
    const hasher = tree.TreeHasher.init(.memory);
    for (ranges) |range| {
        var actual: [1]tree.Digest = undefined;
        try hasher.subtreeRoots(&leaves, &.{.{ .level = range.height, .index = range.address >> range.height }}, &actual);
        try std.testing.expectEqualDeep(actual[0], range.after);
    }
    try admit(a, &edits, ranges);
    ranges[0].after.bytes[31] ^= 1;
    try std.testing.expectError(error.UntrustedPublicSubtrees, admit(a, &edits, ranges));
    try std.testing.expectError(error.InvalidPublicSubtreeEdits, cover(a, &.{ edits[0], edits[0] }));
}
test "public subtree cover scales with the boundary of a large public input" {
    const a = std.testing.allocator;
    const edits = try a.alloc(Edit, 675173);
    defer a.free(edits);
    for (edits, 0..) |*edit, i| edit.* = .{ .address = @intCast(1024 + i), .before = 0, .after = @truncate(i * 13) };
    const ranges = try cover(a, edits);
    defer a.free(ranges);
    try std.testing.expect(ranges.len <= 56);
    var count: usize = 0;
    var path_hashes: usize = 0;
    for (ranges) |range| {
        try std.testing.expectEqual(count, range.first_edit);
        count += range.count;
        path_hashes += 2 * (tree.DEPTH - @as(usize, range.height));
    }
    try std.testing.expectEqual(edits.len, count);
    try std.testing.expect(path_hashes < 2000);
    std.debug.print("PUBLIC_SUBTREE_PLAN words={d} ranges={d} path_hashes={d} old_path_hashes={d}\n", .{ edits.len, ranges.len, path_hashes, 2 * tree.DEPTH * edits.len });
}
