const std = @import("std");

pub fn nextDecommitmentNode(
    prev_queries: []const usize,
    prev_queries_at: usize,
    layer_queries: []const usize,
    layer_queries_at: usize,
) ?usize {
    const prev = if (prev_queries_at < prev_queries.len)
        prev_queries[prev_queries_at] / 2
    else
        null;
    const layer = if (layer_queries_at < layer_queries.len)
        layer_queries[layer_queries_at]
    else
        null;

    if (prev) |p| {
        if (layer) |l| return @min(p, l);
        return p;
    }
    return layer;
}

/// Returns `slice` if present, otherwise an empty slice.
pub fn optionFlattenSlice(slice: ?[]const usize) []const usize {
    return slice orelse &[_]usize{};
}

/// Injects `n_packed_elements` into the bits [248:251] of `word`.
///
/// Preconditions for no-wrap semantics:
/// - `n_packed_elements < 8`
/// - `word < 2^248`
pub fn addLengthPadding(word: *u256, n_packed_elements: usize) void {
    std.debug.assert(n_packed_elements < 8);
    word.* += (@as(u256, @intCast(n_packed_elements)) << 248);
}

test "vcs utils: next decommitment node picks min source" {
    const prev = [_]usize{ 6, 7, 10 };
    const layer = [_]usize{ 4, 8 };
    try std.testing.expectEqual(@as(?usize, 3), nextDecommitmentNode(prev[0..], 0, layer[0..], 0));
    try std.testing.expectEqual(@as(?usize, 4), nextDecommitmentNode(prev[0..], 2, layer[0..], 0));
    try std.testing.expectEqual(@as(?usize, 5), nextDecommitmentNode(prev[0..], 2, layer[0..], 1));
    try std.testing.expectEqual(@as(?usize, null), nextDecommitmentNode(prev[0..], prev.len, layer[0..], layer.len));
}

test "vcs utils: option flatten slice" {
    const values = [_]usize{ 1, 4, 9 };
    try std.testing.expectEqualSlices(usize, values[0..], optionFlattenSlice(values[0..]));
    try std.testing.expectEqual(@as(usize, 0), optionFlattenSlice(null).len);
}

test "vcs utils: add length padding" {
    var word: u256 = 0x1234;
    addLengthPadding(&word, 5);
    try std.testing.expectEqual(@as(u256, 5), word >> 248);
    try std.testing.expectEqual(@as(u256, 0x1234), word & 0xffff);
}
