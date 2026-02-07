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

    return switch (prev) {
        null => layer,
        else => |p| switch (layer) {
            null => p,
            else => |l| @min(p, l),
        },
    };
}

test "vcs utils: next decommitment node picks min source" {
    const prev = [_]usize{ 6, 7, 10 };
    const layer = [_]usize{ 4, 8 };
    try @import("std").testing.expectEqual(@as(?usize, 3), nextDecommitmentNode(prev[0..], 0, layer[0..], 0));
    try @import("std").testing.expectEqual(@as(?usize, 4), nextDecommitmentNode(prev[0..], 2, layer[0..], 0));
    try @import("std").testing.expectEqual(@as(?usize, 5), nextDecommitmentNode(prev[0..], 2, layer[0..], 1));
    try @import("std").testing.expectEqual(@as(?usize, null), nextDecommitmentNode(prev[0..], prev.len, layer[0..], layer.len));
}
