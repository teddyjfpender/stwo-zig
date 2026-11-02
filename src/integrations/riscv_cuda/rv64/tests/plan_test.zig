const std = @import("std");
const P = @import("../plan.zig");
test "RV64 CUDA arena regions are aligned disjoint bounded and cover every live plane" {
    for (2..29) |log| {
        const p = try P.Plan.init(@intCast(log), 13);
        const regions = [_]P.Region{ p.tuples, p.weights, p.active, p.challenges, p.leaf_n, p.leaf_d, p.tree, p.fold_n, p.fold_d, p.fold_next_n, p.fold_next_d, p.eq, p.scratch_a, p.scratch_b, p.parameters, p.verdict };
        var end: u64 = 0;
        for (regions) |r| {
            try std.testing.expectEqual(@as(u64, 0), r.offset_words % 64);
            try std.testing.expect(r.words > 0 and r.offset_words >= end);
            end = r.offset_words + r.words;
        }
        try std.testing.expectEqual(end * 4, p.total_bytes);
        try std.testing.expectEqual(@as(u64, p.count - 1) * 16, p.tree.words);
        try std.testing.expectEqual(@as(u64, p.count) * 2, p.fold_next_n.words);
    }
    try std.testing.expectError(error.InvalidGeometry, P.Plan.init(1, 1));
    try std.testing.expectError(error.InvalidGeometry, P.Plan.init(29, 1));
    try std.testing.expectError(error.InvalidGeometry, P.Plan.init(22, 0));
    try std.testing.expectError(error.InvalidGeometry, P.Plan.init(22, 33));
}
