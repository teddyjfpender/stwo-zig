const circle = @import("../../core/circle.zig");

const Coset = circle.Coset;

/// Precomputed twiddles for a specific coset tower.
///
/// A coset tower is every repeated doubling of `root_coset`.
/// The largest circle domain supported by these twiddles is one with
/// `root_coset` as its half-coset.
pub fn TwiddleTree(comptime TwiddlesType: type) type {
    return struct {
        root_coset: Coset,
        twiddles: TwiddlesType,
        itwiddles: TwiddlesType,

        const Self = @This();

        pub fn init(root_coset: Coset, twiddles: TwiddlesType, itwiddles: TwiddlesType) Self {
            return .{
                .root_coset = root_coset,
                .twiddles = twiddles,
                .itwiddles = itwiddles,
            };
        }
    };
}

test "twiddle tree: stores root coset and twiddles" {
    const std = @import("std");
    const T = TwiddleTree([]const u32);

    const root = Coset.halfOdds(4);
    const tree = T.init(root, &[_]u32{ 1, 2, 3 }, &[_]u32{ 4, 5, 6 });

    try std.testing.expectEqual(root.log_size, tree.root_coset.log_size);
    try std.testing.expectEqual(@as(usize, 3), tree.twiddles.len);
    try std.testing.expectEqual(@as(usize, 3), tree.itwiddles.len);
    try std.testing.expectEqual(@as(u32, 2), tree.twiddles[1]);
    try std.testing.expectEqual(@as(u32, 5), tree.itwiddles[1]);
}
