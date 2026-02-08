const std = @import("std");
const circle = @import("../../core/circle.zig");
const fields = @import("../../core/fields/mod.zig");
const m31 = @import("../../core/fields/m31.zig");
const utils = @import("../../core/utils.zig");

const Coset = circle.Coset;
const M31 = m31.M31;

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

pub const TwiddleError = error{
    SingularTwiddle,
};

pub fn precomputeM31(
    allocator: std.mem.Allocator,
    root_coset: Coset,
) (std.mem.Allocator.Error || TwiddleError)!TwiddleTree([]M31) {
    const chunk_size: usize = 1 << 12;
    const twiddles = try slowPrecomputeM31Twiddles(allocator, root_coset);
    errdefer allocator.free(twiddles);

    const itwiddles = try allocator.alloc(M31, twiddles.len);
    errdefer allocator.free(itwiddles);

    if (chunk_size > root_coset.size()) {
        for (twiddles, 0..) |twid, i| {
            itwiddles[i] = twid.inv() catch return TwiddleError.SingularTwiddle;
        }
    } else {
        fields.batchInverseChunked(M31, twiddles, itwiddles, chunk_size) catch {
            return TwiddleError.SingularTwiddle;
        };
    }

    return TwiddleTree([]M31).init(root_coset, twiddles, itwiddles);
}

pub fn deinitM31(allocator: std.mem.Allocator, tree: *TwiddleTree([]M31)) void {
    allocator.free(tree.twiddles);
    allocator.free(tree.itwiddles);
    tree.* = undefined;
}

fn slowPrecomputeM31Twiddles(
    allocator: std.mem.Allocator,
    root_coset: Coset,
) ![]M31 {
    var coset = root_coset;
    const out = try allocator.alloc(M31, root_coset.size());

    var at: usize = 0;
    var i: u32 = 0;
    while (i < root_coset.logSize()) : (i += 1) {
        const layer_len = coset.size() / 2;
        var it = coset.iter();
        var j: usize = 0;
        while (j < layer_len) : (j += 1) {
            out[at + j] = it.next().?.x;
        }
        utils.bitReverse(M31, out[at .. at + layer_len]);
        at += layer_len;
        coset = coset.double();
    }

    std.debug.assert(at + 1 == out.len);
    out[at] = M31.one();
    return out;
}

test "twiddle tree: stores root coset and twiddles" {
    const T = TwiddleTree([]const u32);

    const root = Coset.halfOdds(4);
    const tree = T.init(root, &[_]u32{ 1, 2, 3 }, &[_]u32{ 4, 5, 6 });

    try std.testing.expectEqual(root.log_size, tree.root_coset.log_size);
    try std.testing.expectEqual(@as(usize, 3), tree.twiddles.len);
    try std.testing.expectEqual(@as(usize, 3), tree.itwiddles.len);
    try std.testing.expectEqual(@as(u32, 2), tree.twiddles[1]);
    try std.testing.expectEqual(@as(u32, 5), tree.itwiddles[1]);
}

test "twiddle tree: precompute m31 twiddles and inverses" {
    const alloc = std.testing.allocator;
    var tree = try precomputeM31(alloc, Coset.halfOdds(5));
    defer deinitM31(alloc, &tree);

    try std.testing.expectEqual(tree.twiddles.len, tree.itwiddles.len);
    try std.testing.expectEqual(@as(usize, Coset.halfOdds(5).size()), tree.twiddles.len);

    for (tree.twiddles, tree.itwiddles) |twid, itwid| {
        try std.testing.expect(twid.mul(itwid).eql(M31.one()));
    }
}

test "twiddle tree: precompute m31 uses chunked inverse path for large domains" {
    const alloc = std.testing.allocator;
    var tree = try precomputeM31(alloc, Coset.halfOdds(13));
    defer deinitM31(alloc, &tree);

    try std.testing.expectEqual(@as(usize, Coset.halfOdds(13).size()), tree.twiddles.len);
    try std.testing.expectEqual(tree.twiddles.len, tree.itwiddles.len);

    var i: usize = 0;
    while (i < tree.twiddles.len) : (i += 521) {
        try std.testing.expect(tree.twiddles[i].mul(tree.itwiddles[i]).eql(M31.one()));
    }
}
