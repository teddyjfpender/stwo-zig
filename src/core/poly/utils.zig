const std = @import("std");
const circle = @import("../circle.zig");
const line = @import("line.zig");

pub const Error = error{
    NotEnoughTwiddles,
};

/// Folds values recursively with hierarchical folding factors.
///
/// Preconditions:
/// - `values.len` is a power of two.
/// - `values.len == 1 << folding_factors.len`.
pub fn fold(comptime F: type, values: []const F, folding_factors: []const F) F {
    const n = values.len;
    std.debug.assert(n == (@as(usize, 1) << @intCast(folding_factors.len)));
    if (n == 1) return values[0];

    const half = n / 2;
    const lhs = fold(F, values[0..half], folding_factors[1..]);
    const rhs = fold(F, values[half..], folding_factors[1..]);
    return lhs.add(rhs.mul(folding_factors[0]));
}

/// Computes folding alphas for evaluation-by-folding.
/// Returns values in reverse order: `[double^k(x), ..., x, y]`.
pub fn getFoldingAlphas(
    comptime F: type,
    allocator: std.mem.Allocator,
    point: circle.CirclePoint(F),
    len: usize,
) ![]F {
    const alphas = try allocator.alloc(F, len);
    if (len == 0) return alphas;

    alphas[len - 1] = point.y;
    if (len > 1) {
        var x = point.x;
        var i: usize = len - 1;
        while (i > 0) {
            i -= 1;
            alphas[i] = x;
            x = circle.CirclePoint(F).doubleX(x);
        }
    }
    return alphas;
}

/// Repeats each value `duplicity` times sequentially.
pub fn repeatValue(comptime T: type, allocator: std.mem.Allocator, values: []const T, duplicity: usize) ![]T {
    const out = try allocator.alloc(T, values.len * duplicity);
    var k: usize = 0;
    for (values) |v| {
        var i: usize = 0;
        while (i < duplicity) : (i += 1) {
            out[k] = v;
            k += 1;
        }
    }
    return out;
}

/// Computes line twiddle slices for a domain from a precomputed twiddle tree buffer.
pub fn domainLineTwiddlesFromTree(
    comptime T: type,
    allocator: std.mem.Allocator,
    domain: line.LineDomain,
    twiddle_buffer: []const T,
) Error![][]const T {
    if (domain.coset().size() > twiddle_buffer.len) return Error.NotEnoughTwiddles;

    const log_size = domain.coset().logSize();
    const out = try allocator.alloc([]const T, log_size);
    var i: u32 = 0;
    while (i < log_size) : (i += 1) {
        const len = @as(usize, 1) << @intCast(i);
        const start = twiddle_buffer.len - (len * 2);
        const end = twiddle_buffer.len - len;
        out[log_size - 1 - i] = twiddle_buffer[start..end];
    }
    return out;
}

test "poly utils: repeat value" {
    const out0 = try repeatValue(u32, std.testing.allocator, &[_]u32{ 1, 2, 3 }, 0);
    defer std.testing.allocator.free(out0);
    try std.testing.expectEqual(@as(usize, 0), out0.len);

    const out2 = try repeatValue(u32, std.testing.allocator, &[_]u32{ 1, 2, 3 }, 2);
    defer std.testing.allocator.free(out2);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 1, 2, 2, 3, 3 }, out2);
}

test "poly utils: fold basic" {
    const M31 = @import("../fields/m31.zig").M31;
    const values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    };
    const factors = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(6),
    };
    const got = fold(M31, values[0..], factors[0..]);

    // ((1 + 2*6) + (3 + 4*6)*5)
    const lhs = M31.fromCanonical(1).add(M31.fromCanonical(2).mul(M31.fromCanonical(6)));
    const rhs = M31.fromCanonical(3).add(M31.fromCanonical(4).mul(M31.fromCanonical(6)));
    const expected = lhs.add(rhs.mul(M31.fromCanonical(5)));
    try std.testing.expect(got.eql(expected));
}

test "poly utils: get folding alphas" {
    const M31 = @import("../fields/m31.zig").M31;
    const point: circle.CirclePointM31 = .{
        .x = M31.fromCanonical(9),
        .y = M31.fromCanonical(11),
    };
    const alphas = try getFoldingAlphas(M31, std.testing.allocator, point, 4);
    defer std.testing.allocator.free(alphas);

    try std.testing.expectEqual(@as(usize, 4), alphas.len);
    try std.testing.expect(alphas[3].eql(M31.fromCanonical(11)));
    try std.testing.expect(alphas[2].eql(M31.fromCanonical(9)));
}

test "poly utils: domain line twiddles from tree" {
    const coset = circle.Coset.halfOdds(3);
    const domain = try line.LineDomain.init(coset);
    const twiddles = try domainLineTwiddlesFromTree(u32, std.testing.allocator, domain, &[_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 });
    defer std.testing.allocator.free(twiddles);

    try std.testing.expectEqual(@as(usize, 3), twiddles.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1, 2, 3 }, twiddles[0]);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 4, 5 }, twiddles[1]);
    try std.testing.expectEqualSlices(u32, &[_]u32{6}, twiddles[2]);
}

test "poly utils: domain line twiddles fails on short buffer" {
    const coset = circle.Coset.halfOdds(4);
    const domain = try line.LineDomain.init(coset);
    try std.testing.expectError(
        Error.NotEnoughTwiddles,
        domainLineTwiddlesFromTree(u32, std.testing.allocator, domain, &[_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 }),
    );
}
