const std = @import("std");

pub const m31 = @import("m31.zig");
pub const cm31 = @import("cm31.zig");
pub const qm31 = @import("qm31.zig");

/// Inverts all elements in `column` using Montgomery's trick.
///
/// Preconditions:
/// - `dst.len >= column.len`
/// - all elements in `column` are non-zero.
///
/// Failure modes:
/// - Returns an error if any element inversion fails.
pub fn batchInverseInPlace(comptime F: type, column: []const F, dst: []F) !void {
    const width: usize = 4;
    std.debug.assert(dst.len >= column.len);
    const n = column.len;

    if (n <= width or (n % width) != 0) {
        try batchInverseClassic(F, column, dst);
        return;
    }

    var cum_prod: [width]F = undefined;
    for (&cum_prod) |*v| v.* = F.one();

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const lane = i % width;
        cum_prod[lane] = cum_prod[lane].mul(column[i]);
        dst[i] = cum_prod[lane];
    }

    var tail_inverses: [width]F = undefined;
    try batchInverseClassic(F, dst[n - width .. n], tail_inverses[0..]);

    i = n;
    while (i > width) {
        i -= 1;
        const lane = i % width;
        dst[i] = dst[i - width].mul(tail_inverses[lane]);
        tail_inverses[lane] = tail_inverses[lane].mul(column[i]);
    }

    @memcpy(dst[0..width], tail_inverses[0..]);
}

pub fn batchInverse(comptime F: type, allocator: std.mem.Allocator, column: []const F) ![]F {
    const out = try allocator.alloc(F, column.len);
    errdefer allocator.free(out);
    try batchInverseInPlace(F, column, out);
    return out;
}

pub fn batchInverseChunked(
    comptime F: type,
    column: []const F,
    dst: []F,
    chunk_size: usize,
) !void {
    std.debug.assert(chunk_size > 0);
    std.debug.assert(dst.len >= column.len);

    var start: usize = 0;
    while (start < column.len) : (start += chunk_size) {
        const end = @min(start + chunk_size, column.len);
        try batchInverseInPlace(F, column[start..end], dst[start..end]);
    }
}

fn batchInverseClassic(comptime F: type, column: []const F, dst: []F) !void {
    std.debug.assert(dst.len >= column.len);
    const n = column.len;
    if (n == 0) return;

    dst[0] = column[0];
    var i: usize = 1;
    while (i < n) : (i += 1) {
        dst[i] = dst[i - 1].mul(column[i]);
    }

    var curr_inverse = try dst[n - 1].inv();
    i = n;
    while (i > 1) {
        i -= 1;
        dst[i] = dst[i - 1].mul(curr_inverse);
        curr_inverse = curr_inverse.mul(column[i]);
    }
    dst[0] = curr_inverse;
}

test {
    _ = @import("parity_vectors.zig");
}

fn randNonZeroM31(rng: std.rand.Random) m31.M31 {
    while (true) {
        const x = rng.int(u32) & m31.Modulus;
        if (x != m31.Modulus and x != 0) return m31.M31.fromCanonical(x);
    }
}

test "fields: batch inverse matches scalar inverse (m31)" {
    var prng = std.rand.DefaultPrng.init(0x91f1_7244_6800_5c3a);
    const rng = prng.random();

    var elements: [16]m31.M31 = undefined;
    for (&elements) |*e| e.* = randNonZeroM31(rng);

    const actual = try batchInverse(m31.M31, std.testing.allocator, elements[0..]);
    defer std.testing.allocator.free(actual);

    for (elements, 0..) |e, i| {
        try std.testing.expect(actual[i].eql(try e.inv()));
    }
}

test "fields: batch inverse chunked matches batch inverse (m31)" {
    var prng = std.rand.DefaultPrng.init(0x32c8_4457_f1ab_9920);
    const rng = prng.random();

    var elements: [16]m31.M31 = undefined;
    for (&elements) |*e| e.* = randNonZeroM31(rng);

    const expected = try batchInverse(m31.M31, std.testing.allocator, elements[0..]);
    defer std.testing.allocator.free(expected);

    var actual: [16]m31.M31 = undefined;
    try batchInverseChunked(m31.M31, elements[0..], actual[0..], 4);

    for (expected, 0..) |e, i| {
        try std.testing.expect(actual[i].eql(e));
    }
}
