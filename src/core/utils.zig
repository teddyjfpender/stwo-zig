const std = @import("std");

pub fn allUnique(comptime T: type, allocator: std.mem.Allocator, values: []const T) !bool {
    var used = std.AutoHashMap(T, void).init(allocator);
    defer used.deinit();

    for (values) |v| {
        if (used.contains(v)) return false;
        try used.put(v, {});
    }
    return true;
}

/// Returns the bit-reversed index of `i` represented with `log_size` bits.
pub fn bitReverseIndex(i: usize, log_size: u32) usize {
    if (log_size == 0) return i;
    return @bitReverse(i) >> @intCast(@bitSizeOf(usize) - log_size);
}

/// Performs a naive in-place bit-reversal permutation.
///
/// Preconditions:
/// - `v.len` is a power of two.
pub fn bitReverse(comptime T: type, v: []T) void {
    const n = v.len;
    std.debug.assert(n != 0 and (n & (n - 1)) == 0);
    const log_n: u32 = @intCast(std.math.log2_int(usize, n));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const j = bitReverseIndex(i, log_n);
        if (j > i) {
            std.mem.swap(T, &v[i], &v[j]);
        }
    }
}

pub fn previousBitReversedCircleDomainIndex(
    i: usize,
    domain_log_size: u32,
    eval_log_size: u32,
) usize {
    return offsetBitReversedCircleDomainIndex(i, domain_log_size, eval_log_size, -1);
}

pub fn offsetBitReversedCircleDomainIndex(
    i: usize,
    domain_log_size: u32,
    eval_log_size: u32,
    offset: isize,
) usize {
    var prev_index = bitReverseIndex(i, eval_log_size);
    const half_size: usize = @as(usize, 1) << @intCast(eval_log_size - 1);
    const step_unit: usize = @as(usize, 1) << @intCast(eval_log_size - domain_log_size - 1);
    const step_size: isize = offset * @as(isize, @intCast(step_unit));
    const half_size_isize: isize = @intCast(half_size);

    if (prev_index < half_size) {
        const shifted: isize = @as(isize, @intCast(prev_index)) + step_size;
        prev_index = @intCast(@mod(shifted, half_size_isize));
    } else {
        const shifted: isize = @as(isize, @intCast(prev_index)) - step_size;
        prev_index = @as(usize, @intCast(@mod(shifted, half_size_isize))) + half_size;
    }

    return bitReverseIndex(prev_index, eval_log_size);
}

pub fn circleDomainOrderToCosetOrder(comptime F: type, allocator: std.mem.Allocator, values: []const F) ![]F {
    const n = values.len;
    const out = try allocator.alloc(F, n);
    errdefer allocator.free(out);

    var out_i: usize = 0;
    var i: usize = 0;
    while (i < n / 2) : (i += 1) {
        out[out_i] = values[i];
        out[out_i + 1] = values[n - 1 - i];
        out_i += 2;
    }
    return out;
}

pub fn cosetOrderToCircleDomainOrder(comptime F: type, allocator: std.mem.Allocator, values: []const F) ![]F {
    const n = values.len;
    const half_len = n / 2;
    const out = try allocator.alloc(F, n);
    errdefer allocator.free(out);

    var i: usize = 0;
    while (i < half_len) : (i += 1) {
        out[i] = values[i << 1];
    }
    i = 0;
    while (i < half_len) : (i += 1) {
        out[half_len + i] = values[n - 1 - (i << 1)];
    }
    return out;
}

pub fn circleDomainIndexToCosetIndex(circle_index: usize, log_domain_size: u32) usize {
    const n: usize = @as(usize, 1) << @intCast(log_domain_size);
    if (circle_index < n / 2) {
        return circle_index * 2;
    }
    return (n - 1 - circle_index) * 2 + 1;
}

pub fn cosetIndexToCircleDomainIndex(coset_index: usize, log_domain_size: u32) usize {
    if ((coset_index & 1) == 0) {
        return coset_index / 2;
    }
    return ((@as(usize, 2) << @intCast(log_domain_size)) - coset_index) / 2;
}

/// Performs a coset-natural-order to circle-domain-bit-reversed-order permutation in-place.
///
/// Preconditions:
/// - `v.len` is a power of two.
pub fn bitReverseCosetToCircleDomainOrder(comptime T: type, v: []T) void {
    const n = v.len;
    std.debug.assert(n != 0 and (n & (n - 1)) == 0);
    const log_n: u32 = @intCast(std.math.log2_int(usize, n));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const j = bitReverseIndex(cosetIndexToCircleDomainIndex(i, log_n), log_n);
        if (j > i) {
            std.mem.swap(T, &v[i], &v[j]);
        }
    }
}

test "utils: bit reverse index and permutation" {
    try std.testing.expectEqual(@as(usize, 6), bitReverseIndex(3, 3));

    var values = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    bitReverse(u32, values[0..]);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 4, 2, 6, 1, 5, 3, 7 }, values[0..]);
}

test "utils: offset bit reversed index matches repeated previous" {
    const domain_log_size: u32 = 3;
    const eval_log_size: u32 = 6;
    const initial_index: usize = 5;

    const actual = offsetBitReversedCircleDomainIndex(initial_index, domain_log_size, eval_log_size, -2);
    const prev = previousBitReversedCircleDomainIndex(initial_index, domain_log_size, eval_log_size);
    const prev2 = previousBitReversedCircleDomainIndex(prev, domain_log_size, eval_log_size);
    try std.testing.expectEqual(prev2, actual);
}

test "utils: circle and coset index conversion are inverses" {
    const log_size: u32 = 3;
    const n: usize = @as(usize, 1) << @intCast(log_size);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const coset_idx = circleDomainIndexToCosetIndex(i, log_size);
        const circle_idx = cosetIndexToCircleDomainIndex(coset_idx, log_size);
        try std.testing.expectEqual(i, circle_idx);
    }
}

test "utils: coset-order roundtrip" {
    const src = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const coset = try circleDomainOrderToCosetOrder(u32, std.testing.allocator, src[0..]);
    defer std.testing.allocator.free(coset);
    const back = try cosetOrderToCircleDomainOrder(u32, std.testing.allocator, coset);
    defer std.testing.allocator.free(back);
    try std.testing.expectEqualSlices(u32, src[0..], back);
}

test "utils: bit reverse coset to circle domain order" {
    var values = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    bitReverseCosetToCircleDomainOrder(u32, values[0..]);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 6, 2, 4, 1, 7, 3, 5 }, values[0..]);
}
