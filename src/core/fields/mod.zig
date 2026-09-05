const std = @import("std");
const builtin = @import("builtin");

pub const m31 = @import("m31.zig");
pub const cm31 = @import("cm31.zig");
pub const qm31 = @import("qm31.zig");
pub const packed_qm31 = @import("packed_qm31.zig");

/// Inverts all elements in `column` using Montgomery's trick.
///
/// Preconditions:
/// - `dst.len >= column.len`
/// - all elements in `column` are non-zero.
///
/// Failure modes:
/// - Returns an error if any element inversion fails.
pub fn batchInverseInPlace(comptime F: type, column: []const F, dst: []F) !void {
    std.debug.assert(dst.len >= column.len);
    const n = column.len;

    if (comptime F == cm31.CM31 and builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c) {
        if (n >= 32 and (n & 31) == 0) return batchInverseCM31Packed(column, dst, 32);
        if (n >= 16 and (n & 15) == 0) return batchInverseCM31Packed(column, dst, 16);
        if (n >= 8 and (n & 7) == 0) return batchInverseCM31Packed(column, dst, 8);
    }
    if (comptime F == qm31.QM31 and builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c) {
        if (n >= 32 and (n & 31) == 0) return batchInverseQM31Packed(column, dst, 32);
        if (n >= 16 and (n & 15) == 0) return batchInverseQM31Packed(column, dst, 16);
        if (n >= 8 and (n & 7) == 0) return batchInverseQM31Packed(column, dst, 8);
    }
    if (n > 8 and (n & 7) == 0) return batchInverseStriped(F, column, dst, 8);
    if (n > 4 and (n & 3) == 0) return batchInverseStriped(F, column, dst, 4);
    return batchInverseClassic(F, column, dst);
}

fn batchInverseStriped(
    comptime F: type,
    column: []const F,
    dst: []F,
    comptime width: usize,
) !void {
    const n = column.len;
    std.debug.assert(n > width and (n & (width - 1)) == 0);
    var cum_prod: [width]F = undefined;
    for (&cum_prod) |*v| v.* = F.one();

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const lane = i & (width - 1);
        cum_prod[lane] = cum_prod[lane].mul(column[i]);
        dst[i] = cum_prod[lane];
    }

    var tail_inverses: [width]F = undefined;
    try batchInverseClassic(F, dst[n - width .. n], tail_inverses[0..]);

    i = n;
    while (i > width) {
        i -= 1;
        const lane = i & (width - 1);
        dst[i] = dst[i - width].mul(tail_inverses[lane]);
        tail_inverses[lane] = tail_inverses[lane].mul(column[i]);
    }

    @memcpy(dst[0..width], tail_inverses[0..]);
}

const PackedCM31x4 = struct {
    a: m31.Vec4u32,
    b: m31.Vec4u32,
};

inline fn loadPackedCM31x4(ptr: [*]const cm31.CM31) PackedCM31x4 {
    comptime {
        std.debug.assert(@sizeOf(cm31.CM31) == 2 * @sizeOf(u32));
        std.debug.assert(@offsetOf(cm31.CM31, "a") == 0);
        std.debug.assert(@offsetOf(cm31.CM31, "b") == @sizeOf(u32));
    }
    const raw: *const [8]u32 = @ptrCast(ptr);
    const lo: m31.Vec4u32 = raw[0..4].*;
    const hi: m31.Vec4u32 = raw[4..8].*;
    return .{
        .a = @shuffle(u32, lo, hi, @Vector(4, i32){ 0, 2, -1, -3 }),
        .b = @shuffle(u32, lo, hi, @Vector(4, i32){ 1, 3, -2, -4 }),
    };
}

inline fn storePackedCM31x4(ptr: [*]cm31.CM31, value: PackedCM31x4) void {
    const lo = @shuffle(u32, value.a, value.b, @Vector(4, i32){ 0, -1, 1, -2 });
    const hi = @shuffle(u32, value.a, value.b, @Vector(4, i32){ 2, -3, 3, -4 });
    const raw: *[8]u32 = @ptrCast(ptr);
    raw[0..4].* = lo;
    raw[4..8].* = hi;
}

inline fn mulPackedCM31x4(lhs: PackedCM31x4, rhs: PackedCM31x4) PackedCM31x4 {
    const ac = m31.mulVec4(lhs.a, rhs.a);
    const bd = m31.mulVec4(lhs.b, rhs.b);
    const cross = m31.mulVec4(
        m31.addVec4(lhs.a, lhs.b),
        m31.addVec4(rhs.a, rhs.b),
    );
    return .{
        .a = m31.subVec4(ac, bd),
        .b = m31.subVec4(m31.subVec4(cross, ac), bd),
    };
}

/// Montgomery inversion with independent prefix chains packed across CM31
/// values. Each four-element group maps the real and imaginary coordinates to
/// AdvSIMD lanes, so one Karatsuba product advances four chains. Wider batches
/// interleave several vector chains to cover multiply latency; the measured
/// AArch64 optimum is capped at 32 elements to avoid register-spill growth.
fn batchInverseCM31Packed(
    column: []const cm31.CM31,
    dst: []cm31.CM31,
    comptime width: usize,
) !void {
    comptime std.debug.assert(width == 8 or width == 16 or width == 32);
    std.debug.assert(dst.len >= column.len and column.len >= width and (column.len & (width - 1)) == 0);
    const groups = width / 4;
    const one = PackedCM31x4{
        .a = @splat(1),
        .b = @splat(0),
    };
    var cumulative = [_]PackedCM31x4{one} ** groups;
    var base: usize = 0;
    while (base < column.len) : (base += width) {
        inline for (0..groups) |group| {
            cumulative[group] = mulPackedCM31x4(
                cumulative[group],
                loadPackedCM31x4(column.ptr + base + 4 * group),
            );
            storePackedCM31x4(dst.ptr + base + 4 * group, cumulative[group]);
        }
    }

    const tail_products: [width]cm31.CM31 = dst[column.len - width ..][0..width].*;
    var tail_inverses: [width]cm31.CM31 = undefined;
    try batchInverseClassic(cm31.CM31, &tail_products, &tail_inverses);
    var inverse: [groups]PackedCM31x4 = undefined;
    inline for (0..groups) |group| {
        inverse[group] = loadPackedCM31x4((&tail_inverses).ptr + 4 * group);
    }

    var block = column.len;
    while (block > width) {
        block -= width;
        inline for (0..groups) |group| {
            storePackedCM31x4(
                dst.ptr + block + 4 * group,
                mulPackedCM31x4(
                    loadPackedCM31x4(dst.ptr + block - width + 4 * group),
                    inverse[group],
                ),
            );
        }
        inline for (0..groups) |group| {
            inverse[group] = mulPackedCM31x4(
                inverse[group],
                loadPackedCM31x4(column.ptr + block + 4 * group),
            );
        }
    }
    inline for (0..groups) |group| {
        storePackedCM31x4(dst.ptr + 4 * group, inverse[group]);
    }
}

const PackedQM31x4 = struct {
    c0a: m31.Vec4u32,
    c0b: m31.Vec4u32,
    c1a: m31.Vec4u32,
    c1b: m31.Vec4u32,
};

inline fn loadPackedQM31x4(ptr: [*]const qm31.QM31) PackedQM31x4 {
    comptime std.debug.assert(@sizeOf(qm31.QM31) == 4 * @sizeOf(u32));
    const raw: *const [16]u32 = @ptrCast(ptr);
    const row0: m31.Vec4u32 = raw[0..4].*;
    const row1: m31.Vec4u32 = raw[4..8].*;
    const row2: m31.Vec4u32 = raw[8..12].*;
    const row3: m31.Vec4u32 = raw[12..16].*;
    const low01 = @shuffle(u32, row0, row1, @Vector(4, i32){ 0, 1, -1, -2 });
    const high01 = @shuffle(u32, row0, row1, @Vector(4, i32){ 2, 3, -3, -4 });
    const low23 = @shuffle(u32, row2, row3, @Vector(4, i32){ 0, 1, -1, -2 });
    const high23 = @shuffle(u32, row2, row3, @Vector(4, i32){ 2, 3, -3, -4 });
    return .{
        .c0a = @shuffle(u32, low01, low23, @Vector(4, i32){ 0, 2, -1, -3 }),
        .c0b = @shuffle(u32, low01, low23, @Vector(4, i32){ 1, 3, -2, -4 }),
        .c1a = @shuffle(u32, high01, high23, @Vector(4, i32){ 0, 2, -1, -3 }),
        .c1b = @shuffle(u32, high01, high23, @Vector(4, i32){ 1, 3, -2, -4 }),
    };
}

inline fn storePackedQM31x4(ptr: [*]qm31.QM31, value: PackedQM31x4) void {
    const low01 = @shuffle(u32, value.c0a, value.c0b, @Vector(4, i32){ 0, 1, -1, -2 });
    const high01 = @shuffle(u32, value.c0a, value.c0b, @Vector(4, i32){ 2, 3, -3, -4 });
    const low23 = @shuffle(u32, value.c1a, value.c1b, @Vector(4, i32){ 0, 1, -1, -2 });
    const high23 = @shuffle(u32, value.c1a, value.c1b, @Vector(4, i32){ 2, 3, -3, -4 });
    const raw: *[16]u32 = @ptrCast(ptr);
    raw[0..4].* = @shuffle(u32, low01, low23, @Vector(4, i32){ 0, 2, -1, -3 });
    raw[4..8].* = @shuffle(u32, low01, low23, @Vector(4, i32){ 1, 3, -2, -4 });
    raw[8..12].* = @shuffle(u32, high01, high23, @Vector(4, i32){ 0, 2, -1, -3 });
    raw[12..16].* = @shuffle(u32, high01, high23, @Vector(4, i32){ 1, 3, -2, -4 });
}

inline fn mulPackedQM31x4(lhs: PackedQM31x4, rhs: PackedQM31x4) PackedQM31x4 {
    const lhs_c0 = PackedCM31x4{ .a = lhs.c0a, .b = lhs.c0b };
    const lhs_c1 = PackedCM31x4{ .a = lhs.c1a, .b = lhs.c1b };
    const rhs_c0 = PackedCM31x4{ .a = rhs.c0a, .b = rhs.c0b };
    const rhs_c1 = PackedCM31x4{ .a = rhs.c1a, .b = rhs.c1b };
    const ac = mulPackedCM31x4(lhs_c0, rhs_c0);
    const bd = mulPackedCM31x4(lhs_c1, rhs_c1);
    const cross = mulPackedCM31x4(
        .{
            .a = m31.addVec4(lhs.c0a, lhs.c1a),
            .b = m31.addVec4(lhs.c0b, lhs.c1b),
        },
        .{
            .a = m31.addVec4(rhs.c0a, rhs.c1a),
            .b = m31.addVec4(rhs.c0b, rhs.c1b),
        },
    );
    const cross_minus_products = PackedCM31x4{
        .a = m31.subVec4(m31.subVec4(cross.a, ac.a), bd.a),
        .b = m31.subVec4(m31.subVec4(cross.b, ac.b), bd.b),
    };
    const rbd = PackedCM31x4{
        .a = m31.subVec4(m31.addVec4(bd.a, bd.a), bd.b),
        .b = m31.addVec4(bd.a, m31.addVec4(bd.b, bd.b)),
    };
    return .{
        .c0a = m31.addVec4(ac.a, rbd.a),
        .c0b = m31.addVec4(ac.b, rbd.b),
        .c1a = cross_minus_products.a,
        .c1b = cross_minus_products.b,
    };
}

/// Montgomery inversion with four independent QM31 products in each AdvSIMD
/// operation. The chain schedule is identical to the packed CM31 path above.
fn batchInverseQM31Packed(
    column: []const qm31.QM31,
    dst: []qm31.QM31,
    comptime width: usize,
) !void {
    @setEvalBranchQuota(16_000);
    comptime std.debug.assert(width == 8 or width == 16 or width == 32);
    std.debug.assert(dst.len >= column.len and column.len >= width and (column.len & (width - 1)) == 0);
    const groups = width / 4;
    const one = PackedQM31x4{
        .c0a = @splat(1),
        .c0b = @splat(0),
        .c1a = @splat(0),
        .c1b = @splat(0),
    };
    var cumulative = [_]PackedQM31x4{one} ** groups;
    var base: usize = 0;
    while (base < column.len) : (base += width) {
        inline for (0..groups) |group| {
            cumulative[group] = mulPackedQM31x4(
                cumulative[group],
                loadPackedQM31x4(column.ptr + base + 4 * group),
            );
            storePackedQM31x4(
                dst.ptr + base + 4 * group,
                cumulative[group],
            );
        }
    }

    const tail_products: [width]qm31.QM31 =
        dst[column.len - width ..][0..width].*;
    var tail_inverses: [width]qm31.QM31 = undefined;
    try batchInverseClassic(qm31.QM31, &tail_products, &tail_inverses);
    var inverse: [groups]PackedQM31x4 = undefined;
    inline for (0..groups) |group| {
        inverse[group] = loadPackedQM31x4(
            (&tail_inverses).ptr + 4 * group,
        );
    }

    var block = column.len;
    while (block > width) {
        block -= width;
        inline for (0..groups) |group| {
            storePackedQM31x4(
                dst.ptr + block + 4 * group,
                mulPackedQM31x4(
                    loadPackedQM31x4(
                        dst.ptr + block - width + 4 * group,
                    ),
                    inverse[group],
                ),
            );
        }
        inline for (0..groups) |group| {
            inverse[group] = mulPackedQM31x4(
                inverse[group],
                loadPackedQM31x4(column.ptr + block + 4 * group),
            );
        }
    }
    inline for (0..groups) |group| {
        storePackedQM31x4(dst.ptr + 4 * group, inverse[group]);
    }
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

fn randNonZeroM31(rng: std.Random) m31.M31 {
    while (true) {
        const x = rng.int(u32) & m31.Modulus;
        if (x != m31.Modulus and x != 0) return m31.M31.fromCanonical(x);
    }
}

fn randNonZeroQM31(rng: std.Random) qm31.QM31 {
    while (true) {
        const value = qm31.QM31.fromU32Unchecked(
            rng.intRangeLessThan(u32, 0, m31.Modulus),
            rng.intRangeLessThan(u32, 0, m31.Modulus),
            rng.intRangeLessThan(u32, 0, m31.Modulus),
            rng.intRangeLessThan(u32, 0, m31.Modulus),
        );
        if (!value.isZero()) return value;
    }
}

test "fields: batch inverse matches scalar inverse (m31)" {
    var prng = std.Random.DefaultPrng.init(0x91f1_7244_6800_5c3a);
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
    var prng = std.Random.DefaultPrng.init(0x32c8_4457_f1ab_9920);
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

test "fields: packed QM31 batch inverse matches scalar inverse" {
    var prng = std.Random.DefaultPrng.init(0xa44f_977e_7f3d_d21c);
    const rng = prng.random();

    var elements: [64]qm31.QM31 = undefined;
    for (&elements) |*element| element.* = randNonZeroQM31(rng);

    var actual: [64]qm31.QM31 = undefined;
    try batchInverseInPlace(qm31.QM31, &elements, &actual);
    for (elements, actual) |element, inverse| {
        try std.testing.expect(inverse.eql(try element.inv()));
    }
}
