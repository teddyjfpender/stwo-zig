//! Destructive scaled batch inversion through the base-field norm.
//! The caller owns all three disjoint planes. Inputs become striped norm/prefix
//! scratch; output contains scale[i] / original_input[i], including zero scales.
const std = @import("std");
const QM31 = @import("qm31.zig").QM31;
const CM31 = @import("cm31.zig").CM31;
const M31 = @import("m31.zig").M31;
const m31 = @import("m31.zig");
const packed_fields = @import("packed_extensions.zig");

pub fn invertScaledOwned(column: []QM31, destination: []QM31, scales: []const M31) error{ InvalidBatchGeometry, DivisionByZero }!void {
    if (column.len != destination.len or column.len != scales.len) return error.InvalidBatchGeometry;
    if (overlap(column, destination) or overlap(column, scales) or overlap(destination, scales)) return error.InvalidBatchGeometry;
    if (column.len == 0) return;

    // q = a + bu; d = a² - (2+i)b². The cofactor
    // (a-bu) conjugate(d) divided by d.a²+d.b² is exactly q^-1.
    // Compute cofactors independently before introducing the prefix chain.
    var first: usize = 0;
    while (first + 4 <= column.len) : (first += 4) {
        const q = packed_fields.loadPackedQM31x4(column.ptr + first);
        const a2 = square(.{ .a = q.c0a, .b = q.c0b });
        const b2 = square(.{ .a = q.c1a, .b = q.c1b });
        const da = m31.subVec4(a2.a, m31.subVec4(m31.addVec4(b2.a, b2.a), b2.b));
        const db = m31.subVec4(a2.b, m31.addVec4(b2.a, m31.addVec4(b2.b, b2.b)));
        const norm = m31.addVec4(m31.mulVec4(da, da), m31.mulVec4(db, db));
        if (@reduce(.Or, norm == @as(m31.Vec4u32, @splat(0)))) return error.DivisionByZero;
        const conjugate = packed_fields.PackedCM31x4{ .a = da, .b = m31.subVec4(@splat(0), db) };
        const c0 = packed_fields.mulPackedCM31x4(.{ .a = q.c0a, .b = q.c0b }, conjugate);
        const c1 = packed_fields.mulPackedCM31x4(.{ .a = m31.subVec4(@splat(0), q.c1a), .b = m31.subVec4(@splat(0), q.c1b) }, conjugate);
        packed_fields.storePackedQM31x4(destination.ptr + first, .{ .c0a = c0.a, .c0b = c0.b, .c1a = c1.a, .c1b = c1.b });
        packed_fields.storePackedQM31x4(column.ptr + first, .{ .c0a = norm, .c0b = @splat(0), .c1a = @splat(0), .c1b = @splat(0) });
    }
    for (column[first..], destination[first..]) |*value, *cofactor| {
        const q = value.*;
        const b2 = q.c1.square();
        const r_b2 = b2.add(b2).add(CM31.fromM31(b2.b.neg(), b2.a));
        const d = q.c0.square().sub(r_b2);
        const norm = d.a.square().add(d.b.square());
        if (norm.isZero()) return error.DivisionByZero;
        const conjugate = CM31.fromM31(d.a, d.b.neg());
        cofactor.* = .{ .c0 = q.c0.mul(conjugate), .c1 = q.c1.neg().mul(conjugate) };
        value.* = QM31.fromM31(norm, M31.zero(), M31.zero(), M31.zero());
    }

    // Eight independent base-field chains avoid a full serial prefix while
    // using the original input plane for all per-element scratch.
    const width = 8;
    var products = [_]M31{M31.one()} ** width;
    for (column, 0..) |*value, index| {
        const lane = index & (width - 1);
        const norm = value.c0.a;
        value.c0 = CM31.fromM31(products[lane], norm);
        products[lane] = products[lane].mul(norm);
    }
    var prefixes: [width]M31 = undefined;
    var product = M31.one();
    for (products, &prefixes) |value, *prefix| {
        prefix.* = product;
        product = product.mul(value);
    }
    var inverse = product.inv() catch return error.DivisionByZero;
    var inverses: [width]M31 align(@alignOf(m31.Vec4u32)) = undefined;
    var lane: usize = width;
    while (lane != 0) {
        lane -= 1;
        inverses[lane] = inverse.mul(prefixes[lane]);
        inverse = inverse.mul(products[lane]);
    }
    var index = column.len;
    while (index & 3 != 0) {
        index -= 1;
        const stripe = index & (width - 1);
        const scaled_inverse = inverses[stripe].mul(column[index].c0.a).mul(scales[index]);
        destination[index] = destination[index].mulM31(scaled_inverse);
        inverses[stripe] = inverses[stripe].mul(column[index].c0.b);
    }
    while (index != 0) {
        index -= 4;
        const stripe = index & (width - 1);
        const prefix = packed_fields.loadPackedQM31x4(column.ptr + index);
        const running = m31.loadVec4(@ptrCast((&inverses).ptr + stripe));
        const factor = m31.mulVec4(m31.mulVec4(running, prefix.c0a), m31.loadVec4(@ptrCast(scales.ptr + index)));
        const cofactor = packed_fields.loadPackedQM31x4(destination.ptr + index);
        packed_fields.storePackedQM31x4(destination.ptr + index, .{
            .c0a = m31.mulVec4(cofactor.c0a, factor),
            .c0b = m31.mulVec4(cofactor.c0b, factor),
            .c1a = m31.mulVec4(cofactor.c1a, factor),
            .c1b = m31.mulVec4(cofactor.c1b, factor),
        });
        const next: *m31.Vec4u32 = @ptrCast(@alignCast((&inverses).ptr + stripe));
        next.* = m31.mulVec4(running, prefix.c0b);
    }
}

inline fn square(value: packed_fields.PackedCM31x4) packed_fields.PackedCM31x4 {
    const ab = m31.mulVec4(value.a, value.b);
    return .{ .a = m31.subVec4(m31.mulVec4(value.a, value.a), m31.mulVec4(value.b, value.b)), .b = m31.addVec4(ab, ab) };
}

fn overlap(a: anytype, b: anytype) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    return a_start < b_start + b.len * @sizeOf(@TypeOf(b[0])) and
        b_start < a_start + a.len * @sizeOf(@TypeOf(a[0]));
}

test "QM31 norm batch preserves scaled inverse across stripes tails and subfields" {
    var random = std.Random.DefaultPrng.init(0x20260928);
    const rng = random.random();
    const allocator = std.testing.allocator;
    for ([_]usize{ 0, 1, 3, 7, 8, 9, 16, 31, 32, 33, 8192 }) |count| {
        const input = try allocator.alloc(QM31, count);
        defer allocator.free(input);
        const destination = try allocator.alloc(QM31, count);
        defer allocator.free(destination);
        const expected = try allocator.alloc(QM31, count);
        defer allocator.free(expected);
        const scales = try allocator.alloc(M31, count);
        defer allocator.free(scales);
        for (input, scales, expected, 0..) |*q, *scale, *want, index| {
            const x = if (index % 5 == 0) QM31.fromBase(M31.fromCanonical(1 + @as(u32, @intCast(index)))) else QM31.fromU32Unchecked(rng.int(u32) % 0x7fffffff, rng.int(u32) % 0x7fffffff, if (index % 5 == 1) 0 else rng.int(u32) % 0x7fffffff, if (index % 5 == 1) 0 else rng.int(u32) % 0x7fffffff);
            q.* = if (x.isZero()) QM31.one() else x;
            scale.* = if (index % 7 == 0) M31.zero() else M31.fromCanonical(rng.int(u32) % 0x7fffffff);
            want.* = (try q.inv()).mulM31(scale.*);
        }
        try invertScaledOwned(input, destination, scales);
        for (expected, destination) |want, got| try std.testing.expect(want.eql(got));
    }
}

test "QM31 norm batch rejects zero denominator even with zero numerator and rejects aliases" {
    var input = [_]QM31{ QM31.one(), QM31.zero(), QM31.one() };
    var output: [3]QM31 = undefined;
    const scales = [_]M31{ M31.one(), M31.zero(), M31.one() };
    try std.testing.expectError(error.DivisionByZero, invertScaledOwned(&input, &output, &scales));
    try std.testing.expectError(error.InvalidBatchGeometry, invertScaledOwned(&input, &input, &scales));
    try std.testing.expectError(error.InvalidBatchGeometry, invertScaledOwned(&input, &output, scales[0..2]));
}
