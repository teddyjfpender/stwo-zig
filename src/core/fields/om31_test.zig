const std = @import("std");
const field = @import("om31.zig");
const packed_fields = @import("packed_om31.zig");
const m31 = @import("m31.zig");
const M = m31.M31;
const Q = @import("qm31.zig").QM31;
const O = field.OM31;
const a = std.testing.allocator;
fn random(random_source: std.Random) O {
    var coordinates: [8]M = undefined;
    for (&coordinates) |*v| v.* = M.fromCanonical(random_source.int(u32) % m31.Modulus);
    return O.fromM31Array(coordinates);
}
fn qPow(x: Q, exponent: u128) Q {
    var b = x;
    var e = exponent;
    var out = Q.one();
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) out = out.mul(b);
        b = b.square();
    }
    return out;
}
// Independent schoolbook polynomial oracle in v, with v^8=4v^4-5.
// No QM31/OM31 multiplication, square or inverse is used by this oracle.
fn polynomial(x: O) [8]M {
    const c = x.toM31Array();
    var out: [8]M = undefined;
    inline for (0..2) |half| {
        out[half] = c[half * 4].sub(c[half * 4 + 1].add(c[half * 4 + 1]));
        out[half + 4] = c[half * 4 + 1];
        out[half + 2] = c[half * 4 + 2].sub(c[half * 4 + 3].add(c[half * 4 + 3]));
        out[half + 6] = c[half * 4 + 3];
    }
    return out;
}
fn fromPolynomial(c: [8]M) O {
    var out: [8]M = undefined;
    inline for (0..2) |half| {
        out[half * 4] = c[half].add(c[half + 4].add(c[half + 4]));
        out[half * 4 + 1] = c[half + 4];
        out[half * 4 + 2] = c[half + 2].add(c[half + 6].add(c[half + 6]));
        out[half * 4 + 3] = c[half + 6];
    }
    return O.fromM31Array(out);
}
fn oracleMul(x: O, y: O) O {
    const l = polynomial(x);
    const r = polynomial(y);
    var c = [_]M{M.zero()} ** 15;
    for (l, 0..) |u, i| for (r, 0..) |v, j| {
        c[i + j] = c[i + j].add(u.mul(v));
    };
    var k: usize = 15;
    while (k > 8) {
        k -= 1;
        const v = c[k];
        c[k - 4] = c[k - 4].add(v.mul(M.fromCanonical(4)));
        c[k - 8] = c[k - 8].sub(v.mul(M.fromCanonical(5)));
    }
    return fromPolynomial(c[0..8].*);
}
fn oraclePow(x: O, exponent: u256) O {
    var b = x;
    var e = exponent;
    var out = O.one();
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) out = oracleMul(out, b);
        b = oracleMul(b, b);
    }
    return out;
}

test "om31: irreducible tower norm Legendre and full Euler witnesses" {
    const p = m31.Modulus;
    try std.testing.expectEqual(@as(u32, 2), p % 5);
    try std.testing.expect(M.fromCanonical(5).pow((p - 1) / 2).eql(M.one().neg()));
    const u = field.NONRESIDUE;
    const r = @import("qm31.zig").R;
    const minus_r = r.neg();
    try std.testing.expect(minus_r.a.square().add(minus_r.b.square()).eql(M.fromCanonical(5)));
    try std.testing.expect(qPow(u, (@import("qm31.zig").P4 - 1) / 2).eql(Q.one().neg()));
    const v = O.basis();
    try std.testing.expect(v.square().eql(O.fromInner(u)));
    try std.testing.expect(v.pow(field.ORDER - 1).eql(O.one()));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(O));
}
test "om31: high-limb independent schoolbook multiplication oracle" {
    var prng = std.Random.DefaultPrng.init(0x4f4d3331);
    for (0..512) |i| {
        var x = random(prng.random());
        const y = random(prng.random());
        if (i % 5 == 0) x = O.fromM31Array(@splat(M.fromCanonical(m31.Modulus - 1)));
        try std.testing.expect(x.mul(y).eql(oracleMul(x, y)));
        try std.testing.expect(x.square().eql(oracleMul(x, x)));
    }
}
test "om31: inversion independently matches exponentiation in polynomial oracle" {
    var prng = std.Random.DefaultPrng.init(0x49564e38);
    for (0..4) |_| {
        const x = random(prng.random());
        const inverse = try x.inv();
        try std.testing.expect(inverse.eql(oraclePow(x, field.ORDER - 2)));
        try std.testing.expect(oracleMul(x, inverse).eql(O.one()));
    }
}
test "om31: field laws conjugation norm and scalar operations" {
    var prng = std.Random.DefaultPrng.init(0x414c4742);
    for (0..64) |_| {
        const x = random(prng.random());
        const y = random(prng.random());
        const z = random(prng.random());
        try std.testing.expect(x.mul(y.add(z)).eql(x.mul(y).add(x.mul(z))));
        try std.testing.expect(x.mul(y).mul(z).eql(x.mul(y.mul(z))));
        try std.testing.expect(x.add(x.neg()).isZero());
        try std.testing.expect(x.mul(x.conjugate()).eql(O.fromInner(x.norm())));
        try std.testing.expect(x.mulBase(M.fromCanonical(123)).eql(x.mul(O.fromBase(M.fromCanonical(123)))));
        try std.testing.expect((try x.div(y)).mul(y).eql(x));
    }
}
test "om31: embedded QM31 remains exactly compatible" {
    const x = Q.fromU32Unchecked(1, 7, 11, 13);
    const y = Q.fromU32Unchecked(17, 19, 23, 29);
    try std.testing.expect(O.fromInner(x).mul(O.fromInner(y)).eql(O.fromInner(x.mul(y))));
    try std.testing.expect((try O.fromInner(x).inv()).eql(O.fromInner(try x.inv())));
}
test "om31: canonical32byte encoding rejects every noncanonical coordinate" {
    var prng = std.Random.DefaultPrng.init(0x43414e38);
    const x = random(prng.random());
    var bytes = x.toBytesLe();
    try std.testing.expect((try O.fromBytesLe(&bytes)).eql(x));
    for (0..8) |i| {
        var invalid = bytes;
        std.mem.writeInt(u32, invalid[4 * i ..][0..4], m31.Modulus, .little);
        try std.testing.expectError(error.NonCanonicalField, O.fromBytesLe(&invalid));
    }
    try std.testing.expectError(error.DivisionByZero, O.zero().inv());
    try std.testing.expectError(error.DivisionByZero, O.one().div(O.zero()));
}
test "om31: scaled norm batch covers tails stripes subfields and zero weights" {
    var prng = std.Random.DefaultPrng.init(0x42415438);
    for ([_]usize{ 0, 1, 3, 7, 8, 9, 16, 31, 32, 33, 1024 }) |n| {
        const input = try a.alloc(O, n);
        defer a.free(input);
        const output = try a.alloc(O, n);
        defer a.free(output);
        const scratch = try a.alloc(Q, 2 * n);
        defer a.free(scratch);
        const scales = try a.alloc(M, n);
        defer a.free(scales);
        for (input, scales, 0..) |*v, *scale, i| {
            v.* = if (i % 5 == 0) O.fromBase(M.fromCanonical(@intCast(i + 1))) else random(prng.random());
            scale.* = if (i % 7 == 0) M.zero() else M.fromCanonical(17);
        }
        try field.invertScaled(input, output, scratch, scales);
        for (input, output, scales) |x, y, scale| try std.testing.expect(x.mul(y).eql(O.fromBase(scale)));
    }
}
test "om31: batch zero and geometry failures are output atomic" {
    const input = [_]O{ O.one(), O.zero(), O.one() };
    var output = [_]O{O.one()} ** 3;
    var scratch: [6]Q = undefined;
    const scales = [_]M{ M.one(), M.zero(), M.one() };
    try std.testing.expectError(error.DivisionByZero, field.invertScaled(&input, &output, &scratch, &scales));
    for (output) |v| try std.testing.expect(v.eql(O.one()));
    try std.testing.expectError(error.InvalidBatchGeometry, field.invertScaled(&input, &output, scratch[0..5], &scales));
    var aliases = [_]O{O.one()} ** 3;
    try std.testing.expectError(error.InvalidBatchGeometry, field.invertScaled(&aliases, &aliases, &scratch, &scales));
}
test "om31: native packed products and secure by base preserve independent lanes" {
    var prng = std.Random.DefaultPrng.init(0x50414338);
    var l: [8]m31.PackedM31 = undefined;
    var r: [8]m31.PackedM31 = undefined;
    for (0..8) |j| for (0..m31.PACK_WIDTH) |i| {
        l[j][i] = prng.random().int(u32) % m31.Modulus;
        r[j][i] = prng.random().int(u32) % m31.Modulus;
    };
    const x = packed_fields.fromCoordinates(l);
    const y = packed_fields.fromCoordinates(r);
    const result = x.mul(y);
    const scales: m31.PackedM31 = @splat(319);
    const scaled = x.mulBase(scales);
    const squared = x.square();
    for (0..m31.PACK_WIDTH) |i| {
        try std.testing.expect(packed_fields.lane(result, i).eql(oracleMul(packed_fields.lane(x, i), packed_fields.lane(y, i))));
        try std.testing.expect(packed_fields.lane(scaled, i).eql(packed_fields.lane(x, i).mulBase(M.fromCanonical(319))));
        try std.testing.expect(packed_fields.lane(squared, i).eql(packed_fields.lane(x, i).square()));
    }
    const transposed = packed_fields.coordinates(x);
    for (l, transposed) |want, got| try std.testing.expectEqual(want, got);
}

test "om31: explicit16row groups preserve high-limb column-major products" {
    var c: [8][16]M = undefined;
    var d: [8][16]M = undefined;
    var bases: [16]M = undefined;
    for (0..16) |i| {
        bases[i] = M.fromCanonical(@intCast(i + 1));
        for (0..8) |j| {
            c[j][i] = M.fromCanonical(m31.Modulus - 1 - @as(u32, @intCast(i * 8 + j)));
            d[j][i] = M.fromCanonical(@intCast(3 + i * 8 + j));
        }
    }
    const x = packed_fields.PackedOM31x16.fromCoordinates(&c);
    const y = packed_fields.PackedOM31x16.fromCoordinates(&d);
    const product = x.mul(y);
    const scaled = x.mulBase(&bases);
    for (0..16) |i| {
        try std.testing.expect(product.lane(i).eql(oracleMul(x.lane(i), y.lane(i))));
        try std.testing.expect(scaled.lane(i).eql(x.lane(i).mulBase(bases[i])));
    }
}
