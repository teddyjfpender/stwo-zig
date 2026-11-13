//! Shared curve/field arithmetic and operation tags; no session or admission policy.
const std = @import("std");

pub const BN254_G1_ADD_TAG: u64 = 0x0003_0100;
pub const BN254_G1_DOUBLE_TAG: u64 = 0x0003_0101;
pub const BN254_FP2_MUL_TAG: u64 = 0x0003_0102;
pub const BLS12_381_G1_ADD_TAG: u64 = 0x0003_0110;
pub const BLS12_381_G1_DOUBLE_TAG: u64 = 0x0003_0111;
pub const BLS12_381_FP2_MUL_TAG: u64 = 0x0003_0112;
pub const ARITH384_MOD_TAG: u64 = 0x0003_0120;
pub const ARITH384_MONT_TAG: u64 = 0x0003_0121;

pub const BN254_P: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
pub const BLS12_381_P: u384 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

/// Prime-field arithmetic on canonical values (< p).
pub fn Field(comptime T: type, comptime p: T) type {
    const W = std.meta.Int(.unsigned, 2 * @bitSizeOf(T));
    return struct {
        pub const P = p;
        pub fn add(a: T, b: T) T {
            const s = @as(W, a) + b;
            return @intCast(if (s >= p) s - p else s);
        }
        pub fn sub(a: T, b: T) T {
            return if (a >= b) a - b else p - (b - a);
        }
        pub fn mul(a: T, b: T) T {
            return @intCast(@as(W, a) * b % p);
        }
        /// Reduces any value of the full width.
        pub fn reduce(a: T) T {
            return a % p;
        }
        pub fn inv(a: T) T {
            return invMod(T, a, p);
        }
    };
}

/// Inverse of `a` modulo odd `m` with gcd(a, m) = 1, a != 0 (binary extended Euclid).
pub fn invMod(comptime T: type, a: T, m: T) T {
    const W = std.meta.Int(.unsigned, @bitSizeOf(T) + 1);
    var u = a % m;
    var v = m;
    var x1: T = 1;
    var x2: T = 0;
    const half = struct {
        fn f(x: T, mod: T) T {
            return if (x & 1 == 0) x >> 1 else @intCast((@as(W, x) + mod) >> 1);
        }
    }.f;
    const subm = struct {
        fn f(x: T, y: T, mod: T) T {
            return if (x >= y) x - y else mod - (y - x);
        }
    }.f;
    while (u != 1 and v != 1) {
        while (u & 1 == 0) {
            u >>= 1;
            x1 = half(x1, m);
        }
        while (v & 1 == 0) {
            v >>= 1;
            x2 = half(x2, m);
        }
        if (u >= v) {
            u -= v;
            x1 = subm(x1, x2, m);
        } else {
            v -= u;
            x2 = subm(x2, x1, m);
        }
    }
    return if (u == 1) x1 else x2;
}

pub const Bn254 = Field(u256, BN254_P);
pub const Bls = Field(u384, BLS12_381_P);

/// Affine short-Weierstrass (a = 0) chord rule. Precondition x1 != x2.
pub fn affineAdd(comptime F: type, comptime T: type, x1: T, y1: T, x2: T, y2: T) [2]T {
    const l = F.mul(F.sub(y2, y1), F.inv(F.sub(x2, x1)));
    const x3 = F.sub(F.sub(F.mul(l, l), x1), x2);
    return .{ x3, F.sub(F.mul(l, F.sub(x1, x3)), y1) };
}

/// Affine tangent rule for a = 0. Precondition y != 0.
pub fn affineDouble(comptime F: type, comptime T: type, x: T, y: T) [2]T {
    const xx = F.mul(x, x);
    const l = F.mul(F.add(F.add(xx, xx), xx), F.inv(F.add(y, y)));
    const x3 = F.sub(F.mul(l, l), F.add(x, x));
    return .{ x3, F.sub(F.mul(l, F.sub(x, x3)), y) };
}

/// Fp2 = Fp[u]/(u^2 + 1) product on canonical coefficients.
pub fn fp2Mul(comptime F: type, comptime T: type, a: [2]T, b: [2]T) [2]T {
    return .{ F.sub(F.mul(a[0], b[0]), F.mul(a[1], b[1])), F.add(F.mul(a[0], b[1]), F.mul(a[1], b[0])) };
}

/// a * b * 2^-384 mod m for odd m (m = 1 gives 0). Any a, b < 2^384.
pub fn mont384(a: u384, b: u384, m: u384) u384 {
    std.debug.assert(m & 1 == 1);
    if (m == 1) return 0;
    const t: u384 = @intCast(@as(u768, a) * b % m);
    const r_mod: u384 = @intCast((@as(u768, 1) << 384) % m);
    const r_inv = invMod(u384, r_mod, m);
    return @intCast(@as(u768, t) * r_inv % m);
}

/// (a * b + c) mod m; m = 0 gives 0.
pub fn mod384(a: u384, b: u384, c: u384, m: u384) u384 {
    if (m == 0) return 0;
    return @intCast((@as(u768, a) * b + c) % m);
}
