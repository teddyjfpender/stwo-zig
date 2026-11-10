//! Isolated algebraic evaluation of the SAME 65 MAC12 convolution residuals.
//! No constraint is removed and no live component/sink/profile calls this code.
//! Generic field operations allow numeric, packed-secure or symbolic callers.
const S = @import("stwo_riscv_frontend").rv64_air.crypto.bn254_mac12.source;

/// Constants are explicit lane values, not native transcript data baked into a
/// recursive key. Caller supplies canonical source p bytes/radix/carry offset.
pub fn Constants(comptime F: type) type {
    return struct { one: F, radix: F, offset: F, modulus: [32]F };
}
fn horner(comptime F: type, view: anytype, start: usize, count: usize, alpha: F) F {
    var out = view.main(start);
    for (1..count) |i| out = out.mul(alpha).add(view.main(start + i));
    return out;
}
/// Returns c0*alpha^64 + ... + c64, matching the original emission order.
/// Holds for arbitrary extension-field MAIN and FIXED values, including
/// non-Boolean signs/active masks and alpha=0; no division is used.
pub fn folded(comptime F: type, view: anytype, alpha: F, c: Constants(F)) F {
    const alpha2 = alpha.mul(alpha);
    var products = view.fixed(S.COEFFICIENT).mul(horner(F, view, S.INPUT, 32, alpha).mul(horner(F, view, S.INPUT + 32, 32, alpha)));
    for (1..S.PRODUCTS) |term| products = products.add(view.fixed(S.COEFFICIENT + term).mul(horner(F, view, S.INPUT + 64 * term, 32, alpha).mul(horner(F, view, S.INPUT + 64 * term + 32, 32, alpha))));
    var alpha33 = alpha;
    for (0..5) |_| alpha33 = alpha33.mul(alpha33); // alpha^32
    alpha33 = alpha33.mul(alpha);
    const delta = horner(F, view, S.INPUT + 32 * 24, 32, alpha).sub(horner(F, view, S.OUTPUT, 32, alpha));
    var ph = c.modulus[0];
    for (c.modulus[1..]) |p| ph = ph.mul(alpha).add(p);
    const qh = horner(F, view, S.QUOTIENT, 33, alpha);
    const bias = view.main(S.ACTIVE).mul(c.offset);
    var ch: F = undefined;
    for (0..64) |j| {
        // Three little-endian bytes describe the actual signed carry, not its
        // offset representation. This is source.carry with factored constants.
        const carry = view.main(S.CARRY + 3 * j + 2).mul(c.radix).add(view.main(S.CARRY + 3 * j + 1)).mul(c.radix).add(view.main(S.CARRY + 3 * j)).sub(bias);
        ch = if (j == 0) carry else ch.mul(alpha).add(carry);
    }
    const sign_factor = c.one.sub(view.main(S.SIGN).add(view.main(S.SIGN)));
    return alpha2.mul(products).add(alpha33.mul(delta)).sub(sign_factor.mul(alpha).mul(qh).mul(ph)).add(c.one.sub(c.radix.mul(alpha)).mul(ch));
}
