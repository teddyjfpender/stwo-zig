//! Affine extension of the original circuit lookup tuples to authenticated
//! OODS masks. The tuple order is the RawLookupRows/CUDA authority order.
//! XOR12's three FIXED masks are the low-ten-bit table operands/result;
//! its two high operand bits are class constants, never proof metadata.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const P = @import("profile.zig");
pub fn LookupFor(comptime F: type) type {
    return struct { numerator: F, tuple: [6]F, len: u8 };
}
fn lit(comptime F: type, v: u32) F {
    return F.fromBase(M.fromCanonical(v));
}
fn use(comptime F: type, relation: u32, a: F, b: F, c: F) LookupFor(F) {
    return .{ .numerator = F.one(), .tuple = .{ lit(F, relation), a, b, c, F.zero(), F.zero() }, .len = 4 };
}
fn gate(comptime F: type, n: F, address: F, a: F, b: F) LookupFor(F) {
    return .{ .numerator = n, .tuple = .{ lit(F, 378353459), address, a, b, F.zero(), F.zero() }, .len = 4 };
}
fn low(comptime F: type, a: F, hi: F, bits: u5) F {
    return a.sub(hi.mul(lit(F, @as(u32, 1) << bits)));
}
pub fn rowFor(comptime F: type, component: P.Component, c: []const F, p: []const F, out: []LookupFor(F)) ![]LookupFor(F) {
    const kind = @intFromEnum(component);
    if (!P.gkrBound(component) or c.len != P.FACTS[kind].main or out.len < P.FACTS[kind].lookups) return error.OuterGkrTupleShape;
    const expected_pp: usize = switch (component) {
        .triple_xor => 5,
        .m_31_to_u_32 => 3,
        .blake_g_gate => 11,
        .verify_bitwise_xor_12 => 3,
        else => unreachable,
    };
    if (p.len != expected_pp) return error.OuterGkrTupleShape;
    switch (component) {
        .triple_xor => {
            out[0] = use(F, 112558620, low(F, c[0], c[8], 8), low(F, c[2], c[10], 8), c[16]);
            out[1] = use(F, 112558620, c[8], c[10], c[17]);
            out[2] = use(F, 112558620, low(F, c[1], c[9], 8), low(F, c[3], c[11], 8), c[18]);
            out[3] = use(F, 112558620, c[9], c[11], c[19]);
            out[4] = use(F, 112558620, c[16], low(F, c[4], c[12], 8), low(F, c[6], c[14], 8));
            out[5] = use(F, 112558620, c[17], c[12], c[14]);
            out[6] = use(F, 112558620, c[18], low(F, c[5], c[13], 8), low(F, c[7], c[15], 8));
            out[7] = use(F, 112558620, c[19], c[13], c[15]);
            for (0..4) |i| out[8 + i] = gate(F, if (i == 3) p[4].neg() else F.one(), p[i], c[2 * i], c[2 * i + 1]);
        },
        .m_31_to_u_32 => {
            out[0] = .{ .numerator = F.one(), .tuple = .{ lit(F, 1008385708), c[1], F.zero(), F.zero(), F.zero(), F.zero() }, .len = 2 };
            out[1] = out[0];
            out[1].tuple[1] = c[2];
            out[2] = out[0];
            out[2].tuple[1] = lit(F, 32767).sub(c[2]);
            out[3] = gate(F, F.one(), p[0], c[0], F.zero());
            out[3].len = 3;
            out[4] = gate(F, p[2].neg(), p[1], c[1], c[2]);
        },
        .blake_g_gate => {
            const xr16lo = c[28].add(c[29].mul(lit(F, 256)));
            const xr16hi = c[26].add(c[27].mul(lit(F, 256)));
            const xr12lo = c[37].add(c[38].mul(lit(F, 16)));
            const xr12hi = c[39].add(c[36].mul(lit(F, 16)));
            out[0] = use(F, 112558620, low(F, c[20], c[22], 8), low(F, c[6], c[24], 8), c[26]);
            out[1] = use(F, 112558620, c[22], c[24], c[27]);
            out[2] = use(F, 521092554, low(F, c[21], c[23], 8), low(F, c[7], c[25], 8), c[28]);
            out[3] = use(F, 521092554, c[23], c[25], c[29]);
            out[4] = use(F, 648362599, low(F, c[2], c[32], 12), low(F, c[30], c[34], 12), c[36]);
            out[5] = use(F, 45448144, c[32], c[34], c[37]);
            out[6] = use(F, 648362599, low(F, c[3], c[33], 12), low(F, c[31], c[35], 12), c[38]);
            out[7] = use(F, 45448144, c[33], c[35], c[39]);
            out[8] = use(F, 112558620, c[40], c[42], low(F, c[18], c[44], 8));
            out[9] = use(F, 112558620, low(F, c[13], c[41], 8), low(F, xr16hi, c[43], 8), c[44]);
            out[10] = use(F, 112558620, c[41], c[43], low(F, c[19], c[45], 8));
            out[11] = use(F, 112558620, low(F, c[12], c[40], 8), low(F, xr16lo, c[42], 8), c[45]);
            out[12] = use(F, 95781001, c[46], c[48], low(F, c[14], c[50], 9));
            out[13] = use(F, 62225763, low(F, xr12hi, c[47], 7), low(F, c[17], c[49], 7), c[50]);
            out[14] = use(F, 95781001, c[47], c[49], low(F, c[15], c[51], 9));
            out[15] = use(F, 62225763, low(F, xr12lo, c[46], 7), low(F, c[16], c[48], 7), c[51]);
            for (0..10) |i| {
                const limb = if (i < 6) i else 6 + i - 6;
                out[16 + i] = gate(F, if (i < 6) F.one() else p[10].neg(), p[limb], c[2 * limb], c[2 * limb + 1]);
            }
        },
        .verify_bitwise_xor_12 => for (0..16) |i| {
            out[i] = use(F, 648362599, p[0].add(lit(F, @intCast((i >> 2) << 10))), p[1].add(lit(F, @intCast((i & 3) << 10))), p[2].add(lit(F, @intCast(((i >> 2) ^ (i & 3)) << 10))));
            out[i].numerator = c[i].neg();
        },
        else => unreachable,
    }
    return out[0..P.FACTS[kind].lookups];
}
