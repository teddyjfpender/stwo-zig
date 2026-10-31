//! Exact affine change of basis: FUNCTION13 Word16 limbs to the already
//! qualified arithmetic byte bus25. No adapter rows, columns or new equations.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const F = A.word16_execution;
fn coefficients(ch: @FieldType(F.types.Challenges, "function")) [25]Q {
    var result: [25]Q = undefined;
    result[0] = ch.coefficients[0].neg();
    for (0..3) |word| for (0..4) |limb| {
        const coefficient = ch.coefficients[1 + 4 * word + limb].neg();
        result[1 + 8 * word + 2 * limb] = coefficient;
        result[2 + 8 * word + 2 * limb] = coefficient.mulM31(M.fromCanonical(256));
    };
    return result;
}
pub fn division(ch: @FieldType(F.types.Challenges, "function")) A.arithmetic.division.provider.Challenges {
    return .{ .offset = ch.offset, .coefficients = coefficients(ch) };
}
pub fn multiplication(ch: @FieldType(F.types.Challenges, "function")) A.arithmetic.multiplication.provider.Challenges {
    return .{ .offset = ch.offset, .coefficients = coefficients(ch) };
}
test "Word16 arithmetic basis preserves all raw opcode identities and every full64 limb" {
    var ch: @FieldType(F.types.Challenges, "function") = undefined;
    ch.offset = Q.fromM31Array(.{ M.fromCanonical(1000003), M.one(), M.fromCanonical(7), M.fromCanonical(11) });
    for (&ch.coefficients, 0..) |*v, i| v.* = Q.fromM31Array(.{ M.fromCanonical(@intCast(3 + i)), M.fromCanonical(@intCast(19 + i)), M.one(), M.zero() });
    const values = [_]u64{ 0, 1, 0xffff, 0x10000, 0x8000000000000000, 0xffffffffffffffff };
    inline for (.{ A.arithmetic.division, A.arithmetic.multiplication }) |Family| {
        for (Family.layout.OPCODES) |opcode| for (values) |a| for (values) |b| {
            const request = Family.trace.Request{ .opcode = opcode, .a = a, .b = b, .result = a ^ b };
            const old = try Family.trace.requestTuple(request);
            var native = ch.offset;
            var tuple: [13]M = undefined;
            tuple[0] = M.fromCanonical(@intFromEnum(opcode));
            for ([_]u64{ a, b, a ^ b }, 0..) |v, w| {
                for (0..4) |j| tuple[1 + 4 * w + j] = M.fromCanonical(@as(u16, @truncate(v >> @as(u6, @intCast(16 * j)))));
            }
            for (ch.coefficients, tuple) |coef, v| native = native.sub(coef.mulM31(v));
            const projected = if (Family == A.arithmetic.division) division(ch).denominator(&old) else multiplication(ch).denominator(&old);
            try std.testing.expect(native.eql(projected));
        };
    }
}
