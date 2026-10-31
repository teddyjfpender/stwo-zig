//! Concrete independently-sized RV64 DIV/REM service v2. Bits are committed
//! only at service rows; byte reconstruction is linear at domain/OODS points.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../../evaluation.zig");
const L = E.L;
pub const OPCODES = [_]E.O{ .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW };
pub const WORDS = [_]L.Word{ .a, .b, .result, .product_low, .product_high, .abs_a, .abs_b, .quotient, .remainder, .remainder_gap, .raw_result, .out_abs, .product_x, .product_y };
pub const CARRIES = [_]L.Carry{ .abs_a, .abs_b, .negate, .div_sum_low, .div_sum_high, .remainder };
pub const SCALARS = [_]usize{ L.divisor_zero, L.divisor_inverse, L.sign_a, L.sign_b, L.negate, L.apply_negate };
pub const WORD_START = OPCODES.len;
pub const CARRY_START = WORD_START + WORDS.len * 64;
pub const PRODUCT_START = CARRY_START + CARRIES.len * 8;
pub const SCALAR_START = PRODUCT_START + 16 * 11;
pub const COUNT = SCALAR_START + SCALARS.len;
pub const MAIN = COUNT + 1;
pub const FIXED = 3; // receiver-derived index, first, last
pub const INTERACTION = 8;
pub const TUPLE = 25; // opcode identity, then full-width a/b/result bytes
pub const Tuple = [TUPLE]E.Q;
pub const Physical = [MAIN]E.Q;
pub const CONSTRAINTS = 1567;
pub fn opcodeIndex(op: E.O) !usize {
    for (OPCODES, 0..) |candidate, i| if (candidate == op) return i;
    return error.InvalidRv64DivisionOpcode;
}
pub fn encode(logical: *const @import("../../rows.zig").Main, op: E.O, output: []M) !void {
    if (output.len != MAIN) return error.InvalidRv64DivisionShape;
    @memset(output, M.zero());
    output[try opcodeIndex(op)] = M.one();
    for (WORDS, 0..) |word, w| for (0..64) |bit| {
        output[WORD_START + w * 64 + bit] = logical[L.bit(word, bit)];
    };
    for (CARRIES, 0..) |kind, c| for (0..8) |i| {
        output[CARRY_START + c * 8 + i] = logical[L.carry(kind, i)];
    };
    for (0..16) |i| for (0..11) |bit| {
        output[PRODUCT_START + i * 11 + bit] = logical[L.productCarry(i) + 1 + bit];
    };
    for (SCALARS, 0..) |source, i| output[SCALAR_START + i] = logical[source];
}
pub fn inflate(physical: *const Physical, fixed: *E.Fixed, logical: *E.Main) void {
    fixed.* = @splat(E.Q.zero());
    logical.* = @splat(E.Q.zero());
    for (OPCODES, 0..) |op, i| fixed[L.fixed.opcode_start + @intFromEnum(op)] = physical[i];
    for (WORDS, 0..) |word, w| for (0..64) |bit| {
        const value = physical[WORD_START + w * 64 + bit];
        logical[L.bit(word, bit)] = value;
        logical[L.byte(word, bit / 8)] = logical[L.byte(word, bit / 8)].add(value.mul(E.q(@as(u32, 1) << @as(u5, @intCast(bit % 8)))));
    };
    for (CARRIES, 0..) |kind, c| for (0..8) |i| {
        logical[L.carry(kind, i)] = physical[CARRY_START + c * 8 + i];
    };
    for (0..16) |i| for (0..11) |bit| {
        const value = physical[PRODUCT_START + i * 11 + bit];
        logical[L.productCarry(i) + 1 + bit] = value;
        logical[L.productCarry(i)] = logical[L.productCarry(i)].add(value.mul(E.q(@as(u32, 1) << @as(u5, @intCast(bit)))));
    };
    for (SCALARS, 0..) |destination, i| logical[destination] = physical[SCALAR_START + i];
}
pub fn tuple(fixed: *const E.Fixed, logical: *const E.Main) Tuple {
    return tupleGeneric(E.Q, fixed, logical);
}
pub fn tupleGeneric(comptime F: type, fixed: *const E.FixedFor(F), logical: *const E.MainFor(F)) [TUPLE]F {
    var result: [TUPLE]F = @splat(F.zero());
    for (OPCODES) |op| result[0] = result[0].add(fixed[L.fixed.opcode_start + @intFromEnum(op)].mul(E.qFor(F, @intFromEnum(op))));
    for ([_]L.Word{ .a, .b, .result }, 0..) |word, w| for (0..8) |i| {
        result[1 + 8 * w + i] = logical[L.byte(word, i)];
    };
    return result;
}
