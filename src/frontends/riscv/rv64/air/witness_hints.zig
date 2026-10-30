//! Arithmetic recipes only. Verifier constraints never call these functions.
const M = @import("stwo_core").fields.m31.M31;
const L = @import("layout.zig");
const R = @import("rows.zig");
const O = @import("../decode.zig").Opcode;
const classify = @import("operations.zig");

pub fn fill(row: *R.Main, opcode: O, immediate: u64) void {
    const a = R.getWord(row, .a);
    const b = R.getWord(row, .b);
    const result = R.getWord(row, .result);
    const width: usize = if (classify.word(opcode)) 4 else 8;
    const rhs = if (classify.immediate(opcode)) immediate else b;
    if (classify.rhs(opcode)) R.putWord(row, .rhs, rhs);
    if (classify.add(opcode) or classify.sub(opcode)) R.carryAdd(row, .alu, a, rhs, width, classify.sub(opcode));
    if (classify.address(opcode)) {
        R.putWord(row, .address, a +% immediate);
        R.carryAdd(row, .address, a, immediate, 8, false);
    }
    if (classify.compare(opcode)) {
        R.putWord(row, .difference, a -% rhs);
        R.carryAdd(row, .compare, a, rhs, 8, true);
        var square_sum: u32 = 0;
        for (0..8) |i| {
            const difference: i32 = @as(i32, @intCast((a >> @as(u6, @intCast(i * 8))) & 255)) - @as(i32, @intCast((rhs >> @as(u6, @intCast(i * 8))) & 255));
            square_sum += @intCast(difference * difference);
        }
        row[L.equal] = R.scalar(@intFromBool(square_sum == 0));
        row[L.equal_inverse] = if (square_sum == 0) M.zero() else R.scalar(square_sum).invUncheckedNonZero();
    }
    if (classify.shift(opcode)) {
        const bits: usize = width * 8;
        var previous = a;
        if (bits == 32) previous &= 0xffffffff;
        for (0..if (bits == 32) @as(usize, 5) else 6) |stage| {
            if ((rhs >> @as(u6, @intCast(stage))) & 1 == 1) {
                const amount: u6 = @intCast(@as(u32, 1) << @as(u5, @intCast(stage)));
                previous = if (classify.left(opcode)) previous << amount else if (classify.arithmeticRight(opcode)) blk: {
                    const signed: i64 = if (bits == 32) @as(i32, @bitCast(@as(u32, @truncate(previous)))) else @bitCast(previous);
                    break :blk @bitCast(signed >> amount);
                } else previous >> amount;
                if (bits == 32) previous &= 0xffffffff;
            }
            for (0..bits) |i| row[L.shift(stage, i)] = R.scalar(@intCast((previous >> @as(u6, @intCast(i))) & 1));
        }
    }
    var x = a;
    var y = b;
    if (classify.div(opcode)) {
        const mask: u64 = if (width == 4) 0xffffffff else 0xffffffffffffffff;
        const sign_a = classify.signedDiv(opcode) and (a >> @as(u6, @intCast(width * 8 - 1))) & 1 == 1;
        const sign_b = classify.signedDiv(opcode) and (b >> @as(u6, @intCast(width * 8 - 1))) & 1 == 1;
        const aa = (if (sign_a) 0 -% a else a) & mask;
        const bb = (if (sign_b) 0 -% b else b) & mask;
        const quotient = if (bb == 0) mask else aa / bb;
        const remainder = if (bb == 0) aa else aa % bb;
        const out_abs = if (classify.remainder(opcode)) remainder else quotient;
        const negative = if (classify.remainder(opcode)) sign_a else sign_a != sign_b;
        const apply_negative = negative and (bb != 0 or classify.remainder(opcode));
        R.putWord(row, .abs_a, aa);
        R.putWord(row, .abs_b, bb);
        R.putWord(row, .quotient, quotient);
        R.putWord(row, .remainder, remainder);
        R.putWord(row, .raw_result, result & mask);
        R.putWord(row, .out_abs, out_abs);
        row[L.sign_a] = R.scalar(@intFromBool(sign_a));
        row[L.sign_b] = R.scalar(@intFromBool(sign_b));
        row[L.negate] = R.scalar(@intFromBool(negative));
        row[L.apply_negate] = R.scalar(@intFromBool(apply_negative));
        row[L.divisor_zero] = R.scalar(@intFromBool(bb == 0));
        var sum: u32 = 0;
        for (0..8) |i| sum += row[L.byte(.abs_b, i)].toU32();
        row[L.divisor_inverse] = if (sum == 0) M.zero() else R.scalar(sum).invUncheckedNonZero();
        if (sign_a) R.carryNegate(row, .abs_a, a & mask, aa, width);
        if (sign_b) R.carryNegate(row, .abs_b, b & mask, bb, width);
        if (apply_negative) R.carryNegate(row, .negate, out_abs, result & mask, width);
        if (bb != 0) {
            const delta = bb - remainder - 1;
            R.putWord(row, .remainder_gap, delta);
            // rem + gap + 1 = divisor, no terminal carry.
            var carry: u32 = 1;
            for (0..width) |i| {
                carry = (@as(u32, @intCast((remainder >> @as(u6, @intCast(8 * i))) & 255)) + @as(u32, @intCast((delta >> @as(u6, @intCast(8 * i))) & 255)) + carry) >> 8;
                row[L.carry(.remainder, i)] = R.scalar(carry);
            }
        }
        x = quotient;
        y = bb;
    }
    if (classify.mul(opcode) or classify.div(opcode)) {
        R.putWord(row, .product_x, x);
        R.putWord(row, .product_y, y);
        const product = @as(u128, x) * y;
        R.putWord(row, .product_low, @truncate(product));
        R.putWord(row, .product_high, @intCast(product >> 64));
        var carry: u32 = 0;
        for (0..16) |k| {
            var sum = carry;
            for (0..8) |i| if (k >= i and k - i < 8) {
                sum += @as(u32, @intCast((x >> @as(u6, @intCast(8 * i))) & 255)) * @as(u32, @intCast((y >> @as(u6, @intCast(8 * (k - i)))) & 255));
            };
            carry = sum >> 8;
            R.putBounded(row, L.productCarry(k), 11, carry);
        }
        if (classify.mul(opcode)) {
            const high: u64 = @intCast(product >> 64);
            const correction_a = if ((opcode == .MULH or opcode == .MULHSU) and a >> 63 == 1) b else 0;
            const correction_b = if (opcode == .MULH and b >> 63 == 1) a else 0;
            R.putWord(row, .high_sub_a, high -% correction_a);
            R.putWord(row, .high_sub_b, high -% correction_a -% correction_b);
            R.carryAdd(row, .high_a, high, correction_a, 8, true);
            R.carryAdd(row, .high_b, high -% correction_a, correction_b, 8, true);
        } else {
            var carry_sum: u32 = 0;
            const remainder = R.getWord(row, .remainder);
            for (0..16) |i| {
                const p: u32 = @intCast((product >> @as(u7, @intCast(8 * i))) & 255);
                const rem: u32 = if (i < 8) @intCast((remainder >> @as(u6, @intCast(8 * i))) & 255) else 0;
                carry_sum = (p + rem + carry_sum) >> 8;
                row[L.carry(if (i < 8) .div_sum_low else .div_sum_high, i % 8)] = R.scalar(carry_sum);
            }
        }
    }
}
