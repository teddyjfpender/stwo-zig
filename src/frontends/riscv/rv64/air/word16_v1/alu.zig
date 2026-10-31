//! Experimental ALU truth chip. Range queries are mandatory obligations,
//! not host checks: twelve write/compare anchors close against U16. Inputs
//! require closed canonical REG/ROM or independently expected u64 fact authority.
const std = @import("std");
const E = @import("../evaluation.zig");
const WordAdd = @import("word_add.zig");
pub const encoding = @import("alu_encoding.zig");
pub const LOCAL_MAIN = encoding.LOCAL_MAIN;
pub const MAIN = LOCAL_MAIN;
pub const CONSTRAINTS = encoding.LOCAL_CONSTRAINTS;
pub const RANGE_QUERIES = encoding.RANGE_QUERIES;
pub fn RowFor(comptime F: type) type {
    return struct {
        payload: [13]F,
        active: F,
        selectors: [10]F,
        sum: [4]F,
        difference: [4]F,
        carry: [4]F,
        borrow: [4]F,
        zero: F,
        inverse: F,
        // Sign of A[3], B[3], sum[1], difference[1].
        sign: [4]F,
        low: [4]F,
        signed_less: F,
    };
}

/// All limb equations have absolute integer magnitude <2^18 once U16
/// memberships and boolean carries hold. Thus an M31 equality cannot wrap
/// into a different integer carry. This bound does not apply to U16 products.
pub fn emitFor(comptime F: type, r: *const RowFor(F), sink: anytype) void {
    const one = F.one();
    const radix = E.qFor(F, 65536);
    var selected = F.zero();
    var operation = F.zero();
    for (r.selectors, 0..) |s, i| {
        sink.emit(s.mul(s.sub(one)));
        selected = selected.add(s);
        operation = operation.add(s.mul(E.qFor(F, @intCast(i))));
    }
    sink.emit(r.active.mul(r.active.sub(one)));
    sink.emit(selected.sub(r.active));
    sink.emit(r.payload[0].sub(operation));
    for (r.carry) |value| sink.emit(value.mul(value.sub(one)));
    for (r.borrow) |value| sink.emit(value.mul(value.sub(one)));
    const signed_limbs = [4]F{ r.payload[4], r.payload[8], r.sum[1], r.difference[1] };
    for (0..4) |i| {
        sink.emit(r.sign[i].mul(r.sign[i].sub(one)));
        sink.emit(signed_limbs[i].sub(r.low[i]).sub(r.sign[i].mul(E.qFor(F, 32768))));
    }
    for (0..4) |i| {
        const previous_carry = if (i == 0) F.zero() else r.carry[i - 1];
        const previous_borrow = if (i == 0) F.zero() else r.borrow[i - 1];
        sink.emit(WordAdd.limbResidualFor(F, r.payload[1 + i], r.payload[5 + i], previous_carry, r.sum[i], r.carry[i]));
        sink.emit(r.payload[1 + i].sub(r.payload[5 + i]).sub(previous_borrow).sub(r.difference[i]).add(radix.mul(r.borrow[i])));
    }
    // Mandatory external U16 membership bounds this integer sum by262140<p.
    // This is not a zero-test equivalence for arbitrary unconstrained limbs.
    var difference_sum = F.zero();
    for (r.difference) |value| difference_sum = difference_sum.add(value);
    sink.emit(r.zero.mul(r.zero.sub(one)));
    sink.emit(r.zero.mul(difference_sum));
    sink.emit(difference_sum.mul(r.inverse).add(r.zero).sub(one));
    const equal = r.zero;
    sink.emit(r.signed_less.sub(signedLessFor(F, r.sign[0], r.sign[1], r.borrow[3])));
    const predicates = [6]F{ r.signed_less, r.borrow[3], equal, one.sub(equal), one.sub(r.signed_less), one.sub(r.borrow[3]) };
    for (0..4) |i| {
        const addw = if (i < 2) r.sum[i] else r.sign[2].mul(E.qFor(F, 65535));
        const subw = if (i < 2) r.difference[i] else r.sign[3].mul(E.qFor(F, 65535));
        var output = r.selectors[0].mul(r.sum[i]).add(r.selectors[1].mul(r.difference[i]))
            .add(r.selectors[2].mul(addw)).add(r.selectors[3].mul(subw));
        if (i == 0) for (predicates, 0..) |predicate, j| {
            output = output.add(r.selectors[4 + j].mul(predicate));
        };
        sink.emit(r.payload[9 + i].sub(output));
    }
    const inactive = one.sub(r.active);
    for (r.payload[1..9]) |value| sink.emit(inactive.mul(value));
}

/// Shared staged predicate; Boolean arguments imply a Boolean result even
/// before input-word canonicality is supplied by the closed REG/ROM relation.
pub fn signedLessFor(comptime F: type, sign_a: F, sign_b: F, borrow: F) F {
    const one = F.one();
    const same_sign = one.sub(sign_a).sub(sign_b).add(E.qFor(F, 2).mul(sign_a).mul(sign_b));
    return sign_a.mul(one.sub(sign_b)).add(same_sign.mul(borrow));
}

/// The final four queries enforce low<32768 by range-checking 2*low.
/// Checking low directly as U16 would leave the sign witness ambiguous.
pub fn rangeValueFor(comptime F: type, r: *const RowFor(F), index: usize) F {
    std.debug.assert(index < RANGE_QUERIES);
    return if (index < 4) r.sum[index] else if (index < 8) r.difference[index - 4] else r.low[index - 8].mul(E.qFor(F, 2));
}

pub fn nativeResult(op: @import("operations.zig").Alu, a: u64, b: u64) u64 {
    return switch (op) {
        .add => a +% b,
        .sub => a -% b,
        .addw => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(a +% b)))))),
        .subw => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(a -% b)))))),
        .slt => @intFromBool(@as(i64, @bitCast(a)) < @as(i64, @bitCast(b))),
        .sltu => @intFromBool(a < b),
        .eq => @intFromBool(a == b),
        .ne => @intFromBool(a != b),
        .ge => @intFromBool(@as(i64, @bitCast(a)) >= @as(i64, @bitCast(b))),
        .geu => @intFromBool(a >= b),
    };
}
pub fn witness(op: @import("operations.zig").Alu, a: u64, b: u64) !RowFor(E.Q) {
    const c = nativeResult(op, a, b);
    var r: RowFor(E.Q) = undefined;
    r.payload[0] = E.q(@intFromEnum(op));
    r.active = E.Q.one();
    for (&r.selectors, 0..) |*value, i| value.* = E.q(@intFromBool(i == @intFromEnum(op)));
    var carry: u32 = 0;
    var borrow: u32 = 0;
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        const av: u32 = @as(u16, @truncate(a >> shift));
        const bv: u32 = @as(u16, @truncate(b >> shift));
        r.payload[1 + i] = E.q(av);
        r.payload[5 + i] = E.q(bv);
        r.payload[9 + i] = E.q(@as(u16, @truncate(c >> shift)));
        const sum = av + bv + carry;
        const difference = av + 65536 - bv - borrow;
        carry = sum >> 16;
        borrow = @intFromBool(difference < 65536);
        r.sum[i] = E.q(sum & 65535);
        r.difference[i] = E.q(difference & 65535);
        r.carry[i] = E.q(carry);
        r.borrow[i] = E.q(borrow);
    }
    const signed_limbs = [4]E.Q{ r.payload[4], r.payload[8], r.sum[1], r.difference[1] };
    for (signed_limbs, 0..) |value, i| {
        const limb = value.toM31Array()[0].v;
        r.sign[i] = E.q(limb >> 15);
        r.low[i] = E.q(limb & 32767);
    }
    var difference_sum = E.Q.zero();
    for (r.difference) |value| difference_sum = difference_sum.add(value);
    r.zero = E.q(@intFromBool(difference_sum.isZero()));
    r.inverse = if (difference_sum.isZero()) E.Q.zero() else try difference_sum.inv();
    r.signed_less = E.q(@intCast(nativeResult(.slt, a, b)));
    return r;
}
