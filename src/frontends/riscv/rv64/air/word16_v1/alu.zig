//! Experimental ALU truth chip. Range queries are mandatory obligations,
//! not host checks: all twenty rangeTuple values must close against U16.
const E = @import("../evaluation.zig");
pub const LOCAL_MAIN = 59;
pub const MAIN = LOCAL_MAIN;
pub const CONSTRAINTS = 64;
pub const RANGE_QUERIES = 20;
pub fn RowFor(comptime F: type) type {
    return struct {
        payload: [13]F,
        active: F,
        selectors: [10]F,
        sum: [4]F,
        difference: [4]F,
        carry: [4]F,
        borrow: [4]F,
        zero: [4]F,
        inverse: [4]F,
        // Sign of A[3], B[3], sum[1], difference[1].
        sign: [4]F,
        low: [4]F,
        zero_pair: [2]F,
        signed_less: F,
    };
}

/// All limb equations have absolute integer magnitude <2^18 once U16
/// memberships and boolean carries hold. Thus an M31 equality cannot wrap
/// into a different integer carry. This bound does not apply to U16 products.
pub fn emitFor(comptime F: type, r: *const RowFor(F), sink: anytype) void {
    const one = F.one();
    const two = E.qFor(F, 2);
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
        sink.emit(r.payload[1 + i].add(r.payload[5 + i]).add(previous_carry).sub(r.sum[i]).sub(radix.mul(r.carry[i])));
        sink.emit(r.payload[1 + i].sub(r.payload[5 + i]).sub(previous_borrow).sub(r.difference[i]).add(radix.mul(r.borrow[i])));
    }
    for (0..4) |i| {
        sink.emit(r.zero[i].mul(r.zero[i].sub(one)));
        sink.emit(r.zero[i].mul(r.difference[i]));
        sink.emit(r.difference[i].mul(r.inverse[i]).add(r.zero[i]).sub(one));
    }
    sink.emit(r.zero_pair[0].sub(r.zero[0].mul(r.zero[1])));
    sink.emit(r.zero_pair[1].sub(r.zero[2].mul(r.zero[3])));
    const equal = r.zero_pair[0].mul(r.zero_pair[1]);
    const same_sign = one.sub(r.sign[0]).sub(r.sign[1]).add(two.mul(r.sign[0]).mul(r.sign[1]));
    sink.emit(r.signed_less.sub(r.sign[0].mul(one.sub(r.sign[1])).add(same_sign.mul(r.borrow[3]))));
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

/// The final four queries enforce low<32768 by range-checking 2*low.
/// Checking low directly as U16 would leave the sign witness ambiguous.
pub fn rangeValueFor(comptime F: type, r: *const RowFor(F), index: usize) F {
    return if (index < 8) r.payload[1 + index] else if (index < 12) r.sum[index - 8] else if (index < 16) r.difference[index - 12] else r.low[index - 16].mul(E.qFor(F, 2));
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
        r.zero[i] = E.q(@intFromBool((difference & 65535) == 0));
        r.inverse[i] = if ((difference & 65535) == 0) E.Q.zero() else try r.difference[i].inv();
    }
    const signed_limbs = [4]E.Q{ r.payload[4], r.payload[8], r.sum[1], r.difference[1] };
    for (signed_limbs, 0..) |value, i| {
        const limb = value.toM31Array()[0].v;
        r.sign[i] = E.q(limb >> 15);
        r.low[i] = E.q(limb & 32767);
    }
    r.zero_pair = .{ r.zero[0].mul(r.zero[1]), r.zero[2].mul(r.zero[3]) };
    r.signed_less = E.q(@intCast(nativeResult(.slt, a, b)));
    return r;
}
