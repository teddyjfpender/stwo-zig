//! Word-range replacement for the byte profile. Only selected positions use
//! Boolean decomposition; all remaining explicit bytes close through LogUp.
const E = @import("../evaluation.zig");
const Plan = @import("../encoding.zig").Plan;
const L = E.L;
/// Profile-specific range representation plus the shared arithmetic authority.
/// All branches depend only on the receiver-derived immutable plan.
pub fn local(v: E.View, out: *E.Sink, plan: *const Plan, physical: []const E.Q) void {
    std.debug.assert(plan.wide_clocks);
    wordRanges(v, out, plan);
    for (0..L.CARRIES) |i| {
        if (!plan.support.carries[i]) continue;
        const value = v.m[L.carry_start + i];
        E.boolean(out, value);
        out.emit(E.Q.one().sub(v.f[L.fixed.carry_start + i]).mul(value));
    }
    clockRanges(v, out, plan);
    for ([_]usize{ L.readable, L.writable, L.divisor_zero, L.sign_a, L.sign_b, L.negate, L.apply_negate, L.equal, L.taken }) |column| E.boolean(out, v.m[column]);
    @import("../arithmetic_constraints.zig").evaluateProfile(v, out, plan.byte_operations);
    if (plan.byte_operations) {
        @import("operations.zig").bitwise(v, physical, plan, out);
        @import("operations.zig").shifts(v, physical, plan, out);
    } else if (plan.support.shifts) @import("../shift_constraints.zig").evaluate(v, out);
    @import("../memory_constraints.zig").evaluate(v, out);
    if (plan.support.product) @import("../product_constraints.zig").evaluateProfile(v, out, plan.compact_product_carries);
    @import("../division_constraints.zig").evaluate(v, out);
}
const std = @import("std");
pub fn wordRanges(v: E.View, out: *E.Sink, plan: *const Plan) void {
    for (0..L.WORDS) |w| {
        if (!plan.support.words[w]) continue;
        const word: L.Word = @enumFromInt(w);
        for (0..8) |i| {
            if (plan.byte_bits[w][i]) {
                var reconstructed = E.Q.zero();
                for (0..8) |j| {
                    const bit = v.bit(word, 8 * i + j);
                    E.boolean(out, bit);
                    reconstructed = reconstructed.add(bit.mul(E.q(@as(u32, 1) << @as(u5, @intCast(j)))));
                }
                out.emit(v.byte(word, i).sub(reconstructed));
            }
            out.emit(E.Q.one().sub(v.f[L.fixed.word_start + w]).mul(v.byte(word, i)));
        }
    }
}

/// Replaces the first thirteen emissions per product carry in the legacy
/// product evaluator: 11 bits, reconstruction, and disabled-carry zero.
/// Arithmetic convolution constraints remain in their existing authority.
pub fn productCarryRange(v: E.View, out: *E.Sink, index: usize, product: E.Q) void {
    const start = L.productCarry(index);
    var reconstructed = v.m[start + 1];
    for (8..11) |bit| {
        const value = v.m[start + 1 + bit];
        E.boolean(out, value);
        reconstructed = reconstructed.add(value.mul(E.q(@as(u32, 1) << @as(u5, @intCast(bit)))));
    }
    out.emit(v.m[start].sub(reconstructed));
    out.emit(E.Q.one().sub(product).mul(v.m[start]));
}

pub fn clockRanges(v: E.View, out: *E.Sink, plan: *const Plan) void {
    for (0..4) |slot| {
        if (!plan.support.slots[slot]) continue;
        const enabled = v.f[L.fixed.slot_start + slot];
        const previous = v.m[L.previousClock(slot)];
        const gap = v.m[L.gap(slot)];
        out.emit(E.Q.one().sub(enabled).mul(previous));
        out.emit(E.Q.one().sub(enabled).mul(gap));
        out.emit(enabled.mul(previous.add(gap).add(E.Q.one()).sub(v.f[L.fixed.tick_start + slot])));
    }
}
