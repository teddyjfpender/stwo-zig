//! Word-range replacement for the byte profile. Only selected positions use
//! Boolean decomposition; all remaining explicit bytes close through LogUp.
const E = @import("../evaluation.zig");
const Q = E.Q;
const Plan = @import("../encoding.zig").Plan;
const L = E.L;
const Inflation = @import("../encoding.zig").Inflation;
/// Profile-specific range representation plus the shared arithmetic authority.
/// All branches depend only on the receiver-derived immutable plan.
pub fn local(v: E.View, out: *E.Sink, plan: *const Plan, physical: []const E.Q) void {
    return localGeneric(Q, v, out, plan, physical);
}
pub fn localGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), plan: *const Plan, physical: []const F) void {
    localImplGeneric(F, v, out, plan, physical, null);
}
/// Only valid for the exact canonical logical substitution in prepared.main.
pub fn localInflated(fixed: *const E.Fixed, prepared: Inflation.Result, out: *E.Sink, plan: *const Plan, physical: []const E.Q) void {
    return localInflatedGeneric(Q, fixed, prepared, out, plan, physical);
}
pub fn localInflatedGeneric(comptime F: type, fixed: *const E.FixedFor(F), prepared: Inflation.ResultFor(F), out: *E.SinkFor(F), plan: *const Plan, physical: []const F) void {
    localImplGeneric(F, .{ .f = fixed, .m = prepared.main }, out, plan, physical, prepared);
}
fn localImplGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), plan: *const Plan, physical: []const F, prepared: ?Inflation.ResultFor(F)) void {
    std.debug.assert(plan.wide_clocks);
    wordRangesImplGeneric(F, v, out, plan, prepared != null);
    for (0..L.CARRIES) |i| {
        if (!plan.support.carries[i]) continue;
        const value = v.m[L.carry_start + i];
        E.booleanFor(F, out, value);
        out.emit(F.one().sub(v.f[L.fixed.carry_start + i]).mul(value));
    }
    clockRangesGeneric(F, v, out, plan);
    for ([_]usize{ L.readable, L.writable, L.divisor_zero, L.sign_a, L.sign_b, L.negate, L.apply_negate, L.equal, L.taken }) |column| E.booleanFor(F, out, v.m[column]);
    @import("../arithmetic_constraints.zig").evaluateProfileWithControlGeneric(F, v, out, plan.byte_operations, plan.control_policy);
    if (plan.byte_operations) {
        @import("operations.zig").bitwiseGeneric(F, v, physical, plan, out);
        @import("operations.zig").shiftsGeneric(F, v, physical, plan, out);
    } else if (plan.support.shifts) @import("../shift_constraints.zig").evaluateGeneric(F, v, out);
    @import("../memory_constraints.zig").evaluateGeneric(F, v, out);
    if (plan.support.product) {
        if (prepared) |result| @import("../product_constraints.zig").evaluateInflatedGeneric(F, v.f, result, out, plan.compact_product_carries) else @import("../product_constraints.zig").evaluateProfileGeneric(F, v, out, plan.compact_product_carries);
    }
    @import("../division_constraints.zig").evaluateGeneric(F, v, out);
}
const std = @import("std");
pub fn wordRanges(v: E.View, out: *E.Sink, plan: *const Plan) void {
    return wordRangesGeneric(Q, v, out, plan);
}
pub fn wordRangesGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), plan: *const Plan) void {
    wordRangesImplGeneric(F, v, out, plan, false);
}
fn wordRangesImplGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), plan: *const Plan, derived: bool) void {
    for (0..L.WORDS) |w| {
        if (!plan.support.words[w]) continue;
        const word: L.Word = @enumFromInt(w);
        for (0..8) |i| {
            if (plan.byte_bits[w][i]) {
                var reconstructed = F.zero();
                for (0..8) |j| {
                    const bit = v.bit(word, 8 * i + j);
                    E.booleanFor(F, out, bit);
                    if (!derived) reconstructed = reconstructed.add(bit.mul(E.qFor(F, @as(u32, 1) << @as(u5, @intCast(j)))));
                }
                if (derived) out.zeros(1) else out.emit(v.byte(word, i).sub(reconstructed));
            }
            out.emit(F.one().sub(v.f[L.fixed.word_start + w]).mul(v.byte(word, i)));
        }
    }
}

/// Replaces the first thirteen emissions per product carry in the legacy
/// product evaluator: 11 bits, reconstruction, and disabled-carry zero.
/// Arithmetic convolution constraints remain in their existing authority.
pub fn productCarryRange(v: E.View, out: *E.Sink, index: usize, product: E.Q) void {
    return productCarryRangeGeneric(Q, v, out, index, product);
}
pub fn productCarryRangeGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), index: usize, product: F) void {
    productCarryRangeImplGeneric(F, v, out, index, product, false);
}
pub fn productCarryRangeInflated(fixed: *const E.Fixed, prepared: Inflation.Result, out: *E.Sink, index: usize, product: E.Q) void {
    return productCarryRangeInflatedGeneric(Q, fixed, prepared, out, index, product);
}
pub fn productCarryRangeInflatedGeneric(comptime F: type, fixed: *const E.FixedFor(F), prepared: Inflation.ResultFor(F), out: *E.SinkFor(F), index: usize, product: F) void {
    productCarryRangeImplGeneric(F, .{ .f = fixed, .m = prepared.main }, out, index, product, true);
}
fn productCarryRangeImplGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), index: usize, product: F, derived: bool) void {
    const start = L.productCarry(index);
    var reconstructed = v.m[start + 1];
    for (8..11) |bit| {
        const value = v.m[start + 1 + bit];
        E.booleanFor(F, out, value);
        if (!derived) reconstructed = reconstructed.add(value.mul(E.qFor(F, @as(u32, 1) << @as(u5, @intCast(bit)))));
    }
    if (derived) out.zeros(1) else out.emit(v.m[start].sub(reconstructed));
    out.emit(F.one().sub(product).mul(v.m[start]));
}

pub fn clockRanges(v: E.View, out: *E.Sink, plan: *const Plan) void {
    return clockRangesGeneric(Q, v, out, plan);
}
pub fn clockRangesGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), plan: *const Plan) void {
    for (0..4) |slot| {
        if (!plan.support.slots[slot]) continue;
        const enabled = v.f[L.fixed.slot_start + slot];
        const previous = v.m[L.previousClock(slot)];
        const gap = v.m[L.gap(slot)];
        out.emit(F.one().sub(enabled).mul(previous));
        out.emit(F.one().sub(enabled).mul(gap));
        out.emit(enabled.mul(previous.add(gap).add(F.one()).sub(v.f[L.fixed.tick_start + slot])));
    }
}
