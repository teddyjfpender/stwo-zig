//! Three signed word events on a shift-register SHA round row.
const std = @import("std");
const core = @import("stwo_core");
const shift = @import("sha_round_shift_air.zig");
const base = @import("sha_direct_word_bus.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const Elements = base.Elements;
pub const tuple = base.tuple;
pub const schedule_base = base.schedule_base;
pub const terminal_base = base.terminal_base;

fn field(comptime F: type, value: u32) F {
    const number = M31.fromCanonical(value);
    return if (F == M31) number else QM31.fromBase(number);
}
fn half(comptime F: type, bits: [32]F, start: usize) F {
    var value = field(F, 0);
    for (0..16) |i| value = value.add(bits[start + i].mul(field(F, @as(u32, 1) << @intCast(i))));
    return value;
}
pub fn Expr(comptime F: type) type {
    return struct { values: [6]F, weight: F };
}

/// Slot zero consumes W[t] on rows 3..66. Slots one and two consume
/// initial a/e history on rows 0..3 and emit final a/e history on rows
/// 64..67. Addresses are fixed; values are committed bits or W halves.
pub fn roundEventExpr(comptime F: type, row: shift.Row(F), fixed: shift.Fixed(F), call_id: F, slot: usize) Expr(F) {
    std.debug.assert(slot < 3);
    if (slot == 0) return .{
        .values = tuple(F, call_id, field(F, schedule_base).add(fixed.round_index), row.w_lo, row.w_hi),
        .weight = field(F, 0).sub(fixed.active),
    };
    const bits = if (slot == 1) row.a else row.e;
    const address = fixed.state_address.add(field(F, if (slot == 1) 0 else 4));
    return .{
        .values = tuple(F, call_id, address, half(F, bits, 0), half(F, bits, 16)),
        .weight = fixed.terminal.sub(fixed.input),
    };
}
