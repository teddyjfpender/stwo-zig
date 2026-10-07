//! Three fixed signed SHA boundary events per fused schedule/round row.
const std = @import("std");
const core = @import("stwo_core");
const air = @import("sha_fused_air.zig");
const base = @import("sha_direct_word_bus.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const Elements = base.Elements;
pub const tuple = base.tuple;
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

/// The first sixteen W words are received from the caller at addresses 8..23.
/// History a/e words are consumed on rows 0..3 of each call, and terminal
/// a/e words are emitted on rows 64..67. Fixed call IDs and selectors bind
/// every tuple to a verifier-owned address and call namespace.
pub fn eventExpr(comptime F: type, row: air.Row(F), fixed: air.Fixed(F), slot: usize) Expr(F) {
    std.debug.assert(slot < 3);
    if (slot == 0) return .{
        .values = tuple(F, fixed.call_id, field(F, 8).add(fixed.round_index), half(F, row.w_bits, 0), half(F, row.w_bits, 16)),
        .weight = field(F, 0).sub(fixed.first16),
    };
    const bits = if (slot == 1) row.a else row.e;
    const address = fixed.state_address.add(field(F, if (slot == 1) 0 else 4));
    return .{
        .values = tuple(F, fixed.call_id, address, half(F, bits, 0), half(F, bits, 16)),
        .weight = fixed.terminal.sub(fixed.input),
    };
}
