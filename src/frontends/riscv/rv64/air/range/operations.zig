//! Byte bitwise and barrel-shift authority. Provider membership authenticates
//! every helper; equations below only select bytes and enforce machine output.
const E = @import("../evaluation.zig");
const Q = E.Q;
const Plan = @import("../encoding.zig").Plan;

pub fn bitwise(v: E.View, physical: []const Q, plan: *const Plan, out: *E.Sink) void {
    return bitwiseGeneric(Q, v, physical, plan, out);
}
pub fn bitwiseGeneric(comptime F: type, v: E.ViewFor(F), physical: []const F, plan: *const Plan, out: *E.SinkFor(F)) void {
    if (!plan.byte_bitwise) return;
    const band = v.sum(&.{ .AND, .ANDI });
    const bor = v.sum(&.{ .OR, .ORI });
    const bxor = v.sum(&.{ .XOR, .XORI });
    for (0..8) |i| {
        const ab = physical[plan.and_start + i];
        const a_plus_b = v.byte(.a, i).add(v.byte(.rhs, i));
        const result = v.byte(.result, i);
        out.emit(band.mul(result.sub(ab)));
        out.emit(bor.mul(result.sub(a_plus_b).add(ab)));
        out.emit(bxor.mul(result.sub(a_plus_b).add(ab.mul(E.qFor(F, 2)))));
    }
}

pub fn shifts(v: E.View, physical: []const Q, plan: *const Plan, out: *E.Sink) void {
    return shiftsGeneric(Q, v, physical, plan, out);
}
pub fn shiftsGeneric(comptime F: type, v: E.ViewFor(F), physical: []const F, plan: *const Plan, out: *E.SinkFor(F)) void {
    if (!plan.support.shifts) return;
    var selectors = F.zero();
    var offset = F.zero();
    for (0..8) |i| {
        const selector = physical[plan.shift_selectors + i];
        E.booleanFor(F, out, selector);
        selectors = selectors.add(selector);
        offset = offset.add(selector.mul(E.qFor(F, @intCast(i))));
    }
    out.emit(selectors.sub(F.one()));
    out.emit(offset.sub(v.bit(.rhs, 3)).sub(v.bit(.rhs, 4).mul(E.qFor(F, 2))).sub(v.bit(.rhs, 5).mul(E.qFor(F, 4))));
    out.emit(physical[plan.shift_amount].sub(v.bit(.rhs, 0)).sub(v.bit(.rhs, 1).mul(E.qFor(F, 2))).sub(v.bit(.rhs, 2).mul(E.qFor(F, 4))));
    const left64 = v.sum(&.{ .SLL, .SLLI });
    const right64 = v.sum(&.{ .SRL, .SRLI });
    const signed64 = v.sum(&.{ .SRA, .SRAI });
    const left32 = v.sum(&.{ .SLLW, .SLLIW });
    const right32 = v.sum(&.{ .SRLW, .SRLIW });
    const signed32 = v.sum(&.{ .SRAW, .SRAIW });
    for (0..8) |i| {
        const result = v.byte(.result, i);
        const l64 = selectedGeneric(F, physical, plan, i, 8, true, F.zero());
        const r64 = selectedGeneric(F, physical, plan, i, 8, false, F.zero());
        const s64 = selectedGeneric(F, physical, plan, i, 8, false, v.bit(.a, 63));
        out.emit(left64.mul(result.sub(l64)));
        out.emit(right64.mul(result.sub(r64)));
        out.emit(signed64.mul(result.sub(s64)));
        if (i < 4) {
            const l32 = selectedGeneric(F, physical, plan, i, 4, true, F.zero());
            const r32 = selectedGeneric(F, physical, plan, i, 4, false, F.zero());
            const s32 = selectedGeneric(F, physical, plan, i, 4, false, v.bit(.a, 31));
            out.emit(left32.mul(result.sub(l32)));
            out.emit(right32.mul(result.sub(r32)));
            out.emit(signed32.mul(result.sub(s32)));
        }
    }
    // High W bytes are sign-extended by the shared arithmetic word equations.
}

fn selectedGeneric(comptime F: type, physical: []const F, plan: *const Plan, byte: usize, width: usize, left: bool, sign: F) F {
    var result = F.zero();
    for (0..8) |offset| {
        const distance = offset % width;
        var value = F.zero();
        if (left) {
            if (byte >= distance) value = value.add(helperGeneric(F, physical, plan, byte - distance, 0));
            if (byte > distance) value = value.add(helperGeneric(F, physical, plan, byte - distance - 1, 1));
        } else {
            const source = byte + distance;
            value = value.add(if (source < width) helperGeneric(F, physical, plan, source, 2) else helperGeneric(F, physical, plan, 8, 2).mul(sign));
            value = value.add(if (source + 1 < width) helperGeneric(F, physical, plan, source + 1, 3) else helperGeneric(F, physical, plan, 8, 3).mul(sign));
        }
        result = result.add(physical[plan.shift_selectors + offset].mul(value));
    }
    return result;
}
fn helperGeneric(comptime F: type, physical: []const F, plan: *const Plan, input: usize, output: usize) F {
    return physical[plan.shift_outputs + input * 4 + output];
}
