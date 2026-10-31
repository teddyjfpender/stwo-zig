const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const F = @import("frame.zig");
const P = @import("packed_frame.zig");
const C = @import("../program/packed_control.zig");
const R = @import("../program/setup.zig");
const Q = E.Q;
const M = core.fields.m31.M31;
fn advice(pc: u64, next: u64, active: bool) P.Advice {
    const row = R.deriveRow(pc, 0x00108093);
    var native: [P.WIDTH]M = undefined;
    P.fillFromRowBase(&native, &row, next, active);
    var result: P.Advice = undefined;
    for (&result, native) |*value, field| value.* = Q.fromBase(field);
    return result;
}
fn check(current: *const P.Advice, previous: *const P.Advice, i: u32, steps: u32, initial: u64, final: u64, log: u32) bool {
    var values: [256]Q = undefined;
    var out = E.Sink{ .values = &values };
    P.evaluate(current, previous, .{ E.q(i), E.q(@intFromBool(i == 0)), E.q(@intFromBool(i + 1 == @as(u32, 1) << @intCast(log))) }, .{ .steps = steps, .initial_pc = initial, .final_pc = final }, log, &out);
    for (values[0..out.count]) |value| if (!value.isZero()) return false;
    return true;
}
test "packed frame carries all64 PC bits and holds unmasked adjacency through inactive padding" {
    const initial: u64 = 0xfffffffffffffffc;
    var previous: P.Advice = @splat(Q.zero());
    for (0..32) |i| {
        const pc: u64 = if (i == 0) initial else 0;
        const row = advice(pc, 0, i == 0);
        try std.testing.expect(check(&row, &previous, @intCast(i), 1, initial, 0, 5));
        if (i == 1) {
            var forged_previous = previous;
            forged_previous[P.NEXT_PC] = E.q(4);
            try std.testing.expect(!check(&row, &forged_previous, 1, 1, initial, 0, 5));
            var forged = row;
            forged[P.ENTRY + C.field.pc] = E.q(4);
            try std.testing.expect(!check(&forged, &previous, 1, 1, initial, 0, 5));
        }
        previous = row;
    }
    // Jointly alter the last active NEXT and every inactive PC/NEXT. Local
    // adjacency holds, but the independently expected terminal PC still wins.
    var forged_chain = advice(initial, 4, true);
    for (1..32) |i| {
        const row = advice(4, 4, false);
        try std.testing.expectEqual(i != 31, check(&row, &forged_chain, @intCast(i), 1, initial, 0, 5));
        forged_chain = row;
    }
    var all_active_previous: P.Advice = @splat(Q.zero());
    for (0..32) |i| {
        const pc: u64 = 0x1000 + 4 * i;
        const row = advice(pc, pc + 4, true);
        try std.testing.expect(check(&row, &all_active_previous, @intCast(i), 32, 0x1000, 0x1080, 5));
        all_active_previous = row;
    }
}
test "packed frame rejects canonical limb compensation which aliases a single M31 word" {
    const pc: u64 = @as(u64, 1) << 48;
    var row = advice(pc, pc + 4, true);
    const prior: P.Advice = @splat(Q.zero());
    try std.testing.expect(check(&row, &prior, 0, 1, pc, pc + 4, 5));
    // 2^48 == 2^17 in M31; BOTH triples satisfy24/24/16 bounds.
    const old = row[P.ENTRY + C.field.pc ..][0..3].*;
    row[P.ENTRY + C.field.pc] = E.q(131072);
    row[P.ENTRY + C.field.pc + 2] = Q.zero();
    const bad = row[P.ENTRY + C.field.pc ..][0..3].*;
    const factor24 = Q.fromBase(M.fromU64(@as(u64, 1) << 24));
    const factor48 = Q.fromBase(M.fromU64(@as(u64, 1) << 48));
    try std.testing.expectEqualDeep(old[0].add(old[1].mul(factor24)).add(old[2].mul(factor48)), bad[0].add(bad[1].mul(factor24)).add(bad[2].mul(factor48)));
    try std.testing.expect(!check(&row, &prior, 0, 1, pc, pc + 4, 5));
    const inflated = F.inflateWithControl(&row, .{ Q.zero(), Q.one(), Q.zero() }, .limbs24_v2);
    for ([_]usize{ E.L.fixed.pc, E.L.fixed.increment, E.L.fixed.target, E.L.fixed.next_pc }) |start| for (inflated[start..][0..8]) |value| try std.testing.expect(value.isZero());
}
