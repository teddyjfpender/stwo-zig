//! All query projections, shared by native advice and polynomial evaluation.
const E = @import("../evaluation.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const m = L.main;
pub fn tick(comptime F: type, index: F, slot: u32) F {
    return index.mul(T.literal(F, 4)).add(T.literal(F, slot + 1));
}
pub fn function(comptime F: type, row: []const F) [13]F {
    var out: [13]F = undefined;
    out[0] = row[m.operation];
    const pc = row[m.use_pc];
    const imm = row[m.use_immediate];
    const dyn = row[m.dynamic_next];
    for (0..4) |i| {
        out[1 + i] = row[m.a + i].add(pc.mul(row[m.pc + i].sub(row[m.a + i])));
        out[5 + i] = row[m.b + i].add(imm.mul(row[m.immediate + i].sub(row[m.b + i])));
        out[9 + i] = row[m.c + i].add(dyn.mul(row[m.next_pc + i].sub(row[m.c + i])));
    }
    return out;
}
pub fn register(comptime F: type, fixed: []const F, row: []const F, slot: usize, after: bool) [6]F {
    const start: usize = switch (slot) {
        0 => m.a,
        1 => m.b,
        2 => if (after) m.c else m.previous_rd,
        else => unreachable,
    };
    return .{ row[m.registers + slot], row[start], row[start + 1], row[start + 2], row[start + 3], if (after) tick(F, fixed[0], @intCast(slot)) else row[m.previous_clock + slot] };
}
pub fn rom(comptime F: type, row: []const F) [30]F {
    var out: [30]F = undefined;
    out[0] = F.one();
    for (0..4) |i| {
        out[L.rom.pc + i] = row[m.pc + i];
        out[L.rom.next_pc + i] = F.one().sub(row[m.dynamic_next]).mul(row[m.next_pc + i]);
        out[L.rom.immediate + i] = row[m.immediate + i];
        out[L.rom.link + i] = row[m.dynamic_next].mul(row[m.c + i]);
    }
    out[L.rom.operation] = row[m.operation];
    @memcpy(out[L.rom.registers..][0..3], row[m.registers..][0..3]);
    @memcpy(out[L.rom.zero..][0..3], row[m.zero..][0..3]);
    @memcpy(out[L.rom.flags..][0..5], row[m.use_immediate..][0..5]);
    out[L.rom.taken] = row[m.branch].mul(row[m.c]);
    return out;
}
pub fn owner(comptime F: type, fixed: []const F, row: []const F, epoch: F) [19]F {
    var out: [19]F = undefined;
    out[0] = row[m.operation];
    @memcpy(out[1..5], row[m.a..][0..4]);
    @memcpy(out[5..9], row[m.immediate..][0..4]);
    @memcpy(out[9..13], row[m.b..][0..4]);
    @memcpy(out[13..17], row[m.c..][0..4]);
    out[17] = epoch;
    out[18] = tick(F, fixed[0], 3);
    return out;
}
