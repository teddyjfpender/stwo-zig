//! All query projections, shared by native advice and polynomial evaluation.
const E = @import("../evaluation.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const m = L.main;
pub fn tick(comptime F: type, index: F, slot: u32) F {
    return index.mul(T.literal(F, 4)).add(T.literal(F, slot + 1));
}
/// Exact substitution of the old clock-gap equality. REG closure, canonical
/// boundaries and fixed after-times still establish chronological induction.
pub fn previousClock(comptime F: type, index: F, row: []const F, slot: u32) F {
    return tick(F, index, slot).sub(F.one()).sub(row[m.gap16 + slot]).sub(T.literal(F, 65536).mul(row[m.gap8 + slot]));
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
    return .{ row[m.registers + slot], row[start], row[start + 1], row[start + 2], row[start + 3], if (after) tick(F, fixed[0], @intCast(slot)) else previousClock(F, fixed[0], row, @intCast(slot)) };
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
    for (0..3) |slot| out[L.rom.zero + slot] = F.one().sub(row[m.enabled + slot]);
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

/// Compact decode projections (Geometry.cpu_compact_decode). Honest REG,
/// FUNCTION13 and OWNER19 tuples equal the legacy ones value-for-value,
/// except that AUIPC/JAL request ADD(0, pc+imm) / ADD(0, pc+4).
pub const compact = struct {
    const k = L.compact;
    /// felt(next) = next0 + 65536*next1.
    pub fn nextFelt(comptime F: type, row: []const F) F {
        return row[k.next].add(T.literal(F, 65536).mul(row[k.next + 1]));
    }
    pub fn compactPreviousClock(comptime F: type, index: F, row: []const F, slot: u32) F {
        return tick(F, index, slot).sub(F.one()).sub(row[k.gap16 + slot]).sub(T.literal(F, 65536).mul(row[k.gap8 + slot]));
    }
    /// A_eff = A and B_eff = B (both linear). On dynamic rows C_eff is the
    /// committed target (next0, next1, 0, 0); AND16 then proves those two
    /// limbs canonical and the two upper limbs of the true target zero.
    pub fn function(comptime F: type, row: []const F) [13]F {
        var out: [13]F = undefined;
        out[0] = row[k.operation];
        const dyn = row[k.dynamic_next];
        const target = [4]F{ row[k.next], row[k.next + 1], F.zero(), F.zero() };
        for (0..4) |i| {
            out[1 + i] = row[k.a + i];
            out[5 + i] = row[k.b + i];
            out[9 + i] = row[k.c + i].add(dyn.mul(target[i].sub(row[k.c + i])));
        }
        return out;
    }
    pub fn register(comptime F: type, fixed: []const F, row: []const F, slot: usize, after: bool) [6]F {
        const start: usize = switch (slot) {
            0 => k.a,
            1 => k.b,
            2 => if (after) k.c else k.previous_rd,
            else => unreachable,
        };
        return .{ row[k.registers + slot], row[start], row[start + 1], row[start + 2], row[start + 3], if (after) tick(F, fixed[0], @intCast(slot)) else compactPreviousClock(F, fixed[0], row, @intCast(slot)) };
    }
    /// ROM30 query of `Entry.romTupleCompact`. The pc coordinate is read from
    /// the previous row (row 0: the public initial PC), so the PC chain is
    /// definitional; every coordinate has degree <= 2.
    /// `initial_pc` is felt(public initial PC) as a lane value.
    pub fn rom(comptime F: type, fixed: []const F, row: []const F, previous_main: []const F, initial_pc: F) [30]F {
        var out: [30]F = @splat(F.zero());
        const first = fixed[L.fixed.first];
        const dyn = row[k.dynamic_next];
        const free1 = F.one().sub(row[k.enabled + 1]);
        out[0] = F.one();
        out[L.rom.pc] = first.mul(initial_pc).add(F.one().sub(first).mul(nextFelt(F, previous_main)));
        out[L.rom.next_pc] = F.one().sub(dyn).mul(nextFelt(F, row));
        out[L.rom.operation] = row[k.operation];
        @memcpy(out[L.rom.registers..][0..3], row[k.registers..][0..3]);
        for (0..3) |slot| out[L.rom.zero + slot] = F.one().sub(row[k.enabled + slot]);
        for (0..4) |i| {
            out[L.rom.immediate + i] = free1.mul(row[k.b + i]);
            out[L.rom.link + i] = dyn.mul(row[k.c + i]);
        }
        out[L.rom.flags + 0] = row[k.ls_imm];
        out[L.rom.flags + 1] = row[k.branch];
        out[L.rom.flags + 2] = row[k.ls_imm + 1];
        out[L.rom.flags + 3] = dyn;
        out[L.rom.flags + 4] = row[k.function];
        out[L.rom.taken] = row[k.branch].mul(row[k.c]);
        return out;
    }
    /// OWNER19 with IMM = (low16, sign, sign, sign) and B_store = B: affine,
    /// so the OWNER+U16 fraction keeps degree 3.
    pub fn owner(comptime F: type, fixed: []const F, row: []const F, epoch: F) [19]F {
        var out: [19]F = undefined;
        out[0] = row[k.operation];
        @memcpy(out[1..5], row[k.a..][0..4]);
        out[5] = row[k.ls_imm];
        for (6..9) |i| out[i] = row[k.ls_imm + 1];
        @memcpy(out[9..13], row[k.b..][0..4]);
        @memcpy(out[13..17], row[k.c..][0..4]);
        out[17] = epoch;
        out[18] = tick(F, fixed[0], 3);
        return out;
    }
};
