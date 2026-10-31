//! Native column formatting only. Arithmetic results come from compact advice;
//! family chips, not this formatter, establish their semantics.
const M = @import("stwo_core").fields.m31.M31;
const Feature = @import("features.zig");
const L = @import("layout.zig");
pub fn RowFor(comptime F: type) type {
    return [L.main.COUNT]F;
}
pub const Main = RowFor(M);
pub const Values = struct { a: u64, b: u64, c: u64, previous_rd: u64 };
pub fn active(entry: Feature.Entry, index: u32, next_pc: u64, values: Values, clocks: [3]u32) !Main {
    if (!entry.valid or index >= (1 << L.MAX_LOG) - 1) return error.InvalidExecutionRow;
    if (next_pc & 3 != 0) return error.InvalidExecutionNextPc;
    if (!entry.dynamic_next and next_pc != entry.staticNext(entry.branch and values.c != 0)) return error.InvalidExecutionNextPc;
    var out = base(index, entry.pc, next_pc);
    out[L.main.active] = M.one();
    out[L.main.operation] = M.fromCanonical(entry.operation);
    for (entry.ids, 0..) |id, slot| {
        out[L.main.registers + slot] = M.fromCanonical(id);
        out[L.main.zero + slot] = M.fromCanonical(@intFromBool(id == 0));
        out[L.main.enabled + slot] = M.fromCanonical(@intFromBool(id != 0));
        const tick = 4 * index + @as(u32, @intCast(slot)) + 1;
        if (clocks[slot] >= tick or (id == 0 and clocks[slot] != 0)) return error.InvalidExecutionClock;
        out[L.main.previous_clock + slot] = M.fromCanonical(clocks[slot]);
        const gap = tick - clocks[slot] - 1;
        out[L.main.gap16 + slot] = M.fromCanonical(@as(u16, @truncate(gap)));
        out[L.main.gap8 + slot] = M.fromCanonical(gap >> 16);
    }
    if ((entry.ids[0] == 0 and values.a != 0) or (entry.ids[1] == 0 and values.b != 0) or (entry.ids[2] == 0 and values.previous_rd != 0)) return error.InvalidExecutionZeroRegister;
    Feature.put(&out, L.main.a, values.a);
    Feature.put(&out, L.main.b, values.b);
    Feature.put(&out, L.main.c, values.c);
    Feature.put(&out, L.main.previous_rd, values.previous_rd);
    Feature.put(&out, L.main.immediate, entry.immediate);
    for ([_]bool{ entry.use_immediate, entry.branch, entry.use_pc, entry.dynamic_next, entry.function }, 0..) |flag, i| out[L.main.use_immediate + i] = M.fromCanonical(@intFromBool(flag));
    return out;
}
pub fn padding(index: u32, final_pc: u64) !Main {
    if (index >= 1 << L.MAX_LOG) return error.InvalidExecutionRow;
    return base(index, final_pc, final_pc);
}
fn base(index: u32, pc: u64, next_pc: u64) Main {
    var out: Main = @splat(M.zero());
    Feature.put(&out, L.main.pc, pc);
    Feature.put(&out, L.main.next_pc, next_pc);
    for (0..3) |slot| {
        out[L.main.zero + slot] = M.one();
        const gap = 4 * index + @as(u32, @intCast(slot));
        out[L.main.gap16 + slot] = M.fromCanonical(@as(u16, @truncate(gap)));
        out[L.main.gap8 + slot] = M.fromCanonical(gap >> 16);
    }
    return out;
}
