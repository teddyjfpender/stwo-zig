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
        out[L.main.enabled + slot] = M.fromCanonical(@intFromBool(id != 0));
        const tick = 4 * index + @as(u32, @intCast(slot)) + 1;
        if (clocks[slot] >= tick or (id == 0 and clocks[slot] != 0)) return error.InvalidExecutionClock;
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
        const gap = 4 * index + @as(u32, @intCast(slot));
        out[L.main.gap16 + slot] = M.fromCanonical(@as(u16, @truncate(gap)));
        out[L.main.gap8 + slot] = M.fromCanonical(gap >> 16);
    }
    return out;
}

/// Compact decode rows (Geometry.cpu_compact_decode). The returned Main has
/// L.compact.COUNT meaningful columns; the tail is zero and never committed.
pub const compact = struct {
    const k = L.compact;
    pub fn active(entry: Feature.Entry, index: u32, next_pc: u64, values: Values, clocks: [3]u32) !Main {
        if (!entry.compactValid() or index >= (1 << L.MAX_LOG) - 1) return error.InvalidExecutionRow;
        if (next_pc & 3 != 0 or next_pc >= Feature.COMPACT_PC_LIMIT) return error.InvalidExecutionNextPc;
        const taken = entry.branch and values.c != 0;
        if (!entry.dynamic_next and next_pc != entry.staticNext(taken)) return error.InvalidExecutionNextPc;
        if (taken and !entry.compactTakenEdge()) return error.InvalidExecutionNextPc;
        var out = compactBase(index, next_pc);
        out[k.active] = M.one();
        out[k.operation] = M.fromCanonical(entry.operation);
        for (entry.ids, 0..) |id, slot| {
            out[k.registers + slot] = M.fromCanonical(id);
            out[k.enabled + slot] = M.fromCanonical(@intFromBool(id != 0));
            const tick = 4 * index + @as(u32, @intCast(slot)) + 1;
            if (clocks[slot] >= tick or (id == 0 and clocks[slot] != 0)) return error.InvalidExecutionClock;
            const gap = tick - clocks[slot] - 1;
            out[k.gap16 + slot] = M.fromCanonical(@as(u16, @truncate(gap)));
            out[k.gap8 + slot] = M.fromCanonical(gap >> 16);
        }
        if ((entry.ids[0] == 0 and values.a != 0) or (entry.ids[1] == 0 and values.b != 0) or (entry.ids[2] == 0 and values.previous_rd != 0)) return error.InvalidExecutionZeroRegister;
        Feature.put(&out, k.a, values.a);
        // Immediate rows never read rs2 (compactValid), so values.b == 0 here.
        Feature.put(&out, k.b, if (entry.use_immediate) entry.compactB() else values.b);
        Feature.put(&out, k.c, values.c);
        Feature.put(&out, k.previous_rd, values.previous_rd);
        const ls = entry.compactLs().?;
        out[k.ls_imm] = M.fromCanonical(ls[0]);
        out[k.ls_imm + 1] = M.fromCanonical(ls[1]);
        out[k.branch] = M.fromCanonical(@intFromBool(entry.branch));
        out[k.dynamic_next] = M.fromCanonical(@intFromBool(entry.dynamic_next));
        out[k.function] = M.fromCanonical(@intFromBool(entry.function));
        return out;
    }
    pub fn padding(index: u32, final_pc: u64) !Main {
        if (index >= 1 << L.MAX_LOG) return error.InvalidExecutionRow;
        if (final_pc & 3 != 0 or final_pc >= Feature.COMPACT_PC_LIMIT) return error.InvalidExecutionNextPc;
        return compactBase(index, final_pc);
    }
    fn compactBase(index: u32, next_pc: u64) Main {
        var out: Main = @splat(M.zero());
        out[k.next] = M.fromCanonical(@as(u16, @truncate(next_pc)));
        out[k.next + 1] = M.fromCanonical(@as(u16, @truncate(next_pc >> 16)));
        for (0..3) |slot| {
            const gap = 4 * index + @as(u32, @intCast(slot));
            out[k.gap16 + slot] = M.fromCanonical(@as(u16, @truncate(gap)));
            out[k.gap8 + slot] = M.fromCanonical(gap >> 16);
        }
        return out;
    }
};
