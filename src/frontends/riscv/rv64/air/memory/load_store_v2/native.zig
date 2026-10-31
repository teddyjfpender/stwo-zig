//! Narrow native event hints only; acceptance comes from LS19/RAM14 equations.
const std = @import("std");
const core = @import("stwo_core");
const Decode = @import("../../../decode.zig");
const V1 = @import("../load_store_v1/mod.zig");
const R = @import("../closed_ram/mod.zig");
const T = @import("types.zig");
const M = T.M;
pub const Event = struct { opcode: Decode.Opcode, immediate: u64, a: u64, b: u64 = 0, c: u64 = 0, epoch: u16, tick: u24, before: R.types.State, after: R.types.State };
pub const Description = struct { width: u4, signed: bool, write: bool, flag: usize };
pub fn describe(opcode: Decode.Opcode) !Description {
    inline for (V1.load_specs ++ V1.store_specs, 0..) |spec, i| if (opcode == spec.opcode) return .{ .width = @intCast(spec.width), .signed = spec.signed, .write = i >= V1.load_specs.len, .flag = i };
    return error.NotLoadStoreOpcode;
}
pub fn validate(event: Event) !void {
    const d = try describe(event.opcode);
    const ea = event.a +% event.immediate;
    if (event.tick == 0 or event.tick & 3 != 0 or ea & (d.width - 1) != 0 or event.before.rights != event.after.rights or event.after.epoch != event.epoch or event.after.tick != event.tick) return error.InvalidLoadStoreEvent;
    if (event.before.epoch > event.epoch or (event.before.epoch == event.epoch and event.before.tick >= event.tick)) return error.InvalidLoadStoreEventTime;
    const bits: usize = 8 * @as(usize, d.width);
    const mask: u64 = if (d.width == 8) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(bits))) - 1;
    const shift: u6 = @intCast(8 * (ea & 7));
    if (d.write) {
        if (event.before.rights & 2 == 0 or event.c != 0 or event.after.value != ((event.before.value & ~(mask << shift)) | ((event.b & mask) << shift))) return error.InvalidLoadStoreEvent;
    } else {
        const value = (event.before.value >> shift) & mask;
        const wanted = if (d.signed and (value & (@as(u64, 1) << @as(u6, @intCast(bits - 1)))) != 0) value | ~mask else value;
        if (event.before.rights & 1 == 0 or event.b != 0 or event.c != wanted or event.after.value != event.before.value) return error.InvalidLoadStoreEvent;
    }
}
pub fn row(event: ?Event) [79]M {
    var values: [79]M = @splat(M.zero());
    const e = event orelse return values;
    const d = describe(e.opcode) catch unreachable;
    const ea = e.a +% e.immediate;
    const address = ea & ~@as(u64, 7);
    values[0] = M.one();
    values[1] = M.fromCanonical(@intFromBool(d.write));
    values[2] = M.fromCanonical(@intFromBool(e.before.epoch == e.epoch));
    values[3] = M.fromCanonical(e.tick);
    R.trace.word(values[4..], address);
    values[8] = M.fromCanonical(e.before.epoch);
    values[9] = M.fromCanonical(e.epoch);
    values[10] = M.fromCanonical(@as(u16, @truncate(e.before.tick)));
    values[11] = M.fromCanonical(e.before.tick >> 16);
    values[12] = M.fromCanonical(@as(u16, @truncate(e.tick)));
    values[13] = M.fromCanonical(e.tick >> 16);
    R.trace.word(values[14..], e.before.value);
    R.trace.word(values[18..], e.after.value);
    values[22] = M.fromCanonical(e.before.rights & 1);
    values[23] = M.fromCanonical(e.before.rights >> 1);
    if (e.before.epoch == e.epoch) {
        const gap = e.tick - e.before.tick - 1;
        values[25] = M.fromCanonical(@as(u16, @truncate(gap)));
        values[26] = M.fromCanonical(gap >> 16);
        values[27] = M.fromCanonical((@as(u32, @as(u16, @truncate(e.before.tick))) + @as(u16, @truncate(gap)) + 1) >> 16);
    } else values[24] = M.fromCanonical(e.epoch - e.before.epoch - 1);
    const L = V1.layout;
    R.trace.word(values[L.a..], e.a);
    R.trace.word(values[L.immediate..], e.immediate);
    R.trace.word(values[L.b..], e.b);
    R.trace.word(values[L.c..], e.c);
    R.trace.word(values[L.effective..], ea);
    values[L.opcode] = M.fromCanonical(@intFromEnum(e.opcode));
    values[L.flags + d.flag] = M.one();
    const offset: usize = @intCast(ea & 7);
    values[L.offsets + offset] = M.one();
    values[L.quotient] = M.fromCanonical(@as(u16, @truncate(address)) / 8);
    const top = offset / 2 + (if (d.width == 1) 0 else d.width / 2 - 1);
    const limb: u16 = @truncate(e.before.value >> @as(u6, @intCast(16 * top)));
    const fact = V1.selection.fact(2 * @as(usize, limb) + (offset & 1));
    values[L.selected_limb] = M.fromCanonical(limb);
    values[L.selected_byte] = M.fromCanonical(fact[2]);
    values[L.selected_sign] = M.fromCanonical(fact[3]);
    values[L.limb_sign] = M.fromCanonical(fact[4]);
    values[L.b_low] = M.fromCanonical(@as(u8, @truncate(e.b)));
    values[L.b_high] = M.fromCanonical(@as(u8, @truncate(e.b >> 8)));
    var carry: u32 = 0;
    for (0..4) |i| {
        carry = (values[L.a + i].v + values[L.immediate + i].v + carry) >> 16;
        values[L.address_carries + i] = M.fromCanonical(carry);
    }
    return values;
}
pub fn boundaryRow(cells: []const R.types.Cell, index: usize) [23]M {
    var values: [23]M = @splat(M.zero());
    if (index >= cells.len) return values;
    const cell = cells[index];
    values[0] = M.one();
    R.trace.word(values[1..], cell.address);
    R.trace.word(values[5..], cell.state.value);
    values[9] = M.fromCanonical(cell.state.epoch);
    values[10] = M.fromCanonical(@as(u16, @truncate(cell.state.tick)));
    values[11] = M.fromCanonical(cell.state.tick >> 16);
    values[12] = M.fromCanonical(cell.state.rights & 1);
    values[13] = M.fromCanonical(cell.state.rights >> 1);
    if (index != 0) {
        R.trace.word(values[14..], cell.address - cells[index - 1].address);
        var carry: u32 = 0;
        var sum = M.zero();
        for (0..4) |i| {
            carry = (@as(u32, @as(u16, @truncate(cells[index - 1].address >> @as(u6, @intCast(16 * i))))) + values[14 + i].v + carry) >> 16;
            values[18 + i] = M.fromCanonical(carry);
            sum = sum.add(values[14 + i]);
        }
        values[22] = sum.inv() catch unreachable;
    }
    return values;
}
