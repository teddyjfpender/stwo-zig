//! Native lookup-only projection. No carry/alignment/selector witness replay.
//! The accepting polynomial authority remains equations.zig / closed_ram.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const T = @import("types.zig");
const Decode = @import("../../../../decode.zig");
pub const Row = struct {
    range16: [22]u16 = @splat(0),
    range8: [19]u8 = @splat(0),
    id: u32 = 0,
    active: bool = false,
    pub fn fromCall(call: ?*const T.Call, lane: usize, id: u32) Row {
        const c = call orelse return .{};
        const before = c.predecessors[lane];
        var out = Row{ .active = true, .id = id };
        split(&out.range16, 0, c.pointer + 8 * lane);
        out.range16[4] = before.epoch;
        out.range16[5] = c.epoch;
        out.range16[6] = @truncate(before.tick);
        out.range16[7] = @truncate(c.tick);
        split(&out.range16, 8, c.before[lane]);
        split(&out.range16, 12, c.after[lane]);
        split(&out.range16, 18, c.pointer);
        out.range8[0] = @intCast(before.tick >> 16);
        out.range8[1] = @intCast(c.tick >> 16);
        if (before.epoch == c.epoch) {
            const gap = c.tick - before.tick - 1;
            out.range16[17] = @truncate(gap);
            out.range8[2] = @intCast(gap >> 16);
        } else out.range16[16] = c.epoch - before.epoch - 1;
        for (0..8) |i| {
            out.range8[3 + i] = @truncate(c.before[lane] >> @as(u6, @intCast(8 * i)));
            out.range8[11 + i] = @truncate(c.after[lane] >> @as(u6, @intCast(8 * i)));
        }
        return out;
    }
    pub fn ramTuple(self: Row, after: bool) [14]M {
        var out: [14]M = @splat(M.zero());
        out[0] = M.one();
        for (0..4) |i| out[1 + i] = M.fromCanonical(self.range16[i]);
        out[5] = M.fromCanonical(self.range16[if (after) 5 else 4]);
        out[6] = M.fromCanonical(self.range16[if (after) 7 else 6]);
        out[7] = M.fromCanonical(self.range8[if (after) 1 else 0]);
        for (0..4) |i| out[8 + i] = M.fromCanonical(self.range16[(if (after) @as(usize, 12) else 8) + i]);
        out[12] = M.fromCanonical(@intFromBool(self.active));
        out[13] = out[12];
        return out;
    }
    pub fn ownerTuple(self: Row) [19]M {
        var out: [19]M = @splat(M.zero());
        out[0] = M.fromCanonical(@intFromEnum(Decode.Opcode.ECALL));
        for (0..4) |i| out[1 + i] = M.fromCanonical(self.range16[18 + i]);
        out[9] = M.one();
        out[10] = M.one();
        out[17] = M.fromCanonical(self.range16[5]);
        out[18] = M.fromCanonical(@as(u32, self.range16[7]) + 65536 * @as(u32, self.range8[1]));
        return out;
    }
    pub fn ioTuple(self: Row, lane: usize, after: bool) [11]M {
        var out: [11]M = undefined;
        out[0] = M.fromCanonical(self.id);
        out[1] = M.fromCanonical(@intFromBool(after));
        out[2] = M.fromCanonical(@intCast(lane));
        for (0..8) |i| out[3 + i] = M.fromCanonical(self.range8[(if (after) @as(usize, 11) else 3) + i]);
        return out;
    }
};
fn split(out: []u16, start: usize, value: u64) void {
    for (0..4) |i| out[start + i] = @truncate(value >> @as(u6, @intCast(16 * i)));
}
