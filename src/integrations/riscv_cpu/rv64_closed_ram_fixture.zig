//! Native witness for independently expected CLOSED RAM facts; not an authority.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram;
const P = @import("rv64_closed_ram_public.zig");
const L = R.layout;
const T = R.types;
const M = core.fields.m31.M31;
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    traces: [7]R.trace.Trace,
    pub fn init(a: std.mem.Allocator, expected: P.Expected) !Fixture {
        try expected.validate();
        var result: Fixture = undefined;
        result.allocator = a;
        var built: usize = 0;
        errdefer for (result.traces[0..built]) |*trace| trace.deinit();
        const kinds = [_]L.Kind{ .transition, .transition, .initial, .terminal, .owner, .range16, .range8 };
        const logs = [_]u32{ 5, 6, 5, 5, 5, 16, 8 };
        const rows = [_]u32{ expected.split, @intCast(expected.operations.len - expected.split), @intCast(expected.initial.len), @intCast(expected.terminal.len), @intCast(expected.operations.len), 0, 0 };
        for (&result.traces, kinds, logs, rows) |*trace, kind, log, count| {
            trace.* = try R.trace.Trace.init(a, kind, log, count);
            built += 1;
        }
        boundary(&result.traces[2], expected.initial);
        boundary(&result.traces[3], expected.terminal);
        var roster: T.PublicRows = @splat(@splat(M.zero()));
        const states = try a.alloc(T.State, expected.initial.len);
        defer a.free(states);
        for (states, expected.initial) |*state, cell| state.* = cell.state;
        for (expected.operations, 0..) |op, index| {
            const ci = try expected.cellIndex(op.address);
            const before = states[ci];
            var row: T.Row = @splat(M.zero());
            row[0] = M.one();
            row[1] = M.fromCanonical(@intFromBool(op.write));
            row[2] = M.fromCanonical(@intFromBool(before.epoch == op.epoch));
            row[3] = M.fromCanonical(op.id);
            R.trace.word(row[4..], op.address);
            row[8] = M.fromCanonical(before.epoch);
            row[9] = M.fromCanonical(op.epoch);
            row[10] = M.fromCanonical(@as(u16, @truncate(before.tick)));
            row[11] = M.fromCanonical(before.tick >> 16);
            row[12] = M.fromCanonical(@as(u16, @truncate(op.tick)));
            row[13] = M.fromCanonical(op.tick >> 16);
            R.trace.word(row[14..], before.value);
            R.trace.word(row[18..], op.value);
            row[22] = M.fromCanonical(before.rights & 1);
            row[23] = M.fromCanonical(before.rights >> 1);
            if (before.epoch == op.epoch) {
                if (before.tick >= op.tick) return error.InvalidClosedRamNativeOrder;
                const gap: u24 = op.tick - before.tick - 1;
                row[25] = M.fromCanonical(@as(u16, @truncate(gap)));
                row[26] = M.fromCanonical(gap >> 16);
                const sum = @as(u32, @as(u16, @truncate(before.tick))) + @as(u16, @truncate(gap)) + 1;
                row[27] = M.fromCanonical(sum >> 16);
            } else {
                if (before.epoch >= op.epoch) return error.InvalidClosedRamNativeOrder;
                row[24] = M.fromCanonical(op.epoch - before.epoch - 1);
            }
            const shard: usize = if (index < expected.split) 0 else 1;
            result.traces[shard].put(if (shard == 0) index else index - expected.split, &row);
            roster[index][0] = row[3];
            @memcpy(roster[index][1..5], row[4..8]);
            roster[index][5] = row[9];
            roster[index][6] = row[12];
            roster[index][7] = row[13];
            @memcpy(roster[index][8..12], row[18..22]);
            roster[index][12] = row[1];
            roster[index][13] = M.one();
            states[ci] = .{ .value = op.value, .epoch = op.epoch, .tick = op.tick, .rights = before.rights };
        }
        result.traces[4].bindPublic(roster);
        try result.recount();
        return result;
    }
    pub fn deinit(self: *Fixture) void {
        for (&self.traces) |*trace| trace.deinit();
        self.* = undefined;
    }
    pub fn recount(self: *Fixture) !void {
        const a = self.allocator;
        const c16 = try a.alloc(u64, 65536);
        defer a.free(c16);
        @memset(c16, 0);
        var c8: [256]u64 = @splat(0);
        for (self.traces[0..4]) |*trace| trace.countRanges(c16, &c8);
        try self.traces[5].setCounts(c16);
        try self.traces[6].setCounts(&c8);
    }
    pub fn columns(self: *const Fixture, tree: u2) ![]@import("stwo_prover_engine").pcs.ColumnEvaluation {
        const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
        var count: usize = 0;
        for (self.traces) |trace| count += L.widths(trace.kind)[tree];
        const out = try self.allocator.alloc(Column, count);
        var cursor: usize = 0;
        for (self.traces) |trace| {
            const data = switch (tree) {
                0 => trace.fixed,
                1 => trace.main,
                2 => trace.interaction,
                else => unreachable,
            };
            for (0..L.widths(trace.kind)[tree]) |c| {
                out[cursor] = .{ .log_size = trace.log_size, .values = data[c * trace.size() ..][0..trace.size()] };
                cursor += 1;
            }
        }
        return out;
    }
    pub fn generate(self: *Fixture, ch: T.Challenges) ![7]T.Claims {
        var claims: [7]T.Claims = undefined;
        for (&self.traces, &claims) |*trace, *claim| claim.* = try trace.generate(ch);
        return claims;
    }
};
pub fn boundary(trace: *R.trace.Trace, cells: []const T.Cell) void {
    var roster: T.PublicRows = @splat(@splat(M.zero()));
    for (cells, 0..) |cell, i| {
        const row = &roster[i];
        row[0] = M.one();
        R.trace.word(row[1..], cell.address);
        R.trace.word(row[5..], cell.state.value);
        row[9] = M.fromCanonical(cell.state.epoch);
        row[10] = M.fromCanonical(@as(u16, @truncate(cell.state.tick)));
        row[11] = M.fromCanonical(cell.state.tick >> 16);
        row[12] = M.fromCanonical(cell.state.rights & 1);
        row[13] = M.fromCanonical(cell.state.rights >> 1);
    }
    trace.bindPublic(roster);
    for (cells[1..], 1..) |cell, i| {
        var row: [23]M = @splat(M.zero());
        @memcpy(row[0..14], &roster[i]);
        R.trace.word(row[14..], cell.address - cells[i - 1].address);
        var carry: u32 = 0;
        var sum: M = M.zero();
        for (0..4) |c| {
            const prev: u16 = @truncate(cells[i - 1].address >> @as(u6, @intCast(16 * c)));
            carry = (@as(u32, prev) + row[14 + c].v + carry) >> 16;
            row[18 + c] = M.fromCanonical(carry);
            sum = sum.add(row[14 + c]);
        }
        row[22] = sum.inv() catch unreachable;
        trace.put(i, &row);
    }
}
