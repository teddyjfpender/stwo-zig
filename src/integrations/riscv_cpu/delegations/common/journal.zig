//! Service witness admission and RAM bookkeeping. No permutation is recomputed.
//! Algebraic authority remains in the CPU/header/bridge/Keccak components.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const execution = frontend.rv64;
const S = @import("../../rv64_full_statement.zig");
const BridgeCall = rv.crypto.keccak.bridge.trace.Call;
const Q = @import("stwo_core").fields.qm31.QM31;
pub fn merge(call: execution.services.Call, record: execution.machine.Retirement, first_id: u32, ordinal: usize, statement: S.Statement, values: []u64, clocks: []u32) !BridgeCall {
    if (call.call_id != @as(u64, first_id) + ordinal or !std.meta.eql(record, call.retirement()) or call.pointer & 7 != 0 or call.pointer > std.math.maxInt(u64) - 199) return error.InvalidRv64ServiceRetirement;
    const tick: u32 = @intCast(4 * call.clock);
    var result = BridgeCall{ .call_id = call.call_id, .clock = call.clock, .pointer = call.pointer, .before = call.before, .after = call.after, .previous_clocks = undefined };
    for (0..25) |lane| {
        const index = try S.cellIndex(statement.cells, call.pointer + 8 * lane);
        const cell = statement.cells[index];
        if (!cell.readable or !cell.writable) return error.InvalidRv64ServicePermissions;
        if (values[index] != call.before[lane] or clocks[index] >= tick) return error.InvalidRv64ServiceMemoryChain;
        result.previous_clocks[lane] = clocks[index];
        values[index] = call.after[lane];
        clocks[index] = tick;
    }
    return result;
}
/// Native witness consistency only. The receiving verifier closes this effect
/// through the bridge's constrained RAM terms in the global rational claim.
pub fn ramContribution(calls: []const BridgeCall, challenges: rv.relations.Challenges) !Q {
    var sum = Q.zero();
    for (calls) |call| for (0..25) |lane| {
        const address = call.pointer + 8 * lane;
        const before = rv.relations.boundaryTuple(1, address, call.previous_clocks[lane], call.before[lane], true, true);
        const after = rv.relations.boundaryTuple(1, address, @intCast(4 * call.clock), call.after[lane], true, true);
        sum = sum.add(try challenges.denominator(before).inv()).sub(try challenges.denominator(after).inv());
    };
    return sum;
}

const Secp = rv.crypto.secp256k1;
const Runtime = execution.ethereum_services;
/// Sparse external RAM transitions, grouped by typed service family. The
/// caller retains source calls only until construction; this owner stores no
/// source-call pointers and survives compact tape release.
pub const SecpJournal = struct {
    allocator: std.mem.Allocator,
    rows: [2][]Secp.bridge.trace.Call,
    first_ids: [2]u32,
    cursors: [2]u32 = .{ 0, 0 },
    pub fn init(a: std.mem.Allocator, calls: []const Runtime.SecpCall, first_ids: [2]u32, steps: u32, profile: execution.execution_profile.Profile) !SecpJournal {
        if (profile != .ethereum_services_v1 and profile != .ethereum_services_v2) return error.InvalidRv64SecpProfile;
        if (calls.len > steps) return error.InvalidRv64SecpCount;
        var counts: [2]usize = .{ 0, 0 };
        for (calls, 0..) |call, i| {
            if ((call.packet_format == .big_endian_bytes_v1) != (profile == .ethereum_services_v1) or (i != 0 and calls[i - 1].clock >= call.clock)) return error.InvalidRv64SecpPacket;
            const kind: usize = if (call.kind == .add) 0 else 1;
            if (call.call_id != @as(u64, first_ids[kind]) + counts[kind]) return error.InvalidRv64SecpCount;
            counts[kind] += 1;
        }
        for (first_ids, counts) |first, count| if (first == 0 or first >= @import("stwo_core").fields.m31.Modulus or @as(u64, first) + count > @import("stwo_core").fields.m31.Modulus) return error.InvalidRv64SecpCount;
        const add = try a.alloc(Secp.bridge.trace.Call, counts[0]);
        errdefer a.free(add);
        return .{ .allocator = a, .rows = .{ add, try a.alloc(Secp.bridge.trace.Call, counts[1]) }, .first_ids = first_ids };
    }
    pub fn deinit(self: *SecpJournal) void {
        for (self.rows) |rows| self.allocator.free(rows);
        self.* = undefined;
    }
    pub fn mergeAt(self: *SecpJournal, call: Runtime.SecpCall, record: execution.machine.Retirement, statement: S.Statement, values: []u64, clocks: []u32) !usize {
        const kind: usize = if (call.kind == .add) 0 else 1;
        const cursor = self.cursors[kind];
        if (cursor >= self.rows[kind].len or call.call_id != @as(u64, self.first_ids[kind]) + cursor or !std.meta.eql(call.retirement(), record) or call.pointer & 31 != 0) return error.InvalidRv64SecpRetirement;
        const words = call.wordCount();
        if (call.pointer > std.math.maxInt(u64) - (words * 8 - 1) or call.clock == 0 or call.clock >= 1 << 22) return error.InvalidRv64SecpRetirement;
        const tick: u32 = @intCast(4 * call.clock);
        var row = Secp.bridge.trace.Call{ .call_id = call.call_id, .clock = call.clock, .pointer = call.pointer, .before = call.before, .after = call.after, .previous_clocks = @splat(0), .writable = @splat(false) };
        for (0..words) |lane| {
            const index = try S.cellIndex(statement.cells, call.pointer + 8 * lane);
            const cell = statement.cells[index];
            if (!cell.readable or (lane < 12 and !cell.writable) or (lane >= 12 and call.before[lane] != call.after[lane])) return error.InvalidRv64SecpPermissions;
            if (values[index] != call.before[lane] or clocks[index] >= tick) return error.InvalidRv64SecpMemoryChain;
            row.previous_clocks[lane] = clocks[index];
            row.writable[lane] = cell.writable;
            values[index] = call.after[lane];
            clocks[index] = tick;
        }
        self.rows[kind][cursor] = row;
        self.cursors[kind] += 1;
        return kind;
    }
    pub fn complete(self: *const SecpJournal) !void {
        for (self.rows, self.cursors) |rows, count| if (rows.len != count) return error.InvalidRv64SecpCount;
    }
    pub fn writeAdvice(self: *const SecpJournal, main: []@import("stwo_core").fields.m31.M31, start: usize, n: usize, row: usize, flags: [3]bool) void {
        const M = @import("stwo_core").fields.m31.M31;
        for (flags, 0..) |flag, i| main[(start + i) * n + row] = M.fromCanonical(@intFromBool(flag));
        for (self.cursors, 0..) |count, i| main[(start + 3 + i) * n + row] = M.fromCanonical(count);
    }
    pub fn ramContribution(self: *const SecpJournal, challenges: rv.relations.Challenges) !Q {
        try self.complete();
        var sum = Q.zero();
        for (self.rows, 0..) |rows, kind| for (rows) |call| for (0..@as(usize, if (kind == 0) 24 else 12)) |lane| {
            const address = call.pointer + 8 * lane;
            const before = rv.relations.boundaryTuple(1, address, call.previous_clocks[lane], call.before[lane], true, call.writable[lane]);
            const after = rv.relations.boundaryTuple(1, address, @intCast(4 * call.clock), call.after[lane], true, call.writable[lane]);
            sum = sum.add(try challenges.denominator(before).inv()).sub(try challenges.denominator(after).inv());
        };
        return sum;
    }
};
