//! Owned packed SHA provider rows. Caller AIR must close the 24 input and eight
//! output word wires. Fixed topology depends only on the admitted call count.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const calls = @import("sha256_packed_call.zig");
const source = @import("sha256_packed_source.zig");
const graph = @import("sha256_compression_graph.zig");
const sha = @import("sha256_compression.zig");
const program = @import("sha256_word_program.zig");
pub const Round = calls.ForKind(.round);
pub const Schedule = calls.ForKind(.schedule);
pub const FeedForward = calls.ForKind(.feed_forward);
pub const topology = blk: {
    @setEvalBranchQuota(10000);
    break :blk graph.build();
};
pub const Call = struct { execution_clock: u32, state: sha.State, block: [64]u8 };

pub const Geometry = struct {
    call_count: usize,
    logs: [4]u32,
    pub fn init(count: usize) !Geometry {
        var logs: [4]u32 = undefined;
        for ([_]usize{ graph.source_count, 48, 64, 8 }, &logs) |per_call, *log| {
            const active = try std.math.mul(usize, count, per_call);
            const padded = try std.math.ceilPowerOfTwo(usize, @max(2, active));
            log.* = @intCast(std.math.log2_int(usize, padded));
            // M31 circle domains and all row indices must remain representable.
            if (log.* > 30) return error.ShaTraceTooLarge;
        }
        return .{ .call_count = count, .logs = logs };
    }
};

pub const Rows = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry,
    sources: []source.Row,
    schedule: []Schedule.Row,
    rounds: []Round.Row,
    feed_forward: []FeedForward.Row,
    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.feed_forward);
        self.allocator.free(self.rounds);
        self.allocator.free(self.schedule);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
    pub fn tuple(self: Rows) @TypeOf(.{ self.sources, self.schedule, self.rounds, self.feed_forward }) {
        return .{ self.sources, self.schedule, self.rounds, self.feed_forward };
    }
};

fn allocate(comptime T: type, a: std.mem.Allocator, log: u32) ![]T {
    const rows = try a.alloc(T, @as(usize, 1) << @intCast(log));
    @memset(rows, @splat(M.zero()));
    return rows;
}

fn empty(a: std.mem.Allocator, geometry: Geometry) !Rows {
    const sources = try allocate(source.Row, a, geometry.logs[0]);
    errdefer a.free(sources);
    const schedule = try allocate(Schedule.Row, a, geometry.logs[1]);
    errdefer a.free(schedule);
    const rounds = try allocate(Round.Row, a, geometry.logs[2]);
    errdefer a.free(rounds);
    const feed_forward = try allocate(FeedForward.Row, a, geometry.logs[3]);
    return .{ .allocator = a, .geometry = geometry, .sources = sources, .schedule = schedule, .rounds = rounds, .feed_forward = feed_forward };
}

/// Four final allocations, no per-call or per-round heap scratch. A single
/// compression's stack-local values are overwritten before the next call.
pub fn prepare(a: std.mem.Allocator, records: []const Call) !Rows {
    const View = struct {
        items: []const Call,
        pub fn len(self: @This()) usize {
            return self.items.len;
        }
        pub fn get(self: @This(), index: usize) Call {
            return self.items[index];
        }
    };
    return prepareView(a, View{ .items = records });
}

/// Borrow a caller-owned tape through len/get; no intermediate call array.
pub fn prepareView(a: std.mem.Allocator, records: anytype) !Rows {
    var previous: u32 = 0;
    for (0..records.len()) |index| {
        const record = records.get(index);
        if (record.execution_clock <= previous or record.execution_clock >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidShaCallOrder;
        previous = record.execution_clock;
    }
    var result = try empty(a, try Geometry.init(records.len()));
    errdefer result.deinit();
    for (0..records.len()) |index| {
        const record = records.get(index);
        const trace = sha.witness(record.state, record.block);
        var values: [graph.wire_count]u32 = undefined;
        const input = graph.sources(record.state, record.block);
        @memcpy(values[0..graph.source_count], &input);
        for (topology.expansion, 16..) |op, t| values[op.output[0]] = trace.schedule[t];
        for (topology.rounds, 0..) |op, t| {
            values[op.output[0]] = trace.states[t + 1][0];
            values[op.output[1]] = trace.states[t + 1][4];
        }
        for (topology.feed_forward, 0..) |op, t| values[op.output[0]] = trace.output_state[t];
        for (input, 0..) |value, wire| result.sources[index * graph.source_count + wire] = try source.row(record.execution_clock, @intCast(wire), value, &topology.uses);
        try operations(.schedule, result.schedule[index * 48 ..][0..48], &topology.expansion, record.execution_clock, &values);
        try operations(.round, result.rounds[index * 64 ..][0..64], &topology.rounds, record.execution_clock, &values);
        try operations(.feed_forward, result.feed_forward[index * 8 ..][0..8], &topology.feed_forward, record.execution_clock, &values);
    }
    return result;
}

fn operations(comptime kind: program.Kind, rows: []calls.ForKind(kind).Row, ops: []const graph.Operation(kind), id: u32, values: *const [graph.wire_count]u32) !void {
    for (rows, ops) |*row, op| {
        var input: [program.inputCount(kind)]u32 = undefined;
        for (op.input, &input) |wire, *word| word.* = values[wire];
        row.* = try calls.ForKind(kind).row(id, op, &topology.uses, input);
    }
}

/// Independent verifier-side reconstruction: no call IDs, message, state,
/// output or execution tape can select the dependency graph or multiplicities.
pub fn fixed(a: std.mem.Allocator, count: usize) !Rows {
    var result = try empty(a, try Geometry.init(count));
    errdefer result.deinit();
    for (0..count) |index| {
        for (0..graph.source_count) |wire| result.sources[index * graph.source_count + wire] = try source.row(1, @intCast(wire), 0, &topology.uses);
        for (topology.expansion, 0..) |op, t| result.schedule[index * 48 + t] = try Schedule.fixedRow(1, op, &topology.uses);
        for (topology.rounds, 0..) |op, t| result.rounds[index * 64 + t] = try Round.fixedRow(1, op, &topology.uses);
        for (topology.feed_forward, 0..) |op, t| result.feed_forward[index * 8 + t] = try FeedForward.fixedRow(1, op, &topology.uses);
    }
    return result;
}

fn allocationCase(a: std.mem.Allocator) !void {
    const records = [_]Call{
        .{ .execution_clock = 3, .state = sha.initial_state, .block = @splat(0x37) },
        .{ .execution_clock = 7, .state = @splat(0xffffffff), .block = @splat(0x91) },
        .{ .execution_clock = 9, .state = @splat(0), .block = @splat(0) },
    };
    var prepared = try prepare(a, &records);
    defer prepared.deinit();
    var expected = try fixed(a, records.len);
    defer expected.deinit();
    const actual_tuple = prepared.tuple();
    const expected_tuple = expected.tuple();
    inline for (.{ source, Schedule, Round, FeedForward }, 0..) |Air, i| {
        try std.testing.expectEqual(expected_tuple[i].len, actual_tuple[i].len);
        for (actual_tuple[i], expected_tuple[i]) |actual, wanted| {
            try std.testing.expectEqualSlices(M, wanted[Air.PHYSICAL_MAIN_COLUMN_COUNT..], actual[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
    }
    try std.testing.expectEqualSlices(u32, &.{ 9, 8, 8, 5 }, &prepared.geometry.logs);
    // Call namespaces are taken from retirement clocks, not batch ordinals.
    for (records, 0..) |record, index| {
        try std.testing.expectEqual(record.execution_clock, prepared.sources[index * graph.source_count][4].toU32());
        try std.testing.expectEqual(record.execution_clock, prepared.rounds[index * 64][Round.PHYSICAL_MAIN_COLUMN_COUNT - 1].toU32());
    }
}
test "SHA provider batches own only final rows and reconstruct private-independent topology" {
    try allocationCase(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
    var no_calls = try prepare(std.testing.allocator, &.{});
    defer no_calls.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1 }, &no_calls.geometry.logs);
    inline for (no_calls.tuple()) |rows| for (rows) |row| for (row) |value| try std.testing.expectEqual(M.zero(), value);
    const call = Call{ .execution_clock = 1, .state = sha.initial_state, .block = @splat(0) };
    try std.testing.expectError(error.InvalidShaCallOrder, prepare(std.testing.allocator, &.{ call, call }));
    try std.testing.expectError(error.Overflow, Geometry.init(std.math.maxInt(usize)));
}
