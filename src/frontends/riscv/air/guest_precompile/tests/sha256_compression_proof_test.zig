//! Canonical standalone compression STARK. Public boundaries are independently
//! projected; production CPU dispatch/memory/caller activation is still separate.
const std = @import("std");
const f = @import("../../../recursion/air/blake3_proof_fixture.zig");
const gate = @import("../../../recursion/air/blake3_proof_gate_test_support.zig");
const calls = @import("../sha256_packed_call.zig");
const source = @import("../sha256_packed_source.zig");
const sha = @import("../sha256_compression.zig");
const graph = @import("../sha256_compression_graph.zig");
const provider = @import("../sha256_compression_rows.zig");
const boundary = @import("../../../recursion/air/blake3_boundary.zig");
const R = calls.ForKind(.round);
const S = calls.ForKind(.schedule);
const A = calls.ForKind(.feed_forward);
const F = @import("../../../recursion/air/universal_component_roster.zig").ForAirs(.{ source, S, R, A, boundary }, &.{ "sha_source", "sha_schedule", "sha_round", "sha_feed_forward", "sha_boundary" });
const logs = [_]u32{ 7, 6, 6, 3, 5 };
const call_id = 17;
fn boundaries(a: std.mem.Allocator, id: u32, state: sha.State, block: [64]u8, output: sha.State) ![]boundary.Row {
    const result = try a.alloc(boundary.Row, 32);
    const sources = graph.sources(state, block);
    const g = graph.build();
    for (sources[0..24], 0..) |value, i| result[i] = try boundary.logicalRow(id, @intCast(graph.input_boundary_offset + i), f.M31.one(), value);
    for (output, 0..) |value, i| result[24 + i] = try boundary.logicalRow(id, g.output[i], f.M31.one().neg(), value);
    return result;
}
fn trusted(a: std.mem.Allocator, state: sha.State, block: [64]u8, output: sha.State) ![]f.Column {
    const boundary_rows = try boundaries(a, call_id, state, block, output);
    defer a.free(boundary_rows);
    var columns: std.ArrayList(f.Column) = .empty;
    errdefer {
        for (columns.items) |column| a.free(column.values);
        columns.deinit(a);
    }
    try @import("../sha256_preprocessed.zig").append(a, 1, false, &columns);
    try f.project(boundary, a, boundary_rows, logs[4], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
const Protocol = struct {
    pub fn config(_: @This()) !f.core.pcs.PcsConfig {
        return @import("../../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    }
    pub fn mix(self: @This(), channel: *f.Channel) !void {
        channel.mixU32s(&.{ 0x53484143, 1 });
        (try self.config()).mixInto(channel);
    }
    pub fn admitRoot(_: @This(), _: f.Hasher.Hash) !void {}
    pub fn mixClaims(_: @This(), channel: *f.Channel, claims: []const f.QM31) !void {
        channel.mixU32s(&.{ 0x53484143, 2 });
        channel.mixFelts(claims);
    }
    pub fn observeProof(_: @This(), _: std.mem.Allocator, _: anytype, prove_ns: u64) !void {
        std.debug.print("SHA_AIR_PROVE elapsed_ns={d}\n", .{prove_ns});
    }
    pub fn observeVerified(_: @This(), verify_ns: u64) !void {
        std.debug.print("SHA_AIR_VERIFY elapsed_ns={d}\n", .{verify_ns});
    }
};
test "SHA canonical compression STARK verifies and rejects substituted digest admission" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(i * 71 + 9);
    const state = sha.initial_state;
    const output = sha.compress(state, block);
    var prepared = try provider.prepare(a, &.{.{ .execution_clock = call_id, .state = state, .block = block }});
    defer prepared.deinit();
    const boundary_rows = try boundaries(a, call_id, state, block, output);
    defer a.free(boundary_rows);
    const rows = prepared.tuple() ++ .{boundary_rows};
    const pp = try trusted(a, state, block, output);
    var wrong = output;
    wrong[0] ^= 1;
    const wrong_pp = try trusted(a, state, block, wrong);
    var timer = try std.time.Timer.start();
    const parameters: [F.Airs.len][0]f.M31 = @splat(.{});
    try gate.ForBackend(f.Cpu).runForParametersProtocol(F, a, rows, logs, pp, wrong_pp, parameters, Protocol{}, void);
    std.debug.print("SHA_COMPRESSION_STARK verified=true queries=70 pow_bits=26 elapsed_ns={d} cpu_memory_dispatch=false\n", .{timer.read()});
}

fn batchBoundaryRows(a: std.mem.Allocator, records: []const provider.Call, wrong_last_digest: bool) ![]boundary.Row {
    const result = try a.alloc(boundary.Row, records.len * 32);
    for (records, 0..) |record, index| {
        var output = sha.compress(record.state, record.block);
        if (wrong_last_digest and index + 1 == records.len) output[0] ^= 1;
        const rows = try boundaries(a, record.execution_clock, record.state, record.block, output);
        defer a.free(rows);
        @memcpy(result[index * 32 ..][0..32], rows);
    }
    return result;
}

fn batchTrusted(a: std.mem.Allocator, count: usize, rows: []const boundary.Row, boundary_log: u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    errdefer {
        for (columns.items) |column| a.free(column.values);
        columns.deinit(a);
    }
    try @import("../sha256_preprocessed.zig").append(a, count, false, &columns);
    try f.project(boundary, a, rows, boundary_log, 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn checkBatchWireBalance(a: std.mem.Allocator, rows: anytype) !void {
    const M = f.M31;
    var sums = std.AutoHashMap([6]u32, M).init(a);
    defer sums.deinit();
    const Visitor = struct {
        sums: *@TypeOf(sums),
        pub fn accepts(_: *@This(), id: anytype) bool {
            return id == @import("../../lang/relation.zig").id(.recursion_wire);
        }
        pub fn visit(self: *@This(), _: anytype, numerator: M, tuple: []const M) !void {
            if (tuple.len != 6) return error.InvalidShaWireTuple;
            var key: [6]u32 = undefined;
            for (tuple, &key) |value, *word| word.* = value.toU32();
            const slot = try self.sums.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M.zero();
            slot.value_ptr.* = slot.value_ptr.add(numerator);
        }
    };
    var visitor = Visitor{ .sums = &sums };
    inline for (F.Airs, 0..) |Air, i| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const plan = try f.binding.Binding(Air).authenticate(&definition);
        for (rows[i]) |row| try plan.visitPreparedBaseEntries(row, &visitor);
    }
    var it = sums.iterator();
    var failures: usize = 0;
    while (it.next()) |entry| if (!entry.value_ptr.isZero()) {
        if (failures < 8) std.debug.print("SHA_WIRE_IMBALANCE tuple={any} sum={d}\n", .{ entry.key_ptr.*, entry.value_ptr.toU32() });
        failures += 1;
    };
    if (failures != 0) return error.ShaBatchWireImbalance;
}

test "six linked SHA compression calls prove in one batch and reject a changed boundary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var records: [6]provider.Call = undefined;
    for (0..2) |header_index| {
        var header: [80]u8 = undefined;
        for (&header, 0..) |*byte, i| byte.* = @truncate(i * 71 + header_index * 47 + 9);
        var first_block: [64]u8 = undefined;
        @memcpy(&first_block, header[0..64]);
        const first = sha.compress(sha.initial_state, first_block);
        var second_block: [64]u8 = @splat(0);
        @memcpy(second_block[0..16], header[64..80]);
        second_block[16] = 0x80;
        std.mem.writeInt(u64, second_block[56..64], 640, .big);
        const first_digest = sha.compress(first, second_block);
        var third_block: [64]u8 = @splat(0);
        @memcpy(third_block[0..32], &sha.stateBytes(first_digest));
        third_block[32] = 0x80;
        std.mem.writeInt(u64, third_block[56..64], 256, .big);
        const at = header_index * 3;
        records[at] = .{ .execution_clock = @intCast(at + 1), .state = sha.initial_state, .block = first_block };
        records[at + 1] = .{ .execution_clock = @intCast(at + 2), .state = first, .block = second_block };
        records[at + 2] = .{ .execution_clock = @intCast(at + 3), .state = sha.initial_state, .block = third_block };
        const last = sha.stateBytes(sha.compress(sha.initial_state, third_block));
        var first_hash: [32]u8 = undefined;
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&header, &first_hash, .{});
        std.crypto.hash.sha2.Sha256.hash(&first_hash, &expected, .{});
        if (!std.meta.eql(expected, last)) return error.BatchShaReferenceMismatch;
    }
    var prepared = try provider.prepare(a, &records);
    defer prepared.deinit();
    const batch_logs: [F.Airs.len]u32 = prepared.geometry.logs ++ .{8};
    if (!std.mem.eql(u32, &batch_logs, &.{ 10, 9, 9, 6, 8 })) return error.BatchShaGeometryMismatch;
    const boundary_rows = try batchBoundaryRows(a, &records, false);
    const wrong_rows = try batchBoundaryRows(a, &records, true);
    const rows = prepared.tuple() ++ .{boundary_rows};
    try checkBatchWireBalance(a, rows);
    const pp = try batchTrusted(a, records.len, boundary_rows, batch_logs[4]);
    const wrong_pp = try batchTrusted(a, records.len, wrong_rows, batch_logs[4]);
    const parameters: [F.Airs.len][0]f.M31 = @splat(.{});
    var timer = try std.time.Timer.start();
    try gate.ForBackend(f.Cpu).runForParametersProtocol(F, a, rows, batch_logs, pp, wrong_pp, parameters, Protocol{}, void);
    std.debug.print("SHA256D_SIX_CALL_STARK verified=true public_boundaries=true elapsed_ns={d}\n", .{timer.read()});
}
