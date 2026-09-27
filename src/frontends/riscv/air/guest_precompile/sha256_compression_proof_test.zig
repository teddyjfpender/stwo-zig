//! Canonical standalone compression STARK. Public boundaries are independently
//! projected; production CPU dispatch/memory/caller activation is still separate.
const std = @import("std");
const f = @import("../../recursion/air/blake3_proof_fixture.zig");
const gate = @import("../../recursion/air/blake3_proof_gate_test_support.zig");
const calls = @import("sha256_packed_call.zig");
const source = @import("sha256_packed_source.zig");
const sha = @import("sha256_compression.zig");
const graph = @import("sha256_compression_graph.zig");
const provider = @import("sha256_compression_rows.zig");
const boundary = @import("../../recursion/air/blake3_boundary.zig");
const R = calls.ForKind(.round);
const S = calls.ForKind(.schedule);
const A = calls.ForKind(.feed_forward);
const F = @import("../../recursion/air/universal_component_roster.zig").ForAirs(.{ source, S, R, A, boundary }, &.{ "sha_source", "sha_schedule", "sha_round", "sha_feed_forward", "sha_boundary" });
const logs = [_]u32{ 7, 6, 6, 3, 5 };
const call_id = 17;
fn boundaries(a: std.mem.Allocator, state: sha.State, block: [64]u8, output: sha.State) ![]boundary.Row {
    const result = try a.alloc(boundary.Row, 32);
    const sources = graph.sources(state, block);
    const g = graph.build();
    for (sources[0..24], 0..) |value, i| result[i] = try boundary.logicalRow(call_id, @intCast(graph.input_boundary_offset + i), f.M31.one(), value);
    for (output, 0..) |value, i| result[24 + i] = try boundary.logicalRow(call_id, g.output[i], f.M31.one().neg(), value);
    return result;
}
fn trusted(a: std.mem.Allocator, state: sha.State, block: [64]u8, output: sha.State) ![]f.Column {
    const boundary_rows = try boundaries(a, state, block, output);
    defer a.free(boundary_rows);
    var columns: std.ArrayList(f.Column) = .empty;
    errdefer {
        for (columns.items) |column| a.free(column.values);
        columns.deinit(a);
    }
    try @import("sha256_preprocessed.zig").append(a, 1, false, &columns);
    try f.project(boundary, a, boundary_rows, logs[4], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
const Protocol = struct {
    pub fn config(_: @This()) !f.core.pcs.PcsConfig {
        return @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
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
    const boundary_rows = try boundaries(a, state, block, output);
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
