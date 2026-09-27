//! Authenticated field tuple -> canonical bytes -> complete BLAKE3 hash.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const encoding = @import("blake3_field_bytes.zig");
const bridge = @import("blake3_input_bridge.zig");
const private = @import("blake3_private_hash_witness.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ encoding, bridge });
const coordinates = [4]f.M31{ f.M31.zero(), f.M31.fromCanonical(2147483646), f.M31.fromCanonical(256), f.M31.fromCanonical(0x76543210) };
const schedule = encoding.Schedule{ .source_circuit = 1401, .source_wire = 0, .destination_circuit = 1402, .destination_first = 0, .uses = @splat(1) };
const Data = struct {
    hash: private.Rows,
    encoded: []encoding.Row,
    fn logs(self: Data) [5]u32 {
        return self.hash.hash_rows.logs() ++ .{ @as(u32, 1), @as(u32, 2) };
    }
};
test "BLAKE3 canonical field bytes feed an authenticated complete hash proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var bytes: [16]u8 = undefined;
    for (coordinates, 0..) |value, i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], value.toU32(), .little);
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&bytes, &expected, .{});
    const live = try assemble(a, true, &bytes, expected);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.hash.hash_rows.g_rows, logs[0]), try f.padded(f.xor, a, live.hash.hash_rows.xor_rows, logs[1]), try f.padded(f.boundary, a, live.hash.hash_rows.boundary_rows, logs[2]), try f.padded(encoding, a, live.encoded, logs[3]), try f.padded(bridge, a, live.hash.bridge_rows, logs[4]) };
    const trusted = try preprocessing(a, expected);
    var wrong = expected;
    wrong[31] ^= 0x80;
    const false_pp = try preprocessing(a, wrong);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, expected: [32]u8) ![]f.Column {
    const data = try assemble(a, false, &.{}, expected);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.hash.hash_rows.g_rows, data.hash.hash_rows.xor_rows, data.hash.hash_rows.boundary_rows, data.encoded, data.hash.bridge_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, comptime live: bool, bytes: []const u8, expected: [32]u8) !Data {
    const caller = private.Caller{ .circuit = 1402, .first_wire = 0 };
    var hash = if (live) (try private.prepare(a, 1403, caller, bytes, expected)).rows else try private.trustedRows(a, 1403, caller, 16, expected);
    const boundary = try f.boundary.logicalCoordinates(1401, 0, f.M31.one(), coordinates);
    hash.hash_rows.boundary_rows = try std.mem.concat(a, f.boundary.Row, &.{ hash.hash_rows.boundary_rows, &.{boundary} });
    const encoded = try a.alloc(encoding.Row, 1);
    encoded[0] = if (live) try encoding.logicalRow(schedule, f.core.fields.qm31.QM31.fromM31Array(coordinates)) else try encoding.fixedRow(schedule);
    return .{ .hash = hash, .encoded = encoded };
}
