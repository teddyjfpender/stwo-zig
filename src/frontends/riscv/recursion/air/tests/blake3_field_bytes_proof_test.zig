//! Authenticated field tuple -> canonical bytes -> complete BLAKE3 hash.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const encoding = @import("../blake3_field_bytes.zig");
const framed = @import("../blake3_frame_witness.zig");
const bridge = framed.route;
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ encoding, bridge });
const coordinates = [4]f.M31{ f.M31.zero(), f.M31.fromCanonical(2147483646), f.M31.fromCanonical(256), f.M31.fromCanonical(0x76543210) };
const schedule = encoding.Schedule{ .source_circuit = 1401, .source_wire = 0, .destination_circuit = 1402, .destination_first = 0, .uses = @splat(1) };
const Data = struct {
    hash: framed.Prepared,
    encoded: []encoding.Row,
    fn logs(self: Data) [5]u32 {
        return .{ log(self.hash.rows.g_rows.len), log(self.hash.rows.xor_rows.len), log(self.hash.rows.boundary_rows.len), 1, log(self.hash.route_rows.len) };
    }
    fn log(n: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, n));
    }
};
test "BLAKE3 canonical field bytes feed an authenticated complete hash proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var native = f.Hasher.defaultWithInitialState();
    native.updateLeaf(&coordinates);
    const expected = native.finalize();
    const live = try assemble(a, true, expected);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.hash.rows.g_rows, logs[0]), try f.padded(f.xor, a, live.hash.rows.xor_rows, logs[1]), try f.padded(f.boundary, a, live.hash.rows.boundary_rows, logs[2]), try f.padded(encoding, a, live.encoded, logs[3]), try f.padded(bridge, a, live.hash.route_rows, logs[4]) };
    const trusted = try preprocessing(a, expected);
    var wrong = expected;
    wrong[31] ^= 0x80;
    const false_pp = try preprocessing(a, wrong);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, expected: [32]u8) ![]f.Column {
    const data = try assemble(a, false, expected);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.hash.rows.g_rows, data.hash.rows.xor_rows, data.hash.rows.boundary_rows, data.encoded, data.hash.route_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, comptime live: bool, expected: [32]u8) !Data {
    const payload = framed.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = 1402, .first_wire = 0 }, .word_count = 4 };
    const placeholders: [4]f.M31 = @splat(f.M31.zero());
    const frame = f.core.channel.blake3.Frame{ .leaf = if (live) &coordinates else &placeholders };
    var hash = if (live) try framed.preparePayload(a, 1403, frame, &.{}, payload, expected) else try framed.trustedPayload(a, 1403, frame, &.{}, payload, expected);
    const boundary = try f.boundary.logicalCoordinates(1401, 0, f.M31.one(), coordinates);
    hash.rows.boundary_rows = try std.mem.concat(a, f.boundary.Row, &.{ hash.rows.boundary_rows, &.{boundary} });
    var actual_schedule = schedule;
    @memcpy(&actual_schedule.uses, hash.payload_uses);
    const encoded = try a.alloc(encoding.Row, 1);
    encoded[0] = if (live) try encoding.logicalRow(actual_schedule, f.core.fields.qm31.QM31.fromM31Array(coordinates)) else try encoding.fixedRow(actual_schedule);
    return .{ .hash = hash, .encoded = encoded };
}
