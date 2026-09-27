//! A real BLAKE3-backed STARK for all seven compression rounds and feedforward.
//! Small test security parameters are not a production recursion profile.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const core = f.core;
const M31 = f.M31;

test "BLAKE3 compression committed proof verifies with trusted preprocessing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const circuit = 991;
    const cv = core.crypto.blake3_compression.IV;
    const block: [16]u32 = @splat(0x12345678);
    const prepared = try @import("blake3_compression_witness.zig").prepare(circuit, cv, block, 0, 64, 11);
    const topology = @import("blake3_compression_plan.zig").canonical();
    var boundary_rows: [48]f.boundary.Row = undefined;
    for (prepared.initial, 0..) |word, i| boundary_rows[i] = try f.boundary.logicalRow(circuit, @intCast(i), M31.fromCanonical(topology.uses[i]), word);
    for (prepared.output, topology.output, 0..) |word, id, i| boundary_rows[32 + i] = try f.boundary.logicalRow(circuit, id, M31.one().neg(), word);
    const rows = .{
        try f.padded(f.g, a, &prepared.g_rows, 6),
        try f.padded(f.xor, a, &prepared.xor_rows, 4),
        try f.padded(f.boundary, a, &boundary_rows, 6),
    };
    const trusted_pp = try f.trustedPreprocessed(a, circuit, prepared.initial, prepared.output);
    var false_output = prepared.output;
    false_output[0] ^= 1;
    const false_pp = try f.trustedPreprocessed(a, circuit, prepared.initial, false_output);
    try @import("blake3_proof_gate_test_support.zig").run(a, rows, f.logs, trusted_pp, false_pp);
}

test "BLAKE3 full hash committed proofs cover empty partial and unbalanced chunk trees" {
    var input: [2049]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i % 251);
    for ([_]usize{ 0, 65, 2049 }) |len| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const witness = @import("blake3_hash_witness.zig");
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(input[0..len], &digest, .{});
        const prepared = try witness.prepare(a, 713, input[0..len], digest);
        const logs = prepared.rows.logs();
        const rows = .{
            try f.padded(f.g, a, prepared.rows.g_rows, logs[0]),
            try f.padded(f.xor, a, prepared.rows.xor_rows, logs[1]),
            try f.padded(f.boundary, a, prepared.rows.boundary_rows, logs[2]),
        };
        const trusted_pp = try hashPreprocessing(a, input[0..len], digest);
        digest[0] ^= 1;
        const false_pp = try hashPreprocessing(a, input[0..len], digest);
        try @import("blake3_proof_gate_test_support.zig").run(a, rows, logs, trusted_pp, false_pp);
    }
}
fn hashPreprocessing(a: std.mem.Allocator, input: []const u8, digest: [32]u8) ![]f.Column {
    const rows = try @import("blake3_hash_witness.zig").trustedRows(a, 713, input, digest);
    const logs = rows.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (f.Airs, .{ rows.g_rows, rows.xor_rows, rows.boundary_rows }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
