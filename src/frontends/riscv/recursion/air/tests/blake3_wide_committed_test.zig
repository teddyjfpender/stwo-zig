//! A real BLAKE3-backed STARK for all seven compression rounds and feedforward.
//! Small test security parameters are not a production recursion profile.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const core = f.core;
const M31 = f.M31;

test "wide recursion compression proof verifies and rejects substituted fixed root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const circuit = 991;
    const cv = core.crypto.blake3_compression.IV;
    const block: [16]u32 = @splat(0x12345678);
    const prepared = try @import("../blake3_compression_witness.zig").prepare(circuit, cv, block, 0, 64, 11);
    const topology = @import("../blake3_compression_plan.zig").canonical();
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
    const Wide = @import("../universal_component_roster.zig").ForAirs(.{ @import("../blake3_g_call_wide.zig"), f.xor, f.boundary }, &.{ "g", "xor", "boundary" });
    try @import("../blake3_proof_gate_test_support.zig").runFor(Wide, a, rows, f.logs, trusted_pp, false_pp);
}
