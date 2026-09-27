//! Matched compression qualification. This is not a CSP or full-parent benchmark.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const core = f.core;
const Protocol = struct {
    pub fn config(_: @This()) !core.pcs.PcsConfig {
        return .{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    }
    pub fn mix(_: @This(), channel: *f.Channel) !void {
        channel.mixU32s(&.{ 0x42334350, 1 });
    }
    pub fn admitRoot(_: @This(), _: f.Hasher.Hash) !void {}
    pub fn mixClaims(_: @This(), channel: *f.Channel, claims: []const f.QM31) !void {
        f.mixClaims(channel, claims);
    }
};
fn Observer(comptime label: []const u8) type {
    return struct {
        pub fn check(comptime F: type, a: std.mem.Allocator, capture: *const core.verifier.ProofCapture(f.Hasher), _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, config: core.pcs.PcsConfig) !void {
            _ = F;
            try std.testing.expectEqual(@as(u32, 26), config.pow_bits);
            try std.testing.expectEqual(@as(usize, 70), config.fri_config.n_queries);
            var columns: usize = 0;
            var cells: usize = 0;
            for (capture.column_log_sizes) |logs| for (logs) |log| {
                columns += 1;
                cells += @as(usize, 1) << @intCast(log);
            };
            const layout = try @import("../blake3_native_hash_layout.zig").Layout.init(a, .{ .g = 0, .xor = 0 }, capture);
            std.debug.print("BLAKE3_COMPRESSION_COST arm={s} queries=70 pow=26 columns={d} cells={d} next_path_g={d} next_path_xor={d} next_g_log={d}\n", .{ label, columns, cells, layout.paths.g, layout.paths.xor, layout.logs[0] });
        }
    };
}
test "BLAKE3 round and G canonical compression cost census" {
    var timer = try std.time.Timer.start();
    try baseline();
    std.debug.print("BLAKE3_COMPRESSION_FIXTURE arm=g elapsed_ns={d}\n", .{timer.lap()});
    try @import("blake3_round_proof_test.zig").prove(Protocol{}, Observer("round"));
    std.debug.print("BLAKE3_COMPRESSION_FIXTURE arm=round elapsed_ns={d}\n", .{timer.read()});
}
fn baseline() !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, i| word.* = @as(u32, @intCast(i)) *% 0x89abcdef;
    const prepared = try @import("blake3_compression_witness.zig").prepare(19, core.crypto.blake3_compression.IV, block, 0x123456789abcdef0, 63, 11);
    const topology = @import("blake3_compression_plan.zig").canonical();
    var boundaries: [48]f.boundary.Row = undefined;
    for (prepared.initial, 0..) |word, i| boundaries[i] = try f.boundary.logicalRow(19, @intCast(i), f.M31.fromCanonical(topology.uses[i]), word);
    for (prepared.output, topology.output, 0..) |word, wire, i| boundaries[32 + i] = try f.boundary.logicalRow(19, wire, f.M31.one().neg(), word);
    const rows = .{ try f.padded(f.g, a, &prepared.g_rows, 6), try f.padded(f.xor, a, &prepared.xor_rows, 4), try f.padded(f.boundary, a, &boundaries, 6) };
    const pp = try f.trustedPreprocessed(a, 19, prepared.initial, prepared.output);
    var wrong_output = prepared.output;
    wrong_output[0] ^= 1;
    const wrong = try f.trustedPreprocessed(a, 19, prepared.initial, wrong_output);
    const parameters: [3][0]f.M31 = @splat(.{});
    try @import("blake3_proof_gate_test_support.zig").ForBackend(f.Cpu).runForParametersProtocol(f.PublicFixture, a, rows, f.logs, pp, wrong, parameters, Protocol{}, Observer("g"));
}
