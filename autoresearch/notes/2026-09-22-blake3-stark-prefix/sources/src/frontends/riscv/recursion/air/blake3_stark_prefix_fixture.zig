//! A real full-STARK capture supplies the transcript for a second typed proof.
//! This fixture knows the proof-gate prefix; production prefixes are separate.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const transcript = @import("blake3_transcript_witness.zig");
const pcs = @import("blake3_pcs_transcript.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ transcript.challenge, transcript.route, transcript.query_mask });
const Capture = f.core.verifier.ProofCapture(f.Hasher);
pub fn check(a: std.mem.Allocator, capture: *Capture, config: f.core.pcs.PcsConfig, claims: []const f.QM31) !void {
    try std.testing.expectEqual(@as(usize, 4), capture.commitments.len);
    var channel = f.Channel{};
    var ops: std.ArrayList(transcript.Operation) = .empty;
    defer ops.deinit(a);
    try words(a, &ops, &channel, &.{ 0x42334350, 1 });
    for (capture.commitments[0..2]) |root| {
        channel.mixRoot(root);
        try ops.append(a, .{ .root = root });
    }
    // UniversalRelations.draw consumes two secure fields per accepted block.
    for (0..f.universal.DRAW_COUNT / 2) |_| {
        const before = channel.n_draws;
        const fields = try channel.drawSecureFelts(a, 2);
        defer a.free(fields);
        var values: [8]f.M31 = undefined;
        values[0..4].* = fields[0].toM31Array();
        values[4..8].* = fields[1].toM31Array();
        try ops.append(a, .{ .secure = .{ .attempts = @intCast(channel.n_draws - before), .consumption = .two, .values = values } });
    }
    try words(a, &ops, &channel, &.{ 0x42334343, 1 });
    channel.mixFelts(claims);
    try ops.append(a, .{ .felts = claims });
    channel.mixRoot(capture.commitments[2]);
    try ops.append(a, .{ .root = capture.commitments[2] });
    const prefix = channel;
    const prefix_len = ops.items.len;
    const lifting_log = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    const root = capture.commitments[3];
    capture.commitments[3][31] ^= 0x80;
    try std.testing.expectError(error.InvalidBlake3PcsTranscript, pcs.appendStarkVerifier(a, &ops, &channel, capture, config, lifting_log));
    capture.commitments[3] = root;
    try std.testing.expect(std.meta.eql(prefix, channel));
    try std.testing.expectEqual(prefix_len, ops.items.len);
    const query_storage = try pcs.appendStarkVerifier(a, &ops, &channel, capture, config, lifting_log);
    defer a.free(query_storage);
    var live = try transcript.prepare(a, 1000, ops.items);
    defer live.deinit();
    var fixed = try transcript.trusted(a, 1000, ops.items);
    defer fixed.deinit();
    try std.testing.expectEqual(channel.n_draws, live.next_draw);
    const logs = live.logs();
    const rows = .{ try f.padded(transcript.g, a, live.g_rows, logs[0]), try f.padded(transcript.xor, a, live.xor_rows, logs[1]), try f.padded(transcript.boundary, a, live.boundary_rows, logs[2]), try f.padded(transcript.challenge, a, live.challenge_rows, logs[3]), try f.padded(transcript.route, a, live.route_rows, logs[4]), try f.padded(transcript.query_mask, a, live.query_rows, logs[5]) };
    const trusted = try preprocessing(a, fixed, logs);
    fixed.boundary_rows[0][8] = fixed.boundary_rows[0][8].add(f.M31.one());
    const false_pp = try preprocessing(a, fixed, logs);
    // No observer here: this proves the transcript, not another capture ladder.
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn words(a: std.mem.Allocator, ops: *std.ArrayList(transcript.Operation), channel: *f.Channel, values: []const u32) !void {
    channel.mixU32s(values);
    try ops.append(a, .{ .words = values });
}
fn preprocessing(a: std.mem.Allocator, data: transcript.Prepared, logs: [6]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.g_rows, data.xor_rows, data.boundary_rows, data.challenge_rows, data.route_rows, data.query_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
