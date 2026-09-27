//! Prepare a real full-STARK transcript for the joined parent fixture.
//! This fixture knows the proof-gate prefix; production prefixes are separate.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const transcript = @import("blake3_transcript_witness.zig");
const pcs = @import("blake3_pcs_transcript.zig");
pub const Prepared = struct {
    live: transcript.Prepared,
    fixed: transcript.Prepared,
    pub fn deinit(self: *Prepared) void {
        self.fixed.deinit();
        self.live.deinit();
    }
};
const Capture = f.core.verifier.ProofCapture(f.Hasher);
pub fn prepare(a: std.mem.Allocator, capture: *const Capture, config: f.core.pcs.PcsConfig, claims: []const f.QM31) !Prepared {
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
    var substituted = capture.*;
    substituted.commitments = try a.dupe(f.Hasher.Hash, capture.commitments);
    defer a.free(substituted.commitments);
    substituted.commitments[3][31] ^= 0x80;
    try std.testing.expectError(error.InvalidBlake3PcsTranscript, pcs.appendStarkVerifier(a, &ops, &channel, &substituted, config, lifting_log));
    try std.testing.expect(std.meta.eql(prefix, channel));
    try std.testing.expectEqual(prefix_len, ops.items.len);
    const query_storage = try pcs.appendStarkVerifier(a, &ops, &channel, capture, config, lifting_log);
    defer a.free(query_storage);
    // Arithmetic circuits occupy 1500..1505; hash schedules own this range.
    var live = try transcript.prepare(a, 1_000_000, ops.items);
    errdefer live.deinit();
    var fixed = try transcript.trusted(a, 1_000_000, ops.items);
    errdefer fixed.deinit();
    try std.testing.expectEqual(channel.n_draws, live.next_draw);
    return .{ .live = live, .fixed = fixed };
}
fn words(a: std.mem.Allocator, ops: *std.ArrayList(transcript.Operation), channel: *f.Channel, values: []const u32) !void {
    channel.mixU32s(values);
    try ops.append(a, .{ .words = values });
}
