//! Prepare a real full-STARK transcript for the joined parent fixture.
//! This fixture knows the proof-gate prefix; production prefixes are separate.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const transcript = @import("blake3_transcript_witness.zig");
const pcs = @import("blake3_pcs_transcript.zig");
pub const encoding = @import("blake3_field_bytes.zig");
pub const InputRead = struct { node: u32, value: f.QM31, private: bool };
pub const Sources = @import("blake3_challenge_links.zig").Sources;
pub const Prepared = struct {
    // All inputs belong to composition circuit 1500. Storage lives in live.arena.
    input_reads: []const InputRead = &.{},
    sample_links: []const @import("blake3_sample_links.zig").Link = &.{},
    encoded_rows: []encoding.Row = &.{},
    fixed_encoded_rows: []encoding.Row = &.{},
    challenge_sources: Sources,
    challenge_links: []const @import("blake3_challenge_links.zig").Link = &.{},
    terminal: ?@import("blake3_terminal_links.zig").Prepared = null,
    paths: ?@import("blake3_stark_paths_fixture.zig").Prepared = null,
    live: transcript.Prepared,
    fixed: transcript.Prepared,
    pub fn deinit(self: *Prepared) void {
        if (self.terminal) |*terminal| terminal.deinit();
        if (self.paths) |*paths| paths.deinit();
        self.fixed.deinit();
        self.live.deinit();
    }
};
const Capture = f.core.verifier.ProofCapture(f.Hasher);
pub fn prepare(a: std.mem.Allocator, capture: *const Capture, config: f.core.pcs.PcsConfig, claims: []const f.QM31, sources: Sources) !Prepared {
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
    for (0..f.universal.DRAW_COUNT / 2) |i| {
        const before = channel.n_draws;
        const fields = try channel.drawSecureFelts(a, 2);
        defer a.free(fields);
        var values: [8]f.M31 = undefined;
        values[0..4].* = fields[0].toM31Array();
        values[4..8].* = fields[1].toM31Array();
        try ops.append(a, .{ .secure = .{ .output = .{ .universal = i }, .attempts = @intCast(channel.n_draws - before), .consumption = .two, .values = values } });
    }
    try words(a, &ops, &channel, &.{ 0x42334343, 1 });
    channel.mixFelts(claims);
    try ops.append(a, .{ .routed_felts = .{ .values = claims, .source = .{ .circuit = 4_000_000, .first_wire = 0 } } });
    channel.mixRoot(capture.commitments[2]);
    try ops.append(a, .{ .root = capture.commitments[2] });
    const prefix = channel;
    const prefix_len = ops.items.len;
    const lifting_log = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    var substituted = capture.*;
    substituted.commitments = try a.dupe(f.Hasher.Hash, capture.commitments);
    defer a.free(substituted.commitments);
    substituted.commitments[3][31] ^= 0x80;
    try std.testing.expectError(error.InvalidBlake3PcsTranscript, pcs.appendStarkVerifierFrom(a, &ops, &channel, &substituted, config, lifting_log, .{ .export_challenges = true, .sampled_values = .{ .circuit = 4_000_001, .first_wire = 0 }, .terminal_coefficients = .{ .circuit = 4_000_002, .first_wire = 0 } }));
    try std.testing.expect(std.meta.eql(prefix, channel));
    try std.testing.expectEqual(prefix_len, ops.items.len);
    const query_storage = try pcs.appendStarkVerifierFrom(a, &ops, &channel, capture, config, lifting_log, .{ .export_challenges = true, .sampled_values = .{ .circuit = 4_000_001, .first_wire = 0 }, .terminal_coefficients = .{ .circuit = 4_000_002, .first_wire = 0 } });
    defer a.free(query_storage);
    // Arithmetic circuits occupy 1500..1505; hash schedules own this range.
    var live = try transcript.prepare(a, 1_000_000, ops.items);
    errdefer live.deinit();
    var fixed = try transcript.trusted(a, 1_000_000, ops.items);
    errdefer fixed.deinit();
    try std.testing.expectEqual(channel.n_draws, live.next_draw);
    const count = try std.math.add(usize, claims.len, capture.sampled_values.len);
    const reads = try live.arena.allocator().alloc(InputRead, count);
    const encoded_count = try std.math.add(usize, count, capture.last_layer_coefficients.len);
    const encoded = try live.arena.allocator().alloc(encoding.Row, encoded_count);
    const trusted_encoded = try fixed.arena.allocator().alloc(encoding.Row, encoded_count);
    try std.testing.expectEqual(@as(usize, 3), live.payload_reads.len);
    try std.testing.expectEqual(live.payload_reads.len, fixed.payload_reads.len);
    var cursor: usize = 0;
    var encoded_cursor: usize = 0;
    for (live.payload_reads, fixed.payload_reads) |receipt, trusted_receipt| {
        try std.testing.expectEqualDeep(receipt.source, trusted_receipt.source);
        try std.testing.expectEqualSlices(u32, receipt.uses, trusted_receipt.uses);
        const is_claim = receipt.source.circuit == 4_000_000;
        const is_terminal = receipt.source.circuit == 4_000_002;
        if (!is_claim and !is_terminal and receipt.source.circuit != 4_000_001) return error.InvalidParentInputSource;
        const values = if (is_claim) claims else if (is_terminal) capture.last_layer_coefficients else capture.sampled_values;
        const first = if (is_claim) sources.claim_start else sources.sample_start;
        try std.testing.expectEqual(values.len * 4, receipt.uses.len);
        for (values, 0..) |value, i| {
            const node = if (is_terminal) @as(u32, @intCast(i)) else try std.math.add(u32, first, @intCast(i));
            const schedule = encoding.Schedule{ .source_circuit = if (is_terminal) @import("blake3_terminal_links.zig").PACK_CIRCUIT else 1500, .source_wire = node, .destination_circuit = receipt.source.circuit, .destination_first = @intCast(i * 4), .uses = receipt.uses[i * 4 ..][0..4].* };
            if (!is_terminal) {
                reads[cursor] = .{ .node = node, .value = value, .private = is_claim };
                cursor += 1;
            }
            encoded[encoded_cursor] = try encoding.logicalRow(schedule, value);
            trusted_encoded[encoded_cursor] = try encoding.fixedRow(schedule);
            encoded_cursor += 1;
        }
    }
    try std.testing.expectEqual(count, cursor);
    try std.testing.expectEqual(encoded_count, encoded_cursor);
    return .{ .challenge_sources = sources, .live = live, .fixed = fixed, .input_reads = reads, .encoded_rows = encoded, .fixed_encoded_rows = trusted_encoded };
}
fn words(a: std.mem.Allocator, ops: *std.ArrayList(transcript.Operation), channel: *f.Channel, values: []const u32) !void {
    channel.mixU32s(values);
    try ops.append(a, .{ .words = values });
}
