//! Prepare a real full-STARK transcript for the joined parent fixture.
//! This fixture knows the proof-gate prefix; production prefixes are separate.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const transcript = @import("blake3_transcript_witness.zig");
const plan_mod = @import("blake3_transcript_plan.zig");
const pcs = @import("blake3_pcs_transcript.zig");
const roots = @import("blake3_root_sources.zig");
const word = @import("blake3_private_word.zig");
pub const encoding = @import("blake3_field_bytes.zig");
pub const InputRead = struct { node: u32, value: f.QM31, private: bool };
pub const Sources = @import("blake3_challenge_links.zig").Sources;
pub const Prepared = struct {
    // All inputs belong to composition circuit 1500. Storage lives in live.arena.
    input_reads: []const InputRead = &.{},
    queries: ?@import("blake3_query_links.zig").Prepared = null,
    sample_links: []const @import("blake3_sample_links.zig").Link = &.{},
    word_rows: []word.Row = &.{},
    fixed_word_rows: []word.Row = &.{},
    encoded_rows: []encoding.Row = &.{},
    fixed_encoded_rows: []encoding.Row = &.{},
    challenge_sources: Sources,
    challenge_links: []const @import("blake3_challenge_links.zig").Link = &.{},
    terminal: ?@import("blake3_terminal_links.zig").Prepared = null,
    paths: ?@import("blake3_stark_paths_fixture.zig").Prepared = null,
    live: transcript.Prepared,
    fixed: transcript.Prepared,
    transcript_plan_id: [32]u8,
    pub fn deinit(self: *Prepared) void {
        if (self.queries) |*queries| queries.deinit();
        if (self.terminal) |*terminal| terminal.deinit();
        if (self.paths) |*paths| paths.deinit();
        self.fixed.deinit();
        self.live.deinit();
    }
};
const Capture = f.core.verifier.ProofCapture(f.Hasher);
pub fn prepare(a: std.mem.Allocator, capture: *const Capture, config: f.core.pcs.PcsConfig, claims: []const f.QM31, sources: Sources, attempt_capacity: u32) !Prepared {
    try std.testing.expectEqual(@as(usize, 4), capture.commitments.len);
    var channel = f.Channel{};
    var ops: std.ArrayList(transcript.Operation) = .empty;
    defer ops.deinit(a);
    try words(a, &ops, &channel, &.{ 0x42334350, 1 });
    for (capture.commitments[0..2], 0..) |root, i| {
        channel.mixRoot(root);
        try ops.append(a, .{ .routed_root = .{ .value = root, .source = try roots.caller(i) } });
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
    try ops.append(a, .{ .routed_root = .{ .value = capture.commitments[2], .source = try roots.caller(2) } });
    const prefix = channel;
    const prefix_len = ops.items.len;
    const lifting_log = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    var substituted = capture.*;
    substituted.commitments = try a.dupe(f.Hasher.Hash, capture.commitments);
    defer a.free(substituted.commitments);
    substituted.commitments[3][31] ^= 0x80;
    try std.testing.expectError(error.InvalidBlake3PcsTranscript, pcs.appendStarkVerifierFrom(a, &ops, &channel, &substituted, config, lifting_log, .{ .composition_root = try roots.caller(3), .fri_roots = try roots.caller(4), .export_challenges = true, .export_queries = true, .nonce = .{ .circuit = 4_000_004, .first_wire = 0 }, .sampled_values = .{ .circuit = 4_000_001, .first_wire = 0 }, .terminal_coefficients = .{ .circuit = 4_000_002, .first_wire = 0 } }));
    try std.testing.expect(std.meta.eql(prefix, channel));
    try std.testing.expectEqual(prefix_len, ops.items.len);
    const query_storage = try pcs.appendStarkVerifierFrom(a, &ops, &channel, capture, config, lifting_log, .{ .composition_root = try roots.caller(3), .fri_roots = try roots.caller(4), .export_challenges = true, .export_queries = true, .nonce = .{ .circuit = 4_000_004, .first_wire = 0 }, .sampled_values = .{ .circuit = 4_000_001, .first_wire = 0 }, .terminal_coefficients = .{ .circuit = 4_000_002, .first_wire = 0 } });
    defer a.free(query_storage);
    // Arithmetic circuits occupy 1500..1505; hash schedules own this range.
    var transcript_plan = try plan_mod.Plan.init(a, .{ .namespace = 1_000_000, .attempt_capacity = attempt_capacity }, ops.items);
    var live = transcript_plan.prepare(a, ops.items) catch |err| {
        transcript_plan.deinit();
        return err;
    };
    errdefer live.deinit();
    const transcript_plan_id = transcript_plan.id;
    var fixed = transcript_plan.intoFixed();
    errdefer fixed.deinit();
    try std.testing.expectEqual(channel.n_draws, live.next_draw);
    const root_count = capture.commitments.len + capture.fri.layers.len;
    try std.testing.expectEqual(root_count, live.root_reads.len);
    try std.testing.expectEqualDeep(live.root_reads, fixed.root_reads);
    const word_rows = try live.arena.allocator().alloc(word.Row, (root_count - 1) * 8 + 2);
    const fixed_word_rows = try fixed.arena.allocator().alloc(word.Row, word_rows.len);
    var key_rows: [8]transcript.boundary.Row = undefined;
    for (live.root_reads, 0..) |receipt, i| {
        try std.testing.expectEqualDeep(try roots.caller(i), receipt.source);
        const digest = if (i < capture.commitments.len) capture.commitments[i] else capture.fri.layers[i - capture.commitments.len].commitment;
        for (receipt.uses, 0..) |reads, j| {
            const uses = try std.math.add(u32, reads, @intCast(capture.queries.raw.len));
            const node = try std.math.add(u32, receipt.source.first_wire, @intCast(j));
            const value = std.mem.readInt(u32, digest[4 * j ..][0..4], .little);
            if (i == 0) {
                // The preprocessed commitment remains bound to the trusted key.
                if (uses >= f.core.fields.m31.Modulus) return error.InvalidParentRootSource;
                key_rows[j] = try transcript.boundary.logicalRow(roots.CIRCUIT, node, f.M31.fromCanonical(uses), value);
            } else {
                word_rows[(i - 1) * 8 + j] = try word.logicalRow(roots.CIRCUIT, node, uses, value);
                fixed_word_rows[(i - 1) * 8 + j] = try word.logicalRow(roots.CIRCUIT, node, uses, 0);
            }
        }
    }
    live.boundary_rows = try std.mem.concat(live.arena.allocator(), transcript.boundary.Row, &.{ live.boundary_rows, &key_rows });
    fixed.boundary_rows = try std.mem.concat(fixed.arena.allocator(), transcript.boundary.Row, &.{ fixed.boundary_rows, &key_rows });
    const count = try std.math.add(usize, claims.len, capture.sampled_values.len);
    const reads = try live.arena.allocator().alloc(InputRead, count);
    const encoded_count = try std.math.add(usize, count, capture.last_layer_coefficients.len);
    const encoded = try live.arena.allocator().alloc(encoding.Row, encoded_count);
    const trusted_encoded = try fixed.arena.allocator().alloc(encoding.Row, encoded_count);
    try std.testing.expectEqual(@as(usize, 5), live.payload_reads.len);
    try std.testing.expectEqual(live.payload_reads.len, fixed.payload_reads.len);
    var cursor: usize = 0;
    var encoded_cursor: usize = 0;
    var nonce_uses: [2]u32 = @splat(0);
    var nonce_receipts: usize = 0;
    for (live.payload_reads, fixed.payload_reads) |receipt, trusted_receipt| {
        try std.testing.expectEqualDeep(receipt.source, trusted_receipt.source);
        try std.testing.expectEqualSlices(u32, receipt.uses, trusted_receipt.uses);
        if (receipt.source.circuit == 4_000_004) {
            if (receipt.source.first_wire != 0 or receipt.uses.len != 2) return error.InvalidParentInputSource;
            for (&nonce_uses, receipt.uses) |*total, uses| total.* = try std.math.add(u32, total.*, uses);
            nonce_receipts += 1;
            continue;
        }
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
    try std.testing.expectEqual(@as(usize, 2), nonce_receipts);
    for (nonce_uses, 0..) |uses, i| {
        const value: u32 = @truncate(capture.proof_of_work >> @as(u6, @intCast(32 * i)));
        word_rows[word_rows.len - 2 + i] = try word.logicalRow(4_000_004, @intCast(i), uses, value);
        fixed_word_rows[word_rows.len - 2 + i] = try word.logicalRow(4_000_004, @intCast(i), uses, 0);
    }
    try std.testing.expectEqual(count, cursor);
    try std.testing.expectEqual(encoded_count, encoded_cursor);
    return .{ .transcript_plan_id = transcript_plan_id, .word_rows = word_rows, .fixed_word_rows = fixed_word_rows, .challenge_sources = sources, .live = live, .fixed = fixed, .input_reads = reads, .encoded_rows = encoded, .fixed_encoded_rows = trusted_encoded };
}
fn words(a: std.mem.Allocator, ops: *std.ArrayList(transcript.Operation), channel: *f.Channel, values: []const u32) !void {
    channel.mixU32s(values);
    try ops.append(a, .{ .words = values });
}
