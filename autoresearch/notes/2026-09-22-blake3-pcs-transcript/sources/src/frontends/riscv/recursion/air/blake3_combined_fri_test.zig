//! One proof of all FRI paths and canonical arithmetic, sharing private values.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const circuit = @import("fri_verifier_circuit.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const group = @import("blake3_merkle_group_witness.zig");
const encoding = @import("blake3_field_bytes.zig");
const pack = @import("qm31_pack_wire.zig");
const mul = @import("qm31_mul_full.zig");
const inv = @import("qm31_inv.zig");
const linear = @import("linear_ops.zig");
const MW = @import("qm31_mul_full_witness.zig");
const IW = @import("qm31_inv_witness.zig");
const LW = @import("linear_ops_witness.zig");
const transcript = @import("blake3_transcript_witness.zig");
const pcs_transcript = @import("blake3_pcs_transcript.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ group.route, group.word, encoding, pack, mul, inv, linear, transcript.challenge, transcript.query_mask });
const selectors = @import("proof_kind.zig").ProofKind.segment_leaf.selectors();
const Capture = f.core.pcs.verifier.VerifiedProofCapture(f.Hasher);
fn Tuple(comptime lists: bool) type {
    var types: [F.Airs.len]type = undefined;
    for (F.Airs, &types) |Air, *T| T.* = if (lists) std.ArrayList(Air.Row) else []Air.Row;
    return std.meta.Tuple(&types);
}
const Rows = Tuple(false);
test "BLAKE3 private FRI values join all paths and canonical arithmetic in one proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var capture = try @import("blake3_pcs_capture_test.zig").verifiedCapture(a, 4);
    defer capture.deinit(a);
    const profile = circuit.Profile{ .lifting_log_size = 6, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_widths = &.{ 16, 2 }, .query_count = 17 };
    var input = try @import("../fri_arithmetic_capture.zig").Owned.init(a, profile, &capture);
    defer input.deinit();
    var graph = try circuit.build(a, profile);
    defer graph.deinit();
    var evaluation = try graph.evaluate(a, input.inputs);
    defer evaluation.deinit();
    // A bad captured alpha must fail replay without changing the caller state.
    var bad_channel = f.Channel{};
    var bad_ops: std.ArrayList(transcript.Operation) = .empty;
    for (capture.commitments) |root| {
        bad_channel.mixRoot(root);
        try bad_ops.append(a, .{ .root = root });
    }
    const initial = bad_channel;
    const prefix_len = bad_ops.items.len;
    const alpha = capture.fri.layers[0].folding_alpha;
    capture.fri.layers[0].folding_alpha = alpha.add(f.QM31.one());
    try std.testing.expectError(error.InvalidBlake3PcsTranscript, pcs_transcript.appendOpening(a, &bad_ops, &bad_channel, &capture, pcsConfig(), 6));
    capture.fri.layers[0].folding_alpha = alpha;
    try std.testing.expectEqual(prefix_len, bad_ops.items.len);
    try std.testing.expect(std.meta.eql(initial, bad_channel));
    const query = capture.queries.raw[0];
    capture.queries.raw[0] ^= 1;
    try std.testing.expectError(error.InvalidBlake3PcsTranscript, pcs_transcript.appendOpening(a, &bad_ops, &bad_channel, &capture, pcsConfig(), 6));
    capture.queries.raw[0] = query;
    try std.testing.expectEqual(prefix_len, bad_ops.items.len);
    try std.testing.expect(std.meta.eql(initial, bad_channel));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, transcriptAllocations, .{&capture});
    const live = try assemble(a, &capture, &graph, evaluation.values, true);
    const fixed = try assemble(a, &capture, &graph, evaluation.values, false);
    try auditWires(a, live);
    var logs: [F.Airs.len]u32 = undefined;
    var rows: Rows = undefined;
    inline for (F.Airs, 0..) |Air, i| {
        logs[i] = if (live[i].len <= 1) 1 else std.math.log2_int_ceil(usize, live[i].len);
        rows[i] = try f.padded(Air, a, live[i], logs[i]);
        if (i >= 7 and i <= 9) for (rows[i]) |*row| {
            row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = selectors;
        };
    }
    const trusted = try preprocessing(a, fixed, logs);
    // The first boundary is the public active-selector input; FRI values have
    // no expected-value anchor and cannot be altered through preprocessing.
    fixed[2][0][8] = fixed[2][0][8].add(f.M31.one());
    const false_pp = try preprocessing(a, fixed, logs);
    try @import("blake3_proof_gate_test_support.zig").runForParameters(F, a, rows, logs, trusted, false_pp, .{ .{}, .{}, .{}, .{}, .{}, .{}, .{}, selectors, selectors, selectors, .{}, .{} });
}
fn assemble(a: std.mem.Allocator, capture: *const Capture, graph: *const circuit.Circuit, values: []const f.QM31, live: bool) !Rows {
    var out: Tuple(true) = undefined;
    inline for (0..F.Airs.len) |i| out[i] = .empty;
    var wiring = try @import("fri_hash_wire_plan.zig").Plan.init(a, graph, 1500, 1600);
    defer wiring.deinit();
    const lane = lower.Lane{ .circuit_id = 1500, .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph.graph(), .exports = wiring.exports };
    var binary = lane;
    binary.circuit_id = 1501;
    binary.active_in = .binary;
    const reference = try lower.Reference.seal(&.{ lane, binary });
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    const counts = plan.counts(.segment_leaf);
    const buffers = lower.InvocationBuffers{ .multiply = try a.alloc(MW.Invocation, counts.multiply), .inverse = try a.alloc(IW.Invocation, counts.inverse), .linear = try a.alloc(LW.Invocation, counts.linear) };
    const ev = lower.Evaluation{ .circuit_identity = graph.identity_digest, .values = values };
    if (live) try plan.materializeInto(reference, .{ .lanes = &.{ ev, ev } }, .segment_leaf, buffers);
    for (plan.multiply_rows, 0..) |fixed, i| try out[7].append(a, MW.logicalInputs(if (live) MW.mainRow(buffers.multiply[i]) else @splat(f.M31.zero()), MW.preprocessedRow(fixed), .segment_leaf));
    for (plan.inverse_rows, 0..) |fixed, i| try out[8].append(a, IW.logicalInputs(if (live) try IW.mainRow(buffers.inverse[i]) else @splat(f.M31.zero()), IW.preprocessedRow(fixed), .segment_leaf));
    for (plan.linear_rows, 0..) |fixed, i| try out[9].append(a, LW.logicalInputs(if (live) try LW.mainRow(buffers.linear[i]) else @splat(f.M31.zero()), LW.preprocessedRow(fixed), .segment_leaf));
    const uses = try lower.computeLaneUseCountsInto(lane, try a.alloc(u32, graph.nodes.len));
    var private_count: usize = 0;
    for (graph.bindings) |binding| {
        const weight = f.M31.fromCanonical(uses[binding.node_id]);
        const row = if (binding.source == .authenticated_value_word) blk: {
            private_count += 1;
            break :blk try f.boundary.privateCoordinates(1500, binding.node_id, weight, if (live) values[binding.node_id].toM31Array() else @splat(f.M31.zero()));
        } else try f.boundary.logicalCoordinates(1500, binding.node_id, weight, values[binding.node_id].toM31Array());
        try out[2].append(a, row);
    }
    try std.testing.expectEqual(wiring.exports.len, private_count);
    for (plan.public_terms) |term| if (term.active_in == .segment) {
        const weight = f.M31.fromCanonical(term.multiplicity);
        try out[2].append(a, try f.boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
    };
    var namespace: u32 = 2000;
    for (capture.fri.layers, 0..) |layer, l| for (0..layer.query_count) |q| {
        const schedules = try wiring.group(l, q);
        const leaf_width: u32 = if (layer.fold_step > 1) 4 else 1;
        const s = group.Statement{ .namespace = namespace, .payload = .{ .circuit = 1601, .first_wire = schedules[0].destination_wire * 4 }, .leaf_count = layer.fold_width / leaf_width, .words_per_leaf = leaf_width * 4, .index = @intCast(layer.positions[q] >> @intCast(layer.fold_step)), .depth = @intCast(layer.path_depth), .root = layer.commitment };
        namespace += 100; // Fixture bound: at most four leaves and five upper levels.
        const words = try a.alloc(f.M31, layer.fold_width * 4);
        for (layer.queryValues(q), 0..) |value, i| @memcpy(words[i * 4 ..][0..4], &value.toM31Array());
        var hash = if (live) try group.prepare(a, s, words, layer.queryPath(q)) else try group.trusted(a, s);
        defer hash.deinit();
        if (live) try std.testing.expectEqualSlices(u8, &s.root, &hash.computed_root.?);
        inline for (.{ hash.g_rows, hash.xor_rows, hash.boundary_rows, hash.route_rows, hash.word_rows }, 0..) |hash_rows, i| try out[i].appendSlice(a, hash_rows);
        for (schedules, layer.queryValues(q), 0..) |schedule, value, i| {
            const encoded = encoding.Schedule{ .source_circuit = schedule.destination_circuit, .source_wire = schedule.destination_wire, .destination_circuit = 1601, .destination_first = s.payload.first_wire + @as(u32, @intCast(i * 4)), .uses = hash.payload_uses[i * 4 ..][0..4].* };
            try out[5].append(a, if (live) try encoding.logicalRow(encoded, value) else try encoding.fixedRow(encoded));
            try out[6].append(a, if (live) try pack.logicalRow(schedule, value) else try pack.fixedRow(schedule));
        }
    };
    var channel = f.Channel{};
    var operations: std.ArrayList(transcript.Operation) = .empty;
    for (capture.commitments) |root| {
        channel.mixRoot(root);
        try operations.append(a, .{ .root = root });
    }
    const query_storage = try pcs_transcript.appendOpening(a, &operations, &channel, capture, pcsConfig(), graph.lifting_log_size);
    defer a.free(query_storage);
    var transcript_rows = if (live) try transcript.prepare(a, 10000, operations.items) else try transcript.trusted(a, 10000, operations.items);
    defer transcript_rows.deinit();
    try std.testing.expectEqual(channel.n_draws, transcript_rows.next_draw);
    try out[0].appendSlice(a, transcript_rows.g_rows);
    try out[1].appendSlice(a, transcript_rows.xor_rows);
    try out[2].appendSlice(a, transcript_rows.boundary_rows);
    try out[3].appendSlice(a, transcript_rows.route_rows);
    try out[10].appendSlice(a, transcript_rows.challenge_rows);
    try out[11].appendSlice(a, transcript_rows.query_rows);
    var result: Rows = undefined;
    inline for (0..F.Airs.len) |i| result[i] = try out[i].toOwnedSlice(a);
    return result;
}
fn preprocessing(a: std.mem.Allocator, rows: Rows, logs: [F.Airs.len]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn auditWires(a: std.mem.Allocator, rows: Rows) !void {
    const wire_id = @import("../../air/lang/relation.zig").id(.recursion_wire);
    var counts = std.AutoHashMap([6]u32, f.M31).init(a);
    defer counts.deinit();
    inline for (F.Airs, 0..) |Air, i| {
        var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
        defer definition.deinit();
        const plan = try f.binding.Binding(Air).authenticate(&definition);
        for (rows[i]) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != wire_id) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).v;
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = f.M31.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var iterator = counts.valueIterator();
    while (iterator.next()) |value| try std.testing.expect(value.isZero());
    // Replace one private scalar emission while keeping all consumers unchanged.
    // Exact tuple counts must fail even before randomized interaction challenges.
    for (rows[2]) |row| if (row[4].isZero() and row[5].v == 1500 and !row[7].isZero()) {
        var key = [6]u32{ row[5].v, row[6].v, row[0].v, row[1].v, row[2].v, row[3].v };
        const old = counts.getPtr(key) orelse return error.MissingPrivateWire;
        old.* = old.sub(row[7]);
        try std.testing.expect(!old.isZero());
        key[2] = row[0].add(f.M31.one()).v;
        const changed = try counts.getOrPut(key);
        if (!changed.found_existing) changed.value_ptr.* = f.M31.zero();
        changed.value_ptr.* = changed.value_ptr.*.add(row[7]);
        try std.testing.expect(!changed.value_ptr.isZero());
        return;
    };
    return error.MissingPrivateWire;
}

fn pcsConfig() f.core.pcs.PcsConfig {
    return .{ .pow_bits = 4, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 17, .fold_step = 4 } };
}

fn transcriptAllocations(a: std.mem.Allocator, capture: *const Capture) !void {
    var channel = f.Channel{};
    var operations: std.ArrayList(transcript.Operation) = .empty;
    defer operations.deinit(a);
    for (capture.commitments) |root| {
        channel.mixRoot(root);
        try operations.append(a, .{ .root = root });
    }
    const queries = try pcs_transcript.appendOpening(a, &operations, &channel, capture, pcsConfig(), 6);
    defer a.free(queries);
}
