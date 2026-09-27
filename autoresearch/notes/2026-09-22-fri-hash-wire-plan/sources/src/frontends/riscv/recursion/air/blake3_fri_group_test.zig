//! All folding-group values enter typed hashes, not host-only sibling digests.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const group = @import("blake3_merkle_group_witness.zig");
const encoding = @import("blake3_field_bytes.zig");
const pack = @import("qm31_pack_wire.zig");
const hash_wires = @import("fri_hash_wire_plan.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ group.route, group.word, encoding, pack });
const Data = struct {
    hash: group.Prepared,
    encoded: []encoding.Row,
    packed_rows: []pack.Row,
    boundaries: []f.boundary.Row,
    fn logs(self: Data) [7]u32 {
        return .{ log(self.hash.g_rows.len), log(self.hash.xor_rows.len), log(self.boundaries.len), log(self.hash.route_rows.len), log(self.hash.word_rows.len), log(self.encoded.len), log(self.packed_rows.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
test "BLAKE3 complete FRI folding groups bind every field tuple in a typed proof" {
    const pack_digest = try @import("qm31_pack_wire.zig").computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &pack.SEMANTIC_DIGEST, &pack_digest);
    try std.testing.expectError(error.InvalidQm31PackWire, pack.fixedRow(.{ .source_circuit = 7, .source_nodes = .{ 1, 2, 3, 4 }, .destination_circuit = 7, .destination_wire = 0 }));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]u32{ 1, 2, 4 }) |fold| {
        var capture = try @import("blake3_pcs_capture_test.zig").verifiedCapture(a, fold);
        defer capture.deinit(a);
        var input_plan = try checkArithmetic(a, fold, &capture);
        defer input_plan.deinit();
        for (capture.fri.layers, 0..) |layer, l| {
            const leaf_width: u32 = if (layer.fold_step > 1) 4 else 1;
            const s = group.Statement{ .namespace = 1700, .payload = .{ .circuit = 1601, .first_wire = 0 }, .leaf_count = layer.fold_width / leaf_width, .words_per_leaf = leaf_width * 4, .index = @intCast(layer.positions[0] >> @intCast(layer.fold_step)), .depth = @intCast(layer.path_depth), .root = layer.commitment };
            const values = layer.queryValues(0);
            const live = try assemble(a, s, values, try input_plan.group(l, 0), layer.queryPath(0));
            try std.testing.expectEqualSlices(u8, &s.root, &live.hash.computed_root.?);
            const fixed = try assemble(a, s, values, try input_plan.group(l, 0), null);
            // Hash/route fixed rows depend only on shape, identities and root.
            inline for (F.Airs, .{ live.hash.g_rows, live.hash.xor_rows, live.boundaries, live.hash.route_rows, live.hash.word_rows, live.encoded, live.packed_rows }, .{ fixed.hash.g_rows, fixed.hash.xor_rows, fixed.boundaries, fixed.hash.route_rows, fixed.hash.word_rows, fixed.encoded, fixed.packed_rows }) |Air, rows, trusted| {
                try std.testing.expectEqual(rows.len, trusted.len);
                for (rows, trusted) |row, expected| try std.testing.expectEqualSlices(f.M31, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], expected[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
            }
            if (fold == 4 and l == 0) {
                const sizes = live.logs();
                const rows = .{ try f.padded(group.g, a, live.hash.g_rows, sizes[0]), try f.padded(group.xor, a, live.hash.xor_rows, sizes[1]), try f.padded(group.boundary, a, live.boundaries, sizes[2]), try f.padded(group.route, a, live.hash.route_rows, sizes[3]), try f.padded(group.word, a, live.hash.word_rows, sizes[4]), try f.padded(encoding, a, live.encoded, sizes[5]), try f.padded(pack, a, live.packed_rows, sizes[6]) };
                const trusted = try preprocessing(a, fixed);
                const changed = try a.dupe(f.QM31, values);
                // Mutate the LAST leaf, which the previous first-leaf proof did
                // not connect to field wires at all.
                changed[changed.len - 1] = changed[changed.len - 1].add(f.QM31.one());
                const false_pp = try preprocessing(a, try assemble(a, s, changed, try input_plan.group(l, 0), null));
                try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, sizes, trusted, false_pp);
            }
            var bad = s;
            bad.leaf_count = 3;
            try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.trusted(a, bad));
            bad = s;
            bad.payload.circuit = s.namespace;
            try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.trusted(a, bad));
            bad = s;
            bad.index = @as(u32, 1) << s.depth;
            try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.trusted(a, bad));
            try std.testing.expectError(error.InvalidBlake3MerkleGroup, group.prepare(a, s, &.{}, layer.queryPath(0)));
        }
    }
}
fn assemble(a: std.mem.Allocator, s: group.Statement, values: []const f.QM31, pack_schedules: []const pack.Schedule, siblings: ?[]const [32]u8) !Data {
    const words = try a.alloc(f.M31, values.len * 4);
    for (values, 0..) |value, i| @memcpy(words[i * 4 ..][0..4], &value.toM31Array());
    const hash = if (siblings) |path| try group.prepare(a, s, words, path) else try group.trusted(a, s);
    const encoded = try a.alloc(encoding.Row, values.len);
    const packed_rows = try a.alloc(pack.Row, values.len);
    var boundaries: std.ArrayList(f.boundary.Row) = .empty;
    try boundaries.appendSlice(a, hash.boundary_rows);
    for (values, encoded, 0..) |value, *row, i| {
        const schedule = encoding.Schedule{ .source_circuit = 1600, .source_wire = pack_schedules[i].destination_wire, .destination_circuit = s.payload.circuit, .destination_first = s.payload.first_wire + @as(u32, @intCast(i * 4)), .uses = hash.payload_uses[i * 4 ..][0..4].* };
        row.* = if (siblings != null) try encoding.logicalRow(schedule, value) else try encoding.fixedRow(schedule);
        const pack_schedule = pack_schedules[i];
        packed_rows[i] = if (siblings != null) try pack.logicalRow(pack_schedule, value) else try pack.fixedRow(pack_schedule);
        for (pack_schedule.source_nodes, value.toM31Array()) |node, coordinate| try boundaries.append(a, try f.boundary.logicalCoordinates(1500, node, f.M31.one(), .{ coordinate, f.M31.zero(), f.M31.zero(), f.M31.zero() }));
    }
    return .{ .hash = hash, .encoded = encoded, .packed_rows = packed_rows, .boundaries = try boundaries.toOwnedSlice(a) };
}
fn preprocessing(a: std.mem.Allocator, data: Data) ![]f.Column {
    const sizes = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.hash.g_rows, data.hash.xor_rows, data.boundaries, data.hash.route_rows, data.hash.word_rows, data.encoded, data.packed_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, sizes[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn checkArithmetic(a: std.mem.Allocator, fold: u32, capture: anytype) !hash_wires.Plan {
    const circuit = @import("fri_verifier_circuit.zig");
    const adapter = @import("../fri_arithmetic_capture.zig");
    const profile = circuit.Profile{
        .lifting_log_size = if (fold == 4) 6 else 4,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .fold_widths = switch (fold) {
            1 => &.{ 2, 2, 2 },
            2 => &.{ 4, 2 },
            4 => &.{ 16, 2 },
            else => unreachable,
        },
        .query_count = 17,
    };
    var owned = try adapter.Owned.init(std.testing.allocator, profile, capture);
    defer owned.deinit();
    var graph = try circuit.build(a, profile);
    defer graph.deinit();
    var evaluation = try graph.evaluate(a, owned.inputs);
    defer evaluation.deinit();
    // Every captured hash coordinate has the exact same scalar value at the
    // canonical arithmetic input selected by (layer, query, offset, word).
    var wiring = try hash_wires.Plan.init(a, &graph, 1500, 1600);
    errdefer wiring.deinit();
    try checkLowering(a, &graph, evaluation.values, &wiring);
    try std.testing.expectError(error.InvalidFriHashWirePlan, wiring.group(wiring.widths.len, 0));
    try std.testing.expectError(error.InvalidFriHashWirePlan, hash_wires.Plan.init(a, &graph, 1500, 1500));
    var coordinates: usize = 0;
    for (graph.bindings) |binding| switch (binding.source) {
        .authenticated_value_word => |source| {
            const value = capture.fri.layers[source.layer].queryValues(source.query)[source.offset].toM31Array()[source.word];
            try std.testing.expect(evaluation.values[binding.node_id].eql(f.QM31.fromM31(value, f.M31.zero(), f.M31.zero(), f.M31.zero())));
            const schedules = try wiring.group(source.layer, source.query);
            try std.testing.expectEqual(binding.node_id, schedules[source.offset].source_nodes[source.word]);
            coordinates += 1;
        },
        else => {},
    };
    var expected: usize = 0;
    for (capture.fri.layers) |layer| expected += layer.values.len * 4;
    try std.testing.expectEqual(expected, coordinates);
    try std.testing.expectEqual(expected, wiring.exports.len);
    const original = capture.deep_answers[0];
    capture.deep_answers[0] = original.add(f.QM31.one());
    defer capture.deep_answers[0] = original;
    try std.testing.expect(owned.inputs.deep_answers[0].eql(original));
    var changed = try adapter.Owned.init(a, profile, capture);
    defer changed.deinit();
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.evaluate(a, changed.inputs));
    const position = capture.fri.layers[0].positions[0];
    capture.fri.layers[0].positions[0] ^= 1;
    defer capture.fri.layers[0].positions[0] = position;
    try std.testing.expectError(error.InvalidFriArithmeticCapture, adapter.Owned.init(a, profile, capture));
    return wiring;
}

fn checkLowering(a: std.mem.Allocator, graph: anytype, values: []const f.QM31, wiring: *const hash_wires.Plan) !void {
    const lower = @import("verifier_arithmetic_lowering.zig");
    const lane = lower.Lane{ .circuit_id = 1500, .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph.graph(), .exports = wiring.exports };
    var binary = lane;
    binary.circuit_id = 1501;
    binary.active_in = .binary;
    const reference = try lower.Reference.seal(&.{ lane, binary });
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    const ordinary = try lower.computeUseCountsInto(lane.graph, try a.alloc(u32, graph.nodes.len));
    const extended = try lower.computeLaneUseCountsInto(lane, try a.alloc(u32, graph.nodes.len));
    for (wiring.exports) |item| try std.testing.expectEqual(ordinary[item.node_id] + 1, extended[item.node_id]);
    const counts = plan.counts(.segment_leaf);
    const buffers = lower.InvocationBuffers{
        .multiply = try a.alloc(@import("qm31_mul_full_witness.zig").Invocation, counts.multiply),
        .inverse = try a.alloc(@import("qm31_inv_witness.zig").Invocation, counts.inverse),
        .linear = try a.alloc(@import("linear_ops_witness.zig").Invocation, counts.linear),
    };
    const evaluation = lower.Evaluation{ .circuit_identity = graph.identity_digest, .values = values };
    for ([_]lower.ProofKind{ .segment_leaf, .binary_node }) |kind| try plan.materializeInto(reference, .{ .lanes = &.{ evaluation, evaluation } }, kind, buffers);
    try std.testing.expect(counts.multiply > 0 and counts.linear > 0);
}
