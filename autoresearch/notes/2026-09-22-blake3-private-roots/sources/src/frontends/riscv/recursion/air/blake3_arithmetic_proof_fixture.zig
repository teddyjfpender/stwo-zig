//! Existing production FRI arithmetic AIRs committed under BLAKE3.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const mul = @import("qm31_mul_full.zig");
const inv = @import("qm31_inv.zig");
const linear = @import("linear_ops.zig");
const MW = @import("qm31_mul_full_witness.zig");
const IW = @import("qm31_inv_witness.zig");
const LW = @import("linear_ops_witness.zig");
const transcript = @import("blake3_transcript_witness.zig");
const Prefix = @import("blake3_stark_prefix_fixture.zig");
const scalar = @import("scalar_wire_source.zig");
const opening = @import("blake3_opening_inputs.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const word = @import("blake3_private_word.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ mul, inv, linear, transcript.challenge, transcript.route, transcript.query_mask, word, encoding, pack, scalar });
const selectors = @import("proof_kind.zig").ProofKind.segment_leaf.selectors();
pub const Graph = @import("composition_circuit.zig").CircuitGraph;
pub fn check(a: std.mem.Allocator, graph: Graph, values: []const f.QM31) !void {
    return checkMany(a, &.{graph}, &.{values});
}
pub fn checkMany(a: std.mem.Allocator, graphs: []const Graph, values: []const []const f.QM31) !void {
    return checkWithTranscript(a, graphs, values, null);
}
pub fn checkWithTranscript(a: std.mem.Allocator, graphs: []const Graph, values: []const []const f.QM31, prefix: ?*const Prefix.Prepared) !void {
    if (graphs.len == 0 or graphs.len != values.len) return error.InvalidArithmeticFixture;
    const lanes = try a.alloc(lower.Lane, graphs.len * 2);
    const evaluations = try a.alloc(lower.Evaluation, lanes.len);
    for (graphs, values, 0..) |graph, evaluated, i| {
        lanes[2 * i] = .{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
        lanes[2 * i + 1] = lanes[2 * i];
        lanes[2 * i + 1].circuit_id += 1;
        lanes[2 * i + 1].active_in = .binary;
        evaluations[2 * i] = .{ .circuit_identity = graph.identity_digest, .values = evaluated };
        evaluations[2 * i + 1] = evaluations[2 * i];
    }
    const reference = try lower.Reference.seal(lanes);
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    const counts = plan.counts(.segment_leaf);
    const buffers = lower.InvocationBuffers{ .multiply = try a.alloc(MW.Invocation, counts.multiply), .inverse = try a.alloc(IW.Invocation, counts.inverse), .linear = try a.alloc(LW.Invocation, counts.linear) };
    try plan.materializeInto(reference, .{ .lanes = evaluations }, .segment_leaf, buffers);
    const mrows = try a.alloc(mul.Row, counts.multiply);
    const irows = try a.alloc(inv.Row, counts.inverse);
    const lrows = try a.alloc(linear.Row, counts.linear);
    for (mrows, buffers.multiply, plan.multiply_rows) |*row, invocation, fixed| row.* = MW.logicalInputs(MW.mainRow(invocation), MW.preprocessedRow(fixed), .segment_leaf);
    for (irows, buffers.inverse, plan.inverse_rows) |*row, invocation, fixed| row.* = IW.logicalInputs(try IW.mainRow(invocation), IW.preprocessedRow(fixed), .segment_leaf);
    for (lrows, buffers.linear, plan.linear_rows) |*row, invocation, fixed| row.* = LW.logicalInputs(try LW.mainRow(invocation), LW.preprocessedRow(fixed), .segment_leaf);
    const use_counts = try a.alloc([]u32, graphs.len);
    for (graphs, use_counts) |graph, *uses| uses.* = try lower.computeUseCountsInto(graph, try a.alloc(u32, graph.nodes.len));
    const external = try a.alloc(bool, graphs[0].nodes.len);
    const private_inputs = try a.alloc(bool, graphs[0].nodes.len);
    const packed_inputs = try a.alloc(bool, graphs[0].nodes.len);
    @memset(external, false);
    @memset(private_inputs, false);
    @memset(packed_inputs, false);
    const deep_reads = try a.alloc(u32, if (graphs.len > 1) graphs[1].nodes.len else 0);
    @memset(deep_reads, 0);
    var pack_rows: std.ArrayList(pack.Row) = .empty;
    var trusted_pack: std.ArrayList(pack.Row) = .empty;
    if (prefix) |data| {
        for (data.input_reads) |read| {
            if (read.node >= graphs[0].nodes.len or graphs[0].nodes[read.node].op != .input or external[read.node] or !read.value.eql(values[0][read.node])) return error.InvalidParentInputSource;
            external[read.node] = true;
            private_inputs[read.node] = read.private;
        }
        for (data.sample_links) |link| {
            if (graphs.len < 2 or link.composition >= external.len or !external[link.composition] or private_inputs[link.composition] or packed_inputs[link.composition]) return error.InvalidParentSampleLink;
            packed_inputs[link.composition] = true;
            const value = values[0][link.composition];
            const weight = try std.math.add(u32, use_counts[0][link.composition], 1);
            for (link.deep, value.toM31Array()) |node, coordinate| {
                if (node >= deep_reads.len or graphs[1].nodes[node].op != .input or deep_reads[node] != 0 or !values[1][node].eql(f.QM31.fromBase(coordinate))) return error.InvalidParentSampleLink;
                deep_reads[node] = weight;
            }
            const schedule = pack.Schedule{ .source_circuit = lanes[2].circuit_id, .source_nodes = link.deep, .destination_circuit = lanes[0].circuit_id, .destination_wire = link.composition };
            try pack_rows.append(a, try pack.weightedLogicalRow(schedule, value, weight));
            try trusted_pack.append(a, try pack.weightedFixedRow(schedule, weight));
        }
        for (data.input_reads) |read| if (!read.private and !packed_inputs[read.node]) return error.InvalidParentSampleLink;
    }
    const paths = if (prefix) |data| data.paths else null;
    const opening_inputs = try a.alloc([]bool, graphs.len);
    for (graphs, opening_inputs) |graph, *mask| {
        mask.* = try a.alloc(bool, graph.nodes.len);
        @memset(mask.*, false);
    }
    var scalar_rows: std.ArrayList(scalar.Row) = .empty;
    var trusted_scalars: std.ArrayList(scalar.Row) = .empty;
    if (paths) |data| {
        for (data.inputs.sources) |source| {
            const lane = source.lane;
            const node = source.node;
            if ((lane != 1 and lane != 2) or lane >= graphs.len or node >= graphs[lane].nodes.len or graphs[lane].nodes[node].op != .input or opening_inputs[lane][node] or !values[lane][node].eql(f.QM31.fromBase(source.value))) return error.InvalidOpeningInput;
            if (lane == 1 and deep_reads[node] != 0) return error.InvalidOpeningInput;
            opening_inputs[lane][node] = true;
            const weight = try std.math.add(u32, use_counts[lane][node], 1);
            const circuit = lanes[2 * lane].circuit_id;
            if (source.canonical) |canonical| {
                if (lane != 1 or canonical >= data.inputs.canonical.len or !source.value.eql(data.inputs.canonical[canonical].value)) return error.InvalidOpeningInput;
                try scalar_rows.append(a, try scalar.routedRow(circuit, node, weight, opening.CANONICAL_CIRCUIT, canonical, source.value));
                try trusted_scalars.append(a, try scalar.routedRow(circuit, node, weight, opening.CANONICAL_CIRCUIT, canonical, f.M31.zero()));
            } else {
                if (lane != 2) return error.InvalidOpeningInput;
                try scalar_rows.append(a, try scalar.logicalRow(circuit, node, weight, source.value));
                try trusted_scalars.append(a, try scalar.logicalRow(circuit, node, weight, f.M31.zero()));
            }
        }
        for (data.inputs.canonical, 0..) |source, i| {
            try scalar_rows.append(a, try scalar.logicalRow(opening.CANONICAL_CIRCUIT, @intCast(i), source.uses, source.value));
            try trusted_scalars.append(a, try scalar.logicalRow(opening.CANONICAL_CIRCUIT, @intCast(i), source.uses, f.M31.zero()));
        }
        try pack_rows.appendSlice(a, data.inputs.packing);
        try trusted_pack.appendSlice(a, data.inputs.fixed_packed);
    }
    if (prefix) |data| if (data.terminal) |terminal| {
        if (graphs.len < 3) return error.InvalidParentTerminalLink;
        for (terminal.answers) |link| {
            if (link.deep >= deep_reads.len or deep_reads[link.deep] != 0) return error.InvalidParentTerminalLink;
            const value = try terminalScalar(graphs[1], values[1], opening_inputs[1], link.deep);
            const other = try terminalScalar(graphs[2], values[2], opening_inputs[2], link.fri);
            if (!value.eql(other)) return error.InvalidParentTerminalLink;
            const count = try std.math.add(u32, use_counts[1][link.deep], 1);
            try scalar_rows.append(a, try scalar.logicalRow(1502, link.deep, count, value));
            try trusted_scalars.append(a, try scalar.logicalRow(1502, link.deep, count, f.M31.zero()));
            try scalar_rows.append(a, try scalar.routedRow(1504, link.fri, use_counts[2][link.fri], 1502, link.deep, value));
            try trusted_scalars.append(a, try scalar.routedRow(1504, link.fri, use_counts[2][link.fri], 1502, link.deep, f.M31.zero()));
        }
        for (terminal.coefficients, 0..) |nodes, i| {
            var coordinates: [4]f.M31 = undefined;
            for (nodes, &coordinates) |node, *value| {
                value.* = try terminalScalar(graphs[2], values[2], opening_inputs[2], node);
                const count = try std.math.add(u32, use_counts[2][node], 1);
                try scalar_rows.append(a, try scalar.logicalRow(1504, node, count, value.*));
                try trusted_scalars.append(a, try scalar.logicalRow(1504, node, count, f.M31.zero()));
            }
            const schedule = pack.Schedule{ .source_circuit = 1504, .source_nodes = nodes, .destination_circuit = @import("blake3_terminal_links.zig").PACK_CIRCUIT, .destination_wire = @intCast(i) };
            try pack_rows.append(a, try pack.logicalRow(schedule, f.QM31.fromM31Array(coordinates)));
            try trusted_pack.append(a, try pack.fixedRow(schedule));
        }
    };
    if (prefix) |data| {
        const challenge_circuit = @import("blake3_challenge_links.zig").CIRCUIT;
        for (data.challenge_links, 0..) |link, index| {
            var coordinates: [4]f.M31 = undefined;
            var weight: u32 = 0;
            const first: u32 = @intCast(index * 4);
            const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
            if (link.composition) |node| {
                if (node >= graphs[0].nodes.len or graphs[0].nodes[node].op != .input or external[node] or packed_inputs[node] or opening_inputs[0][node]) return error.InvalidParentChallengeLink;
                opening_inputs[0][node] = true;
                coordinates = values[0][node].toM31Array();
                weight = use_counts[0][node];
                if (weight != 0) {
                    const schedule = pack.Schedule{ .source_circuit = challenge_circuit, .source_nodes = nodes, .destination_circuit = 1500, .destination_wire = node };
                    try pack_rows.append(a, try pack.weightedLogicalRow(schedule, values[0][node], weight));
                    try trusted_pack.append(a, try pack.weightedFixedRow(schedule, weight));
                }
            }
            if (link.scalar) |destination| {
                const lane = destination.lane;
                if (lane == 0 or lane >= graphs.len) return error.InvalidParentChallengeLink;
                for (destination.nodes, 0..) |node, i| {
                    if (lane == 1 and (node >= deep_reads.len or deep_reads[node] != 0)) return error.InvalidParentChallengeLink;
                    const value = try terminalScalar(graphs[lane], values[lane], opening_inputs[lane], node);
                    if (link.composition != null and !coordinates[i].eql(value)) return error.InvalidParentChallengeLink;
                    coordinates[i] = value;
                    const circuit = lanes[2 * lane].circuit_id;
                    try scalar_rows.append(a, try scalar.routedRow(circuit, node, use_counts[lane][node], challenge_circuit, nodes[i], value));
                    try trusted_scalars.append(a, try scalar.routedRow(circuit, node, use_counts[lane][node], challenge_circuit, nodes[i], f.M31.zero()));
                }
                weight = try std.math.add(u32, weight, 1);
            } else if (link.composition == null) return error.InvalidParentChallengeLink;
            for (coordinates, nodes, 0..) |value, node, i| {
                const source_wire = try std.math.add(u32, link.source.first_wire, @intCast(i));
                try scalar_rows.append(a, try scalar.routedRow(challenge_circuit, node, weight, link.source.circuit, source_wire, value));
                try trusted_scalars.append(a, try scalar.routedRow(challenge_circuit, node, weight, link.source.circuit, source_wire, f.M31.zero()));
            }
        }
    }
    var boundaries: std.ArrayList(f.boundary.Row) = .empty;
    for (graphs, values, use_counts, 0..) |graph, evaluated, uses, i| {
        for (graph.nodes, 0..) |node, id| if (node.op == .input) {
            if ((i == 0 and packed_inputs[id]) or opening_inputs[i][id]) continue;
            var count = uses[id];
            var private = false;
            if (i == 0 and external[id]) {
                count = try std.math.add(u32, count, 1);
                private = private_inputs[id];
            }
            if (i == 1 and deep_reads[id] > 0) {
                count = try std.math.add(u32, count, deep_reads[id]);
                private = true;
            }
            const coordinates = evaluated[id].toM31Array();
            const circuit = lanes[2 * i].circuit_id;
            try boundaries.append(a, if (private) try f.boundary.privateCoordinates(circuit, @intCast(id), f.M31.fromCanonical(count), coordinates) else try f.boundary.logicalCoordinates(circuit, @intCast(id), f.M31.fromCanonical(count), coordinates));
        };
    }
    for (plan.public_terms) |term| if (term.active_in == .segment) {
        const weight = f.M31.fromCanonical(term.multiplicity);
        try boundaries.append(a, try f.boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
    };
    var trusted_boundaries: std.ArrayList(f.boundary.Row) = .empty;
    try trusted_boundaries.appendSlice(a, boundaries.items);
    if (prefix) |data| {
        try boundaries.appendSlice(a, data.live.boundary_rows);
        try trusted_boundaries.appendSlice(a, data.fixed.boundary_rows);
    }
    if (paths) |data| {
        try boundaries.appendSlice(a, data.live.boundary_rows);
        try trusted_boundaries.appendSlice(a, data.fixed.boundary_rows);
    }
    const grow = try concat(f.g.Row, a, if (prefix) |data| data.live.g_rows else &.{}, if (paths) |data| data.live.g_rows else &.{});
    const xrow = try concat(f.xor.Row, a, if (prefix) |data| data.live.xor_rows else &.{}, if (paths) |data| data.live.xor_rows else &.{});
    const crow = if (prefix) |data| data.live.challenge_rows else &.{};
    const rrow = try concat(transcript.route.Row, a, if (prefix) |data| data.live.route_rows else &.{}, if (paths) |data| data.live.route_rows else &.{});
    const qrow = if (prefix) |data| data.live.query_rows else &.{};
    const wrow = try concat(word.Row, a, if (prefix) |data| data.root_rows else &.{}, if (paths) |data| data.live.word_rows else &.{});
    const erow = try concat(encoding.Row, a, if (prefix) |data| data.encoded_rows else &.{}, if (paths) |data| data.inputs.encoded else &.{});
    const logs = [13]u32{ log(grow.len), log(xrow.len), log(boundaries.items.len), log(mrows.len), log(irows.len), log(lrows.len), log(crow.len), log(rrow.len), log(qrow.len), log(wrow.len), log(erow.len), log(pack_rows.items.len), log(scalar_rows.items.len) };
    const rows = .{ try f.padded(f.g, a, grow, logs[0]), try f.padded(f.xor, a, xrow, logs[1]), try f.padded(f.boundary, a, boundaries.items, logs[2]), try padded(mul, a, mrows, logs[3]), try padded(inv, a, irows, logs[4]), try padded(linear, a, lrows, logs[5]), try f.padded(transcript.challenge, a, crow, logs[6]), try f.padded(transcript.route, a, rrow, logs[7]), try f.padded(transcript.query_mask, a, qrow, logs[8]), try f.padded(word, a, wrow, logs[9]), try f.padded(encoding, a, erow, logs[10]), try f.padded(pack, a, pack_rows.items, logs[11]), try f.padded(scalar, a, scalar_rows.items, logs[12]) };
    // Reconstruct operation preprocessing solely from the admitted lowering plan.
    const trusted_m = try a.alloc(mul.Row, mrows.len);
    const trusted_i = try a.alloc(inv.Row, irows.len);
    const trusted_l = try a.alloc(linear.Row, lrows.len);
    for (trusted_m, plan.multiply_rows) |*row, fixed| row.* = MW.logicalInputs(@splat(f.M31.zero()), MW.preprocessedRow(fixed), .segment_leaf);
    for (trusted_i, plan.inverse_rows) |*row, fixed| row.* = IW.logicalInputs(@splat(f.M31.zero()), IW.preprocessedRow(fixed), .segment_leaf);
    for (trusted_l, plan.linear_rows) |*row, fixed| row.* = LW.logicalInputs(@splat(f.M31.zero()), LW.preprocessedRow(fixed), .segment_leaf);
    const trusted_rows = .{ try concat(f.g.Row, a, if (prefix) |data| data.fixed.g_rows else &.{}, if (paths) |data| data.fixed.g_rows else &.{}), try concat(f.xor.Row, a, if (prefix) |data| data.fixed.xor_rows else &.{}, if (paths) |data| data.fixed.xor_rows else &.{}), trusted_boundaries.items, trusted_m, trusted_i, trusted_l, if (prefix) |data| data.fixed.challenge_rows else crow, try concat(transcript.route.Row, a, if (prefix) |data| data.fixed.route_rows else &.{}, if (paths) |data| data.fixed.route_rows else &.{}), if (prefix) |data| data.fixed.query_rows else qrow, try concat(word.Row, a, if (prefix) |data| data.fixed_root_rows else &.{}, if (paths) |data| data.fixed.word_rows else &.{}), try concat(encoding.Row, a, if (prefix) |data| data.fixed_encoded_rows else &.{}, if (paths) |data| data.inputs.fixed_encoded else &.{}), trusted_pack.items, trusted_scalars.items };
    const trusted = try preprocessing(a, trusted_rows, logs);
    trusted_boundaries.items[0][8] = trusted_boundaries.items[0][8].add(f.M31.one());
    const false_pp = try preprocessing(a, trusted_rows, logs);
    try @import("blake3_proof_gate_test_support.zig").runForParameters(F, a, rows, logs, trusted, false_pp, .{ .{}, .{}, .{}, selectors, selectors, selectors, .{}, .{}, .{}, .{}, .{}, .{}, .{} });
}
fn log(n: usize) u32 {
    return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
}
fn padded(comptime Air: type, a: std.mem.Allocator, rows: []const Air.Row, size: u32) ![]Air.Row {
    const result = try f.padded(Air, a, rows, size);
    for (result) |*row| row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = selectors;
    return result;
}
fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [13]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn concat(comptime T: type, a: std.mem.Allocator, first: []const T, second: []const T) ![]const T {
    return std.mem.concat(a, T, &.{ first, second });
}

fn terminalScalar(graph: Graph, values: []const f.QM31, occupied: []bool, node: u32) !f.M31 {
    if (node >= graph.nodes.len or graph.nodes[node].op != .input or occupied[node]) return error.InvalidParentTerminalLink;
    const value = values[node].tryIntoM31() catch return error.InvalidParentTerminalLink;
    occupied[node] = true;
    return value;
}
