//! Tiny constrained index/PC/clock join, with public inputs supplied by the
//! batch admission. Same strict <2^30 interpretation as the existing fold.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const bus = @import("../block_v6_native_batch_public_v1.zig");
const spans = @import("../block_v5_open_parent_public_bus_v1.zig");
const recorder = @import("composition_graph_recorder.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const storage = @import("blake3_parent_row_storage.zig");
const append_mod = @import("blake3_parent_append.zig");
const boundary = @import("blake3_boundary.zig");

pub fn append(target: *storage.Prepared, children: []const bus.Child, circuit_id: u32, wires: *std.ArrayList(bus.Wire)) ![32]u8 {
    if (children.len == 0 or children.len > bus.MAX_CHILDREN or circuit_id >= core.fields.m31.Modulus - 2) return error.InvalidNativeBatchCount;
    try @import("blake3_parent_namespace.zig").rejectRange(target, circuit_id, circuit_id + 2);
    const a = target.allocator;
    var builder = recorder.Builder.init(a);
    defer builder.deinit();
    var symbols: [bus.MAX_CHILDREN][6]recorder.Scalar = undefined;
    var input_values: [bus.MAX_CHILDREN * 6]Q = undefined;
    for (children, 0..) |child, i| {
        try spans.validateSpanBound(child.span);
        for (&symbols[i], spans.spanWords(child.span), 0..) |*symbol, value, j| {
            symbol.* = (try builder.input()).value;
            input_values[6 * i + j] = Q.fromBase(M.fromCanonical(value));
        }
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    for (symbols[0..children.len]) |child| try builder.constrainZero(child[1].sub(recorder.Scalar.one()));
    for (symbols[0 .. children.len - 1], symbols[1..children.len]) |left, right| {
        try builder.constrainZero(left[0].add(left[1]).sub(right[0]));
        try builder.constrainZero(left[3].add(recorder.Scalar.one()).sub(right[2]));
        try builder.constrainZero(left[5].sub(right[4]));
    }
    builder.deactivate();
    var graph = try builder.finish();
    defer graph.deinit();
    const evaluated = try a.alloc(Q, graph.nodes.len);
    defer a.free(evaluated);
    try graph.evaluateInto(input_values[0 .. children.len * 6], evaluated);
    const lanes = [_]lower.Lane{
        .{ .circuit_id = circuit_id, .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph.graph() },
        .{ .circuit_id = circuit_id + 1, .active_in = .binary, .circuit_identity = graph.identity_digest, .graph = graph.graph() },
    };
    const reference = try lower.Reference.seal(&lanes);
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    var rows = try @import("arithmetic_fusion_rows.zig").materialize(a, &plan, reference, .{
        .lanes = &.{ .{ .circuit_identity = graph.identity_digest, .values = evaluated }, .{ .circuit_identity = graph.identity_digest, .values = evaluated } },
    }, .segment_leaf);
    defer rows.deinit();
    var boundaries: std.ArrayList(boundary.Row) = .empty;
    defer boundaries.deinit(a);
    for (plan.public_terms) |term| {
        if (term.active_in != .segment) continue;
        const weight = M.fromCanonical(term.multiplicity);
        try boundaries.append(a, try boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
    }
    const counts = try a.alloc(u32, graph.nodes.len);
    defer a.free(counts);
    const uses = try lower.computeUseCountsInto(graph.graph(), counts);
    var input_count: usize = 0;
    for (uses[0 .. children.len * 6], 0..) |count, i| if (count != 0) {
        try wires.append(a, .{ .circuit = circuit_id, .wire = @intCast(i), .uses = count, .child = @intCast(i / 6), .source = .span, .coordinate = @intCast(i % 6) });
        input_count += 1;
    };
    var chunks = append_mod.init();
    defer append_mod.deinit(a, &chunks);
    inline for (.{ 2, 3, 4, 5, 18 }, .{ boundaries.items, rows.multiply, rows.inverse, rows.linear, rows.opening }) |slot, values|
        try chunks[slot].append(a, .{ .live = values, .fixed = values });
    try append_mod.append(target, &chunks);
    target.input_count = try std.math.add(usize, target.input_count, input_count);
    return graph.identity_digest;
}
