//! Compare exact signed lookup multisets across the proposed graph contraction.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const fused = @import("../detached_pcs_opening4_v1.zig");
const old = @import("../detached_opening_accumulate4_v1.zig");
const input = @import("../pcs_deep_input.zig");
const witness = @import("../pcs_deep_input_witness.zig");
const binding = @import("../universal_relation_binding.zig");
const Entry = @import("../relation_interaction.zig").Entry;

test "fused PCS opening preserves the exact signed external lookup multiset" {
    const allocator = std.testing.allocator;
    var fused_def = try fused.build(allocator);
    defer fused_def.deinit();
    var old_def = try old.build(allocator);
    defer old_def.deinit();
    var input_def = try input.build(allocator);
    defer input_def.deinit();
    const fused_plan = try binding.Binding(fused).authenticate(&fused_def);
    const old_plan = try binding.Binding(old).authenticate(&old_def);
    const input_plan = try binding.Binding(input).authenticate(&input_def);
    const nodes: [4]u32 = .{ 101, 102, 103, 104 };
    const weights: [4]QM31 = @splat(QM31.fromU32Unchecked(2, 3, 5, 7));
    const queries: [4]M31 = .{ M31.zero(), M31.one(), M31.fromCanonical(3), M31.fromCanonical(core.fields.m31.Modulus - 1) };
    const accumulator = QM31.fromU32Unchecked(11, 13, 17, 19);
    var output = accumulator;
    var lhs: [4]QM31 = undefined;
    for (queries, weights, &lhs) |q, w, *value| {
        value.* = QM31.fromU32Unchecked(q.toU32(), 0, 0, 0);
        output = output.add(value.mul(w));
    }
    var schedule = fused.Schedule{ .circuit = 412, .verifier = 1, .accumulator = 0, .queries = undefined, .weights = .{ 11, 12, 13, 14 }, .output = 90, .uses = 7 };
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(allocator);
    for (0..4) |term| {
        const q = fused.Query{ .tree = @intCast(term), .column = @intCast(7 + term), .query = 19 };
        schedule.queries[term] = q;
        const metadata = witness.Row{ .source = .{ .queried_value = .{ .tree = q.tree, .column = q.column, .query = q.query } }, .lane = 1, .binding = @intCast(term), .verifier_id = schedule.verifier, .circuit_id = schedule.circuit, .node_id = nodes[term], .use_count = 1 };
        const row = witness.logicalInputs(.{ M31.one(), queries[term] }, metadata.values(), .binary_node);
        try entries.appendSlice(allocator, &input_plan.preparedEntries(row));
    }
    const old_row = try old.logicalRow(.{ .circuit = schedule.circuit, .accumulator = schedule.accumulator, .lhs = nodes, .rhs = schedule.weights, .output = schedule.output, .uses = schedule.uses }, accumulator, lhs, weights, output);
    try entries.appendSlice(allocator, &old_plan.preparedEntries(old_row));
    const prefix = entries.items.len;
    const row = try fused.logicalRow(schedule, accumulator, queries, weights, output);
    var replacement = fused_plan.preparedEntries(row);
    for (&replacement) |*entry| entry.numerator = entry.numerator.neg();
    try entries.appendSlice(allocator, &replacement);
    try std.testing.expect(closed(entries.items));
    // A coordinate mutation leaves arithmetic true but breaks external closure.
    schedule.queries[2].column += 1;
    entries.shrinkRetainingCapacity(prefix);
    replacement = fused_plan.preparedEntries(try fused.logicalRow(schedule, accumulator, queries, weights, output));
    for (&replacement) |*entry| entry.numerator = entry.numerator.neg();
    try entries.appendSlice(allocator, &replacement);
    try std.testing.expect(!closed(entries.items));
}
fn closed(entries: []const Entry) bool {
    for (entries) |key| {
        var sum = QM31.zero();
        for (entries) |entry| {
            if (entry.schema != key.schema or entry.schema_version != key.schema_version or entry.domain != key.domain or entry.arity != key.arity) continue;
            var equal = true;
            for (entry.values[0..entry.arity], key.values[0..key.arity]) |a, b| equal = equal and a.eql(b);
            if (equal) sum = sum.add(entry.numerator);
        }
        if (!sum.isZero()) return false;
    }
    return true;
}
