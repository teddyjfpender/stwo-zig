//! Native transcript query bytes joined to DEEP positions and shared FRI bits.
const std = @import("std");
const core = @import("stwo_core");
const native = @import("blake3_native_transcript.zig");
const deep_mod = @import("blake3_native_deep.zig");
const fri_mod = @import("blake3_native_fri.zig");
const query_links = @import("blake3_query_links.zig");
const scalar = @import("scalar_wire_source.zig");
const encoding = @import("blake3_field_bytes.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const DEEP_CIRCUIT: u32 = 1502;
pub const FRI_CIRCUIT: u32 = 1504;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    links: query_links.Prepared,
    rows: []scalar.Row,
    fixed: []scalar.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    pub fn deinit(self: *Prepared) void {
        self.links.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
/// Path/projection consumers must extend bit multiplicities before parent use.
pub fn prepare(a: std.mem.Allocator, transcript: *const native.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared) !Prepared {
    try transcript.plan.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    try fri.evaluation.validateAgainst(&fri.graph);
    const dp = deep.graph.profile();
    const fp = fri.graph.profile();
    if (dp.query_count != fp.query_count or dp.lifting_log_size != fp.lifting_log_size or transcript.plan.fixed.query_outputs.len != transcript.live.query_outputs.len) return error.InvalidNativeQueryLink;
    for (transcript.plan.fixed.query_outputs, transcript.live.query_outputs) |fixed, live| if (!std.meta.eql(fixed, live)) return error.InvalidNativeQueryLink;
    var links = try query_links.build(a, transcript.live.query_outputs, &deep.graph, &fri.graph, dp.query_count, fp.fold_widths.len);
    errdefer links.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const deep_uses = try lower.computeUseCountsInto(deep.graph.graph(), try temp.alloc(u32, deep.graph.nodes.len));
    const fri_uses = try lower.computeUseCountsInto(fri.graph.graph(), try temp.alloc(u32, fri.graph.nodes.len));
    const count = try std.math.add(usize, try std.math.mul(usize, links.queries.len, 63), links.fri_derived.len);
    const rows = try temp.alloc(scalar.Row, count);
    const fixed = try temp.alloc(scalar.Row, count);
    const encoded = try temp.alloc(encoding.Row, links.queries.len);
    const fixed_encoded = try temp.alloc(encoding.Row, links.queries.len);
    var cursor: usize = 0;
    for (links.queries, transcript.live.query_outputs, 0..) |query, output, index| {
        if (output.operation >= transcript.operations.len or transcript.operations[output.operation] != .queries) return error.InvalidNativeQueryLink;
        const operation = transcript.operations[output.operation].queries;
        if (operation.values.len != links.queries.len or operation.log_domain_size != dp.lifting_log_size) return error.InvalidNativeQueryLink;
        const position = try base(deep.evaluation.values, query.position);
        if (position.v != operation.values[index]) return error.InvalidNativeQueryLink;
        const weight = try std.math.add(u32, deep_uses[query.position], 1);
        rows[cursor] = try scalar.logicalRow(DEEP_CIRCUIT, query.position, weight, position);
        fixed[cursor] = try scalar.logicalRow(DEEP_CIRCUIT, query.position, weight, M.zero());
        cursor += 1;
        // The transcript emits this byte word. Negative encoding emission
        // consumes it, exactly as in the qualified joined PCS fixture.
        const schedule = encoding.Schedule{ .source_circuit = DEEP_CIRCUIT, .source_wire = query.position, .destination_circuit = query.source.circuit, .destination_first = query.source.wire, .uses = .{ core.fields.m31.Modulus - 1, 0, 0, 0 } };
        encoded[index] = try encoding.logicalRow(schedule, Q.fromBase(position));
        fixed_encoded[index] = try encoding.fixedRow(schedule);
        for (query.bits) |bit| {
            const value = try base(deep.evaluation.values, bit.deep);
            if (value.v > 1 or !value.eql(try base(fri.evaluation.values, bit.fri))) return error.InvalidNativeQueryLink;
            const uses = try std.math.add(u32, deep_uses[bit.deep], 1);
            rows[cursor] = try scalar.logicalRow(DEEP_CIRCUIT, bit.deep, uses, value);
            fixed[cursor] = try scalar.logicalRow(DEEP_CIRCUIT, bit.deep, uses, M.zero());
            cursor += 1;
            rows[cursor] = try scalar.routedRow(FRI_CIRCUIT, bit.fri, fri_uses[bit.fri], DEEP_CIRCUIT, bit.deep, value);
            fixed[cursor] = try scalar.routedRow(FRI_CIRCUIT, bit.fri, fri_uses[bit.fri], DEEP_CIRCUIT, bit.deep, M.zero());
            cursor += 1;
        }
    }
    for (links.fri_derived) |node| {
        rows[cursor] = try scalar.logicalRow(FRI_CIRCUIT, node, fri_uses[node], try base(fri.evaluation.values, node));
        fixed[cursor] = try scalar.logicalRow(FRI_CIRCUIT, node, fri_uses[node], M.zero());
        cursor += 1;
    }
    std.debug.assert(cursor == rows.len);
    return .{ .arena = arena, .links = links, .rows = rows, .fixed = fixed, .encoded = encoded, .fixed_encoded = fixed_encoded };
}
fn base(values: []const Q, node: u32) !M {
    if (node >= values.len) return error.InvalidNativeQueryLink;
    const value = values[node].toM31Array()[0];
    if (!values[node].eql(Q.fromBase(value))) return error.InvalidNativeQueryLink;
    return value;
}
