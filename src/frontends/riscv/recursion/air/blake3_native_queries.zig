//! Native transcript query bytes joined to DEEP positions and shared FRI bits.
const std = @import("std");
const core = @import("stwo_core");
const deep_mod = @import("blake3_native_deep.zig");
const fri_mod = @import("blake3_native_fri.zig");
const query_links = @import("blake3_query_links.zig");
const scalar = @import("scalar_wire_source.zig");
const encoding = @import("blake3_field_bytes.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Direct = @import("blake3_pcs_source_columns_v1.zig");
pub const DEEP_CIRCUIT: u32 = 1502;
pub const FRI_CIRCUIT: u32 = 1504;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    links: query_links.Prepared,
    rows: []scalar.Row,
    fixed: []scalar.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    columns: ?@import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 12, 10 }) = null,
    paths_applied: bool = false,
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.links.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn rowCount(self: *const Prepared) usize {
        return if (self.columns) |*columns| columns.count(12) else self.rows.len;
    }
    pub fn appendInputs(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (!self.paths_applied or self.rows.len != 0 or self.fixed.len != 0) return error.InvalidNativeQueryLink;
            try columns.appendTo(12, b);
        } else try b.append(12, self.rows, self.fixed);
    }
    pub fn appendEncoded(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (!self.paths_applied or self.encoded.len != 0 or self.fixed_encoded.len != 0) return error.InvalidNativeQueryLink;
            try columns.appendTo(10, b);
        } else try b.append(10, self.encoded, self.fixed_encoded);
    }
};
/// Path/projection consumers must extend bit multiplicities before parent use.
pub fn prepare(a: std.mem.Allocator, transcript: anytype, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared) !Prepared {
    const direct = try Direct.Queries.init(a, transcript, deep, fri);
    // No fallible work follows this single ownership transfer. The real query
    // links remain at this Prepared's stable path-planning lifetime.
    return .{ .arena = std.heap.ArenaAllocator.init(a), .links = direct.links, .columns = direct.columns, .rows = &.{}, .fixed = &.{}, .encoded = &.{}, .fixed_encoded = &.{} };
}
/// Explicit dense-row parity oracle.
pub fn prepareRows(a: std.mem.Allocator, transcript: anytype, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared) !Prepared {
    try transcript.plan.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    try fri.evaluation.validateAgainst(&fri.graph);
    const dp = deep.graph.profile();
    const fp = fri.graph.profile();
    if (dp.query_count != fp.query_count or dp.lifting_log_size != fp.lifting_log_size) return error.InvalidNativeQueryLink;
    const outputs = transcript.plan.fixed.query_outputs;
    if (@hasField(@TypeOf(transcript.*), "live")) {
        if (outputs.len != transcript.live.query_outputs.len) return error.InvalidNativeQueryLink;
        for (outputs, transcript.live.query_outputs) |fixed, live| if (!std.meta.eql(fixed, live)) return error.InvalidNativeQueryLink;
    }
    var links = try query_links.build(a, outputs, &deep.graph, &fri.graph, dp.query_count, fp.fold_widths.len);
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
    for (links.queries, outputs, 0..) |query, output, index| {
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

/// Materialize path/projection fanout after path planning. Recomputing from the
/// graph makes this idempotent; no row is changed until every count is admitted.
pub fn applyPathReads(a: std.mem.Allocator, self: *Prepared, deep: *const deep_mod.Prepared, projection: []const [31]u32) !void {
    if (self.columns) |*columns| {
        if (self.rows.len != 0 or self.fixed.len != 0 or self.encoded.len != 0 or self.fixed_encoded.len != 0) return error.InvalidNativeQueryLink;
        return Direct.Queries.applyPathReadsInto(a, columns, &self.links, &self.paths_applied, deep, projection);
    }
    try deep.graph.validateEvaluation(&deep.evaluation);
    if (projection.len != self.links.queries.len) return error.InvalidNativeQueryLink;
    const scratch = try a.alloc(u32, deep.graph.nodes.len);
    defer a.free(scratch);
    const uses = try lower.computeUseCountsInto(deep.graph.graph(), scratch);
    const weights = try a.alloc([31]u32, projection.len);
    defer a.free(weights);
    for (self.links.queries, projection, weights, 0..) |query, projected, *out, q| {
        for (query.bits, query.path_uses, projected, 0..) |bit, paths, extra, b| {
            const row = q * 63 + 1 + 2 * b;
            if (bit.deep >= uses.len or row >= self.rows.len or row >= self.fixed.len or self.rows[row][1].v != DEEP_CIRCUIT or self.rows[row][2].v != bit.deep or self.fixed[row][1].v != DEEP_CIRCUIT or self.fixed[row][2].v != bit.deep) return error.InvalidNativeQueryLink;
            const weight = try std.math.add(u32, try std.math.add(u32, try std.math.add(u32, uses[bit.deep], 1), paths), extra);
            if (weight >= core.fields.m31.Modulus) return error.InvalidNativeQueryLink;
            out[b] = weight;
        }
    }
    for (weights, 0..) |tuple, q| for (tuple, 0..) |weight, bit| {
        const row = q * 63 + 1 + 2 * bit;
        self.rows[row][3] = M.fromCanonical(weight);
        self.fixed[row][3] = M.fromCanonical(weight);
    };
}
