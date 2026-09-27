//! Independently admitted query/projection/answer fixed ports. Main assignments
//! never enter this factory. Opening payload ports are supplied by the original
//! StarkPaths emitter separately; this artifact is not a complete parent key.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Arena = @import("stable_graph_arena_v1.zig");
const Shape = @import("../block_v5_recursive_parent_shape_v1.zig").Shape;
const Deep = @import("pcs_deep_circuit.zig");
const Fri = @import("fri_verifier_circuit.zig");
const Links = @import("blake3_query_links.zig");
const Terminal = @import("blake3_terminal_links.zig");
const Projection = @import("blake3_projection_links.zig");
const Scalar = @import("scalar_wire_source.zig");
const Encoding = @import("blake3_field_bytes.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
const Rows = @import("block_v5_recursive_fixed_port_rows_v1.zig");
const ProjectionRows = Rows.ForSlots(.{ 11, 7 });
const QueryRows = Rows.ForSlots(.{ 12, 10 });
const AnswerRows = Rows.ForSlots(.{12});

pub const ProjectionFixed = struct {
    rows: ProjectionRows,
    ports: [32]?[]Projection.route.Endpoint,
    bit_reads: [][31]u32,
    /// Result allocations belong to a stable caller-owned arena. No values or
    /// raw query positions are accepted. The schedule is exactly the original
    /// parity-preserving index recipe, using original fixedRow primitives.
    pub fn init(storage: *const Arena.Owned, lifting: u32, logs: []const u32, queries: []const Links.Query) !ProjectionFixed {
        const a = storage.allocator();
        if (lifting == 0 or lifting > 31) return error.InvalidProjectionLink;
        var counts: [32]u32 = @splat(0);
        for (logs) |log| {
            if (log == 0 or log > lifting) return error.InvalidProjectionLink;
            counts[log] = try std.math.add(u32, counts[log], 1);
            if (counts[log] >= core.fields.m31.Modulus) return error.InvalidProjectionLink;
        }
        var count_rows: usize = 0;
        for (counts, 0..) |count, log| {
            if (count != 0) count_rows = try std.math.add(usize, count_rows, try std.math.mul(usize, queries.len, (log + 3) / 4));
        }
        var rows = try ProjectionRows.init(a, .{ count_rows, count_rows });
        errdefer rows.deinit();
        const bit_reads = try a.alloc([31]u32, queries.len);
        @memset(bit_reads, @splat(0));
        var ports: [32]?[]Projection.route.Endpoint = @splat(null);
        var wire: u32 = 0;
        for (counts, 0..) |count, log| {
            if (count == 0) continue;
            const outputs = try a.alloc(Projection.route.Endpoint, queries.len);
            ports[log] = outputs;
            for (queries, outputs, 0..) |query, *output, q| {
                var previous: ?Projection.route.Endpoint = null;
                var start: usize = 0;
                while (start < log) : (start += 4) {
                    if (wire >= core.fields.m31.Modulus) return error.InvalidProjectionLink;
                    var nodes: [4]u32 = undefined;
                    var affine = Projection.route.AffineSchedule{ .sources = .{ previous, .{ .circuit = 5_000_004, .wire = wire } }, .destination = .{ .circuit = 5_000_005, .wire = wire }, .uses = if (start + 4 >= log) count else 1 };
                    if (previous != null) {
                        for (0..4) |i| affine.coefficients[i][i] = M.one();
                    }
                    for (0..4) |j| {
                        const bit = start + j;
                        const source = if (bit == 0 or bit >= log) 0 else lifting - log + bit;
                        nodes[j] = query.bits[source].deep;
                        bit_reads[q][source] = try std.math.add(u32, bit_reads[q][source], 1);
                        if (bit < log) affine.coefficients[bit / 8][4 + j] = M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(bit % 8)));
                    }
                    try rows.appendLogicalFixed(11, try Projection.pack.fixedRow(.{ .source_circuit = 1502, .source_nodes = nodes, .destination_circuit = 5_000_004, .destination_wire = wire }));
                    try rows.appendLogicalFixed(7, try Projection.route.fixedAffine(affine));
                    previous = affine.destination;
                    wire += 1;
                }
                output.* = previous.?;
            }
        }
        try rows.finish();
        return .{ .rows = rows, .ports = ports, .bit_reads = bit_reads };
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    arena: Arena.Owned,
    shape_id: [32]u8,
    projection: ProjectionFixed,
    query_rows: QueryRows,
    answer_rows: AnswerRows,
    pub const complete_fixed_setup = false;
    pub fn init(a: std.mem.Allocator, shape: *const Shape, dg: *const Deep.Circuit, fg: *const Fri.Circuit, links: *const Links.Prepared) !*Owned {
        return compileProfile(4, a, shape, dg, fg, links);
    }
    fn initProfile(comptime commitments: usize, a: std.mem.Allocator, shape: anytype, dg: *const Deep.Circuit, fg: *const Fri.Circuit, links: *const Links.Prepared) !*Owned {
        if (commitments != 4 and commitments != 10) @compileError("fixed PCS ports require four/ten original commitments");
        if (@typeInfo(@TypeOf(shape.columns)).array.len != commitments) @compileError("fixed PCS commitment inventory mismatch");
        try shape.validate();
        try dg.validate();
        try fg.validate();
        if (!std.meta.eql(dg.profile().identityDigest(), shape.deepProfile().identityDigest()) or !std.meta.eql(fg.profile().identityDigest(), shape.friProfile().identityDigest()) or links.queries.len != shape.config.fri_config.n_queries) return error.UntrustedRecursiveParentShape;
        try validateBindings(dg, fg, links);
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        var arena = try Arena.Owned.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const logs = try temp.alloc(u32, try columnCount(shape));
        var cursor: usize = 0;
        for (shape.columns) |columns| {
            @memcpy(logs[cursor..][0..columns.len], columns);
            cursor += columns.len;
        }
        const projected = try ProjectionFixed.init(&arena, shape.lifting_log, logs, links.queries);
        const du = try Lower.computeUseCountsInto(dg.graph(), try temp.alloc(u32, dg.nodes.len));
        const fu = try Lower.computeUseCountsInto(fg.graph(), try temp.alloc(u32, fg.nodes.len));
        var query_rows = try QueryRows.init(temp, .{ try std.math.add(usize, try std.math.mul(usize, links.queries.len, 63), links.fri_derived.len), links.queries.len });
        for (links.queries, projected.bit_reads) |query, extra| {
            try query_rows.appendLogicalFixed(12, try Scalar.logicalRow(1502, query.position, try std.math.add(u32, du[query.position], 1), M.zero()));
            try query_rows.appendLogicalFixed(10, try Encoding.fixedRow(.{ .source_circuit = 1502, .source_wire = query.position, .destination_circuit = query.source.circuit, .destination_first = query.source.wire, .uses = .{ core.fields.m31.Modulus - 1, 0, 0, 0 } }));
            for (query.bits, query.path_uses, extra) |bit, paths, projected_uses| {
                const weight = try std.math.add(u32, try std.math.add(u32, try std.math.add(u32, du[bit.deep], 1), paths), projected_uses);
                try query_rows.appendLogicalFixed(12, try Scalar.logicalRow(1502, bit.deep, weight, M.zero()));
                try query_rows.appendLogicalFixed(12, try Scalar.routedRow(1504, bit.fri, fu[bit.fri], 1502, bit.deep, M.zero()));
            }
        }
        for (links.fri_derived) |node| try query_rows.appendLogicalFixed(12, try Scalar.logicalRow(1504, node, fu[node], M.zero()));
        try query_rows.finish();
        var terminal = try Terminal.build(temp, dg, fg, links.queries.len, try fg.profile().lastLayerCoefficientCount());
        defer terminal.deinit();
        var answer_rows = try AnswerRows.init(temp, .{try std.math.mul(usize, terminal.answers.len, 2)});
        for (terminal.answers) |link| try answer_rows.appendLogicalFixed(12, try Scalar.logicalRow(1502, link.deep, try std.math.add(u32, du[link.deep], 1), M.zero()));
        for (terminal.answers) |link| try answer_rows.appendLogicalFixed(12, try Scalar.routedRow(1504, link.fri, fu[link.fri], 1502, link.deep, M.zero()));
        try answer_rows.finish();
        self.* = .{ .allocator = a, .lease = lease, .arena = arena, .shape_id = shape.seal, .projection = projected, .query_rows = query_rows, .answer_rows = answer_rows };
        return self;
    }
    pub fn validateAgainst(self: *const Owned, shape: *const Shape, dg: *const Deep.Circuit, fg: *const Fri.Circuit, links: *const Links.Prepared) !void {
        try shape.validate();
        if (!std.meta.eql(self.shape_id, shape.seal)) return error.UntrustedRecursiveParentShape;
        try self.projection.rows.finish();
        try self.query_rows.finish();
        try self.answer_rows.finish();
        // Cold immutable admission, not a self-resealable expected-key token.
        const independently = try Owned.init(self.allocator, shape, dg, fg, links);
        defer independently.deinit();
        inline for (.{ 11, 7 }) |slot| try equalRows(try self.projection.rows.metadata(slot), try independently.projection.rows.metadata(slot));
        inline for (.{ 12, 10 }) |slot| try equalRows(try self.query_rows.metadata(slot), try independently.query_rows.metadata(slot));
        try equalRows(try self.answer_rows.metadata(12), try independently.answer_rows.metadata(12));
        if (self.projection.bit_reads.len != independently.projection.bit_reads.len) return error.UntrustedRecursiveParentFixedPorts;
        for (self.projection.bit_reads, independently.projection.bit_reads) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedRecursiveParentFixedPorts;
        for (self.projection.ports, independently.projection.ports) |actual, expected| {
            if ((actual == null) != (expected == null)) return error.UntrustedRecursiveParentFixedPorts;
            if (actual) |values| {
                const retained = expected.?;
                if (values.len != retained.len) return error.UntrustedRecursiveParentFixedPorts;
                for (values, retained) |value, original| if (!std.meta.eql(value, original)) return error.UntrustedRecursiveParentFixedPorts;
            }
        }
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const lease = self.lease;
        self.arena.deinit();
        a.destroy(self);
        if (lease) |owner| owner.destroy();
    }
};
pub fn compileProfile(comptime commitments: usize, a: std.mem.Allocator, shape: anytype, dg: *const Deep.Circuit, fg: *const Fri.Circuit, links: *const Links.Prepared) !*Owned {
    return Owned.initProfile(commitments, a, shape, dg, fg, links);
}
fn columnCount(shape: anytype) !usize {
    var count: usize = 0;
    for (shape.columns) |columns| count = try std.math.add(usize, count, columns.len);
    return count;
}

fn equalRows(actual: anytype, expected: @TypeOf(actual)) !void {
    if (actual.len != expected.len) return error.UntrustedRecursiveParentFixedPorts;
    for (actual, expected) |a, b| if (!std.meta.eql(a, b)) return error.UntrustedRecursiveParentFixedPorts;
}
fn validateBindings(dg: *const Deep.Circuit, fg: *const Fri.Circuit, links: *const Links.Prepared) !void {
    const n = dg.profile().query_count;
    if (links.queries.len != n or links.fri_derived.len != try std.math.mul(usize, n, try std.math.add(usize, try std.math.mul(usize, fg.profile().fold_widths.len, 2), 1))) return error.InvalidParentQueryLink;
    for (links.queries) |query| {
        if (query.position >= dg.nodes.len) return error.InvalidParentQueryLink;
        for (query.bits, query.path_uses) |bit, uses| if (bit.deep >= dg.nodes.len or bit.fri >= fg.nodes.len or uses >= core.fields.m31.Modulus) return error.InvalidParentQueryLink;
    }
    for (links.fri_derived) |node| if (node >= fg.nodes.len) return error.InvalidParentQueryLink;
    for (dg.bindings) |binding| switch (binding.source) {
        .query_position => |q| {
            if (q >= n or links.queries[q].position != binding.node_id) return error.InvalidParentQueryLink;
        },
        .query_bit => |source| {
            if (source.query >= n or source.bit >= 31 or links.queries[source.query].bits[source.bit].deep != binding.node_id) return error.InvalidParentQueryLink;
        },
        else => {},
    };
    for (fg.bindings) |binding| switch (binding.source) {
        .query_bit => |source| {
            if (source.query >= n or source.bit >= 31 or links.queries[source.query].bits[source.bit].fri != binding.node_id) return error.InvalidParentQueryLink;
        },
        .fri_position => |source| {
            if (source.layer >= fg.profile().fold_widths.len or source.query >= n or links.fri_derived[source.layer * n * 2 + source.query] != binding.node_id) return error.InvalidParentQueryLink;
        },
        .fri_offset => |source| {
            if (source.layer >= fg.profile().fold_widths.len or source.query >= n or links.fri_derived[source.layer * n * 2 + n + source.query] != binding.node_id) return error.InvalidParentQueryLink;
        },
        .last_layer_position => |q| {
            if (q.query >= n or links.fri_derived[fg.profile().fold_widths.len * n * 2 + q.query] != binding.node_id) return error.InvalidParentQueryLink;
        },
        else => {},
    };
}
