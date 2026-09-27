//! Original trace/FRI opening ports from trusted emitter payload coordinates.
//! No capture, private opening values, sorted indices or evaluations are needed.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Arena = @import("stable_graph_arena_v1.zig");
const Shape = @import("../block_v5_recursive_parent_shape_v1.zig").Shape;
const Deep = @import("pcs_deep_circuit.zig");
const Fri = @import("fri_verifier_circuit.zig");
const Paths = @import("blake3_stark_paths.zig");
const Leaf = @import("blake3_lifted_leaf_plan.zig");
const Wiring = @import("fri_hash_wire_plan.zig");
const Original = @import("blake3_opening_inputs.zig");
const Projection = @import("block_v5_recursive_parent_fixed_pcs_ports_v1.zig").ProjectionFixed;
const Scalar = @import("scalar_wire_source.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
const Boundary = @import("blake3_boundary.zig");
const Rows = @import("block_v5_recursive_fixed_port_rows_v1.zig").ForSlots(.{ 2, 10, 11, 16, 17, 12 });
pub const Owned = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    arena: Arena.Owned,
    rows: Rows,
    shape_id: [32]u8,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, dg: *const Deep.Circuit, fg: *const Fri.Circuit, paths: *const Paths.FixedShape, projection: *const Projection) !*Owned {
        return compileProfile(4, a, shape, dg, fg, paths, projection);
    }
    fn initProfile(comptime commitments: usize, a: std.mem.Allocator, shape: anytype, dg: *const Deep.Circuit, fg: *const Fri.Circuit, paths: *const Paths.FixedShape, projection: *const Projection) !*Owned {
        if (commitments != 4 and commitments != 10) @compileError("fixed opening ports require four/ten original commitments");
        if (@typeInfo(@TypeOf(shape.columns)).array.len != commitments) @compileError("fixed opening commitment inventory mismatch");
        try shape.validate();
        try dg.validate();
        try fg.validate();
        try projection.rows.finish();
        if (!std.meta.eql(shape.seal, paths.shape_id) or !std.meta.eql(dg.profile().identityDigest(), shape.deepProfile().identityDigest()) or !std.meta.eql(fg.profile().identityDigest(), shape.friProfile().identityDigest())) return error.UntrustedRecursiveParentShape;
        const n: usize = shape.config.fri_config.n_queries;
        if (paths.input_routes.len != try std.math.mul(usize, commitments + shape.widths.len, n)) return error.InvalidOpeningInput;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        var arena = try Arena.Owned.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        var starts: [commitments + 1]usize = @splat(0);
        for (shape.columns, 0..) |logs, i| starts[i + 1] = try std.math.add(usize, starts[i], logs.len);
        const nodes = try temp.alloc(u32, try std.math.mul(usize, starts[commitments], n));
        @memset(nodes, std.math.maxInt(u32));
        for (dg.bindings) |binding| if (binding.source == .queried_value) {
            const source = binding.source.queried_value;
            if (source.tree >= commitments or source.column >= shape.columns[source.tree].len or source.query >= n) return error.InvalidOpeningInput;
            const index = (starts[source.tree] + source.column) * n + source.query;
            if (nodes[index] != std.math.maxInt(u32)) return error.InvalidOpeningInput;
            nodes[index] = binding.node_id;
        };
        for (nodes) |node| if (node == std.math.maxInt(u32)) return error.InvalidOpeningInput;
        var fri_plan = try Wiring.Plan.init(temp, fg, 1504, 5_000_001);
        defer fri_plan.deinit();
        const encoding_count = try std.math.add(usize, nodes.len, fri_plan.schedules.len);
        var rows = try Rows.init(temp, .{ starts[commitments], encoding_count, fri_plan.schedules.len, nodes.len, nodes.len, try std.math.add(usize, nodes.len, fri_plan.exports.len) });
        const du = try Lower.computeUseCountsInto(dg.graph(), try temp.alloc(u32, dg.nodes.len));
        const fu = try Lower.computeUseCountsInto(fg.graph(), try temp.alloc(u32, fg.nodes.len));
        for (shape.columns, 0..) |logs, tree| {
            var geometry = try Leaf.build(temp, logs);
            defer geometry.deinit();
            for (0..n) |q| {
                const route = paths.input_routes[tree * n + q];
                if (route.tree != tree or route.query != q or route.uses.len != logs.len) return error.InvalidOpeningInput;
                for (geometry.order, route.uses, 0..) |column, uses, i| {
                    const col = starts[tree] + column;
                    const node = nodes[col * n + q];
                    const endpoints = projection.ports[logs[column]] orelse return error.InvalidOpeningInput;
                    if (endpoints.len != n) return error.InvalidOpeningInput;
                    const table = try tableId(col);
                    try rows.appendLogicalFixed(17, try Original.adapter.fixedRow(.{ .index = endpoints[q], .value = .{ .circuit = 1502, .wire = node }, .table = table }));
                    try rows.appendLogicalFixed(10, try Original.encoding.fixedRow(.{ .source_circuit = 1502, .source_wire = node, .destination_circuit = 3_000_000, .destination_first = try std.math.add(u32, route.payload, @intCast(i)), .uses = .{ uses, 0, 0, 0 } }));
                    try rows.appendLogicalFixed(12, try Scalar.logicalRow(1502, node, try std.math.add(u32, du[node], 2), M.zero()));
                }
            }
        }
        for (shape.widths, 0..) |_, layer| for (0..n) |q| {
            const route = paths.input_routes[(commitments + layer) * n + q];
            const schedules = try fri_plan.group(layer, q);
            if (route.tree != commitments + layer or route.query != q or route.uses.len != schedules.len * 4) return error.InvalidOpeningInput;
            for (schedules, 0..) |schedule, i| {
                try rows.appendLogicalFixed(11, try Original.pack.fixedRow(schedule));
                try rows.appendLogicalFixed(10, try Original.encoding.fixedRow(.{ .source_circuit = schedule.destination_circuit, .source_wire = schedule.destination_wire, .destination_circuit = 3_000_000, .destination_first = try std.math.add(u32, route.payload, @intCast(i * 4)), .uses = route.uses[i * 4 ..][0..4].* }));
                for (schedule.source_nodes) |node| try rows.appendLogicalFixed(12, try Scalar.logicalRow(1504, node, try std.math.add(u32, fu[node], 1), M.zero()));
            }
        };
        // Original private sorting changes only main values. Rank/last fixed
        // rows and chain sentinel order depend solely on column/query counts.
        for (0..starts[commitments]) |col| {
            const table = try tableId(col);
            for (0..n) |rank| try rows.appendLogicalFixed(16, try Original.ro.fixedRow(.{ .table = table, .chain = table + 1, .rank = @intCast(rank), .last = rank + 1 == n }));
            try rows.appendLogicalFixed(2, try Boundary.logicalCoordinates(table + 1, 0, M.one(), @splat(M.zero())));
        }
        try rows.finish();
        self.* = .{ .allocator = a, .lease = lease, .arena = arena, .rows = rows, .shape_id = shape.seal };
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const lease = self.lease;
        self.arena.deinit();
        a.destroy(self);
        if (lease) |owner| owner.destroy();
    }
};
pub fn compileProfile(comptime commitments: usize, a: std.mem.Allocator, shape: anytype, dg: *const Deep.Circuit, fg: *const Fri.Circuit, paths: *const Paths.FixedShape, projection: *const Projection) !*Owned {
    return Owned.initProfile(commitments, a, shape, dg, fg, paths, projection);
}
fn tableId(column: usize) !u32 {
    const id = try std.math.add(usize, 6_000_000, try std.math.mul(usize, column, 2));
    if (id >= core.fields.m31.Modulus - 1) return error.InvalidOpeningInput;
    return @intCast(id);
}
