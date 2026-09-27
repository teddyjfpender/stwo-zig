//! All native STARK openings, linked to private arithmetic scalar sources.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const group = @import("blake3_merkle_group_witness.zig");
const inputs = @import("blake3_opening_inputs.zig");
const leaf = @import("blake3_lifted_leaf_plan.zig");
pub const word = group.word;
const Capture = f.core.verifier.ProofCapture(f.Hasher);
pub const Rows = struct {
    g_rows: []group.g.Row,
    xor_rows: []group.xor.Row,
    boundary_rows: []group.boundary.Row,
    route_rows: []group.route.Row,
    word_rows: []word.Row,
    select_rows: []group.select.Row,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    inputs: inputs.Prepared,
    live: Rows,
    fixed: Rows,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
    }
};
const Lists = struct {
    g_rows: std.ArrayList(group.g.Row) = .empty,
    xor_rows: std.ArrayList(group.xor.Row) = .empty,
    boundary_rows: std.ArrayList(group.boundary.Row) = .empty,
    route_rows: std.ArrayList(group.route.Row) = .empty,
    word_rows: std.ArrayList(word.Row) = .empty,
    select_rows: std.ArrayList(group.select.Row) = .empty,
    fn append(self: *Lists, a: std.mem.Allocator, rows: anytype) !void {
        inline for (std.meta.fields(Rows)) |field| try @field(self, field.name).appendSlice(a, @field(rows, field.name));
    }
    fn finish(self: *Lists, a: std.mem.Allocator) !Rows {
        var out: Rows = undefined;
        inline for (std.meta.fields(Rows)) |field| @field(out, field.name) = try @field(self, field.name).toOwnedSlice(a);
        return out;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    live: Lists = .{},
    fixed: Lists = .{},
    next: u32 = 2_000_000,
    payload: u32 = 0,
    count: usize = 0,
    fn opening(self: *Builder, leaves: u32, words: u32, index: u32, depth: u32, root_index: usize, root: [32]u8, directions: []const group.select.Endpoint, values: []const f.M31, siblings: []const [32]u8) ![]const u32 {
        const span = try std.math.add(u32, try std.math.sub(u32, try std.math.mul(u32, leaves, 2), 1), try std.math.mul(u32, depth, 3));
        const end = try std.math.add(u32, self.next, span);
        if (end >= 3_000_000 or depth > 31) return error.InvalidStarkPathNamespace;
        const statement = group.Statement{ .namespace = self.next, .payload = .{ .circuit = 3_000_000, .first_wire = self.payload }, .leaf_count = leaves, .words_per_leaf = words, .index = index, .depth = @intCast(depth), .root = root, .root_source = try @import("blake3_root_sources.zig").caller(root_index), .directions = directions };
        var live = try group.prepare(std.testing.allocator, statement, values, siblings);
        defer live.deinit();
        try std.testing.expectEqualSlices(u8, &root, &live.computed_root.?);
        var fixed = try group.trusted(std.testing.allocator, statement);
        defer fixed.deinit();
        try std.testing.expectEqualSlices(u32, fixed.payload_uses, live.payload_uses);
        try self.live.append(self.a, live);
        try self.fixed.append(self.a, fixed);
        // A wrong sibling must not produce the statement's root. The circuit
        // links all 32 bytes to the canonical root; it does not trust this comparison.
        if (self.count == 0 and siblings.len > 0) {
            const changed = try self.a.dupe([32]u8, siblings);
            defer self.a.free(changed);
            changed[0][31] ^= 0x80;
            var bad = try group.prepare(std.testing.allocator, statement, values, changed);
            defer bad.deinit();
            try std.testing.expect(!std.mem.eql(u8, &root, &bad.computed_root.?));
        }
        self.next = end;
        self.payload = try std.math.add(u32, self.payload, @intCast(values.len));
        self.count += 1;
        return self.a.dupe(u32, live.payload_uses);
    }
};
pub fn prepare(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared) !Prepared {
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var b = Builder{ .a = a };
    var links = try inputs.Builder.init(a, capture, dg, fg, queries);
    defer links.deinit();
    const n = capture.queries.raw.len;
    try std.testing.expectEqual(@as(usize, 4), capture.trace_paths.len);
    const lifting = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    var cursor: usize = 0;
    for (capture.column_log_sizes, capture.trace_paths, capture.commitments, 0..) |logs, path, root, tree| {
        var geometry = try leaf.build(a, logs);
        defer geometry.deinit();
        const positions = try f.core.pcs.utils.prepareTreeQueryPositions(a, capture.queries.raw, lifting, geometry.max_log);
        try std.testing.expectEqualSlices(usize, positions, path.positions);
        try std.testing.expectEqual(geometry.max_log, path.path_depth);
        const columns = try a.alloc([]const f.M31, logs.len);
        for (columns) |*column| {
            const end = try std.math.add(usize, cursor, n);
            if (end > capture.queried_values.len) return error.InvalidStarkPathValues;
            column.* = capture.queried_values[cursor..end];
            cursor = end;
        }
        try geometry.admitQueries(a, positions, columns);
        const query = try a.alloc(f.M31, columns.len);
        for (positions, 0..) |position, q| {
            for (query, columns) |*value, column| value.* = column[q];
            const ordered = try geometry.leaf(a, query);
            const payload = b.payload;
            const uses = try b.opening(1, @intCast(ordered.len), @intCast(position), path.path_depth, tree, root, try queries.traceDirections(a, q, lifting, geometry.max_log), ordered, path.path(q));
            for (geometry.order, ordered, uses, 0..) |column, value, count, i| try links.trace(tree, column, q, try geometry.columnIndex(column, @intCast(position)), value, try std.math.add(u32, payload, @intCast(i)), count);
        }
    }
    try std.testing.expectEqual(capture.queried_values.len, cursor);
    for (capture.fri.layers, 0..) |layer, l| {
        const leaf_width: u32 = if (layer.fold_step > 1) 4 else 1;
        const values = try a.alloc(f.M31, layer.fold_width * 4);
        for (layer.positions, 0..) |position, q| {
            for (layer.queryValues(q), 0..) |value, i| values[i * 4 ..][0..4].* = value.toM31Array();
            const payload = b.payload;
            const uses = try b.opening(layer.fold_width / leaf_width, leaf_width * 4, @intCast(position >> @intCast(layer.fold_step)), layer.path_depth, capture.commitments.len + l, layer.commitment, try queries.directions(a, q, lifting - layer.path_depth, layer.path_depth), values, layer.queryPath(q));
            try links.friGroup(l, q, layer.queryValues(q), payload, uses);
        }
    }
    try std.testing.expectEqual((4 + capture.fri.layers.len) * n, b.count);
    const linked = try links.finish();
    try b.live.route_rows.appendSlice(a, linked.projection.routed);
    try b.fixed.route_rows.appendSlice(a, linked.projection.fixed_routed);
    try b.live.boundary_rows.appendSlice(a, linked.sentinels);
    try b.fixed.boundary_rows.appendSlice(a, linked.sentinels);
    return .{ .arena = arena, .inputs = linked, .live = try b.live.finish(a), .fixed = try b.fixed.finish(a) };
}
