//! All native STARK openings, linked to private arithmetic scalar sources.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const suite = @import("../blake3_engine_protocol.zig");
const group = @import("blake3_merkle_group_witness.zig");
const inputs = @import("blake3_opening_inputs.zig");
const leaf = @import("blake3_lifted_leaf_plan.zig");
pub const word = group.word;
const Capture = core.verifier.ProofCapture(suite.Hasher);
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
    row_allocator: std.mem.Allocator,
    inputs: inputs.Prepared,
    live: Rows,
    fixed: Rows,
    pub fn deinit(self: *Prepared) void {
        freeRows(self.row_allocator, self.live);
        freeRows(self.row_allocator, self.fixed);
        self.arena.deinit();
        self.* = undefined;
    }
};
fn freeRows(a: std.mem.Allocator, rows: Rows) void {
    inline for (std.meta.fields(Rows)) |field| a.free(@field(rows, field.name));
}
const Lists = struct {
    g_rows: std.ArrayList(group.g.Row) = .empty,
    xor_rows: std.ArrayList(group.xor.Row) = .empty,
    boundary_rows: std.ArrayList(group.boundary.Row) = .empty,
    route_rows: std.ArrayList(group.route.Row) = .empty,
    word_rows: std.ArrayList(word.Row) = .empty,
    select_rows: std.ArrayList(group.select.Row) = .empty,
    fn reserveHash(self: *Lists, a: std.mem.Allocator, counts: group.HashCounts) !group.HashDestination {
        try self.g_rows.ensureUnusedCapacity(a, counts.g);
        try self.xor_rows.ensureUnusedCapacity(a, counts.xor);
        return .{ .g_rows = self.g_rows.unusedCapacitySlice()[0..counts.g], .xor_rows = self.xor_rows.unusedCapacitySlice()[0..counts.xor] };
    }
    fn append(self: *Lists, a: std.mem.Allocator, rows: anytype) !void {
        inline for (.{ "boundary_rows", "route_rows", "word_rows", "select_rows" }) |name| try @field(self, name).appendSlice(a, @field(rows, name));
        self.g_rows.items.len += rows.g_rows.len;
        self.xor_rows.items.len += rows.xor_rows.len;
    }
    fn deinit(self: *Lists, a: std.mem.Allocator) void {
        inline for (std.meta.fields(Rows)) |field| @field(self, field.name).deinit(a);
    }
    fn finish(self: *Lists, a: std.mem.Allocator) !Rows {
        var out: Rows = undefined;
        inline for (std.meta.fields(Rows)) |field| @field(out, field.name) = &.{};
        errdefer freeRows(a, out);
        inline for (std.meta.fields(Rows)) |field| @field(out, field.name) = try @field(self, field.name).toOwnedSlice(a);
        return out;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    backing: std.mem.Allocator,
    live: Lists = .{},
    fixed: Lists = .{},
    next: u32 = 2_000_000,
    payload: u32 = 0,
    count: usize = 0,
    fn opening(self: *Builder, leaves: u32, words: u32, index: u32, depth: u32, root_index: usize, root: [32]u8, directions: []const group.select.Endpoint, values: []const M31, siblings: []const [32]u8) ![]const u32 {
        const span = try std.math.add(u32, try std.math.sub(u32, try std.math.mul(u32, leaves, 2), 1), try std.math.mul(u32, depth, 3));
        const end = try std.math.add(u32, self.next, span);
        if (end >= 3_000_000 or depth > 31) return error.InvalidStarkPathNamespace;
        const statement = group.Statement{ .namespace = self.next, .payload = .{ .circuit = 3_000_000, .first_wire = self.payload }, .leaf_count = leaves, .words_per_leaf = words, .index = index, .depth = @intCast(depth), .root = root, .root_source = try @import("blake3_root_sources.zig").caller(root_index), .directions = directions };
        const counts = try group.requiredHashRows(self.backing, statement);
        const live_destination = try self.live.reserveHash(self.backing, counts);
        const fixed_destination = try self.fixed.reserveHash(self.backing, counts);
        var live = try group.prepareInto(self.backing, statement, values, siblings, live_destination);
        defer live.deinit();
        if (!std.mem.eql(u8, &root, &live.computed_root.?)) return error.InvalidStarkPathRoot;
        var fixed = try group.trustedInto(self.backing, statement, fixed_destination);
        defer fixed.deinit();
        if (!std.mem.eql(u32, fixed.payload_uses, live.payload_uses)) return error.InvalidStarkPathReads;
        try self.live.append(self.backing, live);
        try self.fixed.append(self.backing, fixed);
        self.next = end;
        self.payload = try std.math.add(u32, self.payload, @intCast(values.len));
        self.count += 1;
        return self.a.dupe(u32, live.payload_uses);
    }
};
pub fn prepare(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared) !Prepared {
    const original_reads = try backing.alloc([31]u32, queries.queries.len);
    defer backing.free(original_reads);
    for (queries.queries, original_reads) |query, *saved| saved.* = query.path_uses;
    errdefer for (queries.queries, original_reads) |*query, saved| {
        query.path_uses = saved;
    };
    // This builder owns the complete path inventory, so successful replanning
    // replaces its read counts instead of accumulating a second copy.
    for (queries.queries) |*query| query.path_uses = @splat(0);
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var b = Builder{ .a = a, .backing = backing };
    defer b.live.deinit(backing);
    defer b.fixed.deinit(backing);
    var links = try inputs.Builder.init(a, capture, dg, fg, queries);
    defer links.deinit();
    const n = capture.queries.raw.len;
    if (capture.trace_paths.len != 4 or capture.commitments.len != 4 or capture.column_log_sizes.len != 4 or capture.fri.layers.len == 0) return error.InvalidStarkPathGeometry;
    const lifting = capture.fri.layers[0].path_depth + capture.fri.layers[0].fold_step;
    var cursor: usize = 0;
    for (capture.column_log_sizes, capture.trace_paths, capture.commitments, 0..) |logs, path, root, tree| {
        var geometry = try leaf.build(a, logs);
        defer geometry.deinit();
        const positions = try core.pcs.utils.prepareTreeQueryPositions(a, capture.queries.raw, lifting, geometry.max_log);
        if (!std.mem.eql(usize, positions, path.positions)) return error.InvalidStarkPathGeometry;
        if (geometry.max_log != path.path_depth) return error.InvalidStarkPathGeometry;
        const columns = try a.alloc([]const M31, logs.len);
        for (columns) |*column| {
            const end = try std.math.add(usize, cursor, n);
            if (end > capture.queried_values.len) return error.InvalidStarkPathValues;
            column.* = capture.queried_values[cursor..end];
            cursor = end;
        }
        try geometry.admitQueries(a, positions, columns);
        const query = try a.alloc(M31, columns.len);
        for (positions, 0..) |position, q| {
            for (query, columns) |*value, column| value.* = column[q];
            const ordered = try geometry.leaf(a, query);
            const payload = b.payload;
            const uses = try b.opening(1, @intCast(ordered.len), @intCast(position), path.path_depth, tree, root, try queries.traceDirections(a, q, lifting, geometry.max_log), ordered, path.path(q));
            for (geometry.order, ordered, uses, 0..) |column, value, count, i| try links.trace(tree, column, q, try geometry.columnIndex(column, @intCast(position)), value, try std.math.add(u32, payload, @intCast(i)), count);
        }
    }
    if (capture.queried_values.len != cursor) return error.InvalidStarkPathValues;
    for (capture.fri.layers, 0..) |layer, l| {
        const leaf_width: u32 = if (layer.fold_step > 1) 4 else 1;
        const values = try a.alloc(M31, layer.fold_width * 4);
        for (layer.positions, 0..) |position, q| {
            for (layer.queryValues(q), 0..) |value, i| values[i * 4 ..][0..4].* = value.toM31Array();
            const payload = b.payload;
            const uses = try b.opening(layer.fold_width / leaf_width, leaf_width * 4, @intCast(position >> @intCast(layer.fold_step)), layer.path_depth, capture.commitments.len + l, layer.commitment, try queries.directions(a, q, lifting - layer.path_depth, layer.path_depth), values, layer.queryPath(q));
            try links.friGroup(l, q, layer.queryValues(q), payload, uses);
        }
    }
    if ((4 + capture.fri.layers.len) * n != b.count) return error.InvalidStarkPathGeometry;
    const linked = try links.finish();
    try b.live.route_rows.appendSlice(backing, linked.projection.routed);
    try b.fixed.route_rows.appendSlice(backing, linked.projection.fixed_routed);
    try b.live.boundary_rows.appendSlice(backing, linked.sentinels);
    try b.fixed.boundary_rows.appendSlice(backing, linked.sentinels);
    const live_rows = try b.live.finish(backing);
    errdefer freeRows(backing, live_rows);
    const fixed_rows = try b.fixed.finish(backing);
    return .{ .arena = arena, .row_allocator = backing, .inputs = linked, .live = live_rows, .fixed = fixed_rows };
}
