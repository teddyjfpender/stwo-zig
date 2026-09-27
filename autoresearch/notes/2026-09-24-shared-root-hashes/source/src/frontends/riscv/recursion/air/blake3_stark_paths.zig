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
    /// Live hash metadata and main columns belong to the caller in this mode.
    hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    /// Owned trusted hash tails, independently derived from public path geometry.
    fixed_hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    inputs: inputs.Prepared,
    live: Rows,
    fixed: Rows,
    pub fn deinit(self: *Prepared) void {
        freeRows(self.row_allocator, self.live);
        freeRows(self.row_allocator, self.fixed);
        if (self.fixed_hash_metadata) |m| m.free(self.row_allocator);
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
        inline for (std.meta.fields(Rows)) |field| {
            @field(self, field.name).deinit(a);
        }
    }
    fn finish(self: *Lists, a: std.mem.Allocator) !Rows {
        var out: Rows = undefined;
        inline for (std.meta.fields(Rows)) |field| @field(out, field.name) = &.{};
        errdefer freeRows(a, out);
        inline for (std.meta.fields(Rows)) |field| {
            @field(out, field.name) = try @field(self, field.name).toOwnedSlice(a);
        }
        return out;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    backing: std.mem.Allocator,
    columns: ?group.MainColumns = null,
    fixed_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    g_used: usize = 0,
    xor_used: usize = 0,
    cache: *group.PlanCache,
    live: Lists = .{},
    fixed: Lists = .{},
    next: u32 = 2_000_000,
    payload: u32 = 0,
    count: usize = 0,
    shared_root_g_rows: usize = 0,
    profile_timer: ?std.time.Timer = null,
    profile_ns: [4]u64 = @splat(0),
    fn profileLap(self: *Builder, phase: usize) void {
        if (self.profile_timer) |*timer| self.profile_ns[phase] += timer.lap();
    }
    fn opening(self: *Builder, leaves: u32, words: u32, index: u32, depth: u32, root_index: usize, root: [32]u8, directions: []const group.select.Endpoint, values: []const M31, siblings: []const [32]u8, sharing: ?@import("blake3_shared_root_plan.zig").Sharing) ![]const u32 {
        const span = try std.math.add(u32, try std.math.sub(u32, try std.math.mul(u32, leaves, 2), 1), try std.math.mul(u32, depth, 3));
        const end = try std.math.add(u32, self.next, span);
        if (end >= 3_000_000 or depth > 31) return error.InvalidStarkPathNamespace;
        const statement = group.Statement{ .namespace = self.next, .payload = .{ .circuit = 3_000_000, .first_wire = self.payload }, .leaf_count = leaves, .words_per_leaf = words, .index = index, .depth = @intCast(depth), .root = root, .root_source = try @import("blake3_root_sources.zig").caller(root_index), .directions = directions, .shared_root = sharing };
        const counts = try group.requiredHashRowsCached(self.backing, statement, self.cache);
        if (sharing) |plan| {
            if (plan.query_index > 0) self.shared_root_g_rows += self.cache.node.?.g.len;
        }
        const live_destination = if (self.columns == null) try self.live.reserveHash(self.backing, counts) else group.HashDestination{ .g_rows = &.{}, .xor_rows = &.{} };
        const fixed_destination = if (self.fixed_metadata) |m| group.HashDestination{ .fixed = try m.slice(self.g_used, counts.g, self.xor_used, counts.xor) } else try self.fixed.reserveHash(self.backing, counts);
        self.profileLap(0);
        var live = if (self.columns) |out| try group.prepareMainColumnsCached(self.backing, statement, values, siblings, try out.slice(self.g_used, counts.g, self.xor_used, counts.xor), self.cache) else try group.prepareIntoCached(self.backing, statement, values, siblings, live_destination, self.cache);
        defer live.deinit();
        if (!std.mem.eql(u8, &root, &live.computed_root.?)) return error.InvalidStarkPathRoot;
        self.profileLap(1);
        var fixed = try group.trustedIntoCached(self.backing, statement, fixed_destination, self.cache);
        defer fixed.deinit();
        if (!std.mem.eql(u32, fixed.payload_uses, live.payload_uses)) return error.InvalidStarkPathReads;
        self.profileLap(2);
        try self.live.append(self.backing, live);
        self.g_used += counts.g;
        self.xor_used += counts.xor;
        try self.fixed.append(self.backing, fixed);
        self.profileLap(3);
        self.next = end;
        self.payload = try std.math.add(u32, self.payload, @intCast(values.len));
        self.count += 1;
        return self.a.dupe(u32, live.payload_uses);
    }
};
pub fn prepare(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared) !Prepared {
    return build(backing, capture, dg, fg, queries, null);
}
pub const MainColumns = group.MainColumns;
pub fn prepareMainColumns(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared, columns: MainColumns) !Prepared {
    return build(backing, capture, dg, fg, queries, columns);
}
fn build(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared, columns: ?MainColumns) !Prepared {
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
    var cache = group.PlanCache.init(backing);
    defer cache.deinit();
    var b = Builder{ .a = a, .backing = backing, .columns = columns, .cache = &cache };
    if (std.posix.getenv("STWO_RISCV_PARENT_PREPARATION_PROFILE") != null) b.profile_timer = std.time.Timer.start() catch null;
    errdefer if (b.fixed_metadata) |m| m.free(backing);
    if (columns) |out| {
        try out.validate(out.g_rows.metadata.len, out.xor_rows.metadata.len);
        b.fixed_metadata = try @import("blake3_hash_metadata.zig").Rows.allocate(backing, out.g_rows.metadata.len, out.xor_rows.metadata.len);
    }
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
        const query_columns = try a.alloc([]const M31, logs.len);
        for (query_columns) |*column| {
            const end = try std.math.add(usize, cursor, n);
            if (end > capture.queried_values.len) return error.InvalidStarkPathValues;
            column.* = capture.queried_values[cursor..end];
            cursor = end;
        }
        try geometry.admitQueries(a, positions, query_columns);
        const query = try a.alloc(M31, query_columns.len);
        const first_namespace = b.next;
        for (positions, 0..) |position, q| {
            for (query, query_columns) |*value, column| value.* = column[q];
            const ordered = try geometry.leaf(a, query);
            const payload = b.payload;
            const uses = try b.opening(1, @intCast(ordered.len), @intCast(position), path.path_depth, tree, root, try queries.traceDirections(a, q, lifting, geometry.max_log), ordered, path.path(q), if (n > 1 and path.path_depth > 0) .{ .first_namespace = first_namespace, .query_index = @intCast(q), .queries = @intCast(n) } else null);
            for (geometry.order, ordered, uses, 0..) |column, value, count, i| try links.trace(tree, column, q, try geometry.columnIndex(column, @intCast(position)), value, try std.math.add(u32, payload, @intCast(i)), count);
        }
    }
    if (capture.queried_values.len != cursor) return error.InvalidStarkPathValues;
    for (capture.fri.layers, 0..) |layer, l| {
        const leaf_width: u32 = if (layer.fold_step > 1) 4 else 1;
        const values = try a.alloc(M31, layer.fold_width * 4);
        const first_namespace = b.next;
        for (layer.positions, 0..) |position, q| {
            for (layer.queryValues(q), 0..) |value, i| values[i * 4 ..][0..4].* = value.toM31Array();
            const payload = b.payload;
            const uses = try b.opening(layer.fold_width / leaf_width, leaf_width * 4, @intCast(position >> @intCast(layer.fold_step)), layer.path_depth, capture.commitments.len + l, layer.commitment, try queries.directions(a, q, lifting - layer.path_depth, layer.path_depth), values, layer.queryPath(q), if (n > 1 and layer.path_depth > 0) .{ .first_namespace = first_namespace, .query_index = @intCast(q), .queries = @intCast(n) } else null);
            try links.friGroup(l, q, layer.queryValues(q), payload, uses);
        }
    }
    if ((4 + capture.fri.layers.len) * n != b.count) return error.InvalidStarkPathGeometry;
    if (std.posix.getenv("STWO_RISCV_PATH_SHARING_CENSUS") != null) try @import("blake3_path_sharing_census.zig").report(backing, capture, b.g_used, b.shared_root_g_rows);
    if (columns) |out| if (b.g_used != out.g_rows.metadata.len or b.xor_used != out.xor_rows.metadata.len) return error.InvalidBlake3WitnessDestination;
    const linked = try links.finish();
    try b.live.route_rows.appendSlice(backing, linked.projection.routed);
    try b.fixed.route_rows.appendSlice(backing, linked.projection.fixed_routed);
    try b.live.boundary_rows.appendSlice(backing, linked.sentinels);
    try b.fixed.boundary_rows.appendSlice(backing, linked.sentinels);
    if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE"))
        std.debug.print("BLAKE3_PATH_PLAN_REUSE openings={d} graph_builds={d} retained_plans={d}\n", .{ b.count, cache.builds, cache.retainedCount() });
    if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) if (b.fixed_metadata) |m| {
        const full_bytes = m.g_rows.len * @sizeOf(group.g.Row) + m.xor_rows.len * @sizeOf(group.xor.Row);
        const compact_bytes = std.mem.sliceAsBytes(m.g_rows).len + std.mem.sliceAsBytes(m.xor_rows).len;
        std.debug.print("BLAKE3_TRUSTED_PATH_METADATA full_row_bytes={d} compact_bytes={d} removed_bytes={d}\n", .{ full_bytes, compact_bytes, full_bytes - compact_bytes });
    };
    const live_rows = try b.live.finish(backing);
    errdefer freeRows(backing, live_rows);
    const fixed_rows = try b.fixed.finish(backing);
    b.profileLap(0);
    if (b.profile_timer != null) std.debug.print("PARENT_PATH_PREPARATION openings={d} other_ns={d} live_ns={d} trusted_ns={d} append_ns={d} thread={d}\n", .{ b.count, b.profile_ns[0], b.profile_ns[1], b.profile_ns[2], b.profile_ns[3], std.Thread.getCurrentId() });
    return .{ .fixed_hash_metadata = b.fixed_metadata, .hash_metadata = if (columns) |out| out.metadata() else null, .arena = arena, .row_allocator = backing, .inputs = linked, .live = live_rows, .fixed = fixed_rows };
}
