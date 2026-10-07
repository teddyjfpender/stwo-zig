//! All native STARK openings, linked to private arithmetic scalar sources.
const std = @import("std");
const Nonhash = @import("blake3_nonhash_emission_v1.zig");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const suite = @import("../blake3_engine_protocol.zig");
const group = @import("blake3_merkle_group_witness.zig");
const inputs = @import("blake3_opening_inputs.zig");
const frontier = @import("blake3_two_level_frontier.zig");
const discovery = @import("blake3_frontier_capture.zig");
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
    nonhash: ?Nonhash.Owner = null,
    nonhash_fixed: ?Nonhash.FixedOwner = null,
    live: Rows,
    fixed: Rows,
    pub fn appendCohort(self: *const Prepared, comptime slot: usize, target: anytype) !void {
        if (self.nonhash) |*owner| {
            if (self.nonhash_fixed == null or self.live.boundary_rows.len != 0 or self.live.route_rows.len != 0 or self.live.word_rows.len != 0 or self.live.select_rows.len != 0 or self.fixed.boundary_rows.len != 0 or self.fixed.route_rows.len != 0 or self.fixed.word_rows.len != 0 or self.fixed.select_rows.len != 0) return error.InvalidNativeParentRows;
            try owner.appendTrusted(slot, &self.nonhash_fixed.?, target);
        } else {
            if (self.nonhash_fixed != null) return error.InvalidNativeParentRows;
            switch (slot) {
                2 => try target.append(2, self.live.boundary_rows, self.fixed.boundary_rows),
                7 => try target.append(7, self.live.route_rows, self.fixed.route_rows),
                9 => try target.append(9, self.live.word_rows, self.fixed.word_rows),
                13 => try target.append(13, self.live.select_rows, self.fixed.select_rows),
                else => @compileError("invalid path nonhash cohort"),
            }
        }
    }
    pub fn deinit(self: *Prepared) void {
        self.inputs.deinitColumns();
        if (self.nonhash) |*owner| owner.deinit();
        if (self.nonhash_fixed) |*owner| owner.deinit();
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
    count_only: bool = false,
    live_sink: ?Nonhash.Sink = null,
    fixed_sink: ?Nonhash.Sink = null,
    fixed_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    g_used: usize = 0,
    xor_used: usize = 0,
    cache: *group.PlanCache,
    live: Lists = .{},
    fixed: Lists = .{},
    next: u32 = 2_000_000,
    payload: u32 = 0,
    count: usize = 0,
    shared_path_g_rows: usize = 0,
    profile_timer: ?std.time.Timer = null,
    profile_ns: [4]u64 = @splat(0),
    fn profileLap(self: *Builder, phase: usize) void {
        if (self.profile_timer) |*timer| self.profile_ns[phase] += timer.lap();
    }
    fn beginFrontier(self: *Builder, openings: []const discovery.Opening, root_index: usize, root: [32]u8) !?frontier.Context {
        if (openings.len < 2 or openings[0].siblings.len < 2) return null;
        const plan = frontier.Plan{ .namespace = self.next, .queries = @intCast(openings.len), .root_source = try @import("blake3_root_sources.zig").caller(root_index) };
        // The count pass needs only authenticated public topology. Private
        // discovery and root agreement run exactly once in the live pass.
        const context = if (self.count_only) frontier.Context{ .plan = plan, .witness = frontier.empty_witness } else try discovery.collect(self.backing, plan, openings, root);
        self.next = try std.math.add(u32, self.next, try std.math.add(u32, 7, plan.queries));
        if (self.next >= 3_000_000) return error.InvalidStarkPathNamespace;
        const len = try (core.channel.blake3.Frame{ .node = .{ .left = @splat(0), .right = @splat(0) } }).encodedSize();
        const plans = try self.cache.get(len);
        const counts = group.HashCounts{ .g = 3 * plans.node.g.len, .xor = 3 * plans.node.xor.len };
        if (self.count_only) {
            const metadata = if (self.fixed_metadata) |m| try m.slice(self.g_used, counts.g, self.xor_used, counts.xor) else try @import("blake3_hash_metadata.zig").Rows.allocate(self.backing, counts.g, counts.xor);
            defer if (self.fixed_metadata == null) metadata.free(self.backing);
            var shape = try frontier.emitWithPlanEmitting(self.backing, context, false, .{ .fixed = metadata }, null, plans.node, self.fixed_sink.?);
            defer shape.deinit();
            self.g_used += counts.g;
            self.xor_used += counts.xor;
            return context;
        }
        const destination: ?group.HashDestination = if (self.columns == null) try self.live.reserveHash(self.backing, counts) else null;
        const columns: ?group.MainColumns = if (self.columns) |out| try out.slice(self.g_used, counts.g, self.xor_used, counts.xor) else null;
        var live = if (self.live_sink) |sink| try frontier.emitWithPlanEmitting(self.backing, context, true, destination, columns, plans.node, sink) else try frontier.emitWithPlan(self.backing, context, true, destination, columns, plans.node);
        defer live.deinit();
        if (!std.mem.eql(u8, &live.root, &root)) return error.InvalidStarkPathRoot;
        const fixed_destination = if (self.fixed_metadata) |m| group.HashDestination{ .fixed = try m.slice(self.g_used, counts.g, self.xor_used, counts.xor) } else try self.fixed.reserveHash(self.backing, counts);
        var fixed = if (self.fixed_sink) |sink| try frontier.emitWithPlanEmitting(self.backing, context, false, fixed_destination, null, plans.node, sink) else try frontier.emitWithPlan(self.backing, context, false, fixed_destination, null, plans.node);
        defer fixed.deinit();
        try self.live.append(self.backing, live);
        try self.fixed.append(self.backing, fixed);
        self.g_used += counts.g;
        self.xor_used += counts.xor;
        self.shared_path_g_rows += (2 * openings.len - 3) * plans.node.g.len;
        return context;
    }
    fn opening(self: *Builder, leaves: u32, words: u32, index: u32, depth: u32, root_index: usize, root: [32]u8, directions: []const group.select.Endpoint, values: []const M31, siblings: []const [32]u8, sharing: ?@import("blake3_shared_root_plan.zig").Sharing, frontier_use: ?frontier.Use) ![]const u32 {
        const span = try std.math.add(u32, try std.math.sub(u32, try std.math.mul(u32, leaves, 2), 1), try std.math.mul(u32, depth, 3));
        const end = try std.math.add(u32, self.next, span);
        if (end >= 3_000_000 or depth > 31) return error.InvalidStarkPathNamespace;
        const statement = group.Statement{ .namespace = self.next, .payload = .{ .circuit = 3_000_000, .first_wire = self.payload }, .leaf_count = leaves, .words_per_leaf = words, .index = index, .depth = @intCast(depth), .root = root, .root_source = try @import("blake3_root_sources.zig").caller(root_index), .directions = directions, .shared_root = sharing, .frontier = frontier_use };
        const counts = try group.requiredHashRowsCached(self.backing, statement, self.cache);
        if (sharing) |plan| {
            if (plan.query_index > 0) self.shared_path_g_rows += self.cache.node.?.g.len;
        }
        if (self.count_only) {
            const metadata = if (self.fixed_metadata) |m| try m.slice(self.g_used, counts.g, self.xor_used, counts.xor) else try @import("blake3_hash_metadata.zig").Rows.allocate(self.backing, counts.g, counts.xor);
            defer if (self.fixed_metadata == null) metadata.free(self.backing);
            var shape = try group.prepareEmittingCached(self.backing, statement, null, null, .{ .fixed = metadata }, null, self.cache, self.fixed_sink.?);
            defer shape.deinit();
            self.g_used += counts.g;
            self.xor_used += counts.xor;
            self.next = end;
            self.payload = try std.math.add(u32, self.payload, @intCast(values.len));
            self.count += 1;
            return self.a.dupe(u32, shape.payload_uses);
        }
        const live_destination = if (self.columns == null) try self.live.reserveHash(self.backing, counts) else group.HashDestination{ .g_rows = &.{}, .xor_rows = &.{} };
        const fixed_destination = if (self.fixed_metadata) |m| group.HashDestination{ .fixed = try m.slice(self.g_used, counts.g, self.xor_used, counts.xor) } else try self.fixed.reserveHash(self.backing, counts);
        self.profileLap(0);
        var live = if (self.live_sink) |sink| try group.prepareEmittingCached(self.backing, statement, values, siblings, if (self.columns != null) null else live_destination, if (self.columns) |out| try out.slice(self.g_used, counts.g, self.xor_used, counts.xor) else null, self.cache, sink) else if (self.columns) |out| try group.prepareMainColumnsCached(self.backing, statement, values, siblings, try out.slice(self.g_used, counts.g, self.xor_used, counts.xor), self.cache) else try group.prepareIntoCached(self.backing, statement, values, siblings, live_destination, self.cache);
        defer live.deinit();
        if (!std.mem.eql(u8, &root, &live.computed_root.?)) return error.InvalidStarkPathRoot;
        self.profileLap(1);
        var fixed = if (self.fixed_sink) |sink| try group.prepareEmittingCached(self.backing, statement, null, null, fixed_destination, null, self.cache, sink) else try group.trustedIntoCached(self.backing, statement, fixed_destination, self.cache);
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
    return build(true, backing, capture, dg, fg, queries, null);
}
/// Explicit dense-source parity oracle.
pub fn prepareRows(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared) !Prepared {
    return build(false, backing, capture, dg, fg, queries, null);
}
pub const MainColumns = group.MainColumns;
pub fn prepareMainColumns(backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared, columns: MainColumns) !Prepared {
    return build(true, backing, capture, dg, fg, queries, columns);
}
fn build(comptime direct: bool, backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared, columns: ?MainColumns) !Prepared {
    if (!direct) return (try buildMode(false, backing, capture, dg, fg, queries, columns, null, null, false)).?;
    const saved = try backing.alloc([31]u32, queries.queries.len);
    defer backing.free(saved);
    for (queries.queries, saved) |query, *out| out.* = query.path_uses;
    errdefer for (queries.queries, saved) |*query, original| {
        query.path_uses = original;
    };
    var counts = Nonhash.Counts{};
    _ = try buildMode(true, backing, capture, dg, fg, queries, null, null, counts.sink(), true);
    for (queries.queries, saved) |*query, original| query.path_uses = original;
    var live = try Nonhash.Owner.init(backing, counts);
    errdefer live.deinit();
    var fixed = try Nonhash.FixedOwner.init(backing, counts);
    errdefer fixed.deinit();
    var result = (try buildMode(true, backing, capture, dg, fg, queries, columns, live.sink(), fixed.sink(), false)).?;
    errdefer result.deinit();
    try live.finish();
    try fixed.finish();
    result.nonhash = live;
    result.nonhash_fixed = fixed;
    return result;
}

/// Separate fixed-only setup artifact. Contains no capture, private sibling,
/// query value, root agreement or opening-input receipt.
/// Exact original opening source coordinates, retained by trusted shape emission.
/// Trees 0..3 are original trace trees; 4+layer are original FRI trees.
/// Uses are original hash DAG payload reads, never private values/positions.
pub const FixedOpening = struct { tree: usize, query: usize, payload: u32, uses: []u32 };
pub const FixedShape = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    metadata: @import("blake3_hash_metadata.zig").Rows,
    nonhash: Nonhash.FixedOwner,
    shape_id: [32]u8,
    openings: usize,
    input_routes: []FixedOpening,
    pub fn deinit(self: *FixedShape) void {
        const lease = self.allocation_owner;
        self.nonhash.deinit();
        for (self.input_routes) |route| self.allocator.free(route.uses);
        self.allocator.free(self.input_routes);
        self.metadata.free(self.allocator);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
/// Independently selected commitment inventory; the original parent stays four.
/// Native PAGE supplies its actual ten-tree profile, never a parent Shape.
pub fn compileFixedProfile(comptime commitments: usize, backing: std.mem.Allocator, shape: anytype, queries: *@import("blake3_query_links.zig").Prepared) !FixedShape {
    if (commitments != 4 and commitments != 10) @compileError("fixed STARK paths require an admitted four/ten commitment profile");
    if (@typeInfo(@TypeOf(shape.columns)).array.len != commitments) @compileError("fixed STARK commitment inventory mismatch");
    try shape.validate();
    if (queries.queries.len != shape.config.fri_config.n_queries) return error.InvalidStarkPathGeometry;
    const saved = try backing.alloc([31]u32, queries.queries.len);
    defer backing.free(saved);
    for (queries.queries, saved) |query, *out| out.* = query.path_uses;
    errdefer for (queries.queries, saved) |*query, original| {
        query.path_uses = original;
    };
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    var counts = Nonhash.Counts{};
    const census = try emitFixedShape(commitments, backing, shape, queries, counts.sink(), null, null);
    for (queries.queries, saved) |*query, original| query.path_uses = original;
    var nonhash = try Nonhash.FixedOwner.init(backing, counts);
    errdefer nonhash.deinit();
    const metadata = try @import("blake3_hash_metadata.zig").Rows.allocate(backing, census.g, census.xor);
    errdefer metadata.free(backing);
    const input_routes = try backing.alloc(FixedOpening, census.openings);
    for (input_routes) |*route| route.* = .{ .tree = 0, .query = 0, .payload = 0, .uses = &.{} };
    errdefer {
        for (input_routes) |route| backing.free(route.uses);
        backing.free(input_routes);
    }
    const emitted = try emitFixedShape(commitments, backing, shape, queries, nonhash.sink(), metadata, input_routes);
    if (!std.meta.eql(census, emitted)) return error.InvalidStarkPathGeometry;
    try nonhash.finish();
    return .{ .allocator = backing, .allocation_owner = lease, .metadata = metadata, .nonhash = nonhash, .shape_id = shape.seal, .openings = emitted.openings, .input_routes = input_routes };
}
const ShapeCounts = struct { g: usize, xor: usize, openings: usize };
fn emitFixedShape(comptime commitments: usize, backing: std.mem.Allocator, shape: anytype, queries: *@import("blake3_query_links.zig").Prepared, sink: Nonhash.Sink, metadata: ?@import("blake3_hash_metadata.zig").Rows, input_routes: ?[]FixedOpening) !ShapeCounts {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    var cache = group.PlanCache.init(backing);
    defer cache.deinit();
    var b = Builder{ .a = a, .backing = backing, .cache = &cache, .count_only = true, .fixed_sink = sink, .fixed_metadata = metadata };
    defer b.live.deinit(backing);
    defer b.fixed.deinit(backing);
    const n = shape.config.fri_config.n_queries;
    for (shape.columns, 0..) |logs, tree| {
        var geometry = try leaf.build(a, logs);
        defer geometry.deinit();
        const count_only_values = try a.alloc(M31, logs.len);
        @memset(count_only_values, M31.zero());
        const count_only_siblings = try a.alloc([32]u8, geometry.max_log);
        @memset(count_only_siblings, @splat(0));
        const openings = try a.alloc(discovery.Opening, n);
        for (openings, 0..) |*opening, q| opening.* = .{ .leaves = 1, .words = @intCast(logs.len), .index = 0, .values = count_only_values, .siblings = count_only_siblings, .directions = try queries.traceDirections(a, q, shape.lifting_log, geometry.max_log) };
        const shared_frontier = try b.beginFrontier(openings, tree, @splat(0));
        const first_namespace = b.next;
        for (openings, 0..) |opening, q| {
            if (shared_frontier != null) try queries.addPathUses(q, shape.lifting_log - 1, 9);
            const payload = b.payload;
            const ordinal = b.count;
            const uses = try b.opening(opening.leaves, opening.words, 0, geometry.max_log, tree, @splat(0), opening.directions, opening.values, opening.siblings, if (shared_frontier == null and n > 1 and geometry.max_log > 0) .{ .first_namespace = first_namespace, .query_index = @intCast(q), .queries = @intCast(n) } else null, if (shared_frontier) |*context| .{ .context = context, .query = @intCast(q) } else null);
            if (input_routes) |out| {
                if (ordinal >= out.len or uses.len != logs.len) return error.InvalidStarkPathGeometry;
                out[ordinal] = .{ .tree = tree, .query = q, .payload = payload, .uses = try backing.dupe(u32, uses) };
            }
        }
    }
    var remaining = shape.lifting_log;
    for (shape.widths, 0..) |width, layer| {
        const fold_step = std.math.log2_int(u32, width);
        const depth = remaining - fold_step;
        const leaf_width: u32 = if (fold_step > 1) 4 else 1;
        const count_only_values = try a.alloc(M31, width * 4);
        @memset(count_only_values, M31.zero());
        const count_only_siblings = try a.alloc([32]u8, depth);
        @memset(count_only_siblings, @splat(0));
        const openings = try a.alloc(discovery.Opening, n);
        for (openings, 0..) |*opening, q| opening.* = .{ .leaves = width / leaf_width, .words = leaf_width * 4, .index = 0, .values = count_only_values, .siblings = count_only_siblings, .directions = try queries.directions(a, q, shape.lifting_log - depth, depth) };
        const root_index = commitments + layer;
        const shared_frontier = try b.beginFrontier(openings, root_index, @splat(0));
        const first_namespace = b.next;
        for (openings, 0..) |opening, q| {
            if (shared_frontier != null) try queries.addPathUses(q, shape.lifting_log - 1, 9);
            const payload = b.payload;
            const ordinal = b.count;
            const uses = try b.opening(opening.leaves, opening.words, 0, depth, root_index, @splat(0), opening.directions, opening.values, opening.siblings, if (shared_frontier == null and n > 1 and depth > 0) .{ .first_namespace = first_namespace, .query_index = @intCast(q), .queries = @intCast(n) } else null, if (shared_frontier) |*context| .{ .context = context, .query = @intCast(q) } else null);
            if (input_routes) |out| {
                if (ordinal >= out.len or uses.len != width * 4) return error.InvalidStarkPathGeometry;
                out[ordinal] = .{ .tree = root_index, .query = q, .payload = payload, .uses = try backing.dupe(u32, uses) };
            }
        }
        remaining = depth;
    }
    if (b.count != try std.math.mul(usize, commitments + shape.widths.len, n)) return error.InvalidStarkPathGeometry;
    if (metadata) |out| try out.validate(b.g_used, b.xor_used);
    return .{ .g = b.g_used, .xor = b.xor_used, .openings = b.count };
}
fn buildMode(comptime direct: bool, backing: std.mem.Allocator, capture: *const Capture, dg: *const @import("pcs_deep_circuit.zig").Circuit, fg: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared, columns: ?MainColumns, live_sink: ?Nonhash.Sink, fixed_sink: ?Nonhash.Sink, count_only: bool) !?Prepared {
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
    var scratch = std.heap.ArenaAllocator.init(backing);
    defer scratch.deinit();
    const a = if (direct) scratch.allocator() else arena.allocator();
    const output = arena.allocator();
    var cache = group.PlanCache.init(backing);
    defer cache.deinit();
    var b = Builder{ .a = a, .backing = backing, .columns = columns, .cache = &cache, .count_only = count_only, .live_sink = live_sink, .fixed_sink = fixed_sink };
    if (std.posix.getenv("STWO_RISCV_PARENT_PREPARATION_PROFILE") != null) b.profile_timer = std.time.Timer.start() catch null;
    errdefer if (b.fixed_metadata) |m| m.free(backing);
    if (columns) |out| {
        try out.validate(out.g_rows.metadata.len, out.xor_rows.metadata.len);
        b.fixed_metadata = try @import("blake3_hash_metadata.zig").Rows.allocate(backing, out.g_rows.metadata.len, out.xor_rows.metadata.len);
    }
    defer b.live.deinit(backing);
    defer b.fixed.deinit(backing);
    var links: ?inputs.Builder = if (count_only) null else if (direct) try inputs.Builder.initColumns(a, output, backing, capture, dg, fg, queries) else try inputs.Builder.init(a, capture, dg, fg, queries);
    defer if (links) |*owner| owner.deinit();
    const n = capture.queries.raw.len;
    if ((capture.commitments.len != 4 and capture.commitments.len != 5) or capture.trace_paths.len != capture.commitments.len or capture.column_log_sizes.len != capture.commitments.len or capture.fri.layers.len == 0) return error.InvalidStarkPathGeometry;
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
        const openings = try a.alloc(discovery.Opening, positions.len);
        for (positions, openings, 0..) |position, *opening, q| {
            for (query, query_columns) |*value, column| value.* = column[q];
            opening.* = .{ .leaves = 1, .words = @intCast(query.len), .index = @intCast(position), .values = try geometry.leaf(a, query), .siblings = path.path(q), .directions = try queries.traceDirections(a, q, lifting, geometry.max_log) };
        }
        const shared_frontier = try b.beginFrontier(openings, tree, root);
        const first_namespace = b.next;
        for (openings, 0..) |opening, q| {
            const payload = b.payload;
            if (shared_frontier != null) try queries.addPathUses(q, lifting - 1, 9);
            const uses = try b.opening(opening.leaves, opening.words, opening.index, path.path_depth, tree, root, opening.directions, opening.values, opening.siblings, if (shared_frontier == null and n > 1 and path.path_depth > 0) .{ .first_namespace = first_namespace, .query_index = @intCast(q), .queries = @intCast(n) } else null, if (shared_frontier) |*context| .{ .context = context, .query = @intCast(q) } else null);
            if (links) |*owner| for (geometry.order, opening.values, uses, 0..) |column, value, count, i| try owner.trace(tree, column, q, try geometry.columnIndex(column, opening.index), value, try std.math.add(u32, payload, @intCast(i)), count);
        }
    }
    if (capture.queried_values.len != cursor) return error.InvalidStarkPathValues;
    for (capture.fri.layers, 0..) |layer, l| {
        const leaf_width: u32 = if (layer.fold_step > 1) 4 else 1;
        const openings = try a.alloc(discovery.Opening, layer.positions.len);
        for (layer.positions, openings, 0..) |position, *opening, q| {
            const values = try a.alloc(M31, layer.fold_width * 4);
            for (layer.queryValues(q), 0..) |value, i| values[i * 4 ..][0..4].* = value.toM31Array();
            opening.* = .{ .leaves = layer.fold_width / leaf_width, .words = leaf_width * 4, .index = @intCast(position >> @intCast(layer.fold_step)), .values = values, .siblings = layer.queryPath(q), .directions = try queries.directions(a, q, lifting - layer.path_depth, layer.path_depth) };
        }
        const shared_frontier = try b.beginFrontier(openings, capture.commitments.len + l, layer.commitment);
        const first_namespace = b.next;
        for (openings, 0..) |opening, q| {
            const payload = b.payload;
            if (shared_frontier != null) try queries.addPathUses(q, lifting - 1, 9);
            const uses = try b.opening(opening.leaves, opening.words, opening.index, layer.path_depth, capture.commitments.len + l, layer.commitment, opening.directions, opening.values, opening.siblings, if (shared_frontier == null and n > 1 and layer.path_depth > 0) .{ .first_namespace = first_namespace, .query_index = @intCast(q), .queries = @intCast(n) } else null, if (shared_frontier) |*context| .{ .context = context, .query = @intCast(q) } else null);
            if (links) |*owner| try owner.friGroup(l, q, layer.queryValues(q), payload, uses);
        }
    }
    const trees = try std.math.add(usize, capture.commitments.len, capture.fri.layers.len);
    if (try std.math.mul(usize, trees, n) != b.count) return error.InvalidStarkPathGeometry;
    if (count_only) {
        arena.deinit();
        return null;
    }
    if (std.posix.getenv("STWO_RISCV_PATH_SHARING_CENSUS") != null) try @import("blake3_path_sharing_census.zig").report(backing, capture, b.g_used, b.shared_path_g_rows);
    if (columns) |out| if (b.g_used != out.g_rows.metadata.len or b.xor_used != out.xor_rows.metadata.len) return error.InvalidBlake3WitnessDestination;
    var linked = try links.?.finish();
    errdefer linked.deinitColumns();
    if (!direct) {
        try b.live.route_rows.appendSlice(backing, linked.projection.routed);
        try b.fixed.route_rows.appendSlice(backing, linked.projection.fixed_routed);
        try b.live.boundary_rows.appendSlice(backing, linked.sentinels);
        try b.fixed.boundary_rows.appendSlice(backing, linked.sentinels);
    }
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
