//! Private frontier witness construction. Only distinct touched chunks are
//! opened; unchanged subtrees are reused from the authenticated BEFORE graph.
//! This native builder is NOT receiver authority or a continuation proof.
const std = @import("std");
const core = @import("stwo_core");
const values = @import("values.zig");
const graph = @import("graph_model.zig");
const policy = @import("policy.zig");
pub const MAX_OPENINGS = values.MAX_LEAVES;
pub const Opening = struct {
    index: u64,
    before: []const u64,
    after: []const u64,
    terminal_clocks: []const u32,
    rights: []const u2, // R=1 W=2. Untouched holes may carry zero rights.
};
pub const Counts = struct {
    leaves: usize,
    changed_leaves: usize,
    before_nodes: usize,
    after_nodes: usize,
    sides: usize,
    pub fn permutations(self: Counts, geometry: values.Geometry) !usize {
        return try std.math.add(usize, try std.math.mul(usize, try std.math.add(usize, self.leaves, self.changed_leaves), geometry.permutations()), try std.math.mul(usize, try std.math.add(usize, self.before_nodes, self.after_nodes), 4));
    }
};
const Scan = struct { index: u64, changed: bool };
fn changed(opening: Opening) bool {
    return !std.mem.eql(u64, opening.before, opening.after);
}
pub fn validate(geometry: values.Geometry, openings: []const Opening) !void {
    return validateMode(geometry, openings, false);
}
/// A root observation is read-only and creates NO timestamped RAM event.
pub fn validateObservation(geometry: values.Geometry, openings: []const Opening) !void {
    try validateMode(geometry, openings, true);
    for (openings) |opening| for (opening.before, opening.after, opening.terminal_clocks) |before, after, clock| if (before != after or clock != 0) return error.InvalidPrivateRamObservation;
}
fn validateMode(geometry: values.Geometry, openings: []const Opening, allow_untouched: bool) !void {
    if (openings.len == 0 or openings.len > MAX_OPENINGS) return error.InvalidPrivateRamBatch;
    for (openings, 0..) |opening, i| {
        if (opening.index >= @as(u64, 1) << geometry.depth() or (i > 0 and openings[i - 1].index >= opening.index) or opening.before.len != geometry.cells() or opening.after.len != geometry.cells() or opening.terminal_clocks.len != geometry.cells() or opening.rights.len != geometry.cells()) return error.InvalidPrivateRamBatch;
        var touched = false;
        for (opening.before, opening.after, opening.terminal_clocks, opening.rights) |before, after, clock, rights| {
            if (clock >= 1 << 24 or (clock == 0 and before != after) or (clock != 0 and rights == 0)) return error.InvalidPrivateRamBatch;
            touched = touched or clock != 0;
        }
        if (!touched and !allow_untouched) return error.UntouchedPrivateRamOpening;
    }
}
/// Geometry census uses only indices and exact native net-change comparison;
/// no sponge call is run before the final provider arena is allocated.
pub fn count(a: std.mem.Allocator, geometry: values.Geometry, openings: []const Opening) !Counts {
    try validate(geometry, openings);
    return countValidated(a, geometry, openings, null);
}
pub fn countObservation(a: std.mem.Allocator, geometry: values.Geometry, openings: []const Opening) !Counts {
    try validateObservation(geometry, openings);
    return countValidated(a, geometry, openings, null);
}
pub fn countPrepared(a: std.mem.Allocator, geometry: values.Geometry, openings: []const Opening, changes: []bool, observation: bool) !Counts {
    if (changes.len != openings.len) return error.InvalidPreparedRamCounts;
    if (observation) try validateObservation(geometry, openings) else try validate(geometry, openings);
    return countValidated(a, geometry, openings, changes);
}
fn countValidated(a: std.mem.Allocator, geometry: values.Geometry, openings: []const Opening, changes: ?[]bool) !Counts {
    const frontier = try a.alloc(Scan, openings.len);
    defer a.free(frontier);
    var result = Counts{ .leaves = openings.len, .changed_leaves = 0, .before_nodes = 0, .after_nodes = 0, .sides = 0 };
    for (frontier, openings, 0..) |*entry, opening, i| {
        entry.* = .{ .index = opening.index, .changed = changed(opening) };
        result.changed_leaves += @intFromBool(entry.changed);
        if (changes) |flags| flags[i] = entry.changed;
    }
    var used = frontier.len;
    for (0..geometry.depth()) |_| {
        var read: usize = 0;
        var write: usize = 0;
        while (read < used) {
            const first = frontier[read];
            read += 1;
            var any_changed = first.changed;
            if (read < used and frontier[read].index >> 1 == first.index >> 1) {
                any_changed = any_changed or frontier[read].changed;
                read += 1;
            } else result.sides += 1;
            result.before_nodes += 1;
            result.after_nodes += @intFromBool(any_changed);
            frontier[write] = .{ .index = first.index >> 1, .changed = any_changed };
            write += 1;
        }
        used = write;
    }
    if (result.before_nodes + result.after_nodes + result.leaves + result.sides > graph.MAX_RECORDS) return error.PrivateRamBatchResourceLimit;
    return result;
}
pub const Leaf = struct { graph: graph.Leaf, before_id: u32, after_id: u32, before_io: u32, after_io: u32 };
pub const Node = struct { graph: graph.Node, io: u32 };
const Frontier = struct { index: u64, before: values.Digest, after: values.Digest, changed: bool, leaf: bool, source: usize };
pub const Witness = struct {
    allocator: std.mem.Allocator,
    geometry: values.Geometry,
    before: values.Digest,
    after: values.Digest,
    leaves: []Leaf,
    before_nodes: []Node,
    after_nodes: []Node,
    sides: []graph.Side,
    patches: []values.Patch,
    pub fn init(a: std.mem.Allocator, cache: *const values.Cache, openings: []const Opening, recorder: *values.Recorder) !Witness {
        return initMode(a, cache, openings, recorder, false, null);
    }
    pub fn initObservation(a: std.mem.Allocator, cache: *const values.Cache, openings: []const Opening, recorder: *values.Recorder) !Witness {
        return initMode(a, cache, openings, recorder, true, null);
    }
    const PreparedCounts = struct { counts: Counts, changes: []const bool };
    pub fn initPrepared(a: std.mem.Allocator, cache: *const values.Cache, openings: []const Opening, recorder: *values.Recorder, counts: Counts, changes: []const bool) !Witness {
        if (counts.leaves == 0 or counts.leaves > MAX_OPENINGS or counts.leaves != openings.len or changes.len != openings.len) return error.InvalidPreparedRamCounts;
        try validateMode(cache.geometry, openings, true);
        for (openings, changes) |opening, flag| if (changed(opening) != flag) return error.InvalidPreparedRamCounts;
        const records = try std.math.add(usize, try std.math.add(usize, counts.before_nodes, counts.after_nodes), try std.math.add(usize, counts.leaves, counts.sides));
        if (records > graph.MAX_RECORDS or counts.changed_leaves > counts.leaves) return error.PrivateRamBatchResourceLimit;
        return initMode(a, cache, openings, recorder, false, .{ .counts = counts, .changes = changes });
    }
    fn initMode(a: std.mem.Allocator, cache: *const values.Cache, openings: []const Opening, recorder: *values.Recorder, observation: bool, prepared: ?PreparedCounts) !Witness {
        const geometry = cache.geometry;
        const counts = if (prepared) |p| p.counts else try if (observation) countObservation(a, geometry, openings) else count(a, geometry, openings);
        const expected_calls = try counts.permutations(geometry);
        if (recorder.calls.items.len > std.math.maxInt(u32) - expected_calls) return error.PrivateRamBatchResourceLimit;
        try recorder.calls.ensureUnusedCapacity(a, expected_calls);
        const leaves = try a.alloc(Leaf, counts.leaves);
        errdefer a.free(leaves);
        const before_nodes = try a.alloc(Node, counts.before_nodes);
        errdefer a.free(before_nodes);
        const after_nodes = try a.alloc(Node, counts.after_nodes);
        errdefer a.free(after_nodes);
        const sides = try a.alloc(graph.Side, counts.sides);
        errdefer a.free(sides);
        const patches = try a.alloc(values.Patch, counts.changed_leaves + counts.after_nodes);
        errdefer a.free(patches);
        const frontier = try a.alloc(Frontier, openings.len);
        defer a.free(frontier);
        var after_id: u32 = @intCast(openings.len);
        var patch_at: usize = 0;
        // Message IDs must be contiguous. BEFORE messages come first; changed
        // AFTER messages follow. Record leaf references without a second hash.
        for (leaves, frontier, openings, 0..) |*leaf, *entry, opening, i| {
            const io: u32 = @intCast(recorder.calls.items.len);
            const digest = try values.hashValues(geometry, opening.before, recorder);
            if (!values.equal(digest, try cache.get(0, opening.index))) return error.PrivateRamBeforeRootMismatch;
            leaf.* = .{ .graph = .{ .index = opening.index, .before = digest, .after = digest, .changed = if (prepared) |p| p.changes[i] else changed(opening) }, .before_id = @intCast(i), .after_id = 0, .before_io = io, .after_io = 0 };
            entry.* = .{ .index = opening.index, .before = digest, .after = digest, .changed = leaf.graph.changed, .leaf = true, .source = i };
        }
        for (leaves, frontier, openings) |*leaf, *entry, opening| {
            if (!leaf.graph.changed) continue;
            leaf.after_id = after_id;
            after_id += 1;
            leaf.after_io = @intCast(recorder.calls.items.len);
            leaf.graph.after = try values.hashValues(geometry, opening.after, recorder);
            entry.after = leaf.graph.after;
            if (patch_at >= patches.len) return error.InvalidPreparedRamCounts;
            patches[patch_at] = .{ .height = 0, .index = opening.index, .before = leaf.graph.before, .after = leaf.graph.after };
            patch_at += 1;
        }
        var before_at: usize = 0;
        var after_at: usize = 0;
        var side_at: usize = 0;
        var used = frontier.len;
        for (0..geometry.depth()) |h| {
            var read: usize = 0;
            var write: usize = 0;
            while (read < used) {
                const first = frontier[read];
                read += 1;
                var second: ?Frontier = null;
                if (read < used and frontier[read].index >> 1 == first.index >> 1) {
                    second = frontier[read];
                    read += 1;
                }
                const any_changed = first.changed or (if (second) |entry| entry.changed else false);
                const parent_index = first.index >> 1;
                var left = try cache.get(@intCast(h), 2 * parent_index);
                var right = try cache.get(@intCast(h), 2 * parent_index + 1);
                var after_left = left;
                var after_right = right;
                if (first.index & 1 == 0) {
                    left = first.before;
                    after_left = first.after;
                } else {
                    right = first.before;
                    after_right = first.after;
                }
                if (second) |entry| {
                    right = entry.before;
                    after_right = entry.after;
                }
                if (any_changed and !first.changed) markReuse(leaves, before_nodes, first);
                if (second) |entry| {
                    if (any_changed and !entry.changed) markReuse(leaves, before_nodes, entry);
                } else {
                    if (side_at >= sides.len) return error.InvalidPreparedRamCounts;
                    sides[side_at] = .{ .height = @intCast(h), .index = first.index ^ 1, .digest = if (first.index & 1 == 0) right else left, .reuse = any_changed };
                    side_at += 1;
                }
                const before_io: u32 = @intCast(recorder.calls.items.len);
                const before_digest = try values.hashNode(geometry, @intCast(h), left, right, recorder);
                if (!values.equal(before_digest, try cache.get(@intCast(h + 1), parent_index))) return error.PrivateRamBeforeRootMismatch;
                if (before_at >= before_nodes.len) return error.InvalidPreparedRamCounts;
                before_nodes[before_at] = .{ .graph = .{ .height = @intCast(h + 1), .index = parent_index, .left = left, .right = right, .digest = before_digest }, .io = before_io };
                var after_digest = before_digest;
                if (any_changed) {
                    const after_io: u32 = @intCast(recorder.calls.items.len);
                    after_digest = try values.hashNode(geometry, @intCast(h), after_left, after_right, recorder);
                    if (after_at >= after_nodes.len or patch_at >= patches.len) return error.InvalidPreparedRamCounts;
                    after_nodes[after_at] = .{ .graph = .{ .height = @intCast(h + 1), .index = parent_index, .left = after_left, .right = after_right, .digest = after_digest }, .io = after_io };
                    after_at += 1;
                    patches[patch_at] = .{ .height = @intCast(h + 1), .index = parent_index, .before = before_digest, .after = after_digest };
                    patch_at += 1;
                }
                frontier[write] = .{ .index = parent_index, .before = before_digest, .after = after_digest, .changed = any_changed, .leaf = false, .source = before_at };
                before_at += 1;
                write += 1;
            }
            used = write;
        }
        if (used != 1 or before_at != before_nodes.len or after_at != after_nodes.len or side_at != sides.len or patch_at != patches.len) return error.InvalidPreparedRamCounts;
        if (!frontier[0].changed) markReuse(leaves, before_nodes, frontier[0]);
        return .{ .allocator = a, .geometry = geometry, .before = cache.root(), .after = frontier[0].after, .leaves = leaves, .before_nodes = before_nodes, .after_nodes = after_nodes, .sides = sides, .patches = patches };
    }
    pub fn publish(self: *const Witness, cache: *values.Cache) !void {
        if (self.geometry != cache.geometry or !values.equal(self.before, cache.root())) return error.PrivateRamBeforeRootMismatch;
        try cache.applyPatch(self.patches);
        std.debug.assert(values.equal(self.after, cache.root()));
    }
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.leaves);
        self.allocator.free(self.before_nodes);
        self.allocator.free(self.after_nodes);
        self.allocator.free(self.sides);
        self.allocator.free(self.patches);
        self.* = undefined;
    }
};
fn markReuse(leaves: []Leaf, nodes: []Node, entry: Frontier) void {
    if (entry.leaf) leaves[entry.source].graph.reuse = true else nodes[entry.source].graph.reuse = true;
}
