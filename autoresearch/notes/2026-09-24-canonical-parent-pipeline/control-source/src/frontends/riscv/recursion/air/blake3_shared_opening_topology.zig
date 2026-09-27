//! One commitment root's shared opening DAG. This is geometry, not proof admission.
//! Query/payload equality and direction constraints remain the emitter's obligation.
const std = @import("std");
pub const Key = struct { level: u32, position: u32 };
pub const Node = struct {
    key: Key,
    computed: bool = false,
    children: ?[2]u32 = null,
    /// Consumers in the hash DAG only; excludes query bridges and root equality.
    hash_uses: u32 = 0,
    /// Number of requested openings of this subtree, including duplicate queries.
    opening_uses: u32 = 0,
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    depth: u32,
    nodes: []Node,
    /// Preserves the caller's exact query order and duplicate requests.
    openings: []u32,
    root: u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.nodes);
        self.allocator.free(self.openings);
        self.* = undefined;
    }
    /// Re-derive from caller-authenticated geometry before crossing an emitter
    /// boundary. Node addresses or digest equality are not admission authority.
    pub fn validate(self: *const Plan, a: std.mem.Allocator, depth: u32, positions: []const usize) !void {
        if (self.depth != depth) return error.InvalidSharedOpeningPlan;
        var expected = try build(a, depth, positions);
        defer expected.deinit();
        if (self.root != expected.root or self.nodes.len != expected.nodes.len or
            !std.mem.eql(u32, self.openings, expected.openings)) return error.InvalidSharedOpeningPlan;
        for (self.nodes, expected.nodes) |actual, canonical|
            if (!std.meta.eql(actual, canonical)) return error.InvalidSharedOpeningPlan;
    }
    pub fn computedCounts(self: Plan) struct { payloads: usize, ancestors: usize } {
        var result: @TypeOf(self.computedCounts()) = .{ .payloads = 0, .ancestors = 0 };
        for (self.nodes) |node| if (node.computed) {
            if (node.key.level == 0) result.payloads += 1 else result.ancestors += 1;
        };
        return result;
    }
};
fn less(_: void, a: Node, b: Node) bool {
    return a.key.level < b.key.level or (a.key.level == b.key.level and a.key.position < b.key.position);
}
fn ensure(a: std.mem.Allocator, nodes: *std.ArrayList(Node), index: *std.AutoHashMap(Key, u32), key: Key, computed: bool) !u32 {
    const entry = try index.getOrPut(key);
    if (entry.found_existing) {
        if (computed) nodes.items[entry.value_ptr.*].computed = true;
        return entry.value_ptr.*;
    }
    const id = std.math.cast(u32, nodes.items.len) orelse return error.SharedOpeningTooLarge;
    try nodes.append(a, .{ .key = key, .computed = computed });
    entry.value_ptr.* = id;
    return id;
}
/// Positions refer to the opened subtree, after any FRI fold-step shift.
/// Every invocation is a separate root domain, even if digest bytes are equal.
pub fn build(a: std.mem.Allocator, depth: u32, positions: []const usize) !Plan {
    if (depth > 31 or positions.len == 0) return error.InvalidSharedOpeningGeometry;
    const size = @as(u64, 1) << @intCast(depth);
    for (positions) |position| if (position >= size) return error.InvalidSharedOpeningPosition;
    var nodes: std.ArrayList(Node) = .empty;
    defer nodes.deinit(a);
    var index = std.AutoHashMap(Key, u32).init(a);
    defer index.deinit();
    for (positions) |raw| {
        var position: u32 = @intCast(raw);
        _ = try ensure(a, &nodes, &index, .{ .level = 0, .position = position }, true);
        for (0..depth) |level| {
            _ = try ensure(a, &nodes, &index, .{ .level = @intCast(level), .position = position ^ 1 }, false);
            position >>= 1;
            _ = try ensure(a, &nodes, &index, .{ .level = @intCast(level + 1), .position = position }, true);
        }
    }
    // Canonical ordering makes node IDs independent of the order of queries.
    std.mem.sort(Node, nodes.items, {}, less);
    for (nodes.items, 0..) |node, id| index.getPtr(node.key).?.* = @intCast(id);
    for (0..nodes.items.len) |id| {
        const key = nodes.items[id].key;
        if (!nodes.items[id].computed or key.level == 0) continue;
        const left = index.get(.{ .level = key.level - 1, .position = key.position * 2 }).?;
        const right = index.get(.{ .level = key.level - 1, .position = key.position * 2 + 1 }).?;
        std.debug.assert(left < id and right < id);
        nodes.items[id].children = .{ left, right };
        for ([_]u32{ left, right }) |child| nodes.items[child].hash_uses = try std.math.add(u32, nodes.items[child].hash_uses, 1);
    }
    const openings = try a.alloc(u32, positions.len);
    errdefer a.free(openings);
    for (positions, openings) |position, *opening| {
        opening.* = index.get(.{ .level = 0, .position = @intCast(position) }).?;
        nodes.items[opening.*].opening_uses = try std.math.add(u32, nodes.items[opening.*].opening_uses, 1);
    }
    const root = index.get(.{ .level = depth, .position = 0 }).?;
    return .{ .allocator = a, .depth = depth, .nodes = try nodes.toOwnedSlice(a), .openings = openings, .root = root };
}

test "shared opening topology preserves duplicate requests and canonical node order" {
    const a = std.testing.allocator;
    var first = try build(a, 3, &.{ 0, 1, 6, 0 });
    defer first.deinit();
    var second = try build(a, 3, &.{ 6, 0, 1, 0 });
    defer second.deinit();
    try std.testing.expectEqualDeep(first.nodes, second.nodes);
    try std.testing.expectEqual(first.openings[0], first.openings[3]);
    try std.testing.expectEqual(@as(u32, 2), first.nodes[first.openings[0]].opening_uses);
    const counts = first.computedCounts();
    try std.testing.expectEqual(@as(usize, 3), counts.payloads);
    try std.testing.expectEqual(@as(usize, 5), counts.ancestors);
    try std.testing.expectEqual(@as(u32, 0), first.nodes[first.root].hash_uses);
    for (first.nodes, 0..) |node, id| if (id != first.root) {
        try std.testing.expectEqual(@as(u32, 1), node.hash_uses);
    };
}
test "shared opening topology admits zero depth and rejects invalid positions" {
    var plan = try build(std.testing.allocator, 0, &.{ 0, 0 });
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.nodes.len);
    try std.testing.expectEqual(@as(u32, 2), plan.nodes[0].opening_uses);
    try std.testing.expectError(error.InvalidSharedOpeningGeometry, build(std.testing.allocator, 32, &.{0}));
    try std.testing.expectError(error.InvalidSharedOpeningGeometry, build(std.testing.allocator, 3, &.{}));
    try std.testing.expectError(error.InvalidSharedOpeningPosition, build(std.testing.allocator, 3, &.{8}));
}
fn allocationCase(a: std.mem.Allocator) !void {
    var plan = try build(a, 5, &.{ 1, 3, 3, 30, 31 });
    defer plan.deinit();
}
test "shared opening topology releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn digestPair(left: [32]u8, right: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&(left ++ right), &result, .{});
    return result;
}
test "shared opening DAG reconstructs independently built binary trees" {
    const a = std.testing.allocator;
    var random = std.Random.DefaultPrng.init(0x5a17);
    for (0..9) |depth| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const temp = arena.allocator();
        const size = @as(usize, 1) << @intCast(depth);
        const levels = try temp.alloc([][32]u8, depth + 1);
        levels[0] = try temp.alloc([32]u8, size);
        for (levels[0], 0..) |*value, index| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, index, .little);
            std.crypto.hash.Blake3.hash(&bytes, value, .{});
        }
        for (1..depth + 1) |level| {
            levels[level] = try temp.alloc([32]u8, levels[level - 1].len / 2);
            for (levels[level], 0..) |*value, index| value.* = digestPair(levels[level - 1][index * 2], levels[level - 1][index * 2 + 1]);
        }
        for (0..8) |_| {
            var positions: [17]usize = undefined;
            for (&positions) |*position| position.* = random.random().uintLessThan(usize, size);
            var plan = try build(a, @intCast(depth), &positions);
            defer plan.deinit();
            const values = try a.alloc([32]u8, plan.nodes.len);
            defer a.free(values);
            for (plan.nodes, 0..) |node, id| {
                values[id] = if (node.children) |children| digestPair(values[children[0]], values[children[1]]) else levels[node.key.level][node.key.position];
                try std.testing.expectEqualSlices(u8, &levels[node.key.level][node.key.position], &values[id]);
            }
            try std.testing.expectEqualSlices(u8, &levels[depth][0], &values[plan.root]);
            for (positions, plan.openings) |position, opening| try std.testing.expectEqualSlices(u8, &levels[0][position], &values[opening]);
        }
    }
}

test "shared opening admission rejects changed routes and consumer counts" {
    const a = std.testing.allocator;
    const positions = [_]usize{ 1, 3, 6, 1 };
    var plan = try build(a, 3, &positions);
    defer plan.deinit();
    try plan.validate(a, 3, &positions);
    const saved = plan.nodes[0];
    plan.nodes[0].hash_uses += 1;
    try std.testing.expectError(error.InvalidSharedOpeningPlan, plan.validate(a, 3, &positions));
    plan.nodes[0] = saved;
    const children = plan.nodes[plan.root].children.?;
    plan.nodes[plan.root].children = .{ children[1], children[0] };
    try std.testing.expectError(error.InvalidSharedOpeningPlan, plan.validate(a, 3, &positions));
    plan.nodes[plan.root].children = children;
    plan.openings[0] = plan.root;
    try std.testing.expectError(error.InvalidSharedOpeningPlan, plan.validate(a, 3, &positions));
}
