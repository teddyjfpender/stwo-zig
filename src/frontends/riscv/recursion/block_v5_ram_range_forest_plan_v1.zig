//! Minimum-count deterministic <=4 original verifier fan-in. Range leaves occur
//! ONLY at their shard root: no partial/provider deficit can escape a shard.
const std = @import("std");
const core = @import("stwo_core");
const Lane = @import("../prover/block_v5_ram_lanes_proof_v1.zig");
const Plans = @import("../prover/block_v5_ram_lanes_plan_v1.zig");
const Range = @import("../prover/block_v5_range16_v1.zig");
pub const VERSION: u32 = 19;
pub const FAN_IN: usize = 4;
pub const Ref = union(enum) { ram: u32, range: u32, node: u32 };
pub const Kind = enum { partial, shard, aggregate };
pub const Span = struct { first: u32, count: u32 };
pub const Node = struct { kind: Kind, children: [FAN_IN]Ref, child_count: u32, lanes: Span, shards: Span, events: u64, requests: u64 };
pub const Limits = struct { lane: Plans.Limits = .{}, max_nodes: usize = 4096, max_metadata_bytes: usize = 64 << 20 };
pub const Geometry = struct {
    a: std.mem.Allocator,
    nodes: []Node,
    shard_roots: []u32,
    root: ?u32,
    lanes: u32,
    digest: [32]u8,
    pub fn deinit(self: *@This()) void {
        self.a.free(self.nodes);
        self.a.free(self.shard_roots);
        self.* = undefined;
    }
    pub fn require(self: *const @This(), a: std.mem.Allocator, pins: []const Lane.Pin, range: *const Range.Plan, limits: Limits) !void {
        var original = try derive(a, pins, range, limits);
        defer original.deinit();
        if (!std.meta.eql(self.digest, original.digest) or self.root != original.root or self.lanes != original.lanes or !std.mem.eql(u32, self.shard_roots, original.shard_roots) or self.nodes.len != original.nodes.len) return error.UntrustedRamRangeForestTopology;
        for (self.nodes, original.nodes) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRamRangeForestTopology;
    }
};
pub fn requiredNodes(shards: []const Range.Shard) !usize {
    var n: usize = 0;
    for (shards) |shard| {
        if (shard.instance_count == 0) return error.UntrustedRamRangeForestTopology;
        n = try std.math.add(usize, n, try std.math.divCeil(usize, shard.instance_count, 3));
    }
    return std.math.add(usize, n, if (shards.len <= 1) 0 else try std.math.divCeil(usize, shards.len - 1, 3));
}
pub fn derive(a: std.mem.Allocator, pins: []const Lane.Pin, range: *const Range.Plan, limits: Limits) !Geometry {
    try limits.lane.require(pins.len, range.shards.len);
    try Plans.admit(a, range, pins, range.total_events, limits.lane);
    const required = try requiredNodes(range.shards);
    const bytes = try std.math.add(usize, try std.math.mul(usize, required, @sizeOf(Node)), try std.math.mul(usize, try std.math.add(usize, pins.len, range.shards.len), 2 * @sizeOf(Ref) + @sizeOf(u32)));
    if (limits.max_metadata_bytes == 0 or required > limits.max_nodes or bytes > limits.max_metadata_bytes or range.total_events >= core.fields.m31.Modulus) return error.RamRangeForestResourceLimit;
    var nodes: std.ArrayList(Node) = .empty;
    errdefer nodes.deinit(a);
    try nodes.ensureTotalCapacityPrecise(a, required);
    const roots = try a.alloc(u32, range.shards.len);
    errdefer a.free(roots);
    var first_lane: u32 = 0;
    for (range.shards, roots, 0..) |shard, *root, index| {
        if (shard.index != index or shard.first_instance != first_lane or shard.instance_count == 0 or shard.request_count == 0 or shard.request_count > Range.MAX_REQUESTS or @as(u64, first_lane) + shard.instance_count > pins.len) return error.UntrustedRamRangeForestTopology;
        var current: std.ArrayList(Ref) = .empty;
        defer current.deinit(a);
        try current.ensureTotalCapacityPrecise(a, shard.instance_count);
        var requests: u64 = 0;
        for (pins[first_lane..][0..shard.instance_count], 0..) |pin, offset| {
            try pin.validate();
            if (pin.index != first_lane + @as(u32, @intCast(offset))) return error.UntrustedRamRangeForestTopology;
            requests = try std.math.add(u64, requests, pin.request_count);
            current.appendAssumeCapacity(.{ .ram = first_lane + @as(u32, @intCast(offset)) });
        }
        if (requests != shard.request_count) return error.UntrustedRamRangeForestTopology;
        // Four-child reductions only. Carry short tails until a shard root can
        // accept <=3 RAM/partial children plus its ONE original range verifier.
        while (current.items.len > 3) try reduce(a, &nodes, &current, pins, range, .partial, @intCast(index), false);
        try current.append(a, .{ .range = @intCast(index) });
        root.* = try appendNode(a, &nodes, current.items, pins, range, .shard, @intCast(index));
        first_lane = try std.math.add(u32, first_lane, shard.instance_count);
    }
    if (first_lane != pins.len) return error.UntrustedRamRangeForestTopology;
    var current: std.ArrayList(Ref) = .empty;
    defer current.deinit(a);
    try current.ensureTotalCapacityPrecise(a, roots.len);
    for (roots) |root| current.appendAssumeCapacity(.{ .node = root });
    var root: ?u32 = null;
    if (current.items.len == 1) root = current.items[0].node;
    while (current.items.len > 1) {
        try reduce(a, &nodes, &current, pins, range, .aggregate, 0, true);
        if (current.items.len == 1) root = current.items[0].node;
    }
    if (nodes.items.len != required) return error.UntrustedRamRangeForestTopology;
    const owned = try nodes.toOwnedSlice(a);
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x52524647, VERSION, @intCast(pins.len), @intCast(roots.len), @intCast(owned.len), root orelse std.math.maxInt(u32) });
    channel.mixRoot(range.digest);
    for (owned) |node| mixNode(&channel, node);
    return .{ .a = a, .nodes = owned, .shard_roots = roots, .root = root, .lanes = @intCast(pins.len), .digest = channel.digestBytes() };
}
fn reduce(a: std.mem.Allocator, nodes: *std.ArrayList(Node), current: *std.ArrayList(Ref), pins: []const Lane.Pin, range: *const Range.Plan, kind: Kind, shard: u32, allow_short: bool) !void {
    var next: std.ArrayList(Ref) = .empty;
    errdefer next.deinit(a);
    try next.ensureTotalCapacityPrecise(a, current.items.len / 4 + current.items.len % 4 + 1);
    var first: usize = 0;
    while (first < current.items.len) {
        const end = @min(first + 4, current.items.len);
        if (end - first < 4 and (!allow_short or current.items.len > 4)) {
            try next.appendSlice(a, current.items[first..end]);
        } else try next.append(a, .{ .node = try appendNode(a, nodes, current.items[first..end], pins, range, kind, shard) });
        first = end;
    }
    current.deinit(a);
    current.* = next;
}
fn appendNode(a: std.mem.Allocator, nodes: *std.ArrayList(Node), children: []const Ref, pins: []const Lane.Pin, range: *const Range.Plan, kind: Kind, shard: u32) !u32 {
    if (children.len == 0 or children.len > FAN_IN or (kind != .shard and children.len < 2)) return error.UntrustedRamRangeForestTopology;
    var out = Node{ .kind = kind, .children = @splat(.{ .ram = 0 }), .child_count = @intCast(children.len), .lanes = .{ .first = 0, .count = 0 }, .shards = .{ .first = shard, .count = if (kind == .shard) 1 else 0 }, .events = 0, .requests = 0 };
    @memcpy(out.children[0..children.len], children);
    var lane_cursor: ?u32 = null;
    var shard_cursor: ?u32 = null;
    var ranges: u32 = 0;
    for (children) |child| {
        const part = switch (child) {
            .ram => |i| block: {
                if (i >= pins.len or kind == .aggregate) return error.UntrustedRamRangeForestTopology;
                break :block Node{ .kind = .partial, .children = undefined, .child_count = 0, .lanes = .{ .first = i, .count = 1 }, .shards = .{ .first = shard, .count = 0 }, .events = pins[i].claim.events, .requests = pins[i].request_count };
            },
            .range => |i| {
                if (kind != .shard or i != shard or i >= range.shards.len) return error.UntrustedRamRangeForestTopology;
                ranges += 1;
                continue;
            },
            .node => |i| block: {
                if (i >= nodes.items.len) return error.UntrustedRamRangeForestTopology;
                const node = nodes.items[i];
                if ((kind == .aggregate and node.kind == .partial) or (kind != .aggregate and (node.kind != .partial or node.shards.first != shard))) return error.UntrustedRamRangeForestTopology;
                break :block node;
            },
        };
        if (lane_cursor == null) {
            lane_cursor = part.lanes.first;
            out.lanes.first = part.lanes.first;
        }
        if (part.lanes.first != lane_cursor.?) return error.UntrustedRamRangeForestTopology;
        lane_cursor = try std.math.add(u32, lane_cursor.?, part.lanes.count);
        out.lanes.count = try std.math.add(u32, out.lanes.count, part.lanes.count);
        if (kind == .aggregate) {
            if (shard_cursor == null) {
                shard_cursor = part.shards.first;
                out.shards.first = part.shards.first;
            }
            if (part.shards.first != shard_cursor.?) return error.UntrustedRamRangeForestTopology;
            shard_cursor = try std.math.add(u32, shard_cursor.?, part.shards.count);
            out.shards.count = try std.math.add(u32, out.shards.count, part.shards.count);
        }
        out.events = try std.math.add(u64, out.events, part.events);
        out.requests = try std.math.add(u64, out.requests, part.requests);
    }
    if (out.events >= core.fields.m31.Modulus or (kind != .aggregate and out.requests > Range.MAX_REQUESTS) or (kind == .shard and (ranges != 1 or out.lanes.first != range.shards[shard].first_instance or out.lanes.count != range.shards[shard].instance_count or out.requests != range.shards[shard].request_count)) or (kind != .shard and ranges != 0)) return error.UntrustedRamRangeForestTopology;
    const index: u32 = @intCast(nodes.items.len);
    try nodes.append(a, out);
    return index;
}
pub fn mixNode(channel: anytype, node: Node) void {
    channel.mixU32s(&.{ @intFromEnum(node.kind), node.child_count, node.lanes.first, node.lanes.count, node.shards.first, node.shards.count });
    channel.mixU64(node.events);
    channel.mixU64(node.requests);
    for (node.children[0..node.child_count]) |ref| switch (ref) {
        .ram => |i| channel.mixU32s(&.{ 0, i }),
        .range => |i| channel.mixU32s(&.{ 1, i }),
        .node => |i| channel.mixU32s(&.{ 2, i }),
    };
}
