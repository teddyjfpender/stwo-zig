const std = @import("std");

pub const SCHEMA_VERSION: u32 = 1;

pub const StageNode = struct {
    id: []const u8,
    label: []const u8,
    seconds: f64,
    children: ?[]StageNode = null,

    pub fn deinit(self: *StageNode, allocator: std.mem.Allocator) void {
        if (self.children) |children| {
            for (children) |*child| child.deinit(allocator);
            allocator.free(children);
        }
        self.* = undefined;
    }

    pub fn deinitSlice(allocator: std.mem.Allocator, nodes: []StageNode) void {
        for (nodes) |*node| node.deinit(allocator);
        allocator.free(nodes);
    }
};

pub const StageProfile = struct {
    schema_version: u32 = SCHEMA_VERSION,
    runtime: []const u8,
    example: []const u8,
    stages: []StageNode,

    pub fn deinit(self: *StageProfile, allocator: std.mem.Allocator) void {
        StageNode.deinitSlice(allocator, self.stages);
        self.* = undefined;
    }
};

const MutableNode = struct {
    id: []const u8,
    label: []const u8,
    start_ns: i128,
    seconds: f64,
    children: std.ArrayList(*MutableNode),

    fn init(id: []const u8, label: []const u8) MutableNode {
        return .{
            .id = id,
            .label = label,
            .start_ns = std.time.nanoTimestamp(),
            .seconds = 0.0,
            .children = std.ArrayList(*MutableNode).empty,
        };
    }

    fn deinit(self: *MutableNode, allocator: std.mem.Allocator) void {
        for (self.children.items) |child| {
            child.deinit(allocator);
            allocator.destroy(child);
        }
        self.children.deinit(allocator);
        self.* = undefined;
    }
};

pub const Recorder = struct {
    allocator: std.mem.Allocator,
    runtime: []const u8,
    example: []const u8,
    roots: std.ArrayList(*MutableNode),
    stack: std.ArrayList(*MutableNode),

    pub fn init(
        allocator: std.mem.Allocator,
        runtime: []const u8,
        example: []const u8,
    ) Recorder {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .example = example,
            .roots = std.ArrayList(*MutableNode).empty,
            .stack = std.ArrayList(*MutableNode).empty,
        };
    }

    pub fn deinit(self: *Recorder) void {
        for (self.roots.items) |root| {
            root.deinit(self.allocator);
            self.allocator.destroy(root);
        }
        self.roots.deinit(self.allocator);
        self.stack.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn snapshot(self: *const Recorder, allocator: std.mem.Allocator) !StageProfile {
        std.debug.assert(self.stack.items.len == 0);
        return .{
            .runtime = self.runtime,
            .example = self.example,
            .stages = try snapshotNodes(allocator, self.roots.items),
        };
    }

    fn pushStage(self: *Recorder, id: []const u8, label: []const u8) !*MutableNode {
        const node = try self.allocator.create(MutableNode);
        node.* = MutableNode.init(id, label);
        errdefer self.allocator.destroy(node);

        if (self.stack.items.len == 0) {
            try self.roots.append(self.allocator, node);
        } else {
            try self.stack.items[self.stack.items.len - 1].children.append(self.allocator, node);
        }
        try self.stack.append(self.allocator, node);
        return node;
    }

    fn popStage(self: *Recorder, node: *MutableNode) void {
        std.debug.assert(self.stack.items.len > 0);
        std.debug.assert(self.stack.items[self.stack.items.len - 1] == node);
        _ = self.stack.pop();
        const elapsed_ns = std.time.nanoTimestamp() - node.start_ns;
        node.seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    }
};

pub const StageScope = struct {
    recorder: ?*Recorder = null,
    node: ?*MutableNode = null,
    ended: bool = false,

    pub fn begin(
        recorder: ?*Recorder,
        id: []const u8,
        label: []const u8,
    ) !StageScope {
        if (recorder) |active| {
            return .{
                .recorder = active,
                .node = try active.pushStage(id, label),
            };
        }
        return .{};
    }

    pub fn end(self: *StageScope) void {
        if (self.ended) return;
        if (self.recorder) |recorder| {
            recorder.popStage(self.node.?);
        }
        self.ended = true;
    }
};

fn snapshotNodes(
    allocator: std.mem.Allocator,
    nodes: []const *MutableNode,
) ![]StageNode {
    const out = try allocator.alloc(StageNode, nodes.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |*node| node.deinit(allocator);
    }

    for (nodes, 0..) |node, i| {
        out[i] = .{
            .id = node.id,
            .label = node.label,
            .seconds = node.seconds,
            .children = if (node.children.items.len == 0)
                null
            else
                try snapshotNodes(allocator, node.children.items),
        };
        initialized += 1;
    }
    return out;
}

test "prover stage profile: preserves nested order" {
    const alloc = std.testing.allocator;
    var recorder = Recorder.init(alloc, "zig", "wide_fibonacci");
    defer recorder.deinit();

    var outer = try StageScope.begin(&recorder, "outer", "Outer");
    defer outer.end();
    {
        var inner_a = try StageScope.begin(&recorder, "inner_a", "Inner A");
        defer inner_a.end();
    }
    {
        var inner_b = try StageScope.begin(&recorder, "inner_b", "Inner B");
        defer inner_b.end();
    }
    outer.end();

    var profile = try recorder.snapshot(alloc);
    defer profile.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), profile.stages.len);
    try std.testing.expectEqualStrings("outer", profile.stages[0].id);
    const children = profile.stages[0].children orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqualStrings("inner_a", children[0].id);
    try std.testing.expectEqualStrings("inner_b", children[1].id);
}
