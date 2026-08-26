//! Canonical hash-consed direct-polynomial DAG accounting.
//!
//! Node creation and root folding occupy distinct, monotonically ordered
//! events. That distinction is required when an already-interned node is
//! folded as a later root: its lifetime extends to that fold even though no
//! new node is produced.

const std = @import("std");
const fixed_direct = @import("materialization_fixed_direct.zig");
const types = @import("types.zig");

pub const Error = std.mem.Allocator.Error || error{CountOverflow};

const materialized_column_namespace: u64 = @as(u64, 1) << 63;

pub const Op = enum(u8) {
    constant,
    committed,
    fixed_committed,
    row_mask,
    add,
    sub,
    neg,
    mul,
};

pub const Node = struct {
    op: Op,
    lhs: u32 = 0,
    rhs: u32 = 0,
    value: u64 = 0,
    namespace_digest: fixed_direct.Digest = [_]u8{0} ** 32,
};

pub const RootUse = struct {
    node: u32,
    fold_event: usize,
};

pub const OperationCounts = struct {
    additions: u64 = 0,
    subtractions: u64 = 0,
    negations: u64 = 0,
    multiplications: u64 = 0,
    committed: u64 = 0,
};

pub const Arena = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(Node),
    creation_events: std.ArrayList(usize),
    interned: std.AutoHashMap(Node, u32),
    event_clock: usize,

    pub fn init(allocator: std.mem.Allocator) Arena {
        return .{
            .allocator = allocator,
            .nodes = .empty,
            .creation_events = .empty,
            .interned = std.AutoHashMap(Node, u32).init(allocator),
            .event_clock = 0,
        };
    }

    pub fn deinit(self: *Arena) void {
        self.interned.deinit();
        self.creation_events.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn nodeCount(self: *const Arena) usize {
        return self.nodes.items.len;
    }

    pub fn intern(self: *Arena, node: Node) Error!u32 {
        if (self.interned.get(node)) |existing| return existing;
        const id = std.math.cast(u32, self.nodes.items.len) orelse
            return error.CountOverflow;
        const creation_event = std.math.add(usize, self.event_clock, 1) catch
            return error.CountOverflow;
        try self.nodes.append(self.allocator, node);
        errdefer _ = self.nodes.pop();
        try self.creation_events.append(self.allocator, creation_event);
        errdefer _ = self.creation_events.pop();
        try self.interned.put(node, id);
        self.event_clock = creation_event;
        return id;
    }

    pub fn committed(
        self: *Arena,
        value: types.ValueId,
        materialized: bool,
    ) Error!u32 {
        var identity_value: u64 = @intFromEnum(value);
        if (materialized) identity_value |= materialized_column_namespace;
        return self.intern(.{ .op = .committed, .value = identity_value });
    }

    pub fn fixedCommitted(
        self: *Arena,
        namespace_digest: fixed_direct.Digest,
        tree: fixed_direct.CommitmentTree,
        resolved: u64,
    ) Error!u32 {
        return self.intern(.{
            .op = .fixed_committed,
            .lhs = @intFromEnum(tree),
            .value = resolved,
            .namespace_digest = namespace_digest,
        });
    }

    pub fn binary(self: *Arena, op: Op, lhs: u32, rhs: u32) Error!u32 {
        var node = Node{ .op = op, .lhs = lhs, .rhs = rhs };
        if ((op == .add or op == .mul) and node.rhs < node.lhs)
            std.mem.swap(u32, &node.lhs, &node.rhs);
        return self.intern(node);
    }

    /// Records the ordered event at which a root is folded into an accumulator.
    pub fn recordRoot(self: *Arena, node: u32) Error!RootUse {
        if (node >= self.nodes.items.len) return error.CountOverflow;
        const fold_event = std.math.add(usize, self.event_clock, 1) catch
            return error.CountOverflow;
        self.event_clock = fold_event;
        return .{ .node = node, .fold_event = fold_event };
    }

    pub fn operationCounts(self: *const Arena) error{CountOverflow}!OperationCounts {
        var result = OperationCounts{};
        for (self.nodes.items) |node| switch (node.op) {
            .constant, .row_mask => {},
            .committed, .fixed_committed => result.committed = try checkedAdd(result.committed, 1),
            .add => result.additions = try checkedAdd(result.additions, 1),
            .sub => result.subtractions = try checkedAdd(result.subtractions, 1),
            .neg => result.negations = try checkedAdd(result.negations, 1),
            .mul => result.multiplications = try checkedAdd(result.multiplications, 1),
        };
        return result;
    }

    /// Peak live values under canonical first-intern production and the
    /// explicitly recorded root-fold schedule.
    pub fn peakLiveNodes(
        self: *const Arena,
        scratch_allocator: std.mem.Allocator,
        roots: []const RootUse,
    ) Error!u64 {
        if (self.nodes.items.len == 0) return 0;
        if (self.creation_events.items.len != self.nodes.items.len)
            return error.CountOverflow;

        const last_use = try scratch_allocator.dupe(usize, self.creation_events.items);
        defer scratch_allocator.free(last_use);
        for (self.nodes.items, self.creation_events.items) |node, consumer_event| {
            switch (node.op) {
                .constant, .committed, .fixed_committed, .row_mask => {},
                .add, .sub, .mul => {
                    if (node.lhs >= last_use.len or node.rhs >= last_use.len)
                        return error.CountOverflow;
                    last_use[node.lhs] = @max(last_use[node.lhs], consumer_event);
                    last_use[node.rhs] = @max(last_use[node.rhs], consumer_event);
                },
                .neg => {
                    if (node.lhs >= last_use.len) return error.CountOverflow;
                    last_use[node.lhs] = @max(last_use[node.lhs], consumer_event);
                },
            }
        }
        for (roots) |root| {
            if (root.node >= last_use.len or root.fold_event > self.event_clock)
                return error.CountOverflow;
            last_use[root.node] = @max(last_use[root.node], root.fold_event);
        }

        const event_count = std.math.add(usize, self.event_clock, 1) catch
            return error.CountOverflow;
        const releases = try scratch_allocator.alloc(u64, event_count);
        defer scratch_allocator.free(releases);
        @memset(releases, 0);
        for (last_use) |event| {
            if (event == 0 or event > self.event_clock) return error.CountOverflow;
            releases[event] = try checkedAdd(releases[event], 1);
        }

        var next_birth: usize = 0;
        var live: u64 = 0;
        var peak: u64 = 0;
        for (1..event_count) |event| {
            if (next_birth < self.creation_events.items.len and
                self.creation_events.items[next_birth] == event)
            {
                live = try checkedAdd(live, 1);
                peak = @max(peak, live);
                next_birth += 1;
            }
            live = std.math.sub(u64, live, releases[event]) catch
                return error.CountOverflow;
        }
        if (next_birth != self.nodes.items.len or live != 0)
            return error.CountOverflow;
        return peak;
    }
};

fn checkedAdd(lhs: u64, rhs: u64) error{CountOverflow}!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CountOverflow;
}
