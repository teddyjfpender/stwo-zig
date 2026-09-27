//! Exact raw-then-fold recursive PAGE roster. Physical counts are never rounded.
//! This immutable host setup binds independent sources; actual leaf and node
//! verifiers and same-parent byte merges remain mandatory on every path.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Page = @import("../prover/block_v5_memory_source_unified_page_proof_v1.zig");
const Leaf = @import("block_v5_memory_source_page_forest_leaf_v1.zig");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const A = @import("block_v5_memory_source_page_forest_algebra_v1.zig");
pub const FAN_IN = 4;
pub const Ref = union(enum) { leaf: u32, node: u32 };
pub const Range = struct { first: u32, count: u32 };
pub const Node = struct { children: [4]Ref, child_count: u32, range: Range };
pub const Limits = struct { pages: Page.Limits = .{}, max_pages: usize = 524288, max_nodes: usize = 262144, max_metadata_bytes: usize = 512 << 20 };
pub const Geometry = struct {
    allocator: std.mem.Allocator,
    nodes: []Node,
    root: ?u32,
    leaves: u32,
    digest: [32]u8,
    pub fn deinit(self: *Geometry) void {
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
    /// Independent deterministic physical selector re-derivation. This is setup
    /// admission, never a proof token. Production node checks use the pinned
    /// recipe membership path built only after this canonical constructor.
    pub fn require(self: *const Geometry, a: std.mem.Allocator, expected_digest: [32]u8, limits: Limits) !void {
        var expected = try derive(a, self.leaves, limits);
        defer expected.deinit();
        if (!std.meta.eql(self.digest, expected_digest) or !std.meta.eql(expected.digest, expected_digest) or self.root != expected.root or self.nodes.len != expected.nodes.len) return error.UntrustedPageForestTopology;
        for (self.nodes, expected.nodes) |received, original| if (!std.meta.eql(received, original)) return error.UntrustedPageForestTopology;
    }
    pub fn range(self: *const Geometry, ref: Ref) !Range {
        return switch (ref) {
            .leaf => |i| if (i < self.leaves) .{ .first = i, .count = 1 } else error.InvalidPageForestTopology,
            .node => |i| if (i < self.nodes.len) self.nodes[i].range else error.InvalidPageForestTopology,
        };
    }
};
pub fn derive(a: std.mem.Allocator, pages: usize, limits: Limits) !Geometry {
    if (pages > limits.max_pages or pages >= 1 << 30 or limits.max_metadata_bytes == 0 or (pages != 0 and limits.max_nodes == 0)) return error.PageForestResourceLimit;
    if (try std.math.mul(usize, pages, 2 * @sizeOf(Ref) + @sizeOf(Node)) > limits.max_metadata_bytes) return error.PageForestResourceLimit;
    const required_nodes: usize = if (pages <= 1) pages else try std.math.divCeil(usize, pages - 1, 3);
    if (required_nodes > limits.max_nodes) return error.PageForestResourceLimit;
    var nodes: std.ArrayList(Node) = .empty;
    errdefer nodes.deinit(a);
    try nodes.ensureTotalCapacityPrecise(a, required_nodes);
    var current: std.ArrayList(Ref) = .empty;
    defer current.deinit(a);
    try current.ensureTotalCapacityPrecise(a, pages);
    for (0..pages) |i| current.appendAssumeCapacity(.{ .leaf = @intCast(i) });
    var root: ?u32 = null;
    while (current.items.len != 0) {
        var next: std.ArrayList(Ref) = .empty;
        errdefer next.deinit(a);
        try next.ensureTotalCapacityPrecise(a, current.items.len / 4 + current.items.len % 4 + 1);
        var first: usize = 0;
        while (first < current.items.len) {
            const end = @min(first + 4, current.items.len);
            const n = end - first;
            // Carry the exact short remainder; proving it here would add an
            // unnecessary unary/2/3 parent. Only the one-leaf source-root
            // wrapper is intentional: it proves the aggregate closure.
            if (n < 4 and current.items.len > 4) {
                try next.appendSlice(a, current.items[first..end]);
                first = end;
                continue;
            }
            if (nodes.items.len >= limits.max_nodes or try std.math.mul(usize, nodes.items.len + 1, @sizeOf(Node)) > limits.max_metadata_bytes) return error.PageForestResourceLimit;
            var children: [4]Ref = @splat(.{ .leaf = 0 });
            @memcpy(children[0..n], current.items[first..end]);
            var start: ?u32 = null;
            var cursor: u32 = 0;
            for (children[0..n]) |child| {
                const range = switch (child) {
                    .leaf => |i| Range{ .first = i, .count = 1 },
                    .node => |i| nodes.items[i].range,
                };
                if (start == null) {
                    start = range.first;
                    cursor = range.first;
                }
                if (range.first != cursor) return error.InvalidPageForestTopology;
                cursor = try std.math.add(u32, cursor, range.count);
            }
            const index: u32 = @intCast(nodes.items.len);
            try nodes.append(a, .{ .children = children, .child_count = @intCast(n), .range = .{ .first = start.?, .count = cursor - start.? } });
            try next.append(a, .{ .node = index });
            first = end;
        }
        current.deinit(a);
        current = next;
        if (current.items.len == 1) {
            root = current.items[0].node;
            break;
        }
    }
    if (nodes.items.len != required_nodes) return error.InvalidPageForestTopology;
    const owned = try nodes.toOwnedSlice(a);
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x50474647, 1, @intCast(pages), @intCast(owned.len), root orelse std.math.maxInt(u32) });
    for (owned) |node| {
        channel.mixU32s(&.{ node.range.first, node.range.count, node.child_count });
        for (node.children[0..node.child_count]) |ref| switch (ref) {
            .leaf => |i| channel.mixU32s(&.{ 0, i }),
            .node => |i| channel.mixU32s(&.{ 1, i }),
        };
    }
    return .{ .allocator = a, .nodes = owned, .root = root, .leaves = @intCast(pages), .digest = channel.digestBytes() };
}
pub const Summary = struct { range: Range, raw_pages: u32, fold_pages: u32, raw_rows: u32, fold_rows: u32, claims: [A.CLAIM_COUNT]Q };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    context: *const Page.Context,
    raw: []Leaf.ForKind(.raw).Policy,
    fold: []Leaf.ForKind(.fold).Policy,
    geometry: Geometry,
    summaries: []Summary,
    identity: [32]u8,
    recipe_tree: [][32]u8,
    recipe_base: usize,
    recipe_root: [32]u8,
    source: [32]u8,
    seal: [32]u8,
    epoch: [32]u8,
    base: [32]u8,
    limits: Limits,
    pub const complete_source_authority = false;
    pub fn init(a: std.mem.Allocator, context: *const Page.Context, raw: []const Leaf.ForKind(.raw).Policy, fold: []const Leaf.ForKind(.fold).Policy, limits: Limits) !Owned {
        return initAdmitted(a, context, raw, fold, limits, null);
    }
    /// The concrete durable catalogue rehydrates and strictly admits one leaf
    /// at a time. Only descriptor residency differs; pins/claims/recipe and
    /// every original acceptance boundary use the same constructor below.
    pub fn initWithCatalogue(a: std.mem.Allocator, catalogue: *@import("../prover/block_v5_memory_source_page_leaf_catalogue_v1.zig").Catalogue, raw: []const Leaf.ForKind(.raw).Policy, fold: []const Leaf.ForKind(.fold).Policy, limits: Limits) !Owned {
        return initAdmitted(a, catalogue.context(), raw, fold, limits, catalogue);
    }
    fn initAdmitted(a: std.mem.Allocator, context: *const Page.Context, raw: []const Leaf.ForKind(.raw).Policy, fold: []const Leaf.ForKind(.fold).Policy, limits: Limits, catalogue: ?*@import("../prover/block_v5_memory_source_page_leaf_catalogue_v1.zig").Catalogue) !Owned {
        const count = try std.math.add(usize, raw.len, fold.len);
        if (count > limits.max_pages or raw.len != context.raw.len or fold.len != context.fold.len or limits.max_metadata_bytes == 0) return error.PageForestResourceLimit;
        try context.require(a, limits.pages);
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        var geometry = try derive(a, count, limits);
        errdefer geometry.deinit();
        var bytes = try std.math.add(usize, try std.math.mul(usize, raw.len, @sizeOf(Leaf.ForKind(.raw).Policy)), try std.math.mul(usize, fold.len, @sizeOf(Leaf.ForKind(.fold).Policy)));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, geometry.nodes.len, @sizeOf(Node) + @sizeOf(Summary)));
        if (bytes > limits.max_metadata_bytes) return error.PageForestResourceLimit;
        const raw_copy = try a.dupe(Leaf.ForKind(.raw).Policy, raw);
        errdefer a.free(raw_copy);
        var made_raw: usize = 0;
        errdefer for (raw_copy[0..made_raw]) |policy| a.free(policy.schedule);
        const fold_copy = try a.dupe(Leaf.ForKind(.fold).Policy, fold);
        errdefer a.free(fold_copy);
        var made_fold: usize = 0;
        errdefer for (fold_copy[0..made_fold]) |policy| a.free(policy.schedule);
        inline for ([_]Semantic.Kind{ .raw, .fold }) |kind| {
            const source = if (kind == .raw) raw else fold;
            const copy = if (kind == .raw) raw_copy else fold_copy;
            for (source, copy, 0..) |policy, *destination, i| {
                if (catalogue) |owner| try owner.validateLeaf(kind, @intCast(i), policy) else try policy.validate();
                if (!std.meta.eql(policy.admitted.limits.page, limits.pages) or policy.admitted.context != context or !std.meta.eql(policy.admitted.pin, if (kind == .raw) context.raw[i] else context.fold[i])) return error.UntrustedPageForestRoster;
                bytes = try std.math.add(usize, bytes, try std.math.mul(usize, policy.schedule.len, @sizeOf(@TypeOf(policy.schedule[0]))));
                if (bytes > limits.max_metadata_bytes) return error.PageForestResourceLimit;
                destination.schedule = try a.dupe(@TypeOf(policy.schedule[0]), policy.schedule);
                if (kind == .raw) made_raw += 1 else made_fold += 1;
            }
        }
        const summaries = try a.alloc(Summary, geometry.nodes.len);
        errdefer a.free(summaries);
        for (geometry.nodes, summaries) |planned, *aggregate| {
            aggregate.* = .{ .range = planned.range, .raw_pages = 0, .fold_pages = 0, .raw_rows = 0, .fold_rows = 0, .claims = @splat(Q.zero()) };
            for (planned.children[0..planned.child_count]) |ref| {
                const value = switch (ref) {
                    .leaf => |i| leafSummary(raw_copy, fold_copy, i),
                    .node => |i| summaries[i],
                };
                aggregate.raw_pages = try std.math.add(u32, aggregate.raw_pages, value.raw_pages);
                aggregate.fold_pages = try std.math.add(u32, aggregate.fold_pages, value.fold_pages);
                aggregate.raw_rows = try std.math.add(u32, aggregate.raw_rows, value.raw_rows);
                aggregate.fold_rows = try std.math.add(u32, aggregate.fold_rows, value.fold_rows);
                if (aggregate.raw_rows >= 1 << 30 or aggregate.fold_rows >= 1 << 30) return error.PageForestResourceLimit;
                for (&aggregate.claims, value.claims) |*out, v| out.* = out.add(v);
            }
        }
        var tree_base: usize = 1;
        while (tree_base < geometry.nodes.len) tree_base = try std.math.mul(usize, tree_base, 2);
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 2 * tree_base, 32));
        if (bytes > limits.max_metadata_bytes) return error.PageForestResourceLimit;
        const tree = try a.alloc([32]u8, 2 * tree_base);
        errdefer a.free(tree);
        @memset(tree, @splat(0));
        var self = Owned{ .allocator = a, .allocation_owner = lease, .context = context, .raw = raw_copy, .fold = fold_copy, .geometry = geometry, .summaries = summaries, .identity = undefined, .recipe_tree = tree, .recipe_base = tree_base, .recipe_root = undefined, .source = context.admitted.identity, .seal = context.sealed.digest, .epoch = context.epoch.after_draw_digest, .base = context.base.digest, .limits = limits };
        for (geometry.nodes, 0..) |_, i| tree[tree_base + i] = try self.nodeRecipe(@intCast(i));
        var cursor = tree_base;
        while (cursor > 1) {
            cursor -= 1;
            tree[cursor] = pairDigest(tree[2 * cursor], tree[2 * cursor + 1]);
        }
        self.recipe_root = tree[1];
        self.identity = self.setupIdentity();
        return self;
    }
    pub fn require(self: *const Owned, expected: [32]u8) !void {
        if (!std.meta.eql(self.setupIdentity(), expected) or !std.meta.eql(self.identity, expected) or !std.meta.eql(self.source, self.context.admitted.identity) or !std.meta.eql(self.seal, self.context.sealed.digest) or !std.meta.eql(self.epoch, self.context.epoch.after_draw_digest) or !std.meta.eql(self.base, self.context.base.digest) or self.raw.len != self.context.raw.len or self.fold.len != self.context.fold.len or self.summaries.len != self.geometry.nodes.len or self.geometry.leaves != self.raw.len + self.fold.len) return error.UntrustedPageForestRoster;
    }
    /// Local-node check is bounded by fan-in; its typed source owner was built
    /// independently once. It grants no child proof or aggregate authority.
    pub fn node(self: *const Owned, index: u32, expected: [32]u8) !Node {
        try self.require(expected);
        if (index >= self.geometry.nodes.len) return error.InvalidPageForestTopology;
        try self.requireRecipe(index);
        const value = self.geometry.nodes[index];
        if (value.child_count == 0 or value.child_count > 4) return error.InvalidPageForestTopology;
        var cursor = value.range.first;
        var sum = Summary{ .range = value.range, .raw_pages = 0, .fold_pages = 0, .raw_rows = 0, .fold_rows = 0, .claims = @splat(Q.zero()) };
        for (value.children[0..value.child_count]) |ref| {
            if (ref == .node and ref.node >= index) return error.InvalidPageForestTopology;
            if (ref == .leaf) try self.requireLeaf(ref.leaf);
            const part = try self.summary(ref);
            if (part.range.first != cursor) return error.InvalidPageForestTopology;
            cursor = try std.math.add(u32, cursor, part.range.count);
            sum.raw_pages = try std.math.add(u32, sum.raw_pages, part.raw_pages);
            sum.fold_pages = try std.math.add(u32, sum.fold_pages, part.fold_pages);
            sum.raw_rows = try std.math.add(u32, sum.raw_rows, part.raw_rows);
            sum.fold_rows = try std.math.add(u32, sum.fold_rows, part.fold_rows);
            for (&sum.claims, part.claims) |*out, v| out.* = out.add(v);
        }
        if (cursor - value.range.first != value.range.count or !std.meta.eql(sum, self.summaries[index])) return error.MutatedPageForestSummary;
        return value;
    }
    fn requireLeaf(self: *const Owned, index: u32) !void {
        if (index >= self.geometry.leaves) return error.UntrustedPageForestRoster;
        if (index < self.raw.len) {
            const p = self.raw[index];
            if (p.admitted.context != self.context or !std.meta.eql(p.admitted.pin, self.context.raw[index]) or !std.meta.eql(p.admitted.limits.page, self.limits.pages)) return error.UntrustedPageForestRoster;
        } else {
            const ordinal = index - self.raw.len;
            const p = self.fold[ordinal];
            if (p.admitted.context != self.context or !std.meta.eql(p.admitted.pin, self.context.fold[ordinal]) or !std.meta.eql(p.admitted.limits.page, self.limits.pages)) return error.UntrustedPageForestRoster;
        }
    }
    pub fn summary(self: *const Owned, ref: Ref) !Summary {
        return switch (ref) {
            .leaf => |i| if (i < self.geometry.leaves) leafSummary(self.raw, self.fold, i) else error.InvalidPageForestTopology,
            .node => |i| if (i < self.summaries.len) self.summaries[i] else error.InvalidPageForestTopology,
        };
    }
    fn setupIdentity(self: *const Owned) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x50474650, 1, @intCast(self.raw.len), @intCast(self.fold.len), @intCast(self.geometry.nodes.len), self.geometry.root orelse std.math.maxInt(u32) });
        channel.mixRoot(self.source);
        channel.mixRoot(self.seal);
        channel.mixRoot(self.epoch);
        channel.mixRoot(self.base);
        channel.mixRoot(self.recipe_root);
        channel.mixRoot(self.geometry.digest);
        return channel.digestBytes();
    }
    fn nodeRecipe(self: *const Owned, index: u32) ![32]u8 {
        if (index >= self.geometry.nodes.len or index >= self.summaries.len) return error.InvalidPageForestTopology;
        const n = self.geometry.nodes[index];
        if (n.child_count == 0 or n.child_count > 4) return error.InvalidPageForestTopology;
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x5047464e, 1, index, n.range.first, n.range.count, n.child_count });
        mixSummary(&channel, self.summaries[index]);
        for (n.children[0..n.child_count]) |ref| {
            switch (ref) {
                .leaf => |i| {
                    try self.requireLeaf(i);
                    channel.mixU32s(&.{ 0, i });
                    if (i < self.raw.len) mixLeaf(&channel, self.raw[i]) else mixLeaf(&channel, self.fold[i - self.raw.len]);
                },
                .node => |i| {
                    if (i >= index) return error.InvalidPageForestTopology;
                    channel.mixU32s(&.{ 1, i });
                },
            }
            mixSummary(&channel, try self.summary(ref));
        }
        return channel.digestBytes();
    }
    fn requireRecipe(self: *const Owned, index: u32) !void {
        if (self.recipe_base == 0 or !std.math.isPowerOfTwo(self.recipe_base) or self.recipe_base < self.geometry.nodes.len or self.recipe_tree.len != 2 * self.recipe_base) return error.UntrustedPageForestRoster;
        var digest = try self.nodeRecipe(index);
        var position = self.recipe_base + index;
        while (position > 1) {
            digest = if (position & 1 == 0) pairDigest(digest, self.recipe_tree[position + 1]) else pairDigest(self.recipe_tree[position - 1], digest);
            position /= 2;
        }
        if (!std.meta.eql(digest, self.recipe_root)) return error.MutatedPageForestRecipe;
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.allocation_owner;
        for (self.raw) |policy| self.allocator.free(policy.schedule);
        for (self.fold) |policy| self.allocator.free(policy.schedule);
        self.allocator.free(self.raw);
        self.allocator.free(self.fold);
        self.allocator.free(self.summaries);
        self.allocator.free(self.recipe_tree);
        self.geometry.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
fn leafSummary(raw: []const Leaf.ForKind(.raw).Policy, fold: []const Leaf.ForKind(.fold).Policy, index: u32) Summary {
    const is_raw = index < raw.len;
    const claims = if (is_raw) raw[index].claims.semantic.claims else fold[index - raw.len].claims.semantic.claims;
    return .{ .range = .{ .first = index, .count = 1 }, .raw_pages = @intFromBool(is_raw), .fold_pages = @intFromBool(!is_raw), .raw_rows = if (is_raw) raw[index].admitted.pin.raw.page.chunks else 0, .fold_rows = if (is_raw) 0 else fold[index - raw.len].admitted.pin.page.count, .claims = A.flatten(claims) };
}

fn pairDigest(left: [32]u8, right: [32]u8) [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x5047464d, 1 });
    channel.mixRoot(left);
    channel.mixRoot(right);
    return channel.digestBytes();
}
fn mixSummary(channel: anytype, value: Summary) void {
    channel.mixU32s(&.{ value.range.first, value.range.count, value.raw_pages, value.fold_pages, value.raw_rows, value.fold_rows });
    channel.mixFelts(&value.claims);
}
fn mixLeaf(channel: anytype, policy: anytype) void {
    channel.mixRoot(policy.admitted.template_id);
    channel.mixRoot(policy.expected_id);
    channel.mixRoot(policy.key.public_schedule_digest);
    channel.mixFelts(&A.flatten(policy.claims.semantic.claims));
}
