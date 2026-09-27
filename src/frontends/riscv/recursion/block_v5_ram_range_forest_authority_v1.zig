//! Independently owned forest setup and proposal summaries, NOT proof receipts.
//! Original provider policies borrow their independently reconstructed admission.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Geometry = @import("block_v5_ram_range_forest_plan_v1.zig");
const Provider = @import("block_v5_memory_recursive_provider_source_v1.zig");
const Lane = @import("../prover/block_v5_ram_lanes_receiver_v1.zig");
const Plans = @import("../prover/block_v5_ram_lanes_plan_v1.zig");
const RangePlan = @import("../prover/block_v5_range16_v1.zig");
const Seal = @import("../prover/block_v5_source_seal_v1.zig");
pub const Ram = Provider.ForKind(.ram);
pub const Range = Provider.ForKind(.range);
pub const CLAIM_COUNT: usize = 22; // transition/link/initial/endpoint/count +17 planes
pub const Claims = [CLAIM_COUNT]Q;
pub const Owned = struct {
    a: std.mem.Allocator,
    owner: ?*Budget,
    memory: Lane.Pins,
    sealed: Seal.Sealed,
    ram: []Ram.Policy,
    range: []Range.Policy,
    range_plan: RangePlan.Plan,
    geometry: Geometry.Geometry,
    summaries: []Claims,
    recipe_tree: [][32]u8,
    recipe_base: usize,
    recipe_root: [32]u8,
    identity: [32]u8,
    limits: Geometry.Limits,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, memory: Lane.Pins, sealed: Seal.Sealed, ram: []const Ram.Policy, range: []const Range.Policy, limits: Geometry.Limits) !Owned {
        if (ram.len != memory.pins.len or range.len != memory.range_roots.len) return error.UntrustedRamRangeForestRoster;
        try Lane.admit(a, memory, sealed, memory.limits);
        var plan = try Plans.rangePlan(a, memory.pins, memory.expected_total_events, limits.lane);
        errdefer plan.deinit(a);
        var geometry = try Geometry.derive(a, memory.pins, &plan, limits);
        errdefer geometry.deinit();
        var tree_base: usize = 1;
        while (tree_base < geometry.nodes.len) tree_base = try std.math.mul(usize, tree_base, 2);
        var bytes = try std.math.add(usize, try std.math.mul(usize, ram.len, @sizeOf(Ram.Policy)), try std.math.mul(usize, range.len, @sizeOf(Range.Policy)));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, geometry.nodes.len, @sizeOf(Claims) + @sizeOf(Geometry.Node)));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 2 * tree_base, 32));
        if (bytes > limits.max_metadata_bytes) return error.RamRangeForestResourceLimit;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const rc = try a.dupe(Ram.Policy, ram);
        errdefer a.free(rc);
        var made_r: usize = 0;
        errdefer for (rc[0..made_r]) |p| a.free(p.schedule);
        const pc = try a.dupe(Range.Policy, range);
        errdefer a.free(pc);
        var made_p: usize = 0;
        errdefer for (pc[0..made_p]) |p| a.free(p.schedule);
        for (ram, rc, memory.pins) |p, *copy, pin| {
            _ = try p.authority();
            if (!std.meta.eql(p.admitted.pin, pin) or !std.meta.eql(p.admitted.sealed, sealed) or !std.meta.eql(p.admitted.pins, memory.seal)) return error.UntrustedRamRangeForestRoster;
            bytes = try std.math.add(usize, bytes, try std.math.mul(usize, p.schedule.len, @sizeOf(@TypeOf(p.schedule[0]))));
            if (bytes > limits.max_metadata_bytes) return error.RamRangeForestResourceLimit;
            copy.schedule = try a.dupe(@TypeOf(p.schedule[0]), p.schedule);
            made_r += 1;
        }
        for (range, pc, plan.shards, memory.range_roots) |p, *copy, shard, roots| {
            _ = try p.authority();
            if (!std.meta.eql(p.admitted.shard, shard) or !std.meta.eql(p.admitted.roots, roots) or !std.meta.eql(p.admitted.plan_digest, plan.digest) or !std.meta.eql(p.admitted.sealed, sealed) or !std.meta.eql(p.admitted.pins, memory.seal) or !std.meta.eql(p.admitted.config, memory.seal.config) or !std.meta.eql(p.key.config, memory.seal.config)) return error.UntrustedRamRangeForestRoster;
            bytes = try std.math.add(usize, bytes, try std.math.mul(usize, p.schedule.len, @sizeOf(@TypeOf(p.schedule[0]))));
            if (bytes > limits.max_metadata_bytes) return error.RamRangeForestResourceLimit;
            copy.schedule = try a.dupe(@TypeOf(p.schedule[0]), p.schedule);
            made_p += 1;
        }
        const sums = try a.alloc(Claims, geometry.nodes.len);
        errdefer a.free(sums);
        for (geometry.nodes, sums) |entry, *sum| {
            sum.* = @splat(Q.zero());
            for (entry.children[0..entry.child_count]) |ref| {
                const child = switch (ref) {
                    .ram => |i| try ramClaims(rc[i]),
                    .range => continue,
                    .node => |i| sums[i],
                };
                for (sum, child) |*out, value| out.* = out.add(value);
            }
            if (entry.kind != .partial) {
                for (sum[5..]) |*value| value.* = Q.zero();
            }
        }
        const tree = try a.alloc([32]u8, 2 * tree_base);
        errdefer a.free(tree);
        @memset(tree, @splat(0));
        var self = Owned{ .a = a, .owner = lease, .memory = memory, .sealed = sealed, .ram = rc, .range = pc, .range_plan = plan, .geometry = geometry, .summaries = sums, .recipe_tree = tree, .recipe_base = tree_base, .recipe_root = undefined, .identity = undefined, .limits = limits };
        for (geometry.nodes, 0..) |_, i| tree[tree_base + i] = try self.nodeRecipe(@intCast(i));
        var cursor = tree_base;
        while (cursor > 1) {
            cursor -= 1;
            tree[cursor] = pair(tree[2 * cursor], tree[2 * cursor + 1]);
        }
        self.recipe_root = tree[1];
        self.identity = self.setupIdentity();
        return self;
    }
    pub fn require(self: *const Owned, expected: [32]u8) !void {
        if (!std.meta.eql(self.identity, expected) or !std.meta.eql(self.setupIdentity(), expected) or self.ram.len != self.memory.pins.len or self.range.len != self.memory.range_roots.len or self.geometry.lanes != self.ram.len or self.geometry.nodes.len != self.summaries.len or self.geometry.root != (if (self.geometry.nodes.len == 0) @as(?u32, null) else @as(u32, @intCast(self.geometry.nodes.len - 1))) or !std.meta.eql(self.memory.expected_seal_digest, self.sealed.digest)) return error.UntrustedRamRangeForestRoster;
    }
    pub fn node(self: *const Owned, index: u32, expected: [32]u8) !Geometry.Node {
        try self.require(expected);
        if (index >= self.geometry.nodes.len or self.recipe_base == 0 or !std.math.isPowerOfTwo(self.recipe_base) or self.recipe_base < self.geometry.nodes.len or self.recipe_tree.len != 2 * self.recipe_base) return error.UntrustedRamRangeForestTopology;
        const entry = self.geometry.nodes[index];
        if (entry.child_count == 0 or entry.child_count > 4) return error.UntrustedRamRangeForestTopology;
        var digest = try self.nodeRecipe(index);
        var at = self.recipe_base + index;
        while (at > 1) {
            digest = if (at & 1 == 0) pair(digest, self.recipe_tree[at + 1]) else pair(self.recipe_tree[at - 1], digest);
            at /= 2;
        }
        if (!std.meta.eql(digest, self.recipe_root)) return error.MutatedRamRangeForestRecipe;
        return entry;
    }
    pub fn claim(self: *const Owned, ref: Geometry.Ref) !Claims {
        return switch (ref) {
            .ram => |i| if (i < self.ram.len) ramClaims(self.ram[i]) else error.UntrustedRamRangeForestRoster,
            .node => |i| if (i < self.summaries.len) self.summaries[i] else error.UntrustedRamRangeForestRoster,
            .range => error.UntrustedRamRangeForestRoster,
        };
    }
    fn setupIdentity(self: *const Owned) [32]u8 {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x52524641, Geometry.VERSION, @intCast(self.ram.len), @intCast(self.range.len), @intCast(self.geometry.nodes.len) });
        c.mixRoot(self.sealed.digest);
        c.mixRoot(self.memory.seal.memory_plan_digest);
        c.mixRoot(self.geometry.digest);
        c.mixRoot(self.recipe_root);
        return c.digestBytes();
    }
    fn nodeRecipe(self: *const Owned, index: u32) ![32]u8 {
        const n = self.geometry.nodes[index];
        if (n.child_count == 0 or n.child_count > 4) return error.UntrustedRamRangeForestTopology;
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x5252464e, Geometry.VERSION, index });
        Geometry.mixNode(&c, n);
        c.mixFelts(&self.summaries[index]);
        for (n.children[0..n.child_count]) |ref| switch (ref) {
            .ram => |i| {
                if (i >= self.ram.len) return error.UntrustedRamRangeForestRoster;
                const p = self.ram[i];
                if (!std.meta.eql(p.admitted.pin, self.memory.pins[i]) or !std.meta.eql(p.admitted.sealed, self.sealed) or !std.meta.eql(p.admitted.pins, self.memory.seal)) return error.UntrustedRamRangeForestRoster;
                c.mixRoot(p.expected_id);
                c.mixRoot(p.key.public_schedule_digest);
                c.mixRoot(p.admitted.template_id);
                c.mixFelts(&try ramClaims(p));
            },
            .range => |i| {
                if (i >= self.range.len or n.kind != .shard or i != n.shards.first) return error.UntrustedRamRangeForestRoster;
                const p = self.range[i];
                if (!std.meta.eql(p.admitted.shard, self.range_plan.shards[i]) or !std.meta.eql(p.admitted.roots, self.memory.range_roots[i]) or !std.meta.eql(p.admitted.sealed, self.sealed) or !std.meta.eql(p.admitted.pins, self.memory.seal)) return error.UntrustedRamRangeForestRoster;
                c.mixRoot(p.expected_id);
                c.mixRoot(p.key.public_schedule_digest);
                c.mixRoot(p.admitted.template_id);
                c.mixFelts(&.{p.proposal.claim.sum});
                c.mixU64(p.proposal.claim.count);
            },
            .node => |i| {
                if (i >= index) return error.UntrustedRamRangeForestTopology;
                c.mixFelts(&self.summaries[i]);
            },
        };
        return c.digestBytes();
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.owner;
        for (self.ram) |p| self.a.free(p.schedule);
        for (self.range) |p| self.a.free(p.schedule);
        self.a.free(self.ram);
        self.a.free(self.range);
        self.a.free(self.summaries);
        self.a.free(self.recipe_tree);
        self.geometry.deinit();
        self.range_plan.deinit(self.a);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub fn ramClaims(p: Ram.Policy) !Claims {
    const s = p.proposal.sums;
    if (s.endpoint_count >= core.fields.m31.Modulus) return error.RamRangeForestFieldCensus;
    return [_]Q{ s.transition_sum, s.link_sum, s.initial_sum, s.endpoint_sum, Q.fromBase(M.fromCanonical(@intCast(s.endpoint_count))) } ++ s.range_sums;
}
fn pair(left: [32]u8, right: [32]u8) [32]u8 {
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x5252464d, Geometry.VERSION });
    c.mixRoot(left);
    c.mixRoot(right);
    return c.digestBytes();
}
