//! Independently admitted original PAGE-root and RAM/range child coordinates.
//! Fresh children and their complete independent policies outlive this owner.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Root = @import("block_v5_memory_source_page_forest_source_v1.zig");
const Providers = @import("block_v5_memory_recursive_provider_source_v1.zig");
pub const Ram = Providers.ForKind(.ram);
pub const Range = Providers.ForKind(.range);
const Lane = @import("../prover/block_v5_ram_lanes_receiver_v1.zig");
const Plans = @import("../prover/block_v5_ram_lanes_plan_v1.zig");
const RangePlan = @import("../prover/block_v5_range16_v1.zig");
const Original = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const VERSION: u32 = 18;
pub const Wire = Original.Wire;
pub const scheduleDigest = Original.scheduleDigest;
pub const OUTPUT_TRANSITION: u32 = 67;
pub const Policy = struct { source: *const Root.Source, memory: Lane.Pins, ram: []const *const Ram.Fresh, range: []const *const Range.Fresh };
/// HARD direct-parent fan-in, including mandatory PAGE root. Large blocks
/// require a separate shard-local RAM/range forest; budgets cannot widen this.
pub const MAX_CHILD_VERIFIERS: usize = 4;
pub const Limits = struct { max_children: usize = MAX_CHILD_VERIFIERS, max_metadata_bytes: usize = 128 << 20 };
pub const Owner = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    policy: Policy,
    limits: Limits,
    ram: []Ram.Source,
    range: []Range.Source,
    plan: RangePlan.Plan,
    transition: Q,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
        try admit(a, policy, limits);
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const ram = try a.alloc(Ram.Source, policy.ram.len);
        errdefer a.free(ram);
        const range = try a.alloc(Range.Source, policy.range.len);
        errdefer a.free(range);
        var transition = Q.zero();
        for (ram, policy.ram) |*source, fresh| {
            source.* = try Ram.Source.init(fresh);
            transition = transition.add(fresh.open.public_values.sums.transition_sum);
        }
        for (range, policy.range) |*source, fresh| source.* = try Range.Source.init(fresh);
        const plan = try Plans.rangePlan(a, policy.memory.pins, policy.memory.expected_total_events, policy.memory.limits.plan);
        return .{ .allocator = a, .allocation_owner = lease, .policy = policy, .limits = limits, .ram = ram, .range = range, .plan = plan, .transition = transition };
    }
    pub fn deinit(self: *Owner) void {
        const lease = self.allocation_owner;
        self.plan.deinit(self.allocator);
        self.allocator.free(self.ram);
        self.allocator.free(self.range);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn validate(self: *const Owner) !void {
        try admit(self.allocator, self.policy, self.limits);
        if (self.ram.len != self.policy.ram.len or self.range.len != self.policy.range.len) return error.UnpairedRecursiveMemoryJoin;
        try Plans.admit(self.allocator, &self.plan, self.policy.memory.pins, self.policy.memory.expected_total_events, self.policy.memory.limits.plan);
        var transition = Q.zero();
        for (self.ram, self.policy.ram) |*source, fresh| {
            if (source.fresh != fresh) return error.UnpairedRecursiveMemoryJoin;
            try source.validate();
            transition = transition.add(fresh.open.public_values.sums.transition_sum);
        }
        for (self.range, self.policy.range) |*source, fresh| {
            if (source.fresh != fresh) return error.UnpairedRecursiveMemoryJoin;
            try source.validate();
        }
        if (!self.transition.eql(transition)) return error.UnpairedRecursiveMemoryJoin;
    }
    pub fn childCount(self: *const Owner) u32 {
        return @intCast(1 + self.ram.len + self.range.len);
    }
    pub fn cell(self: *const Owner, child: u32, index: u32) ![4]M {
        if (child == 0) return self.policy.source.cell(index);
        const ordinal: usize = child - 1;
        if (ordinal < self.ram.len) return self.ram[ordinal].cell(index);
        if (ordinal - self.ram.len < self.range.len) return self.range[ordinal - self.ram.len].cell(index);
        return error.InvalidRecursiveMemoryCell;
    }
    pub fn term(self: *const Owner, child: u32, index: u32) ![4]M {
        const terms = if (child == 0) self.policy.source.terms else if (child - 1 < self.ram.len) self.ram[child - 1].terms else if (child - 1 - self.ram.len < self.range.len) self.range[child - 1 - self.ram.len].terms else return error.InvalidRecursiveMemoryCell;
        if (index >= terms.len) return error.InvalidRecursiveMemoryCell;
        return terms[index].coordinates;
    }
    pub fn output(self: *const Owner, coordinate: u32) ![4]M {
        if (coordinate >= OUTPUT_TRANSITION + 4) return error.InvalidRecursiveMemoryCell;
        const context = self.policy.source.fresh.public.policy.forest.context;
        const source = &context.admitted.source;
        const word = if (coordinate < 7) ([_]u32{ 0x42354d4a, VERSION, 1, @intCast(self.ram.len), @intCast(self.range.len), @truncate(self.policy.memory.expected_total_events), @truncate(self.policy.memory.expected_total_events >> 32) })[coordinate] else if (coordinate < 63) block: {
            const roots = [_][32]u8{ context.base.digest, source.identity, context.sealed.digest, context.epoch.after_draw_digest, source.pins.initial.initial_rw_root, source.pins.expected_final_rw_root, self.policy.memory.seal.memory_plan_digest };
            const relative = coordinate - 7;
            break :block std.mem.readInt(u32, roots[relative / 8][4 * (relative % 8) ..][0..4], .little);
        } else if (coordinate < OUTPUT_TRANSITION) ([_]u32{ @truncate(source.records(.first_touches)), @truncate(source.records(.first_touches) >> 32), @truncate(source.records(.endpoints)), @truncate(source.records(.endpoints) >> 32) })[coordinate - 63] else self.transition.toM31Array()[coordinate - OUTPUT_TRANSITION].v;
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
        return bytes;
    }
};
pub fn admit(a: std.mem.Allocator, policy: Policy, limits: Limits) !void {
    const count = try std.math.add(usize, 1, try std.math.add(usize, policy.ram.len, policy.range.len));
    const bytes = try std.math.add(usize, try std.math.mul(usize, policy.ram.len, @sizeOf(Ram.Source) + @sizeOf(Q)), try std.math.mul(usize, policy.range.len, @sizeOf(Range.Source) + @sizeOf(RangePlan.Shard)));
    if (count > MAX_CHILD_VERIFIERS or count > limits.max_children or count >= core.fields.m31.Modulus or limits.max_metadata_bytes == 0 or bytes > limits.max_metadata_bytes) return error.RecursiveMemoryJoinResourceLimit;
    try policy.source.validate();
    const forest = policy.source.fresh.public.policy.forest;
    if (forest.geometry.root == null or policy.source.fresh.policy.public.index != forest.geometry.root.?) return error.NonrootRecursiveMemorySource;
    const context = forest.context;
    try Lane.admit(a, policy.memory, context.base, policy.memory.limits);
    if (!std.meta.eql(policy.memory.source, context.admitted.source.pins) or !std.meta.eql(policy.memory.expected_seal_digest, context.base.digest) or policy.ram.len != policy.memory.pins.len or policy.range.len != policy.memory.range_roots.len) return error.UntrustedRecursiveMemoryJoinAuthority;
    const word = try @import("../prover/block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, context.base);
    if (!std.meta.eql(word, context.epoch.challenges.source.word)) return error.UntrustedSourcePageJoinWordEpoch;
    var plan = try Plans.rangePlan(a, policy.memory.pins, policy.memory.expected_total_events, policy.memory.limits.plan);
    defer plan.deinit(a);
    for (policy.ram, policy.memory.pins, 0..) |fresh, pin, index| {
        try fresh.validate();
        const original = fresh.policy.admitted;
        if (!std.meta.eql(original.pin, pin) or original.pin.index != index or !std.meta.eql(original.sealed, context.base) or !std.meta.eql(original.pins, policy.memory.seal) or !std.meta.eql(original.config, context.fold_plan.config)) return error.UntrustedRecursiveMemoryRam;
    }
    for (policy.range, plan.shards, policy.memory.range_roots) |fresh, shard, roots| {
        try fresh.validate();
        const original = fresh.policy.admitted;
        if (!std.meta.eql(original.shard, shard) or !std.meta.eql(original.roots, roots) or !std.meta.eql(original.plan_digest, plan.digest) or !std.meta.eql(original.sealed, context.base) or !std.meta.eql(original.pins, policy.memory.seal) or !std.meta.eql(original.config, context.fold_plan.config)) return error.UntrustedRecursiveMemoryRange;
    }
    if (context.admitted.source.records(.first_touches) > policy.memory.expected_total_events) return error.UntrustedSourcePageJoinCensus;
}
pub const Values = struct {
    public: *const Owner,
    pub fn validate(self: @This()) !void {
        try self.public.validate();
    }
    pub fn requireConfig(self: @This(), config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.policy.memory.seal.config)) return error.UntrustedRecursiveMemoryJoinSecurity;
    }
    pub fn at(self: @This(), wire: Wire) ![4]M {
        const value = switch (wire.kind) {
            .output_slot => try self.public.output(wire.coordinate),
            .child_cell => try self.public.cell(wire.child, wire.coordinate),
            .child_term => {
                if (wire.part != null) return error.InvalidRecursiveMemoryCell;
                return self.public.term(wire.child, wire.coordinate);
            },
            else => return error.InvalidRecursiveMemoryCell,
        };
        return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
    }
    pub fn mix(self: @This(), channel: anytype) !void {
        const owner = self.public;
        const context = owner.policy.source.fresh.public.policy.forest.context;
        channel.mixU32s(&.{ 0x42354d4a, VERSION, 1, @intCast(owner.ram.len), @intCast(owner.range.len) });
        channel.mixU64(owner.policy.memory.expected_total_events);
        inline for (.{ context.base.digest, context.admitted.source.identity, context.sealed.digest, context.epoch.after_draw_digest, context.admitted.source.pins.initial.initial_rw_root, context.admitted.source.pins.expected_final_rw_root, owner.policy.memory.seal.memory_plan_digest }) |root| channel.mixRoot(root);
        channel.mixU64(context.admitted.source.records(.first_touches));
        channel.mixU64(context.admitted.source.records(.endpoints));
        channel.mixFelts(&.{owner.transition});
    }
};
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
        sum = if (wire.negative) sum.sub(term) else sum.add(term);
    }
    return sum;
}
pub const init = Owner.init;
