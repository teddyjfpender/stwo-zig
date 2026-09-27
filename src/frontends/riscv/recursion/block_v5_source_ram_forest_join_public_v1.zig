//! Final source PAGE root + ONE compact closed RAM/range root. No all-leaf
//! capture roster, no execution span inference, no complete block authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Source = @import("block_v5_memory_source_page_forest_summary_source_v1.zig");
pub const Memory = @import("block_v5_ram_range_forest_source_v1.zig");
const Forest = @import("block_v5_ram_range_forest_authority_v1.zig");
const Original = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const VERSION: u32 = 20;
pub const Wire = Original.Wire;
pub const Limits = struct { max_children: usize = 2 };
const claim_first: u32 = 43;
pub const CLAIM_FIRST = claim_first;
/// Statically selected setup-only serializers share the exact original owner,
/// value/epoch checks and framing. No Fresh verification API is introduced.
pub fn ForSources(comptime PageSource: type, comptime MemorySource: type) type {
    return struct {
        pub const Source = PageSource;
        pub const Memory = MemorySource;
        pub const CLAIM_FIRST = claim_first;
        pub const Wire = Original.Wire;
        pub const Policy = PolicyImpl;
        const PolicyImpl = struct { source: *const PageSource.Source, memory: *const Forest.Owned, expected_memory_plan: [32]u8, aggregate: ?*const MemorySource.Source };
        pub const Owner = OwnerImpl;
        const OwnerImpl = struct {
            policy: PolicyImpl,
            limits: Limits,
            lease: ?*Budget,
            pub const complete_block_authority = false;
            pub fn init(a: std.mem.Allocator, policy: PolicyImpl, limits: Limits) !OwnerImpl {
                if (limits.max_children == 0 or 1 + @as(usize, @intFromBool(policy.aggregate != null)) > limits.max_children) return error.SourceRamForestResourceLimit;
                const self = OwnerImpl{ .policy = policy, .limits = limits, .lease = null };
                try self.validate();
                return .{ .policy = policy, .limits = limits, .lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null };
            }
            pub fn deinit(self: *@This()) void {
                const lease = self.lease;
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
            pub fn validate(self: *const @This()) !void {
                const p = self.policy;
                try p.source.validate();
                try p.memory.require(p.expected_memory_plan);
                const page = pagePolicy(p.source).forest;
                const ctx = page.context;
                if (page.geometry.root == null or pagePolicy(p.source).index != page.geometry.root.? or !std.meta.eql(ctx.base, p.memory.sealed) or !std.meta.eql(ctx.admitted.source.pins, p.memory.memory.source) or !std.meta.eql(ctx.fold_plan.config, p.memory.memory.seal.config)) return error.UntrustedSourceRamForestAuthority;
                const word = try @import("../prover/block_v5_word_memory_protocol_v1.zig").Challenges.draw(p.source.allocator, ctx.base);
                if (!std.meta.eql(word, ctx.epoch.challenges.source.word)) return error.UntrustedSourceRamForestEpoch;
                if (p.aggregate) |s| {
                    try s.validate();
                    if (p.memory.geometry.root == null or memoryPolicy(s).index != p.memory.geometry.root.? or memoryPolicy(s).forest != p.memory or !std.meta.eql(memoryPolicy(s).expected_plan, p.expected_memory_plan)) return error.UntrustedSourceRamForestRoot;
                } else if (p.memory.geometry.root != null or p.memory.memory.pins.len != 0 or p.memory.memory.range_roots.len != 0 or p.memory.memory.expected_total_events != 0) return error.MissingSourceRamForestRoot;
                if (ctx.admitted.source.records(.first_touches) > p.memory.memory.expected_total_events) return error.UntrustedSourceRamForestCensus;
            }
            pub fn output(self: *const @This(), index: u32) ![4]M {
                if (index >= claim_first + 4) return error.InvalidSourceRamForestCell;
                const p = self.policy;
                const ctx = pagePolicy(p.source).forest.context;
                const word: u32 = if (index < 3) ([_]u32{ 0x5352464a, VERSION, @intFromBool(p.aggregate != null) })[index] else if (index < claim_first) blk: {
                    const roots = [_][32]u8{ ctx.base.digest, ctx.admitted.source.identity, ctx.sealed.digest, ctx.epoch.after_draw_digest, p.expected_memory_plan };
                    const pos = index - 3;
                    break :blk std.mem.readInt(u32, roots[pos / 8][4 * (pos % 8) ..][0..4], .little);
                } else (if (p.aggregate) |s| memorySummary(s).value[0] else Q.zero()).toM31Array()[index - claim_first].v;
                var out: [4]M = undefined;
                for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
                return out;
            }
        };
        pub const Values = ValuesImpl;
        const ValuesImpl = struct {
            public: *const OwnerImpl,
            pub fn validate(self: @This()) !void {
                try self.public.validate();
            }
            pub fn requireConfig(self: @This(), config: core.pcs.PcsConfig) !void {
                if (!std.meta.eql(config, self.public.policy.memory.memory.seal.config)) return error.UntrustedSourceRamForestSecurity;
            }
            pub fn mix(self: @This(), c: anytype) !void {
                try self.validate();
                const p = self.public.policy;
                const ctx = pagePolicy(p.source).forest.context;
                c.mixU32s(&.{ 0x5352464a, VERSION, @intFromBool(p.aggregate != null) });
                inline for (.{ ctx.base.digest, ctx.admitted.source.identity, ctx.sealed.digest, ctx.epoch.after_draw_digest, p.expected_memory_plan }) |root| c.mixRoot(root);
                c.mixFelts(&.{if (p.aggregate) |s| memorySummary(s).value[0] else Q.zero()});
            }
            pub fn at(self: @This(), wire: Original.Wire) ![4]M {
                if (wire.kind == .child_term) return error.ClosedSourceRamForestHasNoPublicTerms;
                const value = if (wire.kind == .output_slot) try self.public.output(wire.coordinate) else if (wire.kind == .child_cell and wire.child == 0) try self.public.policy.source.cell(wire.coordinate) else if (wire.kind == .child_cell and wire.child == 1 and self.public.policy.aggregate != null) try self.public.policy.aggregate.?.cell(wire.coordinate) else return error.InvalidSourceRamForestCell;
                return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
            }
        };
    };
}
pub fn pagePolicy(source: anytype) @TypeOf(if (@hasField(@TypeOf(source.*), "fresh")) source.fresh.public.policy else source.public.policy) {
    return if (comptime @hasField(@TypeOf(source.*), "fresh")) source.fresh.public.policy else source.public.policy;
}
pub fn memoryPolicy(source: anytype) @TypeOf(if (@hasField(@TypeOf(source.*), "fresh")) source.fresh.public.policy else source.public.policy) {
    return if (comptime @hasField(@TypeOf(source.*), "fresh")) source.fresh.public.policy else source.public.policy;
}
pub fn memorySummary(source: anytype) @TypeOf(if (@hasField(@TypeOf(source.*), "fresh")) source.fresh.public.summary else source.public.summary) {
    return if (comptime @hasField(@TypeOf(source.*), "fresh")) source.fresh.public.summary else source.public.summary;
}
const Default = ForSources(Source, Memory);
pub const Policy = Default.Policy;
pub const Owner = Default.Owner;
pub const Values = Default.Values;
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len != 0) return error.ClosedSourceRamForestHasNoPublicTerms;
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x53524657, VERSION, 0 });
    return c.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = relations;
    _ = try scheduleDigest(wires);
    try values.validate();
    return .zero();
}
pub const init = Owner.init;
