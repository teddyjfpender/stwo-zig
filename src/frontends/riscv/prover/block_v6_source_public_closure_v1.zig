//! Original PAGE + RAM + range algebra over root-authenticated public values.
//! This module grants no proof authority. The enclosing receiver must verify
//! exactly these values under its independently admitted mixed-verifier key.
//! Its result still leaves execution, caller, ROM and lookup relations open.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Pages = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const PageAdmission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
const PageBus = @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig");
const Auxiliary = @import("../recursion/block_v6_auxiliary_direct_public_v1.zig");
const Providers = @import("../recursion/block_v6_provider_batch_public_v1.zig");
const LaneReceiver = @import("block_v5_ram_lanes_receiver_v1.zig");
const LanePlan = @import("block_v5_ram_lanes_plan_v1.zig");
const LaneJoin = @import("block_v5_ram_lanes_join_v1.zig");
const Algebra = @import("block_v5_memory_source_page_join_algebra_v1.zig");
const Owner = @import("block_v5_memory_source_page_join_owner_v1.zig");
pub fn Page(comptime kind: Semantic.Kind) type {
    return struct {
        admitted: *const PageAdmission.ForKind(kind).Prepared,
        claims: PageBus.ForKind(kind).Claims,
        public: PageBus.ForKind(kind).Values,
    };
}
pub const Input = struct {
    raw: []const Page(.raw),
    fold: []const Page(.fold),
    lanes: []const Providers.Definition(.ram_lanes).Bus.Values,
    ranges: []const Providers.Definition(.range16).Bus.Values,
};

/// Caller supplies the independent source context and lane roster, never a
/// producer success receipt. All claims are compared with canonical public
/// frames, including routing offsets, before any algebra is evaluated.
pub fn close(backing: std.mem.Allocator, context: *const Pages.Context, memory: LaneReceiver.Pins, input: Input, limits: Owner.Limits) !Owner.Open {
    if (try std.math.add(usize, input.raw.len, input.fold.len) > limits.max_pages or memory.pins.len > limits.max_memory_instances)
        return error.SourcePageJoinResourceLimit;
    if (input.raw.len != context.raw.len or input.fold.len != context.fold.len or input.lanes.len != memory.pins.len or input.ranges.len != memory.range_roots.len)
        return error.IncompleteSourcePublicRoster;
    if (limits.max_setup_bytes == 0) return error.SourcePageJoinResourceLimit;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_setup_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    try context.require(a, limits.pages);
    try LaneReceiver.admit(a, memory, context.base, memory.limits);
    if (!std.meta.eql(context.admitted.source.pins, memory.source) or !std.meta.eql(context.base.digest, memory.expected_seal_digest)) return error.UntrustedSourcePublicAuthority;
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, context.base);
    if (!std.meta.eql(word, context.epoch.challenges.source.word)) return error.UntrustedSourcePageJoinWordEpoch;
    var totals = Algebra.Totals{};
    try pages(.raw, a, context, input.raw, &totals);
    try pages(.fold, a, context, input.fold, &totals);
    var plan = try LanePlan.rangePlan(a, memory.pins, memory.expected_total_events, memory.limits.plan);
    defer plan.deinit(a);
    if (plan.shards.len != input.ranges.len) return error.IncompleteSourcePublicRoster;
    const range_sums = try a.alloc(Q, memory.pins.len);
    defer a.free(range_sums);
    var transition = Q.zero();
    var endpoints: u64 = 0;
    var range_count: u64 = 0;
    for (memory.pins, input.lanes, range_sums) |pin, value, *range_sum| {
        try value.validate();
        if (!std.meta.eql(value.pin, pin) or !std.meta.eql(value.sealed, context.base.digest) or !std.meta.eql(pin.config, context.fold_plan.config)) return error.UntrustedSourcePublicLane;
        const buses = LaneJoin.buses(value.sums);
        transition = transition.add(buses.transition_sum);
        totals.predecessor = totals.predecessor.add(buses.link_sum);
        totals.initial = totals.initial.add(buses.initial_sum);
        totals.endpoint = totals.endpoint.add(buses.endpoint_sum);
        endpoints = try std.math.add(u64, endpoints, buses.endpoint_count);
        range_count = try std.math.add(u64, range_count, buses.range_count);
        range_sum.* = buses.rangeSum();
    }
    for (plan.shards, memory.range_roots, input.ranges) |shard, roots, value| {
        try value.validate();
        if (!std.meta.eql(value.template, @import("block_v5_range16_recursive_admission_v1.zig").templateId(context.fold_plan.config, roots[0])) or !std.meta.eql(value.shard, shard) or !std.meta.eql(value.roots, roots) or !std.meta.eql(value.plan, plan.digest) or !std.meta.eql(value.sealed, context.base.digest)) return error.UntrustedSourcePublicRange;
        var sum = value.sum;
        for (range_sums[shard.first_instance..][0..shard.instance_count]) |request| sum = sum.add(request);
        if (!sum.isZero()) return error.UnclosedV5Range16Relation;
    }
    const source = &context.admitted.source;
    if (endpoints != source.records(.endpoints) or source.records(.first_touches) > memory.expected_total_events) return error.UntrustedSourcePageJoinCensus;
    try Algebra.close(&context.admitted, totals);
    return .{ .transition_sum = transition, .events = memory.expected_total_events, .first_touches = source.records(.first_touches), .endpoints = endpoints, .range_requests = range_count, .memory_instances = @intCast(memory.pins.len), .range_shards = @intCast(plan.shards.len), .raw_pages = @intCast(context.raw.len), .fold_pages = @intCast(context.fold.len), .base_seal = context.base.digest, .page_seal = context.sealed.digest, .epoch = context.epoch.after_draw_digest, .source_identity = source.identity, .memory_plan = memory.seal.memory_plan_digest, .initial_root = source.pins.initial.initial_rw_root, .final_root = source.pins.expected_final_rw_root };
}
fn pages(comptime kind: Semantic.Kind, a: std.mem.Allocator, context: *const Pages.Context, entries: []const Page(kind), totals: *Algebra.Totals) !void {
    const family = if (kind == .raw) Auxiliary.Family.source_raw else Auxiliary.Family.source_fold;
    const expected_pins = if (kind == .raw) context.raw else context.fold;
    for (entries, expected_pins, 0..) |entry, expected, index| {
        try entry.admitted.validate(entry.admitted.template_id);
        const original = entry.admitted.context;
        if (!std.meta.eql(entry.admitted.pin, expected) or !std.meta.eql(original.independent_digest, context.independent_digest) or
            !std.meta.eql(original.admitted.identity, context.admitted.identity) or !std.meta.eql(original.sealed.digest, context.sealed.digest) or
            !std.meta.eql(original.base.digest, context.base.digest) or !std.meta.eql(original.epoch.after_draw_digest, context.epoch.after_draw_digest)) return error.UntrustedSourcePublicPage;
        var rebuilt = try PageBus.ForKind(kind).Values.init(a, entry.admitted, entry.claims);
        defer rebuilt.deinit();
        const actual = [_]Auxiliary.Child{.{ .index = @intCast(index), .value = @unionInit(Auxiliary.Value, @tagName(family), entry.public) }};
        const expected_values = [_]Auxiliary.Child{.{ .index = @intCast(index), .value = @unionInit(Auxiliary.Value, @tagName(family), rebuilt) }};
        // Every frame field is checked, even without an external wire list.
        try (Auxiliary.Values{ .children = &actual }).requireSameFrame(.{ .children = &expected_values });
        const claims = entry.claims.semantic.claims;
        try Algebra.canonical(claims);
        if (kind == .raw) {
            inline for (std.meta.fields(@TypeOf(claims.fold))) |field| if (!@field(claims.fold, field.name).isZero()) return error.UntrustedSourcePageJoinReceipt;
            add(&totals.raw, claims.source);
            totals.indexed = totals.indexed.add(claims.indexed);
        } else {
            inline for (std.meta.fields(@TypeOf(claims.source))) |field| if (!@field(claims.source, field.name).isZero()) return error.UntrustedSourcePageJoinReceipt;
            if (!claims.indexed.isZero()) return error.UntrustedSourcePageJoinReceipt;
            add(&totals.fold, claims.fold);
        }
    }
}
fn add(out: anytype, value: anytype) void {
    inline for (std.meta.fields(@TypeOf(value))) |field| @field(out.*, field.name) = @field(out.*, field.name).add(@field(value, field.name));
}
