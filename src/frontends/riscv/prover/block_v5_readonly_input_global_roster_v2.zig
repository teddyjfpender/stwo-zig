//! Independent source/group/provider/range inventory for the v2 shared epoch.
//! Admission copies bounded metadata once. Only fresh original AIR/PCS proofs
//! and exact group joins close the requests; this authority admits expected pins.
const std = @import("std");
const core = @import("stwo_core");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Collection = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_v2.zig");
const Readonly = @import("block_v5_caller_readonly_protocol_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Range = @import("block_v5_range16_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Digest = [32]u8;
pub const SourceRecord = Collection.SourceRecord;
pub const Group = Collection.Group;
pub const Census = Collection.Census;
pub const ProviderPin = struct {
    shape: Provider.Shard,
    roots: [2]Digest,
    ordinal_digest: Digest,
    plan_digest: Digest,
    config: core.pcs.PcsConfig,
    range_index: u32,
};
pub const RangePin = struct {
    index: u32,
    group_id: u32,
    provider_index: u32,
    shard: Range.Shard,
    plan_digest: Digest,
    roots: [2]Digest,
    counter_digest: Digest,
    config: core.pcs.PcsConfig,
};
pub const Inputs = struct {
    plan_digest: Digest,
    selection_digest: Digest,
    initial_source_plan_digest: Digest,
    config: core.pcs.PcsConfig,
    max_group_events: u64 = core.fields.m31.Modulus - 1,
    sources: []const SourceRecord,
    groups: []const Group,
    providers: []const ProviderPin,
    ranges: []const RangePin,
};
pub const Limits = struct { max_metadata_bytes: usize = 64 * 1024 * 1024 };
/// Distinct immutable borrow. The Authority must outlive every use; releasing
/// this view never frees or copies the actual admitted interval storage.
pub const BorrowedPlan = struct {
    intervals: []const Plan.Interval,
    digest: Digest,
    pub fn deinit(_: *BorrowedPlan) void {}
    pub fn find(self: BorrowedPlan, address: u32) !usize {
        return Plan.findInterval(self.intervals, address);
    }
};
fn zero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}
fn requireRoots(roots: anytype) !void {
    for (roots) |root| if (zero(root)) return error.InvalidGlobalReadonlyRoot;
}
fn mixCensus(channel: anytype, census: Census) void {
    channel.mixU64(census.all_rw);
    channel.mixU64(census.mutable);
    channel.mixU64(census.readonly);
}
/// Exact ordered inventory, before the common seal and before all draws.
/// All ranges are dedicated to one admitted provider; no pooled substitution.
pub fn digest(inputs: Inputs) !Digest {
    try @import("blake3_execution_protocol.zig").validateConfig(inputs.config);
    if (zero(inputs.plan_digest) or zero(inputs.selection_digest) or zero(inputs.initial_source_plan_digest) or
        inputs.sources.len == 0 or inputs.groups.len == 0 or inputs.sources.len >= core.fields.m31.Modulus or
        inputs.groups.len >= core.fields.m31.Modulus or inputs.providers.len > std.math.maxInt(u32) or
        inputs.ranges.len != inputs.providers.len or inputs.max_group_events == 0 or inputs.max_group_events >= core.fields.m31.Modulus) return error.InvalidGlobalReadonlyRoster;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Global.TAG, Global.VERSION, 0x524f5354 });
    channel.mixRoot(Global.abiId());
    channel.mixRoot(inputs.plan_digest);
    channel.mixRoot(inputs.selection_digest);
    channel.mixRoot(inputs.initial_source_plan_digest);
    inputs.config.mixInto(&channel);
    channel.mixU64(inputs.max_group_events);
    channel.mixU64(inputs.sources.len);
    channel.mixU64(inputs.groups.len);
    channel.mixU64(inputs.providers.len);
    channel.mixU64(inputs.ranges.len);
    var source_at: usize = 0;
    var provider_at: usize = 0;
    var next_native: u32 = 0;
    for (inputs.groups, 0..) |group, gi| {
        if (group.index != gi or group.first_source != source_at or group.source_count == 0 or group.census.all_rw > inputs.max_group_events or
            group.source_count > inputs.sources.len - source_at) return error.InvalidGlobalReadonlyGroup;
        try group.census.require(group.census.all_rw);
        if (gi != 0 and try std.math.add(u64, inputs.groups[gi - 1].census.all_rw, inputs.sources[source_at].census.all_rw) <= inputs.max_group_events) return error.NoncanonicalGlobalReadonlyGroupBoundary;
        var actual = Census{ .all_rw = 0, .mutable = 0, .readonly = 0 };
        channel.mixU32s(&.{ 1, group.index, group.first_source, group.source_count });
        mixCensus(&channel, group.census);
        for (inputs.sources[source_at..][0..group.source_count], source_at..) |source, ordinal| {
            if (source.group_id != group.index or zero(source.counter_digest)) return error.InvalidGlobalReadonlySource;
            try source.census.require(source.census.all_rw);
            try requireRoots(source.roots);
            if (source.kind == .native) {
                if (source.index != next_native or (source.census.all_rw == 0) != (source.classifier_roots == null) or
                    (source.census.all_rw == 0 and source.row_log != 0)) return error.InvalidGlobalReadonlySource;
                if (source.classifier_roots) |roots| {
                    try requireRoots(roots);
                    if (source.row_log < 1 or source.row_log > 24 or source.census.all_rw > (@as(u64, 1) << @intCast(source.row_log))) return error.InvalidGlobalReadonlySource;
                }
                next_native += 1;
            } else if (ordinal == 0 or inputs.sources[ordinal - 1].kind != .native or
                source.index != inputs.sources[ordinal - 1].index or source.classifier_roots != null or source.row_log != 0) return error.InvalidGlobalReadonlySource;
            actual = .{ .all_rw = try std.math.add(u64, actual.all_rw, source.census.all_rw), .mutable = try std.math.add(u64, actual.mutable, source.census.mutable), .readonly = try std.math.add(u64, actual.readonly, source.census.readonly) };
            channel.mixU32s(&.{ 2, @intCast(ordinal), @intFromEnum(source.kind), source.index, source.group_id, source.row_log, @intFromBool(source.classifier_roots != null), @intFromEnum(source.counter_schema) });
            for (source.roots) |root| channel.mixRoot(root);
            if (source.classifier_roots) |roots| for (roots) |root| channel.mixRoot(root);
            channel.mixRoot(source.counter_digest);
            mixCensus(&channel, source.census);
        }
        if (!std.meta.eql(actual, group.census)) return error.InvalidGlobalReadonlyGroupCensus;
        source_at += group.source_count;
        var first_fragment: u64 = 0;
        var provider_events: u64 = 0;
        var provider_readonly: u64 = 0;
        while (provider_at < inputs.providers.len and inputs.providers[provider_at].shape.group_id == group.index) : (provider_at += 1) {
            const pin = inputs.providers[provider_at];
            try pin.shape.require();
            if (pin.shape.index != provider_at or pin.shape.first_fragment != first_fragment or pin.range_index != provider_at or
                zero(pin.ordinal_digest) or !std.meta.eql(pin.plan_digest, inputs.plan_digest) or !std.meta.eql(pin.config, inputs.config)) return error.InvalidGlobalReadonlyProvider;
            try requireRoots(pin.roots);
            first_fragment = try std.math.add(u64, first_fragment, pin.shape.fragment_count);
            provider_events = try std.math.add(u64, provider_events, pin.shape.counts.events);
            provider_readonly = try std.math.add(u64, provider_readonly, pin.shape.counts.readonly);
            channel.mixU32s(&.{ 3, pin.shape.index, pin.shape.group_id, pin.shape.fragment_count, pin.shape.row_log, pin.range_index });
            channel.mixU64(pin.shape.first_fragment);
            channel.mixU64(pin.shape.counts.events);
            channel.mixU64(pin.shape.counts.readonly);
            channel.mixU64(pin.shape.counts.range_requests);
            for (pin.roots) |root| channel.mixRoot(root);
            channel.mixRoot(pin.ordinal_digest);
            channel.mixRoot(pin.plan_digest);
            const range_pin = inputs.ranges[provider_at];
            if (range_pin.index != provider_at or range_pin.provider_index != provider_at or range_pin.group_id != group.index or
                range_pin.shard.index != range_pin.index or range_pin.shard.first_instance != provider_at or range_pin.shard.instance_count != 1 or
                range_pin.shard.request_count != pin.shape.counts.range_requests or range_pin.shard.request_count > Range.MAX_REQUESTS or
                zero(range_pin.counter_digest) or !std.meta.eql(range_pin.plan_digest, rangePlanDigest(inputs.plan_digest, pin.shape)) or
                !std.meta.eql(range_pin.config, inputs.config)) return error.InvalidGlobalReadonlyRange;
            try requireRoots(range_pin.roots);
            channel.mixU32s(&.{ 4, range_pin.index, range_pin.group_id, range_pin.provider_index, range_pin.shard.first_instance, range_pin.shard.instance_count });
            channel.mixU64(range_pin.shard.request_count);
            channel.mixRoot(range_pin.plan_digest);
            for (range_pin.roots) |root| channel.mixRoot(root);
            channel.mixRoot(range_pin.counter_digest);
        }
        if (provider_events != group.census.all_rw or provider_readonly != group.census.readonly) return error.IncompleteGlobalReadonlyProviders;
    }
    if (source_at != inputs.sources.len or provider_at != inputs.providers.len or next_native == 0) return error.IncompleteGlobalReadonlyRoster;
    return channel.digestBytes();
}
pub fn rangePlanDigest(plan: Digest, shape: Provider.Shard) Digest {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Global.TAG, Global.VERSION, 0x52414e47, shape.index, shape.group_id, shape.fragment_count, shape.row_log });
    channel.mixRoot(plan);
    channel.mixU64(shape.first_fragment);
    channel.mixU64(shape.counts.events);
    channel.mixU64(shape.counts.readonly);
    channel.mixU64(shape.counts.range_requests);
    return channel.digestBytes();
}
fn sourceEntry(entries: []const Seal.Entry, source: SourceRecord) !Seal.Entry {
    const family: Seal.Family = if (source.kind == .native) .execution else .precompile;
    const access_family: Seal.Family = if (source.kind == .native) .execution_sidecar else .execution_external_sidecar;
    const original = try findEntry(entries, family, source.index);
    const projection = try findEntry(entries, access_family, source.index);
    if (!std.meta.eql(original.roots, source.roots[0..2].*) or !std.meta.eql(projection.roots[0], source.roots[2])) return error.StaleGlobalReadonlySourceRoots;
    return original;
}
/// The original Seal already checks this exact family/index order. Lookup is
/// logarithmic so large source rosters do not acquire quadratic admission work.
fn findEntry(entries: []const Seal.Entry, family: Seal.Family, index: u32) !Seal.Entry {
    var lower: usize = 0;
    var upper = entries.len;
    while (lower < upper) {
        const mid = lower + (upper - lower) / 2;
        const entry = entries[mid];
        if (@intFromEnum(entry.family) < @intFromEnum(family) or (entry.family == family and entry.index < index)) lower = mid + 1 else upper = mid;
    }
    if (lower == entries.len or entries[lower].family != family or entries[lower].index != index) return error.MissingGlobalReadonlySource;
    return entries[lower];
}
pub const Authority = struct {
    state: *State,
    const OriginalPolicy = struct {
        selection_authority: @import("block_v5_readonly_input_selection_v1.zig").Authority,
        selection_limits: Plan.Limits,
        plan_limits: Plan.Limits,
        caller_limits: Readonly.Limits,
        input_length: usize,
        address_count: usize,
    };
    const State = struct { a: std.mem.Allocator, plan: Plan.Owned, original_policy: OriginalPolicy, inputs: Inputs, sources: []SourceRecord, groups: []Group, providers: []ProviderPin, ranges: []RangePin, source_ids: []Digest, sealed: Seal.Sealed, epoch: Global.Epoch };
    pub fn admit(a: std.mem.Allocator, expected: Inputs, original: Readonly.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Authority {
        const bytes = try std.math.add(usize, @sizeOf(State), try std.math.add(usize, try std.math.mul(usize, expected.sources.len, @sizeOf(SourceRecord) + @sizeOf(Digest)), try std.math.add(usize, try std.math.mul(usize, expected.groups.len, @sizeOf(Group)), try std.math.add(usize, try std.math.mul(usize, expected.providers.len, @sizeOf(ProviderPin)), try std.math.mul(usize, expected.ranges.len, @sizeOf(RangePin))))));
        const max_intervals = try std.math.add(usize, try std.math.mul(usize, original.selection.addresses.len, 2), 1);
        if (try std.math.add(usize, bytes, try std.math.mul(usize, max_intervals, @sizeOf(Plan.Interval))) > limits.max_metadata_bytes) return error.GlobalReadonlyAuthorityResourceLimit;
        const roster = try digest(expected);
        try sealed.require(pins, entries);
        if (sealed.register_custody_mode != 1 or !std.meta.eql(sealed.readonly_roster_digest, roster) or !std.meta.eql(expected.config, pins.config) or
            !std.meta.eql(expected.initial_source_plan_digest, sealed.initial_source_plan_digest) or
            !std.meta.eql(expected.selection_digest, original.selection.expected_digest)) return error.UntrustedGlobalReadonlyRoster;
        var plan = try original.admit(a);
        errdefer plan.deinit();
        if (try std.math.add(usize, bytes, try std.math.mul(usize, plan.intervals.len, @sizeOf(Plan.Interval))) > limits.max_metadata_bytes) return error.GlobalReadonlyAuthorityResourceLimit;
        if (!std.meta.eql(plan.digest, expected.plan_digest) or !std.meta.eql(try original.plan.source.digest(), expected.initial_source_plan_digest)) return error.UntrustedGlobalReadonlyPlan;
        var natives: u32 = 0;
        var callers: u32 = 0;
        for (expected.sources) |source_record| {
            _ = try sourceEntry(entries, source_record);
            if (source_record.kind == .native) natives += 1 else callers += 1;
        }
        if (natives != pins.counts[@intFromEnum(Seal.Family.execution) - 1] or callers != pins.counts[@intFromEnum(Seal.Family.precompile) - 1]) return error.IncompleteGlobalReadonlySources;
        const owned_sources = try a.dupe(SourceRecord, expected.sources);
        errdefer a.free(owned_sources);
        const owned_groups = try a.dupe(Group, expected.groups);
        errdefer a.free(owned_groups);
        const owned_providers = try a.dupe(ProviderPin, expected.providers);
        errdefer a.free(owned_providers);
        const owned_ranges = try a.dupe(RangePin, expected.ranges);
        errdefer a.free(owned_ranges);
        const source_ids = try a.alloc(Digest, owned_sources.len);
        errdefer a.free(source_ids);
        for (owned_sources, source_ids, 0..) |source_record, *id, ordinal| {
            const entry = try sourceEntry(entries, source_record);
            var channel = core.proof_suites.Blake3.Channel{};
            channel.mixU32s(&.{ Global.TAG, Global.VERSION, 0x53524345, @intCast(ordinal), @intFromEnum(source_record.kind), source_record.index, source_record.group_id });
            channel.mixRoot(roster);
            channel.mixRoot(sealed.digest);
            channel.mixRoot(expected.plan_digest);
            channel.mixRoot(entry.instance_id);
            for (source_record.roots) |root| channel.mixRoot(root);
            id.* = channel.digestBytes();
        }
        const state = try a.create(State);
        var owned_inputs = expected;
        owned_inputs.sources = owned_sources;
        owned_inputs.groups = owned_groups;
        owned_inputs.providers = owned_providers;
        owned_inputs.ranges = owned_ranges;
        state.* = .{ .a = a, .plan = plan, .original_policy = .{ .selection_authority = original.selection.authority, .selection_limits = original.selection.limits, .plan_limits = original.plan.limits, .caller_limits = original.limits, .input_length = original.input.len, .address_count = original.selection.addresses.len }, .inputs = owned_inputs, .sources = owned_sources, .groups = owned_groups, .providers = owned_providers, .ranges = owned_ranges, .source_ids = source_ids, .sealed = sealed, .epoch = .{ .plan_digest = expected.plan_digest, .roster_digest = roster } };
        return .{ .state = state };
    }
    pub fn deinit(self: *Authority) void {
        const state = self.state;
        const a = state.a;
        state.plan.deinit();
        a.free(state.source_ids);
        a.free(state.ranges);
        a.free(state.providers);
        a.free(state.groups);
        a.free(state.sources);
        a.destroy(state);
        self.* = undefined;
    }
    pub fn epoch(self: *const Authority) Global.Epoch {
        return self.state.epoch;
    }
    pub fn intervals(self: *const Authority) []const Plan.Interval {
        return self.state.plan.intervals;
    }
    pub fn borrowedPlan(self: *const Authority, sealed: Seal.Sealed) !BorrowedPlan {
        try self.requireEpoch(sealed);
        return .{ .intervals = self.state.plan.intervals, .digest = self.state.plan.digest };
    }
    pub fn config(self: *const Authority) core.pcs.PcsConfig {
        return self.state.inputs.config;
    }
    pub fn requireEpoch(self: *const Authority, sealed: Seal.Sealed) !void {
        if (!std.meta.eql(sealed, self.state.sealed)) return error.StaleGlobalReadonlyEpoch;
    }
    /// Authenticate value fields consumed by original first-channel framing.
    /// V2 membership/witness/fixed reconstruction must use only our owned Plan;
    /// this guard does not re-admit external mutable input/address arrays.
    pub fn requireOriginalPolicy(self: *const Authority, original: Readonly.Authority) !void {
        const expected = self.state.original_policy;
        if (!std.meta.eql(original.selection.authority, expected.selection_authority) or
            !std.meta.eql(original.selection.expected_digest, self.state.inputs.selection_digest) or
            !std.meta.eql(original.selection.limits, expected.selection_limits) or
            !std.meta.eql(original.plan.expected_digest, self.state.inputs.plan_digest) or
            !std.meta.eql(original.plan.limits, expected.plan_limits) or
            !std.meta.eql(original.limits, expected.caller_limits) or
            original.input.len != expected.input_length or original.selection.addresses.len != expected.address_count or
            original.plan.addresses.len != expected.address_count or
            !std.meta.eql(try original.plan.source.digest(), self.state.inputs.initial_source_plan_digest)) return error.UntrustedGlobalReadonlyOriginalPolicy;
    }
    pub fn source(self: *const Authority, ordinal: u32) !SourceRecord {
        if (ordinal >= self.state.sources.len) return error.MissingGlobalReadonlySource;
        return self.state.sources[ordinal];
    }
    pub fn sourceIdentity(self: *const Authority, ordinal: u32) !Digest {
        if (ordinal >= self.state.source_ids.len) return error.MissingGlobalReadonlySource;
        return self.state.source_ids[ordinal];
    }
    pub fn requireSource(self: *const Authority, ordinal: u32, kind: @import("block_v5_readonly_input_proposal_v1.zig").Kind, index: u32, group_id: u32, roots: [3]Digest, census: Census, identity: Digest) !void {
        const expected = try self.source(ordinal);
        if (expected.kind != kind or expected.index != index or expected.group_id != group_id or !std.meta.eql(expected.roots, roots) or
            !std.meta.eql(expected.census, census) or !std.meta.eql(try self.sourceIdentity(ordinal), identity)) return error.UntrustedGlobalReadonlySource;
    }
    pub fn requireProvider(self: *const Authority, actual: ProviderPin) !void {
        if (actual.shape.index >= self.state.providers.len or !std.meta.eql(actual, self.state.providers[actual.shape.index])) return error.UntrustedGlobalReadonlyProvider;
    }
    pub fn requireRange(self: *const Authority, actual: RangePin) !void {
        if (actual.index >= self.state.ranges.len or !std.meta.eql(actual, self.state.ranges[actual.index])) return error.UntrustedGlobalReadonlyRange;
    }
    pub fn provider(self: *const Authority, index: u32) !ProviderPin {
        if (index >= self.state.providers.len) return error.MissingGlobalReadonlyProvider;
        return self.state.providers[index];
    }
    pub fn range(self: *const Authority, index: u32) !RangePin {
        if (index >= self.state.ranges.len) return error.MissingGlobalReadonlyRange;
        return self.state.ranges[index];
    }
    pub fn groups(self: *const Authority) []const Group {
        return self.state.groups;
    }
    pub fn sources(self: *const Authority) []const SourceRecord {
        return self.state.sources;
    }
    pub fn providers(self: *const Authority) []const ProviderPin {
        return self.state.providers;
    }
};
