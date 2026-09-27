//! Physical first-pass proposal and actual-source late binding. No proposal
//! or Bound below is a verified receipt, RAM filter or complete authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Classification = @import("block_v5_readonly_input_proof_v1.zig");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Clock = @import("../access_clock.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const Kind = enum(u32) { native = 1, caller = 2 };
pub const Limits = struct { proof: Classification.Limits = .{}, max_metadata_bytes: usize = 4096 };
pub const SourcePin = struct {
    kind: Kind,
    index: u32,
    frame: Frame,
    roots: [2][32]u8,
    access_root: [32]u8,
    roster_digest: [32]u8,
    all_rw_events: u32,
    /// Actual classifier rows, not a virtual source commitment log. Zero only
    /// for independently pinned no-RW absence, where there is no classifier.
    row_log: u32,
    config: core.pcs.PcsConfig,
    pub fn validate(self: SourcePin, limits: Limits) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        _ = try bounds(self.frame);
        if (std.mem.allEqual(u8, &self.roots[0], 0) or std.mem.allEqual(u8, &self.roots[1], 0) or
            std.mem.allEqual(u8, &self.access_root, 0) or std.mem.allEqual(u8, &self.roster_digest, 0) or
            limits.max_metadata_bytes < @sizeOf(Proposal)) return error.InvalidReadonlyInputSourceProposal;
        if (self.all_rw_events == 0) {
            if (self.row_log != 0) return error.InvalidReadonlyInputAbsentGeometry;
        } else try candidatePin(self, @splat(1), .{ @splat(1), @splat(1) }, limits).validate();
    }
};
pub const Census = struct {
    all_rw: u64,
    mutable: u64,
    readonly: u64,
    pub fn require(self: Census, expected: u64) !void {
        if (self.all_rw != expected or self.all_rw != try std.math.add(u64, self.mutable, self.readonly)) return error.StaleReadonlyInputCensus;
    }
};
/// Independent physical/census pin carried by the trusted first-pass planner.
/// A received artifact or Proposal must never supply its own Expected pin.
pub const Expected = struct {
    source: SourcePin,
    selection_digest: [32]u8,
    classifier_roots: ?[2][32]u8,
    census: Census,
    counter_digest: [32]u8,
    event_digest: [32]u8,
    limits: Limits,
};
/// Fixed-size owned value. Neither access rows, intervals, counters nor PCS
/// trees survive collection; originals stay in independently pinned staging.
pub const Proposal = struct {
    expected: Expected,
    pub fn require(self: Proposal, expected: Expected) !void {
        try expected.source.validate(expected.limits);
        try expected.census.require(expected.source.all_rw_events);
        if (!std.meta.eql(self.expected, expected) or
            (expected.source.all_rw_events == 0) != (expected.classifier_roots == null)) return error.StaleReadonlyInputPhysicalProposal;
        if (expected.classifier_roots) |roots| for (roots) |root| {
            if (std.mem.allEqual(u8, &root, 0)) return error.StaleReadonlyInputPhysicalProposal;
        };
    }
    /// Binds actual source-file pins after collection and sorting, never fake
    /// first-touch hashes. Source roots/roster/census are checked independently.
    pub fn bindPlan(self: Proposal, a: std.mem.Allocator, expected: Expected, selection_pins: Selection.Pins, public_input: []const u8, actual_sources: Sources.Pins, expected_source_digest: [32]u8) !Bound {
        try self.require(expected);
        var selection = try Selection.admit(a, selection_pins, public_input);
        defer selection.deinit();
        if (!std.meta.eql(selection.digest, expected.selection_digest)) return error.StaleReadonlyInputSelection;
        try selection.authority.requireSource(actual_sources);
        const source_digest = try actual_sources.digest();
        if (!std.meta.eql(source_digest, expected_source_digest)) return error.StaleReadonlyInputActualSourcePlan;
        var plan = try Plan.derive(a, actual_sources, public_input, selection_pins.addresses, selection_pins.limits);
        errdefer plan.deinit();
        if (plan.intervals.len != selection.intervals.len) return error.StaleReadonlyInputSelection;
        for (plan.intervals, selection.intervals) |actual, early| if (!std.meta.eql(actual, early)) return error.StaleReadonlyInputSelection;
        return .{ .plan = plan, .source_plan_digest = source_digest, .expected = expected };
    }
};
pub const Bound = struct {
    plan: Plan.Owned,
    source_plan_digest: [32]u8,
    expected: Expected,
    pub fn deinit(self: *Bound) void {
        self.plan.deinit();
        self.* = undefined;
    }
    pub fn binding(self: *const Bound) Binding {
        return .{ .plan = &self.plan, .source_plan_digest = self.source_plan_digest, .expected = self.expected };
    }
    pub fn pinAfterSeal(self: *const Bound, source_instance: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !?Classification.Pin {
        return self.binding().pinAfterSeal(source_instance, sealed, pins, entries);
    }
};
/// Explicit immutable borrow, distinct from the owned late-bound Plan.
pub const Binding = struct {
    readonly_roster_digest: [32]u8 = @splat(0),
    plan: *const Plan.Owned,
    source_plan_digest: [32]u8,
    expected: Expected,
    /// Post-seal challenge identity is deliberately separate from the physical
    /// proposal/final Plan. This creates only independently admitted proof pins
    /// and must not be used as the pre-seal Entry.instance_id.
    pub fn pinAfterSeal(self: Binding, source_instance: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !?Classification.Pin {
        try sealed.require(pins, entries);
        if (!std.mem.allEqual(u8, &self.readonly_roster_digest, 0) and !std.meta.eql(self.readonly_roster_digest, sealed.readonly_roster_digest)) return error.StaleReadonlyInputRoster;
        if (sealed.register_custody_mode != 1 or !std.meta.eql(pins.config, self.expected.source.config) or
            !std.meta.eql(self.source_plan_digest, sealed.initialSourcePlanDigest())) return error.StaleReadonlyInputSourceAuthority;
        const source = self.expected.source;
        const family: Seal.Family = if (source.kind == .native) .execution else .precompile;
        const access_family: Seal.Family = if (source.kind == .native) .execution_sidecar else .execution_external_sidecar;
        var found = false;
        var access_found = false;
        for (entries) |entry| {
            if (entry.family == family and entry.index == source.index) {
                if (!std.meta.eql(entry.instance_id, source_instance) or !std.meta.eql(entry.roots, source.roots)) return error.StaleReadonlyInputPhysicalProposal;
                found = true;
            }
            if (entry.family == access_family and entry.index == source.index) {
                if (!std.meta.eql(entry.roots[0], source.access_root)) return error.StaleReadonlyInputPhysicalProposal;
                access_found = true;
            }
        }
        if (!found or !access_found) return error.MissingReadonlyInputSourceEntry;
        const roots = self.expected.classifier_roots orelse return null;
        var result = candidatePin(source, self.plan.digest, roots, self.expected.limits);
        result.source_identity = Classification.sourceIdentity(if (source.kind == .native) .native else .caller, source.index, sealed.digest, source_instance, source.roots, source.access_root);
        try result.validate();
        return result;
    }
};

pub const Inspected = struct {
    trace: ?Classification.Trace,
    census: Census,
    counter_digest: [32]u8,
    event_digest: [32]u8,
    pub fn deinit(self: *Inspected, a: std.mem.Allocator) void {
        if (self.trace) |*trace| trace.deinit(a);
        self.* = undefined;
    }
};
/// Candidate source rows: original aligned byte address and full global clock.
/// No sorting/filtering happens here, and no source authentication is invented.
pub fn inspect(a: std.mem.Allocator, selection: *const Selection.Owned, selection_pins: Selection.Pins, public_input: []const u8, source: SourcePin, events: []const Transition, limits: Limits) !Inspected {
    try source.validate(limits);
    try selection.require(selection_pins, public_input);
    if (events.len != source.all_rw_events) return error.StaleReadonlyInputCensus;
    const span = try bounds(source.frame);
    var event_hash = std.crypto.hash.sha2.Sha256.init(.{});
    event_hash.update("stwo-zig/block-v5/readonly-input-original-events/v1\x00");
    event_hash.update(&physicalIdentity(source, selection.digest));
    for (events) |event| {
        if (event.space != 1 or event.clock <= span.lower or event.clock > span.upper or
            (event.clock - 1) % Clock.STRIDE >= Clock.MAX_ACCESSES_PER_INSTRUCTION) return error.InvalidReadonlyInputSourceClock;
        put(&event_hash, event.address);
        put(&event_hash, event.clock);
        put(&event_hash, event.before);
        put(&event_hash, event.after);
    }
    var trace: ?Classification.Trace = if (events.len == 0) null else try Classification.Trace.initIntervals(a, selection.intervals, selection.digest, events, candidatePin(source, selection.digest, .{ @splat(0), @splat(0) }, limits));
    errdefer if (trace) |*owned| owned.deinit(a);
    var census = Census{ .all_rw = events.len, .mutable = 0, .readonly = 0 };
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/readonly-input-interval-census/v1\x00");
    hash.update(&selection.digest);
    for (selection.intervals, 0..) |interval, i| {
        const count: u64 = if (trace) |value| value.counters[i] else 0;
        put(&hash, count);
        if (interval.readonly) census.readonly = try std.math.add(u64, census.readonly, count) else census.mutable = try std.math.add(u64, census.mutable, count);
    }
    try census.require(source.all_rw_events);
    return .{ .trace = trace, .census = census, .counter_digest = hash.finalResult(), .event_digest = event_hash.finalResult() };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, core.proof_suites.Blake3.Hasher, core.proof_suites.Blake3.MerkleChannel);
        /// Prefix is the original live physical two/three-tree caller/native
        /// commitment. It is borrowed and still owned by its producer.
        pub const Prefix = struct { pcs: *Scheme, source: SourcePin };
        /// Called by the original collector after genuine native physical and
        /// access commitments. No source verifier receipt is created here.
        pub fn collectEvents(a: std.mem.Allocator, selection: *const Selection.Owned, selection_pins: Selection.Pins, public_input: []const u8, source: SourcePin, events: []const Transition, limits: Limits) !Proposal {
            return collectEventsWithCounters(a, selection, selection_pins, public_input, source, events, limits, null);
        }
        /// The optional original first-pass observer borrows counters only
        /// while this genuine classifier witness and commitment remain live.
        pub fn collectEventsWithCounters(a: std.mem.Allocator, selection: *const Selection.Owned, selection_pins: Selection.Pins, public_input: []const u8, source: SourcePin, events: []const Transition, limits: Limits, counter_groups: anytype) !Proposal {
            var inspected = try inspect(a, selection, selection_pins, public_input, source, events, limits);
            defer inspected.deinit(a);
            var roots: ?[2][32]u8 = null;
            if (inspected.trace) |*trace| {
                var first = try Classification.ForBackend(Backend).commit(a, trace, candidatePin(source, selection.digest, .{ @splat(0), @splat(0) }, limits));
                defer first.deinit(a);
                roots = first.roots;
            }
            const proposal = Proposal{ .expected = .{ .source = source, .selection_digest = selection.digest, .classifier_roots = roots, .census = inspected.census, .counter_digest = inspected.counter_digest, .event_digest = inspected.event_digest, .limits = limits } };
            if (@TypeOf(counter_groups) != @TypeOf(null)) if (counter_groups) |groups| try groups.appendNative(proposal, if (inspected.trace) |trace| trace.counters else &.{});
            return proposal;
        }
        pub fn collect(a: std.mem.Allocator, selection: *const Selection.Owned, selection_pins: Selection.Pins, public_input: []const u8, prefix: Prefix, events: []const Transition, limits: Limits) !Proposal {
            const source = prefix.source;
            try source.validate(limits);
            if (!std.meta.eql(prefix.pcs.config, source.config) or prefix.pcs.trees.items.len != (if (source.all_rw_events == 0) @as(usize, 2) else 3)) return error.StaleReadonlyInputPhysicalProposal;
            var actual = try prefix.pcs.roots(a);
            defer actual.deinit(a);
            if (actual.items.len != prefix.pcs.trees.items.len or !std.meta.eql(actual.items[0..2].*, source.roots) or
                (source.all_rw_events != 0 and !std.meta.eql(actual.items[2], source.access_root))) return error.StaleReadonlyInputPhysicalProposal;
            var inspected = try inspect(a, selection, selection_pins, public_input, source, events, limits);
            defer inspected.deinit(a);
            var roots: ?[2][32]u8 = null;
            if (inspected.trace) |*trace| {
                var first = try Classification.ForBackend(Backend).commit(a, trace, candidatePin(source, selection.digest, .{ @splat(0), @splat(0) }, limits));
                defer first.deinit(a);
                roots = first.roots;
            }
            return .{ .expected = .{ .source = source, .selection_digest = selection.digest, .classifier_roots = roots, .census = inspected.census, .counter_digest = inspected.counter_digest, .event_digest = inspected.event_digest, .limits = limits } };
        }
    };
}
pub fn candidatePin(source: SourcePin, digest: [32]u8, roots: [2][32]u8, limits: Limits) Classification.Pin {
    return .{ .plan_digest = digest, .source_identity = physicalIdentity(source, digest), .events = source.all_rw_events, .row_log = source.row_log, .roots = roots, .config = source.config, .limits = limits.proof };
}
pub fn physicalIdentity(source: SourcePin, selection_digest: [32]u8) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354950, 1, @intFromEnum(source.kind), source.index, @intFromEnum(source.frame.clock_frame), source.frame.cycle_count, source.all_rw_events, source.row_log });
    channel.mixU64(source.frame.global_first_cycle);
    channel.mixRoot(selection_digest);
    for (source.roots) |root| channel.mixRoot(root);
    channel.mixRoot(source.access_root);
    channel.mixRoot(source.roster_digest);
    source.config.mixInto(&channel);
    return channel.digestBytes();
}
pub fn bounds(frame: Frame) !struct { lower: u64, upper: u64 } {
    if (frame.global_first_cycle == 0 or frame.cycle_count == 0) return error.InvalidReadonlyInputSourceClock;
    const last = try std.math.add(u64, frame.global_first_cycle, frame.cycle_count - 1);
    return .{ .lower = try std.math.mul(u64, frame.global_first_cycle - 1, Clock.STRIDE), .upper = try std.math.add(u64, try std.math.mul(u64, last - 1, Clock.STRIDE), Clock.MAX_ACCESSES_PER_INSTRUCTION) };
}
fn put(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, @intCast(value), .little);
    hash.update(&raw);
}
