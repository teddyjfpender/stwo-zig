//! Physical first-pass V2 observation from genuine native sidecar rows. No
//! transitions list or per-source interval histogram is allocated. All returned
//! values are proposals; only original fresh source/provider proofs close them.
const std = @import("std");
const Native = @import("blake3_execution_trace.zig");
const Capacity = @import("block_v5_native_capacity_proof_v1.zig");
const Memory = @import("block_v5_native_capacity_fused_stage_v1.zig");
const OriginalStage = @import("block_v5_native_capacity_readonly_stage_v1.zig");
const Proposal = @import("block_v5_readonly_input_proposal_v1.zig");
const Classifier = @import("block_v5_native_readonly_source_proof_v2.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Counters = @import("block_v5_readonly_input_counter_collection_v2.zig");
const SourceTrace = @import("block_v5_native_readonly_source_trace_v2.zig");
const Clock = @import("../access_clock.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
const Hash = std.crypto.hash.sha2.Sha256;

/// The exact ORIGINAL event-order digest. This does not authenticate a source;
/// its physical identity is derived from the already-admitted original pin.
pub const Events = struct {
    hash: Hash,
    lower: u64,
    upper: u64,
    expected: u32,
    count: u32 = 0,
    pub fn init(source: Proposal.SourcePin, selection: [32]u8) !Events {
        const span = try Proposal.bounds(source.frame);
        var hash = Hash.init(.{});
        hash.update("stwo-zig/block-v5/readonly-input-original-events/v1\x00");
        hash.update(&Proposal.physicalIdentity(source, selection));
        return .{ .hash = hash, .lower = span.lower, .upper = span.upper, .expected = source.all_rw_events };
    }
    pub fn append(self: *Events, event: Transition) !void {
        if (self.count >= self.expected) return error.StaleReadonlyInputCensus;
        if (event.space != 1 or event.clock <= self.lower or event.clock > self.upper or
            (event.clock - 1) % Clock.STRIDE >= Clock.MAX_ACCESSES_PER_INSTRUCTION) return error.InvalidReadonlyInputSourceClock;
        put(&self.hash, event.address);
        put(&self.hash, event.clock);
        put(&self.hash, event.before);
        put(&self.hash, event.after);
        self.count += 1;
    }
    pub fn finish(self: *const Events) ![32]u8 {
        if (self.count != self.expected) return error.StaleReadonlyInputCensus;
        var hash = self.hash;
        return hash.finalResult();
    }
};
fn put(hash: *Hash, value: anytype) void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, @intCast(value), .little);
    hash.update(&raw);
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Selection has been genuinely admitted once by the original job
        /// owner; collector retains its exact immutable interval borrow. The
        /// original late bind reconstructs/checks input+intervals again once.
        pub fn collect(a: std.mem.Allocator, owner: *Native.Owner, native: *const Capacity.Proposal, memory: *const Memory.Proposal, memory_limits: Memory.Limits, selection: *const Selection.Owned, limits: Proposal.Limits, groups: *Counters.Owned) !Proposal.Proposal {
            try groups.requireSelectionBorrow(selection.digest, selection.intervals);
            const source = try OriginalStage.sourcePin(native, memory, limits);
            var traces = try Memory.Traces.init(a, owner, memory.frame, memory_limits);
            defer traces.deinit();
            if (traces.slots.len != memory.slots.len) return error.StaleReadonlyInputPhysicalProposal;
            for (traces.slots, memory.slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.StaleReadonlyInputPhysicalProposal;
            const token = try groups.beginSource(.native, source.index, source.all_rw_events);
            errdefer groups.abortSource(token) catch {};
            var events = try Events.init(source, selection.digest);
            var roots: ?[2][32]u8 = null;
            var readonly_events: u64 = 0;
            if (source.all_rw_events != 0) {
                const pin = Proposal.candidatePin(source, selection.digest, .{ @splat(0), @splat(0) }, limits);
                var builder = try SourceTrace.Builder.initBorrowed(a, pin, selection.intervals, selection.digest);
                defer builder.deinit();
                // Canonical original order is slot then logical committed row.
                // No separate traces.census pass or materialized Transition[]:
                // tuple decode, classifier rows, event SHA and observation all
                // consume this one traversal of genuine source access rows.
                for (traces.traces) |*trace| for (0..trace.domainSize()) |logical| {
                    const access = try trace.row(logical);
                    if (!access.active) continue;
                    const event = try @import("block_memory_relation_v2.zig").decodeTransitionTuple(access.tuple);
                    try events.append(event);
                    const interval = try selection.find(event.address);
                    try builder.append(event, interval);
                    try groups.observe(token, @intCast(interval), 1);
                    if (selection.intervals[interval].readonly) readonly_events += 1; // bounded by exact u32 events
                };
                var classified = try builder.finish();
                defer classified.deinit();
                // Actual V2 physical two-tree commitment with original matrix/
                // root math. No future epoch draws or fabricated postseal pin.
                var first = try Classifier.ForBackend(Backend).commitPhysical(a, &classified.original, pin, source.index);
                defer first.deinit(a);
                roots = first.roots;
            } else {
                // Typed absence must agree with every actual source row.
                for (traces.traces) |*trace| for (0..trace.domainSize()) |logical| if ((try trace.row(logical)).active) return error.StaleReadonlyInputCensus;
            }
            const event_digest = try events.finish();
            const census = Proposal.Census{ .all_rw = source.all_rw_events, .mutable = source.all_rw_events - readonly_events, .readonly = readonly_events };
            var result = Proposal.Proposal{ .expected = .{ .source = source, .selection_digest = selection.digest, .classifier_roots = roots, .census = census, .counter_digest = @splat(0), .event_digest = event_digest, .limits = limits } };
            try result.require(result.expected);
            const record = try groups.endSource(token, .{ .kind = .native, .index = source.index, .group_id = token.group_id, .roots = .{ source.roots[0], source.roots[1], source.access_root }, .classifier_roots = roots, .row_log = source.row_log, .counter_digest = @splat(0), .counter_schema = .interval_stream_v2, .census = census });
            result.expected.counter_digest = record.counter_digest;
            return result;
        }
    };
}
