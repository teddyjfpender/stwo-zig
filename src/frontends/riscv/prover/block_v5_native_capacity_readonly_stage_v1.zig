//! Original B5CT/B5CF source cells feed the genuine standalone classifier.
//! Physical proposals retain no trace/tree; replay recreates and pins each root.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("blake3_execution_trace.zig");
const Capacity = @import("block_v5_native_capacity_proof_v1.zig");
const Memory = @import("block_v5_native_capacity_fused_stage_v1.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Proposal = @import("block_v5_readonly_input_proposal_v1.zig");
const Proof = @import("block_v5_readonly_input_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const Sink = struct { context: *anyopaque, put_native_readonly: *const fn (*anyopaque, u32, *Proof.Proof) anyerror!void };
pub fn sourcePin(native: *const Capacity.Proposal, memory: *const Memory.Proposal, limits: Proposal.Limits) !Proposal.SourcePin {
    if (memory.index != native.index or memory.register_custody_mode != 1 or !std.meta.eql(memory.native_roots, native.roots) or !std.meta.eql(memory.template_id, native.template_id)) return error.StaleReadonlyInputPhysicalProposal;
    const events = std.math.cast(u32, memory.event_count) orelse return error.ReadonlyInputProofResourceLimit;
    const log: u32 = if (events == 0) 0 else @max(1, std.math.log2_int_ceil(u32, events));
    const result = Proposal.SourcePin{ .kind = .native, .index = native.index, .frame = memory.frame, .roots = native.roots, .access_root = memory.witness_root, .roster_digest = @import("block_v5_opcode_memory_sidecar_proof_v1.zig").instanceId(@splat(0), native.roots, memory.witness_root, native.index, memory.slots), .all_rw_events = events, .row_log = log, .config = native.template.config };
    try result.validate(limits);
    return result;
}
fn eventsFromOwner(a: std.mem.Allocator, owner: *Native.Owner, memory: *const Memory.Proposal, limits: Memory.Limits) ![]Transition {
    var traces = try Memory.Traces.init(a, owner, memory.frame, limits);
    defer traces.deinit();
    if (traces.slots.len != memory.slots.len or try traces.census() != memory.event_count) return error.StaleReadonlyInputCensus;
    for (traces.slots, memory.slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.StaleReadonlyInputPhysicalProposal;
    const events = try a.alloc(Transition, std.math.cast(usize, memory.event_count) orelse return error.ReadonlyInputProofResourceLimit);
    errdefer a.free(events);
    var at: usize = 0;
    for (traces.traces) |*trace| for (0..trace.domainSize()) |row| {
        const access = try trace.row(row);
        if (!access.active) continue;
        if (at >= events.len) return error.StaleReadonlyInputCensus;
        events[at] = try @import("block_memory_relation_v2.zig").decodeTransitionTuple(access.tuple);
        at += 1;
    };
    if (at != events.len) return error.StaleReadonlyInputCensus;
    return events;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn collect(a: std.mem.Allocator, owner: *Native.Owner, native: *const Capacity.Proposal, memory: *const Memory.Proposal, memory_limits: Memory.Limits, selection: *const Selection.Owned, pins: Selection.Pins, input: []const u8, limits: Proposal.Limits) !Proposal.Proposal {
            return collectWithCounters(a, owner, native, memory, memory_limits, selection, pins, input, limits, null);
        }
        pub fn collectWithCounters(a: std.mem.Allocator, owner: *Native.Owner, native: *const Capacity.Proposal, memory: *const Memory.Proposal, memory_limits: Memory.Limits, selection: *const Selection.Owned, pins: Selection.Pins, input: []const u8, limits: Proposal.Limits, counter_groups: ?*@import("block_v5_readonly_input_counter_collection_v2.zig").Owned) !Proposal.Proposal {
            const source = try sourcePin(native, memory, limits);
            const events = try eventsFromOwner(a, owner, memory, memory_limits);
            defer a.free(events);
            return Proposal.ForBackend(Backend).collectEventsWithCounters(a, selection, pins, input, source, events, limits, counter_groups);
        }
        /// No caller scalar or host classification authorizes the partition.
        /// The sink carries a real classifier STARK for later fresh source join.
        pub fn prove(a: std.mem.Allocator, owner: *Native.Owner, memory: *const Memory.Proposal, memory_limits: Memory.Limits, proposal: Proposal.Proposal, bound: *const Proposal.Binding, selection: *const Selection.Owned, pins: Selection.Pins, input: []const u8, source_instance: [32]u8, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry, sink: Sink) !void {
            if (std.mem.allEqual(u8, &bound.readonly_roster_digest, 0) or !std.meta.eql(bound.readonly_roster_digest, sealed.readonly_roster_digest)) return error.MissingReadonlyInputRoster;
            try proposal.require(bound.expected);
            const pin = try bound.pinAfterSeal(source_instance, sealed, seal_pins, entries);
            const events = try eventsFromOwner(a, owner, memory, memory_limits);
            defer a.free(events);
            var inspected = try Proposal.inspect(a, selection, pins, input, bound.expected.source, events, bound.expected.limits);
            defer inspected.deinit(a);
            if (!std.meta.eql(inspected.census, bound.expected.census) or !std.meta.eql(inspected.event_digest, bound.expected.event_digest) or !std.meta.eql(inspected.counter_digest, bound.expected.counter_digest)) return error.StaleReadonlyInputCensus;
            if (pin) |expected| {
                const trace = if (inspected.trace) |*value| value else return error.MissingReadonlyInputProof;
                var first = try Proof.ForBackend(Backend).commit(a, trace, expected);
                defer first.deinit(a);
                if (!std.meta.eql(first.roots, expected.roots)) return error.StaleReadonlyInputPhysicalProposal;
                var proof = try Proof.ForBackend(Backend).prove(a, &first, trace, expected, bound.plan.*, sealed, seal_pins, entries);
                var owns = true;
                defer if (owns) proof.deinit(a);
                try sink.put_native_readonly(sink.context, expectedIndex(bound), &proof);
                owns = false;
            } else if (inspected.trace != null) return error.UntrustedReadonlyInputAbsence;
        }
        fn expectedIndex(bound: *const Proposal.Binding) u32 {
            return bound.expected.source.index;
        }
    };
}
