//! Actual original warm caller preparation with one shared interval observer.
//! Records/roots/census remain proposals; no provider/source receipt is made.
const std = @import("std");
const Stage = @import("block_v5_caller_readonly_stage_v1.zig");
const Witness = @import("block_v5_caller_readonly_witness_v1.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Counters = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Readonly = @import("block_v5_caller_readonly_protocol_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Statement = @import("blake3_ethereum_sha_profile.zig").admission.Statement;
const External = @import("block_execution_external_trace_v2.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
const Frame = @import("../air/block/memory_event.zig").Frame;

/// Stack-local synchronous callback. The original witness constructor invokes
/// it once per active logical event; it neither escapes nor owns source rows.
pub const Observation = struct {
    groups: *Counters.Owned,
    token: Counters.Token,
    pub fn observer(self: *Observation) Witness.Metadata.Observer {
        return .{ .context = self, .observe = observe };
    }
    fn observe(raw: *anyopaque, interval: u32) !void {
        const self: *Observation = @ptrCast(@alignCast(raw));
        try self.groups.observe(self.token, interval, 1);
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Prepared = Stage.ForBackend(Backend).Prepared;
        pub const Collected = struct {
            observed: Prepared.Observed,
            record: Counters.SourceRecord,
            pub fn deinit(self: *Collected, a: std.mem.Allocator) void {
                self.observed.deinit(a);
                self.* = undefined;
            }
        };
        pub fn collect(a: std.mem.Allocator, prefix: anytype, statement: *const Statement, total_steps: u32, index: u32, frame: Frame, selection: *const Selection.Owned, limits: Readonly.Limits, target: ?*Counter, groups: *Counters.Owned) !Collected {
            try groups.requireSelectionBorrow(selection.digest, selection.intervals);
            try Protocol.validateGeometry(statement, total_steps);
            // Same original arithmetic used by Schedule.rw_events, without
            // building a second Schedule or scanning the selection intervals.
            const expected = try External.expectedEventCountForMode(statement, 1);
            const token = try groups.beginSource(.caller, index, expected);
            errdefer groups.abortSource(token) catch {};
            var observation = Observation{ .groups = groups, .token = token };
            var observed = try Prepared.initPhysicalObserved(a, prefix, statement, total_steps, frame, selection, limits, target, observation.observer());
            errdefer observed.deinit(a);
            if (!std.meta.eql(observed.physical.selection_digest, selection.digest) or observed.physical.all_rw_events != expected) return error.StaleReadonlyCounterCensus;
            const census = Counters.Census{ .all_rw = observed.physical.all_rw_events, .mutable = try std.math.sub(u64, observed.physical.all_rw_events, observed.physical.readonly_events), .readonly = observed.physical.readonly_events };
            const record = try groups.endSource(token, .{ .kind = .caller, .index = index, .group_id = token.group_id, .roots = observed.physical.roots, .classifier_roots = null, .row_log = 0, .counter_digest = @splat(0), .counter_schema = .interval_stream_v2, .census = census });
            // No fallible work after finalizing the shared source. The returned
            // legacy Prepared's histogram digest stays absent (zero); only this
            // explicitly versioned record carries the V2 observer digest.
            return .{ .observed = observed, .record = record };
        }
    };
}
