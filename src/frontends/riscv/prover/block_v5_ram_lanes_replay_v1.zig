//! Streaming physical two-event RAM traces over the immutable sorted run.
//! Collection retains small claims/pins/counters only; one trace and warm PCS
//! live at a time. Segment replay and event-sized witness buffers are absent.
const std = @import("std");
const core = @import("stwo_core");
const Planning = @import("block_v5_ram_lanes_replay_plan_v1.zig");
const Stage = @import("block_v5_ram_lanes_stage_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig").Trace;
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Transitions = @import("../air/block/memory_transition.zig");
pub const SortedSource = @import("block_v5_memory_replay_adapter_v1.zig").SortedSource;
pub const Resources = struct {
    max_trace_bytes: usize = 4 << 30,
    max_sorted_ingress_bytes: usize = 512 << 20,
    stage: Stage.Limits = .{},
    /// Reject impossible independently configured phase budgets before any
    /// source trace or first-round PCS allocation. These are the same M31
    /// buffers/scratch that the proof kernel checks again at point of use.
    pub fn require(self: Resources, claim: Protocol.Claim) !void {
        try self.stage.proof.require(claim);
        if (try Trace.ownedBytes(claim) > self.max_trace_bytes) return error.V5RamLanesResourceLimit;
    }
    pub fn requireGeometry(self: Resources, row_log: u32, config: core.pcs.PcsConfig) !void {
        try self.stage.proof.requireGeometry(row_log);
        try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(row_log, config);
        if (try Trace.ownedBytesForRowLog(row_log) > self.max_trace_bytes) return error.V5RamLanesResourceLimit;
    }
    /// Exact ingress buffers checked again immediately before their allocation.
    pub fn requireResidentIngress(self: Resources, events: u64) !void {
        const length = try std.math.mul(usize, std.math.cast(usize, events) orelse return error.V5RamLanesResourceLimit, 24);
        if (length > self.max_sorted_ingress_bytes or try std.math.add(usize, try std.math.mul(usize, length, 2), 65536 * 20) > self.stage.max_resident_bytes) return error.V5RamLanesResourceLimit;
    }
};
/// The domain minimum is an independently configured backend admission,
/// applied before plan selection, endpoint collection or any physical root.
pub fn admittedLimits(comptime Backend: type, limits: Planning.Limits) !Planning.Limits {
    var result = limits;
    if (comptime @hasDecl(Backend, "RamLaneResident")) result.minimum_row_log = @max(result.minimum_row_log, Backend.RamLaneResident.MIN_ROW_LOG);
    try result.validate();
    return result;
}
/// Resource/config selection happens before endpoint collection or any root.
/// Phase checks remain mandatory; this is not an estimate of total PCS/RSS.
pub fn selectSizes(comptime Backend: type, a: std.mem.Allocator, events: u64, limits: Planning.Limits, config: core.pcs.PcsConfig, resources: Resources) !@import("../air/block/memory_size_plan.zig").Plan {
    const admitted = try admittedLimits(Backend, limits);
    try @import("blake3_execution_protocol.zig").validateConfig(config);
    if (resources.max_trace_bytes == 0) return error.V5RamLanesResourceLimit;
    var mask: u32 = 0;
    if (events != 0) {
        for (admitted.minimum_row_log..admitted.maximum_row_log + 1) |height| {
            const log: u32 = @intCast(height);
            resources.requireGeometry(log, config) catch |err| switch (err) {
                error.V5RamLanesResourceLimit, error.InvalidV5RamLanesPcsGeometry => continue,
                else => return err,
            };
            if (comptime @hasDecl(Backend, "RamLaneResident")) {
                Backend.RamLaneResident.requireRowLog(log) catch |err| switch (err) {
                    error.InvalidSecureResidentColumnGeometry => continue,
                    else => return err,
                };
                resources.requireResidentIngress(@min(events, @as(u64, 2) << @intCast(log))) catch |err| switch (err) {
                    error.V5RamLanesResourceLimit => continue,
                    else => return err,
                };
            }
            mask |= @as(u32, 1) << @intCast(log);
        }
    }
    var selected = try Planning.sizesAdmitted(a, events, admitted, mask);
    errdefer selected.deinit();
    // Every nonempty RAM roster has at least one actual range16 provider.
    // Exact provider grouping/census remains source-derived in Stage/Plan.
    try resources.stage.plan.require(selected.capacities.len, if (events == 0) 0 else 1);
    if (events != 0 and resources.stage.max_counter_bytes < 65536 * @sizeOf(u32)) return error.V5RamLanesResourceLimit;
    return selected;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Sequential = SequentialFor(Backend);
        a: std.mem.Allocator,
        first: Stage.ForBackend(Backend),
        capacities: []u32,
        resources: Resources,
        pub const TraceLease = struct {
            a: std.mem.Allocator,
            state: *Sequential,
            pub fn source(self: *TraceLease) Stage.Source {
                return self.state.source();
            }
            pub fn requireFinished(self: *const TraceLease) !void {
                if (!self.state.finished) return error.IncompleteV5RamReplay;
            }
            pub fn deinit(self: *TraceLease) void {
                self.state.deinit();
                self.a.destroy(self.state);
                self.* = undefined;
            }
        };
        pub fn deinit(self: *Self) void {
            self.first.deinit(self.a);
            self.a.free(self.capacities);
            self.* = undefined;
        }
        pub fn collect(a: std.mem.Allocator, sorted: SortedSource, total: u64, limits: Planning.Limits, config: core.pcs.PcsConfig, resources: Resources) !Self {
            const selected = try selectSizes(Backend, a, total, limits, config, resources);
            var owns_selected = true;
            defer if (owns_selected) selected.allocator.free(selected.capacities);
            var reader = try sorted.open(sorted.context);
            defer reader.deinit();
            owns_selected = false;
            const plan = try Planning.collectAdmitted(a, &reader, total, selected);
            defer a.free(plan.claims);
            errdefer a.free(plan.row_capacities);
            // Check every actual trace allocation before collecting any PCS.
            for (plan.claims) |claim| try resources.require(claim);
            var source = Sequential{ .a = a, .sorted = sorted, .claims = plan.claims, .resources = resources };
            defer source.deinit();
            if (total == 0) source.finished = true; // Planning.collect checked EOF.
            var first = try Stage.ForBackend(Backend).collect(a, source.source(), plan.claims, total, config, resources.stage);
            errdefer first.deinit(a);
            if (!source.finished) return error.IncompleteV5RamReplay;
            return .{ .a = a, .first = first, .capacities = plan.row_capacities, .resources = resources };
        }
        pub fn openTraceSource(self: *const Self, sorted: SortedSource) !TraceLease {
            return openClaims(self.a, sorted, self.first.claims, self.resources);
        }
        /// Source-only lease, also usable by independent count/replay tests.
        /// Claims contain no roots, proof values or verifier authority.
        pub fn openClaims(a: std.mem.Allocator, sorted: SortedSource, claims: []const Protocol.Claim, resources: Resources) !TraceLease {
            if (claims.len != 0) try Protocol.admitSequence(claims, claims[0].total_events);
            for (claims) |claim| {
                try resources.require(claim);
                if (comptime @hasDecl(Backend, "RamLaneResident")) try Backend.RamLaneResident.requireRowLog(claim.row_log);
            }
            const state = try a.create(Sequential);
            errdefer a.destroy(state);
            state.* = .{ .a = a, .sorted = sorted, .claims = claims, .resources = resources };
            if (claims.len == 0) {
                var reader = try sorted.open(sorted.context);
                defer reader.deinit();
                if (try reader.next() != null) return error.InvalidV5RamReplayCensus;
                state.finished = true;
            }
            return .{ .a = a, .state = state };
        }
    };
}
fn SequentialFor(comptime Backend: type) type {
    return struct {
        const Sequential = @This();
        a: std.mem.Allocator,
        sorted: SortedSource,
        claims: []const Protocol.Claim,
        resources: Resources,
        reader: ?Transitions.Reader = null,
        previous: ?Transitions.Transition = null,
        emitted: u64 = 0,
        next: u32 = 0,
        finished: bool = false,
        poisoned: bool = false,
        fn deinit(self: *Sequential) void {
            if (self.reader) |*reader| reader.deinit();
            self.reader = null;
        }
        fn source(self: *Sequential) Stage.Source {
            return .{ .context = self, .load = load, .load_resident = if (comptime @hasDecl(Backend, "RamLaneResident")) loadResident else null };
        }
        fn load(raw: *anyopaque, index: u32) anyerror!Trace {
            const self: *Sequential = @ptrCast(@alignCast(raw));
            if (self.poisoned or self.finished or index != self.next or index >= self.claims.len) return error.InvalidV5RamReplayOrder;
            errdefer self.poisoned = true;
            const claim = self.claims[index];
            if (claim.first_event != self.emitted or !std.meta.eql(claim.preceding, self.previous)) return error.InvalidV5RamReplayCensus;
            if (self.reader == null) self.reader = try self.sorted.open(self.sorted.context);
            var trace = try Trace.init(self.a, claim, .{ .max_row_log = self.resources.stage.proof.max_row_log, .max_events = claim.events, .max_owned_bytes = self.resources.max_trace_bytes });
            errdefer trace.deinit();
            for (0..claim.events) |_| {
                const event = (try self.reader.?.next()) orelse return error.IncompleteV5RamReplay;
                try trace.append(event);
                self.previous = event;
                self.emitted = try std.math.add(u64, self.emitted, 1);
            }
            try trace.seal();
            self.next += 1;
            if (self.next == self.claims.len) {
                if (self.emitted != claim.total_events or try self.reader.?.next() != null) return error.InvalidV5RamReplayCensus;
                self.reader.?.deinit();
                self.reader = null;
                self.finished = true;
            }
            return trace;
        }
        fn loadResident(raw: *anyopaque, index: u32) anyerror!@import("block_v5_ram_lanes_resident_source_v1.zig").Lease {
            const self: *Sequential = @ptrCast(@alignCast(raw));
            if (self.poisoned or self.finished or index != self.next or index >= self.claims.len) return error.InvalidV5RamReplayOrder;
            errdefer self.poisoned = true;
            const claim = self.claims[index];
            if (claim.first_event != self.emitted or !std.meta.eql(claim.preceding, self.previous)) return error.InvalidV5RamReplayCensus;
            const Source = @import("block_v5_ram_lanes_resident_source_v1.zig");
            const length = try std.math.mul(usize, claim.events, 24);
            // During upload only the serialized shard and its resident copy coexist.
            try self.resources.requireResidentIngress(claim.events);
            const Range = @import("block_v5_range16_v1.zig");
            var counter = try Range.Counter.init(self.a);
            var owns_counter = true;
            defer if (owns_counter) counter.deinit();
            const words = try self.a.alloc(u32, length / 4);
            defer self.a.free(words);
            if (self.reader == null) self.reader = try self.sorted.open(self.sorted.context);
            for (0..claim.events) |i| {
                const event = (try self.reader.?.next()) orelse return error.IncompleteV5RamReplay;
                if (event.space != 1 or (i == 0 and !std.meta.eql(event, claim.first)) or (i + 1 == claim.events and !std.meta.eql(event, claim.last))) return error.InvalidV5RamReplayCensus;
                try Source.addRangeRequests(&counter, self.previous, event);
                Source.eventWords(words[6 * i ..][0..6], event);
                self.previous = event;
                self.emitted = try std.math.add(u64, self.emitted, 1);
            }
            const Owner = struct {
                a: std.mem.Allocator,
                resident: Backend.RamLaneResident.Buffer,
                counter: Range.Counter,
                fn release(ctx: *anyopaque) void {
                    const owner: *@This() = @ptrCast(@alignCast(ctx));
                    const allocator = owner.a;
                    var resident = owner.resident;
                    owner.counter.deinit();
                    allocator.destroy(owner);
                    // The buffer's reservation can be the final allocator
                    // lease; release all owning host metadata before it.
                    resident.deinit();
                }
            };
            const owner = try self.a.create(Owner);
            var owns_raw_owner = true;
            errdefer if (owns_raw_owner) self.a.destroy(owner);
            owner.* = .{ .a = self.a, .resident = try Backend.RamLaneResident.upload(self.a, words, self.resources.stage.max_resident_bytes), .counter = counter };
            owns_raw_owner = false;
            owns_counter = false;
            errdefer Owner.release(owner);
            self.next += 1;
            if (self.next == self.claims.len) {
                if (self.emitted != claim.total_events or try self.reader.?.next() != null) return error.InvalidV5RamReplayCensus;
                self.reader.?.deinit();
                self.reader = null;
                self.finished = true;
            }
            return .{ .claim = claim, .uploaded_bytes = length, .counter_values = owner.counter.values, .request_count = owner.counter.total, .buffer = .{ .handle = owner.resident.handle, .contents = owner.resident.contents, .byte_length = owner.resident.byte_length, .budget_owner = owner.resident.external_reservation.owner }, .context = owner, .release = Owner.release };
        }
    };
}
