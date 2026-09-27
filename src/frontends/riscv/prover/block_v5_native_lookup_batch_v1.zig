//! Bounded global native table production and fresh receipt delivery.
//! Only plans and roots survive the census; one group's counters/PCS are live.
const std = @import("std");
const core = @import("stwo_core");
const tables = @import("../air/lookups/tables/mod.zig");
const family = @import("block_v5_native_lookup_proof_v1.zig");
const planning = @import("block_v5_native_lookup_plan_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Boundary = @import("block_v5_proof_boundary_v1.zig").Boundary;
pub const Source = struct {
    context: *anyopaque,
    /// Owned counters for exactly this independently planned execution group.
    load: *const fn (*anyopaque, family.Plan) anyerror!tables.counter.Set,
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; on error the producer still owns it.
    accept: *const fn (*anyopaque, u32, *family.Proof) anyerror!void,
};
pub const Record = struct {
    plan: family.Plan,
    roots: seal.Roots,
    pub fn entry(self: Record) !seal.Entry {
        return .{ .family = .native_lookup, .index = self.plan.index, .instance_id = try self.plan.identity(), .roots = self.roots };
    }
};
fn validateRecords(records: []const Record, execution_count: u32) !void {
    if (records.len == 0) return error.InvalidBlockV5LookupPlan;
    var next: u32 = 0;
    for (records, 0..) |record, index| {
        try record.plan.validate();
        if (record.plan.index != index or record.plan.first_execution != next)
            return error.InvalidBlockV5LookupPartition;
        next = try std.math.add(u32, next, record.plan.execution_count);
    }
    if (next != execution_count) return error.IncompleteBlockV5LookupPartition;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Api = family.ForBackend(Backend);
        records: []Record,
        config: core.pcs.PcsConfig,
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            a.free(self.records);
            self.* = undefined;
        }
        pub fn collect(a: std.mem.Allocator, source: Source, plans: []const family.Plan, execution_count: u32, config: core.pcs.PcsConfig) !Self {
            try planning.validateRoster(plans, execution_count);
            var basis = try Api.FixedBasis.init(a, config);
            defer basis.deinit(a);
            const records = try a.alloc(Record, plans.len);
            errdefer a.free(records);
            for (plans, records) |plan, *record| {
                var counters = try source.load(source.context, plan);
                defer counters.deinit(a);
                var first = try Api.commitFirstRoundWithBasis(a, &counters, plan, &basis);
                defer first.deinit(a);
                record.* = .{ .plan = plan, .roots = first.roots };
            }
            return .{ .records = records, .config = config };
        }
        pub fn prove(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
            return self.proveWithBoundary(a, source, sink, sealed, pins, entries, null);
        }
        pub fn proveWithBoundary(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, boundary: ?Boundary) !void {
            try Boundary.require(boundary);
            try sealed.require(pins, entries);
            try validateRecords(self.records, sealed.execution_instance_count);
            if (!std.meta.eql(self.config, pins.config) or self.records.len != pins.counts[@intFromEnum(seal.Family.native_lookup) - 1])
                return error.UntrustedBlockV5NativeLookupCensus;
            var basis = try Api.FixedBasis.init(a, self.config);
            defer basis.deinit(a);
            for (self.records) |record| {
                try Boundary.require(boundary);
                var counters = try source.load(source.context, record.plan);
                defer counters.deinit(a);
                var first = try Api.commitFirstRoundWithBasis(a, &counters, record.plan, &basis);
                defer first.deinit(a);
                if (!std.meta.eql(first.roots, record.roots)) return error.BlockV5NativeLookupRootReplayMismatch;
                try Boundary.require(boundary);
                var proof = try Api.prove(a, &first, &counters, record.plan, sealed, pins, entries);
                errdefer proof.deinit(a);
                try sink.accept(sink.context, record.plan.index, &proof);
            }
        }
    };
}
pub const ProofSource = struct {
    context: *anyopaque,
    /// The receiver consumes this proof on every path.
    load: *const fn (*anyopaque, u32) anyerror!family.Proof,
};
pub const ReceiptSink = struct {
    context: *anyopaque,
    /// Close this exact group's table-only consumer claims here. A block-wide
    /// sum is deliberately unavailable, since it can hide field wraparound.
    accept: *const fn (*anyopaque, family.Plan, family.OpenReceipt) anyerror!void,
};
/// Records and bounds must be derived independently of proof-carried data.
pub fn receive(comptime Backend: type, a: std.mem.Allocator, source: ProofSource, sink: ReceiptSink, records: []const Record, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
    try sealed.require(pins, entries);
    try validateRecords(records, sealed.execution_instance_count);
    if (records.len != pins.counts[@intFromEnum(seal.Family.native_lookup) - 1]) return error.UntrustedBlockV5NativeLookupCensus;
    const Api = family.ForBackend(Backend);
    var basis = try Api.FixedBasis.init(a, pins.config);
    defer basis.deinit(a);
    for (records) |record| {
        const receipt = try Api.verifyOwnedWithBasis(a, try source.load(source.context, record.plan.index), record.plan, record.roots, sealed, pins, entries, &basis);
        try sink.accept(sink.context, record.plan, receipt);
    }
}
