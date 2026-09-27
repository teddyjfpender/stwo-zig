//! Production protocol selection for sorted memory. Both variants contain
//! real collected roots and proofs; native admission receives plain metadata.
const std = @import("std");
const core = @import("stwo_core");
const Word = @import("block_v5_word_memory_replay_v1.zig");
const Lanes = @import("block_v5_ram_lanes_replay_v1.zig");
const Sorted = @import("block_v5_sorted_memory_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const Registers = @import("block_v5_register_endpoints_v1.zig");
const Boundary = @import("block_v5_proof_boundary_v1.zig").Boundary;
pub const SortedSource = Word.SortedSource;
/// Intersect the geometry options with independent phase authority; never
/// widen a caller's proof or plan caps merely to match a requested row height.
pub fn laneResources(resources_: Lanes.Resources, maximum: u32, max_instances: usize, max_ranges: usize) !Lanes.Resources {
    var resources = resources_;
    resources.stage.proof.max_row_log = @min(resources.stage.proof.max_row_log, maximum);
    resources.stage.plan.max_instances = @min(resources.stage.plan.max_instances, std.math.cast(u32, max_instances) orelse return error.V5RamReplayInstanceLimit);
    resources.stage.plan.max_shards = @min(resources.stage.plan.max_shards, std.math.cast(u32, max_ranges) orelse return error.V5RamReplayInstanceLimit);
    return resources;
}
pub fn ForBackend(comptime Backend: type) type {
    return union(enum) {
        const Self = @This();
        word: Word.ForBackend(Backend),
        lanes: Lanes.ForBackend(Backend),
        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .word => |*value| value.deinit(),
                .lanes => |*value| value.deinit(),
            }
            self.* = undefined;
        }
        pub fn collect(a: std.mem.Allocator, source: SortedSource, total: u64, minimum: u32, maximum: u32, max_instances: usize, max_ranges: usize, mode: u32, config: core.pcs.PcsConfig, resources_: Lanes.Resources) !Self {
            return switch (mode) {
                0 => .{ .word = try Word.ForBackend(Backend).collect(a, source, total, maximum, minimum, config) },
                1 => blk: {
                    const resources = try laneResources(resources_, maximum, max_instances, max_ranges);
                    break :blk .{ .lanes = try Lanes.ForBackend(Backend).collect(a, source, total, .{ .minimum_row_log = minimum, .maximum_row_log = maximum, .max_instances = max_instances }, config, resources) };
                },
                else => error.UntrustedV5RegisterCustodyMode,
            };
        }
        pub fn memoryPlan(self: *const Self) @import("block_v5_block_producer_v1.zig").MemoryPlan {
            return switch (self.*) {
                .word => |value| .{ .config = value.first.config, .plan_digest = value.first.plan_digest },
                .lanes => |value| .{ .config = value.first.config, .plan_digest = value.first.plan_digest },
            };
        }
        pub fn instanceCount(self: *const Self) usize {
            return switch (self.*) {
                .word => |value| value.first.claims.len,
                .lanes => |value| value.first.pins.len,
            };
        }
        pub fn rangeCount(self: *const Self) usize {
            return switch (self.*) {
                .word => |value| value.first.range_roots.len,
                .lanes => |value| value.first.range_roots.len,
            };
        }
        pub fn memoryEntry(self: *const Self, index: usize) !Seal.Entry {
            return switch (self.*) {
                .word => |value| value.first.memoryEntry(index),
                .lanes => |value| try value.first.memoryEntry(index),
            };
        }
        pub fn rangeEntry(self: *const Self, index: usize) !Seal.Entry {
            return switch (self.*) {
                .word => |value| value.first.rangeEntry(index),
                .lanes => |value| try value.first.rangeEntry(index),
            };
        }
        pub fn receiverPins(self: *const Self, seal: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed, total: u64, source: Endpoint.Pins, registers: Registers.Pins) Sorted.Pins {
            return switch (self.*) {
                .word => |value| .{ .word = .{ .seal = seal, .expected_seal_digest = sealed.digest, .first_round = entries, .claims = value.first.claims, .request_counts = value.first.counts, .memory_roots = value.first.memory_roots, .range_roots = value.first.range_roots, .expected_total_events = total, .source = source, .register_endpoints = registers } },
                .lanes => |value| .{ .lanes = .{ .seal = seal, .expected_seal_digest = sealed.digest, .first_round = entries, .pins = value.first.pins, .range_roots = value.first.range_roots, .expected_total_events = total, .source = source, .limits = .{ .proof = value.first.limits.proof, .plan = value.first.limits.plan } } },
            };
        }
        pub fn proveWithStore(self: *const Self, a: std.mem.Allocator, source: SortedSource, store: *@import("block_v5_cpu_bundle_store_v1.zig").Store, pins: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed, boundary: ?Boundary) !void {
            return self.proveWithSinks(a, source, store.packedMemorySink(), store.ramLanesSink(), pins, entries, sealed, boundary);
        }
        /// Native wire families have distinct stores; the sorted RAM proof
        /// families share these exact typed ownership callbacks.
        pub fn proveWithSinks(self: *const Self, a: std.mem.Allocator, source: SortedSource, word_sink: @import("block_v5_word_memory_artifact_v1.zig").Sink, lanes_sink: @import("block_v5_ram_lanes_stage_v1.zig").Sink, pins: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed, boundary: ?Boundary) !void {
            switch (self.*) {
                .word => |*value| {
                    var lease = try value.openTraceSource(source);
                    defer lease.deinit();
                    try value.first.proveWithBoundary(a, lease.source(), word_sink, pins, entries, sealed.digest, sealed, boundary);
                    try lease.requireFinished();
                },
                .lanes => |*value| {
                    var lease = try value.openTraceSource(source);
                    defer lease.deinit();
                    try value.first.proveWithBoundary(a, lease.source(), lanes_sink, pins, entries, sealed.digest, sealed, boundary);
                    try lease.requireFinished();
                },
            }
        }
    };
}
