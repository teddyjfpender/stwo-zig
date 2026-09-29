//! Joined consumers for witness feeds. Each producer is counted exactly once
//! before the dependency graph releases its subcomponent owner.
const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const topology_mod = @import("../witness/feed_topology.zig");
const fixed = @import("../witness/fixed_table_bundle.zig");
const multiplicity = @import("../conformance/multiplicity_tables.zig");
const memory = @import("../witness/cpu_memory_multiplicity.zig");
const Producer = @import("../witness/producer_output.zig").ProducerOutput;

pub const State = struct {
    allocator: std.mem.Allocator,
    topology: topology_mod.Loaded,
    tables: ?multiplicity.Tables,
    counts: ?memory.Counts,

    pub fn init(a: std.mem.Allocator, input: *const adapter.ProverInput, topology: topology_mod.Loaded, fixed_tables: *const fixed.Bundle) !State {
        var tables = try multiplicity.Tables.init(a, fixed_tables);
        errdefer tables.deinit();
        const counts = try memory.initCounts(a, input);
        return .{ .allocator = a, .topology = topology, .tables = tables, .counts = counts };
    }

    pub fn deinit(self: *State) void {
        if (self.tables) |*tables| tables.deinit();
        if (self.counts) |*counts| counts.deinit();
        self.* = undefined;
    }

    pub fn consume(self: *State, producer: *const Producer) !void {
        if (self.tables == null or self.counts == null) return error.IncrementalCountsClosed;
        try self.tables.?.route(self.topology, &.{producer.*});
        try memory.accumulateProducers(self.allocator, self.topology, &.{producer.*}, &self.counts.?);
    }

    pub fn takeTables(self: *State) !multiplicity.Tables {
        const tables = self.tables orelse return error.IncrementalCountsClosed;
        self.tables = null;
        return tables;
    }

    pub fn takeCounts(self: *State) !memory.Counts {
        const counts = self.counts orelse return error.IncrementalCountsClosed;
        self.counts = null;
        return counts;
    }
};
