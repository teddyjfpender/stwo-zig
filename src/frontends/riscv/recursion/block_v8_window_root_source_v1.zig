const std = @import("std");
const Adapter = @import("block_v8_window_root_adapter_v1.zig");
pub const Value = Adapter.Public.Values;
pub const RawWire = Adapter.Public.Wire;
pub const Capture = *const Adapter.Profile.Capture;
pub const Cold = struct {
    allocator: std.mem.Allocator,
    wire_allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    fixed: @import("air/blake3_parent_row_storage.zig").FixedTuple(false),
    wires: []RawWire,
    context: @import("blake3_execution_parent_protocol.zig").Context,
    namespace: @import("air/block_v5_recursive_fixed_namespace_v1.zig").Plan,
    pub fn deinit(self: *Cold) void {
        inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| self.allocator.free(self.fixed[i]);
        self.wire_allocator.free(self.wires);
        self.namespace.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub const Live = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []RawWire,
    pub fn deinit(v: *Live) void {
        v.recursive.deinit();
        v.allocator.free(v.wires);
        v.budget.destroy();
        v.* = undefined;
    }
};
pub const Source = struct {
    root: *const Adapter.Profile.Owned,
    pub fn values(v: Source, a: std.mem.Allocator) !Value {
        return Adapter.Public.reconstruct(a, v.root);
    }
    pub fn seal(v: Source) [32]u8 {
        return v.root.seal;
    }
    pub fn cold(v: Source, a: std.mem.Allocator) !Cold {
        var c = try Adapter.Fixed.Owned.derive(a, v.root, 4, .{});
        errdefer c.deinit();
        const wires = try a.alloc(RawWire, c.wires.len);
        @memcpy(wires, c.wires);
        c.allocator.free(c.wires);
        return .{ .allocator = c.allocator, .wire_allocator = a, .budget = c.budget, .fixed = c.fixed, .wires = wires, .context = c.context, .namespace = c.namespace };
    }
    pub fn prepare(v: Source, a: std.mem.Allocator, capture: Capture) !Live {
        var p = try Adapter.Preparation.prepare(a, v.root, capture, 4, .{});
        errdefer p.deinit();
        const wires = try a.alloc(RawWire, p.wires.len);
        @memcpy(wires, p.wires);
        p.allocator.free(p.wires);
        p.values.deinit();
        return .{ .allocator = a, .budget = p.budget, .recursive = p.recursive, .wires = wires };
    }
};
pub const Batch = struct {
    allocator: std.mem.Allocator,
    entries: []Live,
    pub fn deinit(v: *Batch) void {
        for (v.entries) |*entry| entry.deinit();
        v.allocator.free(v.entries);
    }
};
pub fn prepareBatch(a: std.mem.Allocator, sources: []const Source, captures: []const Capture, workers: u8) !Batch {
    if (sources.len != captures.len or workers != 1) return error.InvalidB8WindowFoldWorkers;
    const entries = try a.alloc(Live, sources.len);
    errdefer a.free(entries);
    var count: usize = 0;
    errdefer for (entries[0..count]) |*entry| entry.deinit();
    for (sources, captures, 0..) |source, capture, i| {
        entries[i] = try source.prepare(a, capture);
        count += 1;
    }
    return .{ .allocator = a, .entries = entries };
}
