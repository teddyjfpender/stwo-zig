//! Independent count-first physical RAM lane geometry. No execution/segment
//! shape, virtual event log or proof receipt chooses committed row height.
const std = @import("std");
const Sizes = @import("../air/block/memory_size_plan.zig");
const Transition = @import("../air/block/memory_transition.zig");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
pub const Limits = struct {
    minimum_row_log: u32,
    maximum_row_log: u32,
    max_instances: usize,
    pub fn validate(self: Limits) !void {
        if (self.minimum_row_log < 1 or self.maximum_row_log > 24 or
            self.minimum_row_log > self.maximum_row_log or self.max_instances == 0) return error.InvalidV5RamReplayLimits;
    }
};
pub const Plan = struct {
    a: std.mem.Allocator,
    row_capacities: []u32,
    claims: []Protocol.Claim,
    total_events: u64,
    pub fn deinit(self: *Plan) void {
        self.a.free(self.row_capacities);
        self.a.free(self.claims);
        self.* = undefined;
    }
};
/// Zero events produces zero instances. Nonempty traces need ceil(events/2)
/// rows; maximize event coverage first, then minimize the exact tail row area.
pub fn sizes(a: std.mem.Allocator, events: u64, limits: Limits) !Sizes.Plan {
    try limits.validate();
    var admitted: u32 = 0;
    for (limits.minimum_row_log..limits.maximum_row_log + 1) |log| admitted |= @as(u32, 1) << @intCast(log);
    return sizesAdmitted(a, events, limits, admitted);
}
/// The production caller derives this bitmap using real phase resource and
/// backend guards. No roots, endpoints, source census or verifier receipt are
/// created by a geometry selection.
pub fn sizesAdmitted(a: std.mem.Allocator, events: u64, limits: Limits, admitted: u32) !Sizes.Plan {
    try limits.validate();
    if (events == 0) return .{ .allocator = a, .capacities = try a.alloc(u32, 0) };
    var maximum_log: ?u32 = null;
    for (limits.minimum_row_log..limits.maximum_row_log + 1) |log| {
        if (admitted & (@as(u32, 1) << @intCast(log)) != 0) maximum_log = @intCast(log);
    }
    const selected_log = maximum_log orelse return error.NoAdmittedV5RamReplayGeometry;
    const rows = events / 2 + events % 2;
    const maximum: u64 = @as(u64, 1) << @intCast(selected_log);
    const count = try std.math.divCeil(u64, rows, maximum);
    if (count > limits.max_instances or count > std.math.maxInt(u32)) return error.V5RamReplayInstanceLimit;
    const capacities = try a.alloc(u32, @intCast(count));
    errdefer a.free(capacities);
    @memset(capacities, @intCast(maximum));
    const tail_rows = rows - (count - 1) * maximum;
    // With homogeneous widths and power-of-two sizes this full-height prefix
    // plus smallest admitted covering tail minimizes area at the exact minimum
    // instance count, including noncontiguous backend-admitted geometries.
    for (limits.minimum_row_log..selected_log + 1) |log| {
        const capacity: u32 = @as(u32, 1) << @intCast(log);
        if (admitted & (@as(u32, 1) << @intCast(log)) != 0 and capacity >= tail_rows) {
            capacities[capacities.len - 1] = capacity;
            break;
        }
    }
    return .{ .allocator = a, .capacities = capacities };
}
/// Cheap boundary census over real sorted transitions. Later trace streaming
/// must match each complete claim exactly and freshly recommit its real roots.
pub fn collect(a: std.mem.Allocator, reader: *Transition.Reader, events: u64, limits: Limits) !Plan {
    return collectSelected(a, reader, events, try sizes(a, events, limits));
}
/// Transfers the independently selected capacities on every path.
pub fn collectAdmitted(a: std.mem.Allocator, reader: *Transition.Reader, events: u64, selected: Sizes.Plan) !Plan {
    return collectSelected(a, reader, events, selected);
}
fn collectSelected(a: std.mem.Allocator, reader: *Transition.Reader, events: u64, selected_owned: Sizes.Plan) !Plan {
    var selected = selected_owned;
    errdefer selected.deinit();
    // Plan owns claims and capacities through one allocator. Reject a foreign
    // transferred capacity owner before inspecting the immutable source.
    if (selected.allocator.ptr != a.ptr or selected.allocator.vtable != a.vtable) return error.InvalidV5RamReplayAllocator;
    if ((events == 0) != (selected.capacities.len == 0)) return error.InvalidV5RamReplayGeometry;
    var covered: u64 = 0;
    for (selected.capacities) |capacity| {
        if (capacity < 2 or capacity > (@as(u32, 1) << 24) or !std.math.isPowerOfTwo(capacity) or covered >= events) return error.InvalidV5RamReplayGeometry;
        covered = try std.math.add(u64, covered, @min(events - covered, @as(u64, capacity) * 2));
    }
    if (covered != events) return error.InvalidV5RamReplayGeometry;
    const claims = try a.alloc(Protocol.Claim, selected.capacities.len);
    errdefer a.free(claims);
    var at: u64 = 0;
    var previous: ?Transition.Transition = null;
    for (selected.capacities, claims) |capacity, *claim| {
        const count: u32 = @intCast(@min(events - at, @as(u64, capacity) * 2));
        const preceding = previous;
        var first: ?Transition.Transition = null;
        for (0..count) |_| {
            const event = (try reader.next()) orelse return error.IncompleteV5RamReplay;
            if (event.space != 1) return error.InvalidV5RamLanesSpace;
            if (previous) |prior| _ = try Transition.adjacency(prior, event);
            if (first == null) first = event;
            previous = event;
        }
        claim.* = .{ .first_event = at, .total_events = events, .events = count, .row_log = std.math.log2_int(u32, capacity), .first = first.?, .last = previous.?, .preceding = preceding };
        try claim.validate();
        at = try std.math.add(u64, at, count);
    }
    if (at != events or try reader.next() != null) return error.InvalidV5RamReplayCensus;
    if (events != 0) try Protocol.admitSequence(claims, events);
    return .{ .a = a, .row_capacities = selected.capacities, .claims = claims, .total_events = events };
}
pub fn require(a: std.mem.Allocator, claims: []const Protocol.Claim, total: u64, limits: Limits) !void {
    var selected = try sizes(a, total, limits);
    defer selected.deinit();
    if (claims.len != selected.capacities.len) return error.InvalidV5RamReplayCensus;
    if (total == 0) return;
    try Protocol.admitSequence(claims, total);
    var remaining = total;
    for (claims, selected.capacities) |claim, capacity| {
        const expected = @min(remaining, @as(u64, capacity) * 2);
        if (claim.rowCapacity() != capacity or claim.events != expected) return error.InvalidV5RamReplayGeometry;
        remaining -= expected;
    }
    if (remaining != 0) return error.InvalidV5RamReplayCensus;
}

test "block-v5 RAM lane replay sizes exact odd tails and non-power-of-two counts" {
    const a = std.testing.allocator;
    const limits = Limits{ .minimum_row_log = 1, .maximum_row_log = 3, .max_instances = 32 };
    var exact = try sizes(a, 33, limits);
    defer exact.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 8, 8, 2 }, exact.capacities);
    var odd = try sizes(a, 5, limits);
    defer odd.deinit();
    try std.testing.expectEqualSlices(u32, &.{4}, odd.capacities);
    var empty = try sizes(a, 0, limits);
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.capacities.len);
    // Abstract all-RAM geometry only; canonical mode1 excludes registers.
    var mainnet = try sizes(a, 356_303_914, .{ .minimum_row_log = 8, .maximum_row_log = 22, .max_instances = 64 });
    defer mainnet.deinit();
    try std.testing.expectEqual(@as(usize, 43), mainnet.capacities.len);
    try std.testing.expectEqual(@as(u32, 1 << 21), mainnet.capacities[42]);
    // Recorded stopped-block RW census, independently filtered in mode1:
    // 356,303,914 total = 298,427,187 registers + 57,876,727 RW accesses.
    var rw = try sizes(a, 57_876_727, .{ .minimum_row_log = 8, .maximum_row_log = 22, .max_instances = 64 });
    defer rw.deinit();
    try std.testing.expectEqual(@as(usize, 7), rw.capacities.len);
    try std.testing.expectEqual(@as(u32, 1 << 22), rw.capacities[6]);
    try std.testing.expectError(error.V5RamReplayInstanceLimit, sizes(a, 33, .{ .minimum_row_log = 1, .maximum_row_log = 3, .max_instances = 2 }));
    try std.testing.expectError(error.V5RamReplayInstanceLimit, sizes(a, std.math.maxInt(u64), limits));
}
