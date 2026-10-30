const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Collector = @import("../block_v8_ram_endpoint_collector_v1.zig");
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
const C = @import("../block_v8_ram_endpoint_component_v1.zig");
const E = Collector.Transition;
const Request = Collector.Request;
const request = Request{ .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 10, .cycle_count = 10 }, .cohort_ordinal = 2, .cohort_count = 5 };
fn event(address: u32, local: u32, before: u32, after: u32) E {
    return .{ .space = 1, .address = address, .clock = 36 + local, .before = before, .after = after };
}
fn checkRows(owned: *const Collector.Owned) !void {
    const matrix = owned.matrix;
    for (0..matrix.size()) |row| {
        const previous = if (row == 0) matrix.size() - 1 else row - 1;
        const current = matrix.row(K.COLUMN_COUNT, C.Spec.FIXED_COUNT, row);
        const before = matrix.row(K.COLUMN_COUNT, C.Spec.FIXED_COUNT, previous);
        for (K.constraintsPrevious(Q, current, before, Q.fromBase(matrix.get(0, row)), Q.fromBase(matrix.get(0, previous)), Q.fromBase(matrix.get(1, row)), Q.fromBase(M.fromCanonical(owned.policy.max_local_clock)))) |constraint| {
            try std.testing.expect(constraint.isZero());
        }
        if (row >= owned.endpoints.len) {
            try std.testing.expect(matrix.get(0, row).isZero());
            for (current) |value| try std.testing.expect(value.isZero());
        } else {
            const expected = @import("../block_v5_word_memory_protocol_v1.zig").transitionTuple(owned.net_transitions[row]);
            const actual = try K.globalTuple(Q, current, owned.policy);
            for (expected, actual) |base, secure| try std.testing.expectEqualDeep(Q.fromBase(base), secure);
        }
    }
}
test "combined endpoint collector orders interleaved native caller accesses by actual clock" {
    const a = std.testing.allocator;
    // Native appends its final read before the caller's earlier write. The
    // collector must merge their actual clocks, not trust append/source order.
    const events = [_]E{ event(0x1000, 29, 11, 13), event(0x2000, 7, 3, 5), event(0x1000, 1, 7, 9), event(0x1000, 13, 9, 11), event(0x2000, 2, 1, 3) };
    const copy = events;
    var result = try Collector.collectGlobal(a, request, &events, .{});
    defer result.deinit();
    try std.testing.expectEqualDeep(copy, events);
    try std.testing.expectEqual(@as(usize, 5), result.logical_events);
    try std.testing.expectEqualSlices(K.Endpoint, &.{ .{ .address = 0x1000, .initial = 7, .final = 13, .last_clock = 29 }, .{ .address = 0x2000, .initial = 1, .final = 5, .last_clock = 7 } }, result.endpoints);
    try std.testing.expectEqual(@as(u64, 11), result.net_transitions[0].clock);
    try std.testing.expectEqual(@as(u64, 11), result.net_transitions[1].clock);
    try checkRows(&result);
    var reverse = events;
    std.mem.reverse(E, &reverse);
    var again = try Collector.collectGlobal(a, request, &reverse, .{});
    defer again.deinit();
    try std.testing.expectEqualDeep(result.endpoints, again.endpoints);
    try std.testing.expectEqualSlices(M, result.matrix.storage, again.matrix.storage);
}
test "endpoint collector rejects forked clocks discontinuous values and malformed accesses" {
    const a = std.testing.allocator;
    var events = [_]E{ event(0x1000, 1, 7, 9), event(0x1000, 3, 9, 11) };
    events[1].clock = events[0].clock;
    try std.testing.expectError(error.DuplicateRamEndpointClock, Collector.collectGlobal(a, request, &events, .{}));
    events[1] = event(0x1000, 3, 10, 11);
    try std.testing.expectError(error.DiscontinuousRamEndpointValue, Collector.collectGlobal(a, request, &events, .{}));
    for ([_]E{ .{ .space = 0, .address = 16, .clock = 37, .before = 0, .after = 0 }, event(0x1001, 1, 0, 1), event(1 << 30, 1, 0, 1) }) |bad| {
        try std.testing.expectError(error.InvalidRamEndpointAccess, Collector.collectGlobal(a, request, &.{bad}, .{}));
    }
    for ([_]u64{ 0, 36, 40, 76 }) |clock| {
        var bad = event(0x1000, 1, 0, 1);
        bad.clock = clock;
        try std.testing.expectError(error.RamEndpointAccessOutsideWindow, Collector.collectGlobal(a, request, &.{bad}, .{}));
    }
}
test "endpoint collector bounds scratch endpoint count row geometry and owned storage" {
    const a = std.testing.allocator;
    const events = [_]E{ event(0x1000, 1, 0, 1), event(0x2000, 2, 0, 2) };
    try std.testing.expectError(error.RamEndpointResourceLimit, Collector.collectGlobal(a, request, &events, .{ .max_events = 1 }));
    try std.testing.expectError(error.RamEndpointResourceLimit, Collector.collectGlobal(a, request, &events, .{ .max_endpoints = 1 }));
    try std.testing.expectError(error.RamEndpointResourceLimit, Collector.collectGlobal(a, request, &events, .{ .max_scratch_bytes = 1 }));
    try std.testing.expectError(error.RamEndpointResourceLimit, Collector.collectGlobal(a, request, &events, .{ .max_live_bytes = 100 }));
    try std.testing.expectError(error.RamEndpointResourceLimit, Collector.collectGlobal(a, request, &events, .{ .max_row_log = 3 }));
    var empty = try Collector.collectGlobal(a, request, &.{}, .{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.endpoints.len);
    try checkRows(&empty);
    var invalid = request;
    invalid.cohort_ordinal = invalid.cohort_count;
    try std.testing.expectError(error.InvalidRamEndpointRequest, Collector.collectGlobal(a, invalid, &events, .{}));
    invalid = request;
    invalid.frame.global_first_cycle = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, Collector.collectGlobal(a, invalid, &events, .{}));
}
fn tuple(address: u32, clock: u32, value: u32) [7]Q {
    var result: [7]Q = .{ Q.one(), Q.fromBase(M.fromCanonical(address)), Q.fromBase(M.fromCanonical(clock)), undefined, undefined, undefined, undefined };
    for (0..4) |index| result[3 + index] = Q.fromBase(M.fromCanonical((value >> @as(u5, @intCast(8 * index))) & 255));
    return result;
}
const Relation = @import("../block_v7_memory_relations_v1.zig").Relation(Q, 7);
fn relation() Relation {
    var result = Relation{ .z = Q.fromU32Unchecked(23, 1, 3, 5), .powers = undefined };
    var power = Q.one();
    for (&result.powers) |*p| {
        p.* = power;
        power = power.mul(Q.fromBase(M.fromCanonical(31)));
    }
    return result;
}
fn edgeSum(ch: Relation, address: u32, before_clock: u32, after_clock: u32, before: u32, after: u32) !Q {
    return (try ch.combineSecure(tuple(address, after_clock, after)).inv()).sub(try ch.combineSecure(tuple(address, before_clock, before)).inv());
}
test "endpoint telescoping includes real native synthetic gap rows and actual consumed clocks" {
    const a = std.testing.allocator;
    const Tracker = @import("../../runner/state_chain.zig");
    var tracker = Tracker.StateChainTracker.init(a);
    defer tracker.deinit();
    const later: u32 = 2 * Tracker.MAX_CLOCK_DIFF + 3;
    try tracker.recordMemTransition(0x1000, 1, 7, 9);
    try tracker.recordMemTransition(0x1000, later, 9, 11);
    const req = Request{ .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = later / 4 + 1 }, .cohort_ordinal = 0, .cohort_count = 1 };
    var result = try Collector.collectGlobal(a, req, &.{ .{ .space = 1, .address = 0x1000, .clock = later, .before = 9, .after = 11 }, .{ .space = 1, .address = 0x1000, .clock = 1, .before = 7, .after = 9 } }, .{});
    defer result.deinit();
    try std.testing.expect(tracker.clock_updates_mem.items.len > 0);
    try std.testing.expectEqual(later, result.endpoints[0].last_clock);
    const ch = relation();
    var sum = Q.zero();
    for (tracker.accesses.items, [_]u32{ 7, 9 }) |access, before| {
        sum = sum.add(try edgeSum(ch, access.addr, access.clk_prev, access.clk, before, access.value));
    }
    const without_gaps = sum;
    for (tracker.clock_updates_mem.items) |gap| {
        sum = sum.add(try edgeSum(ch, gap.addr, gap.clk_prev, gap.clk, gap.value, gap.value));
    }
    const row = result.matrix.row(K.COLUMN_COUNT, C.Spec.FIXED_COUNT, 0);
    const endpoint_sum = (try ch.combineSecure(K.localTuple(Q, row, false)).inv()).sub(try ch.combineSecure(K.localTuple(Q, row, true)).inv());
    try std.testing.expect(sum.add(endpoint_sum).isZero());
    // Omitting the native clock projection is exactly the unsound migration
    // shortcut: actual consumed clocks do not skip their synthetic predecessor.
    try std.testing.expect(!without_gaps.add(endpoint_sum).isZero());
    try checkRows(&result);
}

test "endpoint collection allocation failure releases every partially constructed witness" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(a: std.mem.Allocator) !void {
            var result = try Collector.collectGlobal(a, request, &.{ event(0x1000, 1, 0, 1), event(0x2000, 2, 7, 9) }, .{});
            defer result.deinit();
        }
    }.run, .{});
}

test "endpoint collector preserves maximum byte address carries and final subclock" {
    const a = std.testing.allocator;
    var req = request;
    req.cohort_count = 1 << 20;
    req.cohort_ordinal = req.cohort_count - 1;
    const address: u32 = (1 << 30) - 4;
    var result = try Collector.collectGlobal(a, req, &.{event(address, 39, 0xffff_ffff, 0xdead_beef)}, .{});
    defer result.deinit();
    try std.testing.expectEqual(@as(u32, 39), result.endpoints[0].last_clock);
    try std.testing.expectEqual(@as(u64, 4 * (1 << 20) - 1), result.net_transitions[0].clock);
    try checkRows(&result);
    // Source encoding has already been projected by the adapter. A continuous
    // frame and leaf-local frame with the same admitted window agree here.
    req.frame.clock_frame = .global_continuous;
    var continuous = try Collector.collectGlobal(a, req, &.{event(address, 39, 0xffff_ffff, 0xdead_beef)}, .{});
    defer continuous.deinit();
    try std.testing.expectEqualSlices(M, result.matrix.storage, continuous.matrix.storage);
}
