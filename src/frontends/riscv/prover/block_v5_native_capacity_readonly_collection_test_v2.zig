//! Witness/hash metadata only. No commitments, Fresh receipts or proof runs.
const std = @import("std");
const core = @import("stwo_core");
const New = @import("block_v5_native_capacity_readonly_collection_v2.zig");
const Original = @import("block_v5_readonly_input_proposal_v1.zig");
const Policy = @import("block_v5_readonly_input_test_policy_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const behavioral_test_count = 3;
fn source() !Original.SourcePin {
    // Identity-only metadata for an event hash comparison. These labelled
    // roots are not commitments, keys, proposals or accepted source receipts.
    return .{ .kind = .native, .index = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = (@as(u64, 1) << 32) + 1, .cycle_count = 3 }, .roots = .{ @splat(3), @splat(4) }, .access_root = @splat(5), .roster_digest = @splat(6), .all_rw_events = 3, .row_log = 2, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } };
}
fn events() [3]Transition {
    const first = @as(u64, 1) << 34;
    return .{ .{ .space = 1, .address = Policy.base, .clock = first + 1, .before = 7, .after = 7 }, .{ .space = 1, .address = Policy.base + 4, .clock = first + 5, .before = 0x070809, .after = 5 }, .{ .space = 1, .address = Policy.base, .clock = first + 9, .before = 7, .after = 7 } };
}
test "native readonly streaming collection: exact original event digest full clocks order and identity" {
    const a = std.testing.allocator;
    var selected = try Policy.selection(a, try Policy.sources());
    defer selected.deinit();
    const pin = try source();
    var inspected = try Original.inspect(a, &selected, Policy.pins(&selected), &Policy.input, pin, &events(), .{});
    defer inspected.deinit(a);
    var streamed = try New.Events.init(pin, selected.digest);
    for (events()) |event| try streamed.append(event);
    try std.testing.expectEqualDeep(inspected.event_digest, try streamed.finish());
    var changed = events();
    std.mem.swap(Transition, &changed[0], &changed[2]);
    var reordered = try New.Events.init(pin, selected.digest);
    for (changed) |event| try reordered.append(event);
    try std.testing.expect(!std.meta.eql(try streamed.finish(), try reordered.finish()));
    var other_pin = pin;
    other_pin.index += 1;
    var other = try New.Events.init(other_pin, selected.digest);
    for (events()) |event| try other.append(event);
    try std.testing.expect(!std.meta.eql(try streamed.finish(), try other.finish()));
}
test "native readonly streaming collection: invalid source clocks and exact under overflow census reject" {
    const pin = try source();
    var streamed = try New.Events.init(pin, @splat(1));
    try std.testing.expectError(error.StaleReadonlyInputCensus, streamed.finish());
    var event = events()[0];
    event.space = 0;
    try std.testing.expectError(error.InvalidReadonlyInputSourceClock, streamed.append(event));
    event = events()[0];
    event.clock = streamed.lower;
    try std.testing.expectError(error.InvalidReadonlyInputSourceClock, streamed.append(event));
    event.clock = streamed.upper + 1;
    try std.testing.expectError(error.InvalidReadonlyInputSourceClock, streamed.append(event));
    try std.testing.expectEqual(@as(u32, 0), streamed.count);
    for (events()) |value| try streamed.append(value);
    _ = try streamed.finish();
    try std.testing.expectError(error.StaleReadonlyInputCensus, streamed.append(events()[0]));
    var absent = pin;
    absent.all_rw_events = 0;
    absent.row_log = 0;
    var empty = try New.Events.init(absent, @splat(1));
    _ = try empty.finish();
    try std.testing.expectError(error.StaleReadonlyInputCensus, empty.append(events()[0]));
}
test "native readonly streaming collection: original packed decoder preserves canonical source event bytes" {
    const Relation = @import("block_memory_relation_v2.zig");
    for (events()) |value| {
        const tuple = Relation.transitionTuple(value);
        const decoded = try Relation.decodeTransitionTuple(tuple);
        try std.testing.expectEqualDeep(value, decoded);
        const interval = @import("block_v5_readonly_input_plan_v1.zig").Interval{ .lower = value.address / 4, .upper = value.address / 4 + 1, .readonly = value.before == value.after, .value = if (value.before == value.after) value.before else 0 };
        _ = try @import("block_v5_readonly_input_component_v1.zig").witnessRow(decoded, interval);
    }
}
