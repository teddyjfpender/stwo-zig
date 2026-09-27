//! Metadata/count/custody fixtures only. Future key slots are deliberately
//! unadmitted and never enter capture/proof/receiver acceptance.
const std = @import("std");
const core = @import("stwo_core");
const Setup = @import("block_v5_closed_input_request_policy_owner_v2.zig");
const Plan = @import("../recursion/block_v5_input_request_forest_plan_v1.zig");
const Bus = @import("../recursion/block_v5_closed_input_request_forest_bus_v2.zig");
const OldBus = @import("../recursion/block_v5_input_request_forest_bus_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Pin = @import("block_v5_input_request_forest_run_v1.zig").Pin;
fn rangesCase(a: std.mem.Allocator) !void {
    const ranges = try Setup.rangesFor(a, 65, 65);
    defer a.free(ranges);
    try std.testing.expectEqual(@as(usize, 17), ranges.len);
    var geometry = try Plan.derive(a, ranges, 65, .{});
    defer geometry.deinit();
    try std.testing.expectEqual(@as(usize, 7), geometry.nodes.len);
    try std.testing.expectEqual(Plan.Range{ .first = 0, .count = 65, .leaves = 17 }, geometry.nodes[geometry.root].range);
    try Setup.requireExisting(.publish, ranges.len, geometry.nodes.len);
    const windows = try a.alloc(Pin, ranges.len);
    defer a.free(windows);
    const nodes = try a.alloc(Pin, geometry.nodes.len);
    defer a.free(nodes);
    @memset(windows, .{ .byte_len = 1, .sha256 = @splat(1) });
    @memset(nodes, .{ .byte_len = 2, .sha256 = @splat(2) });
    try Setup.requireExisting(.{ .reconstruct = .{ .windows = windows, .nodes = nodes } }, ranges.len, geometry.nodes.len);
    try std.testing.expectError(error.IncompleteInputRequestPolicyFiles, Setup.requireExisting(.{ .reconstruct = .{ .windows = windows[1..], .nodes = nodes } }, ranges.len, geometry.nodes.len));
    try std.testing.expectError(error.IncompleteInputRequestPolicyFiles, Setup.requireExisting(.{ .reconstruct = .{ .windows = windows, .nodes = nodes[1..] } }, ranges.len, geometry.nodes.len));
    // Length/hash file pins are transport, not admitted keys or proof flags.
    nodes[0].sha256[0] ^= 1;
    try Setup.requireExisting(.{ .reconstruct = .{ .windows = windows, .nodes = nodes } }, ranges.len, geometry.nodes.len);
}
test "closed input policy: exact native window and minimum node file census" {
    try rangesCase(std.testing.allocator);
}
test "closed input policy: every range census allocation failure rolls back" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, rangesCase, .{});
}
fn slotsCase(a: std.mem.Allocator) !void {
    const specs = try Setup.specsFor(a, 7, 7, .csp_q70_pow26);
    defer a.free(specs);
    for (specs) |spec| {
        try std.testing.expectEqual(@as(usize, 0), spec.schedule.len);
        try std.testing.expectEqual(Base.CSP_CONFIG, spec.geometry.config);
        try std.testing.expect(std.mem.allEqual(u8, &spec.expected_id, 0));
        // A geometry bootstrap slot is not a cryptographic admitted key.
        const key = try @import("../recursion/block_v5_closed_input_request_forest_protocol_v2.zig").Key.fromGeometry(spec.geometry, spec.schedule);
        try std.testing.expect(!std.meta.eql(try key.identity(), spec.expected_id));
    }
    specs[1].geometry.config.pow_bits += 1;
    try std.testing.expectEqual(Base.CSP_CONFIG, specs[0].geometry.config);
}
test "closed input policy: future node slots are owned empty and explicitly unadmitted" {
    try slotsCase(std.testing.allocator);
}
test "closed input policy: every future slot allocation failure rolls back" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, slotsCase, .{});
}
test "closed input policy: public window and node files have separate version5 namespace" {
    var first: [96]u8 = undefined;
    var last: [96]u8 = undefined;
    try std.testing.expectEqualStrings("closed-input-node-4294967295.b5ir5", try Setup.nodeFilename(&first, std.math.maxInt(u32)));
    try std.testing.expectEqualStrings("closed-input-window-0.b5wm2", try Setup.windowFilename(&last, 0));
    const Legacy = @import("block_v5_input_request_policy_owner_v1.zig");
    try std.testing.expect(!std.mem.eql(u8, try Setup.windowFilename(&first, 0), try Legacy.windowFilename(&last, 0)));
    try std.testing.expectError(error.NoSpaceLeft, Setup.nodeFilename(first[0..1], 0));
}
test "closed input policy: empty external grammar cannot carry a descendant schedule" {
    const expected = try Bus.scheduleDigest(&.{});
    const wire = Bus.Wire{ .circuit = 500, .wire = 1, .uses = 1, .kind = .child_term, .coordinate = 0 };
    try std.testing.expectError(error.ClosedInputRequestNodeHasNoPublicTerms, Bus.scheduleDigest(&.{wire}));
    try std.testing.expectError(error.InvalidScopedPublicSchedule, OldBus.scheduleDigest(&.{}));
    const Copy = @import("../recursion/block_v5_input_request_schedule_custody_v1.zig").ForWire(Bus.Wire, Bus.scheduleDigest);
    var mutated = expected;
    mutated[0] ^= 1;
    try std.testing.expectError(error.UntrustedInputRequestSchedule, Copy.copy(std.testing.allocator, &.{}, mutated, 1));
    const empty = try Copy.copy(std.testing.allocator, &.{}, expected, 1);
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}
test "closed input policy: retained metadata budget survives original owner release and rejects caps" {
    const parent = try Budget.create(std.testing.allocator, 1 << 20);
    const child = try Budget.createRetainingParent(parent.allocator(), 1 << 16);
    const a = child.allocator();
    const specs = try Setup.specsFor(a, 7, 7, .csp_q70_pow26);
    parent.destroy();
    a.free(specs);
    child.destroy();
    const capped = try Budget.createRetainingParent(std.testing.allocator, 1);
    defer capped.destroy();
    try std.testing.expectError(error.OutOfMemory, Setup.specsFor(capped.allocator(), 1, 1, .csp_q70_pow26));
    try std.testing.expectError(error.InputRequestPolicyResourceLimit, Setup.specsFor(std.testing.allocator, 0, 1, .csp_q70_pow26));
    try std.testing.expectError(error.InputRequestPolicyResourceLimit, Setup.specsFor(std.testing.allocator, 2, 1, .csp_q70_pow26));
    try std.testing.expect(!Setup.Owner.complete_block_authority and !Setup.Owner.complete_source_authority);
}
test "closed input policy: unfinished owner fails before accessing any original authority" {
    const Snapshot = @import("../recursion/block_v5_input_request_policy_snapshot_v1.zig");
    var owner: Setup.Owner = undefined;
    owner.ready = false;
    const expected: Snapshot.Pins = .{ .input = .{ .root = @splat(0), .word_count = 0 }, .coverage = @splat(0), .original_roster = @splat(0), .carrier_key = @splat(0) };
    try std.testing.expectError(error.UnfinishedInputRequestPolicyOwner, owner.validate(expected));
    owner.ready = true;
    owner.forest_initialized = false;
    try std.testing.expectError(error.UnfinishedInputRequestPolicyOwner, owner.validate(expected));
}
