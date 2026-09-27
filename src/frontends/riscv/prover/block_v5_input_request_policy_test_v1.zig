//! Pure custody/count/identity/failure fixtures; no original proof is accepted
//! and no verifier, PCS or STARK body is invoked by a fixture.
const std = @import("std");
const Snapshot = @import("../recursion/block_v5_input_request_policy_snapshot_v1.zig");
const Setup = @import("block_v5_input_request_policy_owner_v1.zig");
const Schedule = @import("../recursion/block_v5_input_request_schedule_custody_v1.zig");
const Bus = @import("../recursion/block_v5_input_request_forest_bus_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("../air/public_data.zig");
const WireStore = Schedule.ForWire(Bus.Wire, Bus.scheduleDigest);
const wires = [_]Bus.Wire{
    .{ .circuit = 4_300_280, .wire = 1, .uses = 7, .negative = false, .kind = .child_cell, .child = 0, .coordinate = 49, .part = 0 },
    .{ .circuit = 4_300_280, .wire = 2, .uses = 1, .negative = true, .kind = .output_slot, .coordinate = 57, .part = 3 },
};
fn scheduleFixture(a: std.mem.Allocator) !void {
    var source = wires;
    const expected = try Bus.scheduleDigest(&source);
    const owned = try WireStore.copy(a, &source, expected, 2);
    defer a.free(owned);
    source[0].coordinate ^= 1;
    try std.testing.expectEqualDeep(wires[0], owned[0]);
    try std.testing.expectEqual(expected, try Bus.scheduleDigest(owned));
}
test "input request policy: exact original schedule copy survives caller mutation" {
    try scheduleFixture(std.testing.allocator);
}
test "input request policy: every schedule factory allocation failure rolls back" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, scheduleFixture, .{});
}
test "input request policy: routing sign uses child coordinate and part pinned independently" {
    const expected = try Bus.scheduleDigest(&wires);
    for (0..5) |fault| {
        var changed = wires;
        switch (fault) {
            0 => changed[0].uses += 1,
            1 => changed[0].negative = true,
            2 => changed[0].child += 1,
            3 => changed[0].coordinate += 1,
            4 => changed[0].part = 1,
            else => unreachable,
        }
        try std.testing.expectError(error.UntrustedInputRequestSchedule, WireStore.copy(std.testing.allocator, &changed, expected, 2));
    }
    try std.testing.expectError(error.InputRequestScheduleResourceLimit, WireStore.copy(std.testing.allocator, &wires, expected, 1));
}
fn ioFixture(a: std.mem.Allocator) !void {
    const shared = [_]u32{ 0x11223344, 0x55667788 };
    const original_input = shared;
    var output = [_]Public.OutputWord{ .{ .addr = 0x2000, .value = 4, .clock = 0 }, .{ .addr = 0x3000, .value = 0xcafef00d, .clock = 17 } };
    const io = Public.IoEntries{ .input_start = 0x1000, .input_len = 8, .input_words = &original_input, .output_len = 4, .output_len_addr = 0x2000, .output_data_addr = 0x3000, .output_words = &output };
    const copied = try Snapshot.cloneIo(a, io, &shared);
    defer a.free(copied.output_words);
    try std.testing.expect(copied.input_words.ptr == shared[0..].ptr);
    try std.testing.expect(copied.output_words.ptr != output[0..].ptr);
    output[1].value = 0;
    try std.testing.expectEqual(@as(u32, 0xcafef00d), copied.output_words[1].value);
    try std.testing.expectEqual(io.input_start, copied.input_start);
    try std.testing.expectEqual(io.output_len_addr, copied.output_len_addr);
    const incorrect = [_]u32{0};
    try std.testing.expectError(error.UntrustedInputRequestPolicyInput, Snapshot.cloneIo(a, io, &incorrect));
}
test "input request policy: common input retained once output and full clocks copied exactly" {
    try ioFixture(std.testing.allocator);
}
test "input request policy: every public output-copy allocation failure propagates" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ioFixture, .{});
}
fn rangeFixture(a: std.mem.Allocator) !void {
    const ranges = try Setup.rangesFor(a, 17, 17);
    defer a.free(ranges);
    try std.testing.expectEqual(@as(usize, 5), ranges.len);
    try std.testing.expectEqual(@as(u32, 16), ranges[4].first);
    try std.testing.expectEqual(@as(u32, 1), ranges[4].count);
    for (ranges) |range| try std.testing.expectEqual(@as(u32, 1), range.leaves);
    try Setup.requireExisting(.publish, 5, 9);
    const pins = [_]@import("block_v5_input_request_forest_run_v1.zig").Pin{.{ .byte_len = 1, .sha256 = @splat(1) }};
    try std.testing.expectError(error.IncompleteInputRequestPolicyFiles, Setup.requireExisting(.{ .reconstruct = .{ .windows = &pins, .nodes = &pins } }, 5, 9));
}
test "input request policy: exact uneven window and node roster before reconstruction" {
    try rangeFixture(std.testing.allocator);
    try std.testing.expectError(error.InputRequestPolicyResourceLimit, Setup.rangesFor(std.testing.allocator, 0, 10));
    try std.testing.expectError(error.InputRequestPolicyResourceLimit, Setup.rangesFor(std.testing.allocator, 11, 10));
    try std.testing.expectError(error.InputRequestPolicyResourceLimit, Setup.rangesFor(std.testing.allocator, 1 << 30, std.math.maxInt(usize)));
}
test "input request policy: range factory allocation failure has no partial owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, rangeFixture, .{});
}
test "input request policy: retained parent survives moved schedule failure and cancellation" {
    const parent = try Budget.create(std.testing.allocator, 1 << 20);
    const child = try Budget.createRetainingParent(parent.allocator(), 1 << 16);
    const a = child.allocator();
    const copied = try WireStore.copy(a, &wires, try Bus.scheduleDigest(&wires), 2);
    parent.destroy();
    // Same exact destruction order as the stable owner: all slices/control
    // storage freed before its retained budget/parent lease is released.
    var invalid = try Bus.scheduleDigest(&wires);
    invalid[0] ^= 1;
    try std.testing.expectError(error.UntrustedInputRequestSchedule, WireStore.copy(a, &wires, invalid, 2));
    a.free(copied);
    child.destroy();
}
test "input request policy: metadata cap admits no uncapped foreign allocator workaround" {
    const parent = try Budget.create(std.testing.allocator, 1 << 20);
    defer parent.destroy();
    const child = try Budget.createRetainingParent(parent.allocator(), 1);
    defer child.destroy();
    try std.testing.expectError(error.OutOfMemory, WireStore.copy(child.allocator(), &wires, try Bus.scheduleDigest(&wires), 2));
    try std.testing.expect(!Setup.Owner.complete_block_authority);
    try std.testing.expect(!Snapshot.Owner.complete_source_authority);
}
fn coverageStorageFixture(a: std.mem.Allocator) !void {
    const C = @import("block_v5_recursive_coverage_plan_v1.zig");
    const Seal = @import("block_v5_source_seal_v1.zig");
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    var logical = [_]Seal.Entry{.{ .family = .execution, .index = 0, .instance_id = @splat(1), .roots = @splat(@splat(2)) }};
    var mappings = [_]C.Mapping{.{ .physical = 0 }};
    var physical = [_]C.Physical{.{ .kind = .native_arithmetic, .subtype = .capacity_v1, .index = 0, .logical = .{ 0, 0 }, .logical_count = 1, .instance_id = @splat(1), .roots = @splat(@splat(2)) }};
    var nodes = [_]C.Node{.{ .children = @splat(.{ .leaf = 0 }), .child_count = 1, .first_leaf = 0, .leaf_count = 1, .schema_counts = @splat(0) }};
    var sources: [C.SOURCE_COUNT]C.SourceRequirement = undefined;
    for (&sources, 0..) |*source, index| source.* = .{ .kind = @enumFromInt(index), .identity = @splat(3), .count = 0 };
    // Structurally initialized storage fixture deliberately has no admitted
    // coverage identity and NEVER enters Snapshot.create or a receiver.
    const original = C.Plan{ .a = a, .meta = .{ .version = C.VERSION, .recipe = @import("block_v5_execution_recipe_v1.zig").canonical, .native_protocol = .capacity_v1, .security = .{ .base = Base.PCS_CONFIG, .recursive = Base.PCS_CONFIG }, .seal_digest = @splat(4), .ram_events = 0, .program_fetches = 0, .register_window_version = 2, .fan_in = .quartet, .logical = &logical, .mappings = &mappings, .physical = &physical, .sources = sources, .nodes = &nodes, .root = .{ .node = 0 } }, .logical_owner = &logical, .mappings_owner = &mappings, .physical_owner = &physical, .nodes_owner = &nodes, .pinned_digest = @splat(5) };
    var copied = try Snapshot.cloneCoverageStorage(a, &original);
    defer copied.deinit();
    logical[0].index = 9;
    mappings[0] = .unassigned;
    physical[0].index = 9;
    nodes[0].leaf_count = 9;
    try std.testing.expectEqual(@as(u32, 0), copied.meta.logical[0].index);
    try std.testing.expect(copied.meta.mappings[0] == .physical);
    try std.testing.expectEqual(@as(u32, 0), copied.meta.physical[0].index);
    try std.testing.expectEqual(@as(u32, 1), copied.meta.nodes[0].leaf_count);
    try std.testing.expect(copied.meta.logical.ptr == copied.logical_owner.ptr);
    try std.testing.expect(copied.meta.nodes.ptr == copied.nodes_owner.ptr);
}
test "input request policy: original coverage storage does not borrow moved roster arrays" {
    try coverageStorageFixture(std.testing.allocator);
}
test "input request policy: every partial coverage storage factory failure rolls back" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, coverageStorageFixture, .{});
}
