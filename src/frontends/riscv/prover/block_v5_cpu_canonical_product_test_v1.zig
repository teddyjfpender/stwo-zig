//! Resource and typed-entry contracts; no runner, commitment, proof or device.
const std = @import("std");
const Stack = @import("block_v5_cpu_canonical_stack_v1.zig");
const Options = @import("block_v5_cpu_product_options_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26;

test "capacity product: installed producer and receiver select one genuine typed stack" {
    const Driver = @import("block_v5_cpu_capacity_driver_v1.zig");
    const Detached = @import("block_v5_cpu_capacity_detached_receive_v1.zig");
    const Global = @import("block_v5_capacity_global_receiver_v1.zig");
    try std.testing.expect(Stack.Driver.Options == Driver.Options);
    try std.testing.expect(Stack.Detached.Pins == Detached.Pins);
    try std.testing.expect(@typeInfo(@typeInfo(@TypeOf(Stack.Detached.verify)).@"fn".return_type.?).error_union.payload == Global.VerifiedGlobals);
    try std.testing.expect(Stack.Driver.Options != @import("block_v5_cpu_driver_v1.zig").Options);
    try std.testing.expectEqualStrings("B5CFILE1", @import("block_v5_cpu_capacity_bundle_store_v1.zig").MANIFEST_MAGIC);
}

test "capacity product: trusted security and independent global caps survive native migration" {
    const capacity = Stack.ProductOptions.options(profile, 67, 4);
    const legacy = Options.options(profile, 67, 4);
    try capacity.validate();
    try legacy.validate();
    try std.testing.expectEqual(@as(usize, 70), capacity.profile.config().fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), capacity.profile.config().pow_bits);
    try std.testing.expectEqualDeep(legacy.collection.planning, capacity.collection.planning);
    try std.testing.expectEqualDeep(legacy.collection.caller, capacity.collection.caller);
    try std.testing.expectEqualDeep(legacy.collection.groups, capacity.collection.groups);
    try std.testing.expectEqualDeep(legacy.collection.globals, capacity.collection.globals);
    try std.testing.expectEqualDeep(legacy.collection.ordinary, capacity.collection.ordinary.memory);
    try std.testing.expectEqual(@as(u32, 1), capacity.collection.ordinary.memory.register_custody_mode);
    try std.testing.expectEqual(capacity.collection.caller.register_custody_mode, capacity.collection.ordinary.memory.register_custody_mode);
    try std.testing.expect(capacity.collection.fixed_basis != null);
    try std.testing.expect(capacity.collection.fixed_basis.?.max_retained_bytes < capacity.total_host_limit);
    try std.testing.expectEqual(@as(u32, 67), capacity.forest.max_execution_count);
    try std.testing.expectEqual(@as(u32, 67), capacity.manifest.max_execution_count);
    try std.testing.expectEqual(@as(usize, 1), capacity.recursive_leaf_queue.capacity);
    var rejected = capacity;
    rejected.recursive_leaf_queue.capacity = 0;
    try std.testing.expectError(error.InvalidV5OwnedQueueOptions, rejected.validate());
}

test "capacity product: actual native and fused phase bounds reject oversized geometry independently" {
    const a = std.testing.allocator;
    var options = Stack.ProductOptions.options(profile, 2, 1);
    var shape = Fixture.shape(3);
    const plan = try Protocol.Plan.fromShape(&shape, 0);
    _ = try options.collection.physical.require(&shape, 0);
    const projections = try Source.slotsFromShapeForMode(a, &shape, 0, 1);
    defer a.free(projections);
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 3 };
    const memory = try Source.memorySlots(a, &shape, 0, frame, 1);
    defer a.free(memory);
    try options.collection.ordinary.fused.require(&shape, 0, projections, memory);
    options.collection.physical.native.max_main_cells = 0;
    try std.testing.expectError(error.NativeCapacityResourceLimit, options.collection.physical.native.require(&plan, &shape));
    // Receiver/fused limits are owned policy values, not mutated through a
    // shared pointer when a producer-only admission is tightened.
    try options.collection.ordinary.fused.require(&shape, 0, projections, memory);
    options.collection.ordinary.fused.max_projection_slots = 0;
    try std.testing.expect(projections.len != 0);
    try std.testing.expectError(error.CapacityFusedResourceLimit, options.collection.ordinary.fused.require(&shape, 0, projections, memory));
}

test "capacity product: report identifies the active grammar and both actual entry bodies compile only" {
    try std.testing.expectEqual(@as(u32, 2), Stack.REPORT_VERSION);
    try std.testing.expectEqual(@as(u32, 1), Stack.NativeProtocol.VERSION);
    try std.testing.expectEqual(@as(u32, 1), Stack.FusedProtocol.VERSION);
    inline for (.{ &@import("../ethereum_block_v5_cpu_produce.zig").main, &@import("../ethereum_block_v5_cpu_verify.zig").main }) |entry| std.mem.doNotOptimizeAway(entry);
}
