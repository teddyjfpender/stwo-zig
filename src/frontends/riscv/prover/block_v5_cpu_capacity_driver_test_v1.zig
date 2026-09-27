//! Nonproving orchestration policy and exact typed API checks. No Runner is
//! constructed, and no collection, commitment, proof or device is invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Common = @import("block_v5_cpu_driver_common_v1.zig");
const Legacy = @import("block_v5_cpu_driver_v1.zig");
const Capacity = @import("block_v5_cpu_capacity_driver_v1.zig");
const Producer = @import("block_v5_block_producer_v1.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;

// Unread collection/codec fields intentionally have no fabricated admission.
// The real run calls this same preflight before allocating any owned state.
fn policy(comptime selected: bool, profile: Profile) Common.ForCapacity(selected).Options {
    var result: Common.ForCapacity(selected).Options = .{
        .profile = profile,
        .collection = undefined,
        .max_roster_entries = 1,
        .store = undefined,
        .forest = .{ .profile = profile, .lane_count = 1, .total_host_limit = 1024, .max_execution_count = 1, .max_proof_bytes = 1024 },
        .manifest = undefined,
        .metadata = undefined,
        .cache = .{ .profile = profile, .aggregate_host_byte_limit = 1024, .worker_options = .{ .worker_count = 1, .host_byte_limit = 1024, .retained_scratch_limit = 0 } },
        .workers = 1,
        .total_host_limit = 4096,
        .families = .{ .coordinators = 1, .capacity = 4, .reservation_limit = 2048, .family_reservation = 1024 },
    };
    result.collection.readonly = null;
    return result;
}
test "capacity driver: readonly requires canonical register windows and rejects missing recursive grammar before collection" {
    var legacy = policy(false, .csp_q70_pow26);
    legacy.collection.readonly = .{ .selection = undefined };
    try std.testing.expectError(error.InvalidV5ReadonlyCollectionMode, legacy.validate());
    var selected = policy(true, .csp_q70_pow26);
    selected.collection.readonly = .{ .selection = undefined };
    selected.collection.ordinary.memory.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidV5ReadonlyCollectionMode, selected.validate());
    selected.collection.ordinary.memory.register_custody_mode = 1;
    selected.collection.caller.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidV5ReadonlyCollectionMode, selected.validate());
    selected.collection.caller.register_custody_mode = 1;
    selected.collection.caller.readonly = null;
    selected.recursive_families = .{};
    try std.testing.expectError(error.UnsupportedReadonlyRecursiveClosure, selected.validate());
    selected.recursive_families = null;
    selected.source_pages = .{};
    try std.testing.expectError(error.UnsupportedReadonlyRecursiveClosure, selected.validate());
    selected.source_pages = null;
    // Only scheduling is admitted here; no undefined source authority is read.
    try selected.validate();
}
test "capacity driver: default aliases remain NativeV3 and capacity options retain real independent policy types" {
    try std.testing.expect(Legacy.Options == Common.ForCapacity(false).Options);
    try std.testing.expect(Legacy.Result == Common.ForCapacity(false).Result);
    try std.testing.expect(Capacity.Options == Common.ForCapacity(true).Options);
    try std.testing.expect(Capacity.Options != Legacy.Options);
    inline for (.{ false, true }) |selected| {
        const Driver = Common.ForCapacity(selected);
        const Collect = @import("block_v5_cpu_collect_v1.zig").ForCapacity(selected);
        const Store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(selected);
        const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(selected);
        try std.testing.expect(@TypeOf(@as(Driver.Options, undefined).collection) == Collect.Limits);
        try std.testing.expect(@TypeOf(@as(Driver.Options, undefined).store) == Store.Limits);
        try std.testing.expect(@TypeOf(@as(Driver.Options, undefined).metadata) == Metadata.Limits);
        const Global = if (selected) @import("block_v5_capacity_global_receiver_v1.zig") else @import("block_v5_global_receiver_v1.zig");
        try std.testing.expect(@TypeOf(@as(Driver.Result, undefined).verified) == Global.VerifiedGlobals);
    }
}
test "capacity driver: both stacks reject recursive profile downgrade and invalid aggregate scheduling before ownership" {
    inline for (.{ false, true }) |selected| {
        var options = policy(selected, .csp_q70_pow26);
        try options.validate();
        options.forest.profile = .diagnostic_q8_pow0;
        try std.testing.expectError(error.InvalidV5CpuDriverOptions, options.validate());
        options.forest.profile = options.profile;
        options.cache.profile = .diagnostic_q8_pow0;
        try std.testing.expectError(error.InvalidV5CpuDriverOptions, options.validate());
        options.cache.profile = options.profile;
        options.workers = 0;
        try std.testing.expectError(error.InvalidV5CpuDriverOptions, options.validate());
        options.workers = 1;
        options.total_host_limit = 0;
        try std.testing.expectError(error.InvalidV5CpuDriverOptions, options.validate());
        options.total_host_limit = options.families.reservation_limit;
        try std.testing.expectError(error.InvalidV5FamilyQueueOptions, options.validate());
        options.total_host_limit = 4096;
        options.families.family_reservation = options.families.reservation_limit + 1;
        try std.testing.expectError(error.InvalidV5FamilyQueueOptions, options.validate());
    }
}
test "capacity driver: staged sources and durable sinks carry distinct capacity native proof authority" {
    inline for (.{ false, true }) |selected| {
        const Stack = Producer.ForCapacity(selected);
        const Source = @import("block_v5_cpu_staged_execution_source_v1.zig").ForCapacity(selected).Source;
        const Store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(selected);
        const ActualSink = @typeInfo(@TypeOf(Store.Store.executionSink)).@"fn".return_type.?;
        try std.testing.expect(@typeInfo(@TypeOf(Source.source)).@"fn".return_type.? == Stack.LightweightExecutionSource);
        try std.testing.expect(@FieldType(ActualSink, "native") == @FieldType(Stack.LightweightExecutionSink, "native"));
        try std.testing.expect(@FieldType(ActualSink, "table") == @FieldType(Stack.LightweightExecutionSink, "table"));
        try std.testing.expect(@hasField(ActualSink, "request") == !selected);
        try std.testing.expect(@hasField(Stack.LightweightExecutionSink, "request") == !selected);
        const Native = if (selected) @import("block_v5_native_capacity_proof_v1.zig") else @import("block_v5_native_execution_proof_v3.zig");
        const Result = @typeInfo(@TypeOf(Source.takeFirstRound)).@"fn".return_type.?;
        try std.testing.expect(@typeInfo(Result).error_union.payload == Native.ForBackend(Cpu).FirstRound);
    }
    try std.testing.expect(@FieldType(Producer.ForCapacity(true).LightweightExecutionSink, "native") != @FieldType(Producer.ForCapacity(false).LightweightExecutionSink, "native"));
}
test "capacity driver: metadata accessor borrows the genuine owned proposal rather than duplicating it" {
    const Root = @import("block_v5_cpu_capacity_root_proposal_v1.zig");
    var proposal: Root.Proposal = undefined;
    proposal.physical.external_retirements = 7;
    proposal.physical.index = 3;
    const view = Capacity.nativeMetadata(&proposal);
    try std.testing.expect(view == &proposal.physical);
    try std.testing.expectEqual(@as(u32, 7), Capacity.externalRetirements(&proposal));
    proposal.physical.external_retirements = 9;
    try std.testing.expectEqual(@as(u32, 9), Capacity.externalRetirements(&proposal));
    try std.testing.expectEqual(@as(u32, 3), view.index);
    // This borrowed metadata test neither validates nor destroys an owned root.
}
