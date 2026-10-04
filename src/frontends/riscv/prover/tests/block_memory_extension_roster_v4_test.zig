const std = @import("std");
const memory = @import("../../air/block/memory_component.zig");
const transition = @import("../../air/block/memory_transition.zig");
const shard = @import("../block_memory_range_shard_v2.zig");
const execution_shard = @import("../block_execution_range_shard_v2.zig");
const seal_mod = @import("../block_memory_source_seal_v2.zig");
const statement_mod = @import("../block_memory_batch_statement_v2.zig");
const batch = @import("../block_memory_batch_verify_v2.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;

test "v4 core entry rejects a zero-call seal before accepting proofs" {
    const a = std.testing.allocator;
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(1), .instance_count = 1 };
    const pinned = statement_mod.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, 0, @splat(2)),
        .expected_events = 0,
        .memory_instances = &.{},
        .range_table_roots = &.{},
        .execution_roots = &.{},
        .provider_roots = &.{},
    };
    const wire = batch.SerializedBatch{ .memory = &.{}, .range_tables = &.{}, .execution = &.{}, .initial_sources = &.{} };
    try std.testing.expectError(error.UnboundExecutionExtensionRoster, batch.verifyCoreOwnedWithExtension(Cpu, a, pinned, wire, &.{}, undefined, undefined));
}

test "v4 extension roster binds sparse witnesses exact counts and separate tables" {
    const a = std.testing.allocator;
    const event = transition.Transition{ .space = 1, .address = 4096, .clock = 1, .before = 0, .after = 7 };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 1, .first = event, .last = event }, 1, 1, null);
    const memory_pins = [_]statement_mod.MemoryPin{.{ .claim = claim, .roots = .{ @splat(1), @splat(2) } }};
    const memory_tables = [_]statement_mod.Roots{.{ @splat(3), @splat(4) }};
    const native_roots = [_]statement_mod.Roots{ .{ @splat(5), @splat(6) }, .{ @splat(7), @splat(8) } };
    const extension_counts = [_]u64{ 0, 103 };
    const extension_roots = [_]seal_mod.FirstRoundEntry{.{ .family = .execution_extension_witness, .index = 1, .roots = .{ @splat(9), @splat(0) } }};
    const extension_tables = [_]statement_mod.Roots{.{ @splat(10), @splat(11) }};
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(12), .instance_count = 2 };
    var memory_plan = try shard.plan(a, &.{claim}, 1);
    defer memory_plan.deinit(a);
    var extension_plan = try execution_shard.plan(a, &extension_counts);
    defer extension_plan.deinit(a);
    var statement = statement_mod.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, 0, @splat(13)),
        .expected_events = 1,
        .memory_instances = &memory_pins,
        .range_table_roots = &memory_tables,
        .execution_roots = &native_roots,
        .execution_extension_roots = &extension_roots,
        .execution_extension_active_counts = &extension_counts,
        .execution_extension_range_table_roots = &extension_tables,
        .provider_roots = &.{},
    };
    const first_digest = try statement.firstRoundDigest(a);
    statement.seal = try seal_mod.SourceSeal.initBoundWithExtension(base, 0, @splat(13), 2, 1, memory_plan.digest, first_digest, extension_plan.digest);
    var admitted = try statement.validate(a);
    admitted.deinit(a);
    var admitted_extension = try statement.requireExecutionExtensions(a);
    admitted_extension.deinit(a);
    const no_proofs = batch.SerializedBatch{ .memory = &.{}, .range_tables = &.{}, .execution = &.{}, .initial_sources = &.{} };
    try std.testing.expectError(error.InvalidExecutionExtensionProofCensus, batch.verifyCoreOwnedWithExtension(Cpu, a, statement, no_proofs, &.{}, undefined, undefined));

    const zero_extension_counts = [_]u64{ 0, 0 };
    statement.execution_extension_active_counts = &zero_extension_counts;
    statement.execution_extension_roots = &.{};
    statement.execution_extension_range_table_roots = &.{};
    try std.testing.expectError(error.EmptyExecutionExtensionRoster, statement.validate(a));
    statement.execution_extension_active_counts = &extension_counts;
    statement.execution_extension_roots = &extension_roots;
    statement.execution_extension_range_table_roots = &extension_tables;

    var altered_roots = extension_roots;
    altered_roots[0].index = 0;
    statement.execution_extension_roots = &altered_roots;
    try std.testing.expectError(error.InvalidExecutionExtensionRoster, statement.validate(a));
    statement.execution_extension_roots = &.{};
    try std.testing.expectError(error.InvalidExecutionExtensionRoster, statement.validate(a));
    altered_roots = extension_roots;
    altered_roots[0].roots[0][0] ^= 1;
    statement.execution_extension_roots = &altered_roots;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, statement.validate(a));
    statement.execution_extension_roots = &extension_roots;

    var altered_counts = extension_counts;
    altered_counts[1] += 1;
    statement.execution_extension_active_counts = &altered_counts;
    try std.testing.expectError(error.UnsealedExecutionExtensionRangeRoster, statement.validate(a));
    statement.execution_extension_active_counts = &extension_counts;
    var altered_tables = extension_tables;
    altered_tables[0][1][0] ^= 1;
    statement.execution_extension_range_table_roots = &altered_tables;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, statement.validate(a));
    statement.execution_extension_range_table_roots = &extension_tables;

    const bound_v4 = statement.seal;
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(13), 2, 1, memory_plan.digest, first_digest);
    try std.testing.expectError(error.UnsealedExecutionExtensionRangeRoster, statement.validate(a));
    statement.seal = bound_v4;
    statement.execution_extension_roots = &.{};
    statement.execution_extension_active_counts = &.{};
    statement.execution_extension_range_table_roots = &.{};
    try std.testing.expectError(error.EmptyExecutionExtensionRoster, statement.validate(a));
}
