const std = @import("std");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
test "shared epoch full finite factories are concrete" {
    std.mem.doNotOptimizeAway(&@import("block_v7_shared_epoch_mixed_preparation_v1.zig").prepareDraining);
    std.mem.doNotOptimizeAway(&@import("block_v7_shared_epoch_mixed_fixed_v1.zig").Owned.derive);
    std.mem.doNotOptimizeAway(&@import("block_v7_shared_epoch_mixed_receiver_v1.zig").verify);
}
test "shared epoch original prefix direct columns equal independent cold roster" {
    const a = std.testing.allocator;
    const config = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    const entries = [_]E.Entry{try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)})};
    const epoch = try E.Epoch.init(@splat(3), config, counts, &entries, 1);
    var prefix = try @import("block_v7_shared_epoch_prefix_v1.zig").Owned.create(a, epoch, 2, 2);
    defer prefix.deinit();
    var rows = try prefix.emit();
    defer rows.deinit();
    var namespace = try @import("air/block_v5_recursive_fixed_namespace_v1.zig").prepare(a, prefix.fixed, 100);
    defer namespace.deinit();
    try namespace.requireIndependentMainPort();
    try namespace.validateLive(&rows);
    var bridge = try @import("block_v7_shared_epoch_bridge_v1.zig").Owned.create(a, &prefix, &namespace.original, &.{ .{ .state = 1, .challenges = 2, .uses = @splat(1) }, .{ .state = 3, .challenges = 4, .uses = @splat(2) } }, true);
    defer bridge.deinit();
    var cold = try @import("block_v7_shared_epoch_bridge_v1.zig").Owned.create(a, &prefix, &namespace.original, &.{ .{ .state = 1, .challenges = 2, .uses = @splat(1) }, .{ .state = 3, .challenges = 4, .uses = @splat(2) } }, false);
    defer cold.deinit();
    try std.testing.expectEqualDeep(bridge.identity, cold.identity);
    try std.testing.expectEqual(@as(usize, 848), bridge.scalars.len);
    try std.testing.expectEqual(@as(usize, 16), bridge.words.len);
    var bridge_rows = try bridge.emit();
    defer bridge_rows.deinit();
    try @import("air/blake3_parent_namespace.zig").rejectRange(&bridge_rows, 0, 1);
    try @import("air/blake3_parent_namespace.zig").rejectRange(&bridge_rows, try namespace.original.end(), @import("stwo_core").fields.m31.Modulus);
    for (bridge.words) |row| {
        try std.testing.expect(row[13].isZero());
        for (0..4) |byte| for (row[25 + 8 * byte + 4 ..][0..4]) |coefficient| try std.testing.expect(coefficient.isZero());
    }
}

test "shared epoch external draws preserve exact values and local provenance" {
    const a = std.testing.allocator;
    const core = @import("stwo_core");
    const M = core.fields.m31.M31;
    const Native = @import("air/blake3_native_transcript.zig");
    const T = @import("air/blake3_transcript_witness.zig");
    const Shared = @import("air/block_v7_shared_epoch_transcript_v1.zig");
    const config = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    const entries = [_]E.Entry{try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)})};
    const epoch = try E.Epoch.init(@splat(3), config, counts, &entries, 1);
    var arena = std.heap.ArenaAllocator.init(a);
    var r = @import("air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    r.mixU32s(&.{ 0x42374550, E.VERSION, 2 });
    r.mixPublicRoot(.{ .circuit = 6_300_001, .first_wire = 0 }, epoch.digest);
    try @import("air/block_v7_epoch_transcript_v1.zig").live(arena.allocator(), &r);
    r.mixU32s(&.{123});
    const before: [8]M = blk: {
        for (r.operations.items) |operation| if (operation == .secure) break :blk operation.secure.values;
        unreachable;
    };
    var planned = Native.Planned{ .arena = arena, .operations = r.operations.items, .claim_payloads = &.{}, .plan = try @import("air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 100, .attempt_capacity = 2 }, r.operations.items), .end = r.native };
    defer planned.deinit();
    try Shared.substitute(a, &planned, epoch, false);
    try planned.validateExternalDraws();
    try std.testing.expectEqualDeep(before, try planned.drawValues(planned.plan.fixed.draw_outputs[0]));
    const saved = planned.external_draws;
    planned.external_draws = saved[1..];
    try std.testing.expectError(error.InvalidExecutionChallenge, planned.validateExternalDraws());
    try std.testing.expectError(error.InvalidExecutionChallenge, planned.drawValues(planned.plan.fixed.draw_outputs[0]));
    planned.external_draws = saved;
    var wrong = planned.plan.fixed.draw_outputs[0];
    wrong.source.first_wire += 1;
    try std.testing.expectError(error.InvalidExecutionChallenge, planned.drawValues(wrong));
    const local = T.DrawOutput{ .operation = 0, .role = .composition, .words = 4, .source = .{ .circuit = 99, .first_wire = 0 } };
    try std.testing.expectError(error.InvalidExecutionChallenge, planned.drawValues(local));
    var op = [_]T.Operation{.{ .secure = .{ .output = .composition, .attempts = 1, .values = @splat(M.one()) } }};
    const actual_ops = planned.operations;
    planned.operations = &op;
    try std.testing.expectEqualDeep(@as([8]M, @splat(M.one())), try planned.drawValues(local));
    op[0].secure.output = .oods;
    try std.testing.expectError(error.InvalidExecutionChallenge, planned.drawValues(local));
    planned.operations = actual_ops;
}
