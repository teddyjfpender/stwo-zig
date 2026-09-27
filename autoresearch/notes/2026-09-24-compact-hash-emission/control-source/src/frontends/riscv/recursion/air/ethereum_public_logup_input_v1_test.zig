const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("ethereum_public_logup_input_v1.zig");
const legacy = @import("vm_public_logup_input.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const support = @import("test_support.zig");

test "Ethereum role input identity preserves legacy seal" {
    var original = try legacy.build(std.testing.allocator);
    defer original.deinit();
    try std.testing.expectEqualDeep(legacy.SEMANTIC_DIGEST, (try digest.computeIdentity(&original.arena)).bytes);
    const identity = try air.semanticIdentity(std.testing.allocator);
    std.debug.print("ETHEREUM_PUBLIC_LOGUP_INPUT_SEMANTIC_DIGEST={s}\n", .{std.fmt.bytesToHex(identity.bytes, .lower)});
    try std.testing.expectEqualDeep(air.SEMANTIC_DIGEST, identity.bytes);
}

test "Ethereum role input preserves legacy constraints and routes with explicit scope" {
    var original = try legacy.build(std.testing.allocator);
    defer original.deinit();
    var routed = try air.build(std.testing.allocator);
    defer routed.deinit();
    var row: [legacy.LOGICAL_INPUT_COUNT]M31 = undefined;
    for (&row, 0..) |*word, index| word.* = M31.fromU64(index * 7 + 1);
    for (0..legacy.LOGICAL_INPUT_COUNT) |mutation| {
        row[mutation] = row[mutation].add(M31.one());
        const new_row = air.logicalRow(row, 1100, 3, row[14].toU32(), 94);
        const old_values = try support.evaluateArena(std.testing.allocator, &original.arena, &row);
        defer std.testing.allocator.free(old_values);
        const new_values = try support.evaluateArena(std.testing.allocator, &routed.arena, &new_row);
        defer std.testing.allocator.free(new_values);
        for (original.arena.constraintsView(), routed.arena.constraintsView()) |old, new|
            try std.testing.expect(old_values[types.idIndex(old.root)].eql(new_values[types.idIndex(new.root)]));
        for (original.events, routed.events[0..legacy.RELATION_EVENT_COUNT]) |old_id, new_id| {
            const a = original.arena.effect(old_id).?;
            const b = routed.arena.effect(new_id).?;
            try std.testing.expectEqualDeep(a.binding, b.binding);
            try std.testing.expect(old_values[types.idIndex(a.liveness.?)].eql(new_values[types.idIndex(b.liveness.?)]));
            for (original.arena.effectValues(old_id).?, routed.arena.effectValues(new_id).?) |x, y|
                try std.testing.expect(old_values[types.idIndex(x)].eql(new_values[types.idIndex(y)]));
        }
    }
}

test "Ethereum role input uses one value for source consumption arithmetic and publication" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var row = [_]M31{M31.zero()} ** legacy.LOGICAL_INPUT_COUNT;
    row[0] = M31.one();
    row[1] = M31.fromCanonical(123);
    row[2] = M31.one();
    row[3] = M31.one();
    row[8] = M31.fromCanonical(42);
    row[9] = M31.fromCanonical(100);
    row[10] = M31.fromCanonical(7);
    row[11] = M31.fromCanonical(42);
    row[13] = M31.one();
    const logical = air.logicalRow(row, 1100, 3, 1115, 94);
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &logical);
    defer std.testing.allocator.free(values);
    for ([_]usize{ 0, 4, 5, 6 }) |event_index| {
        const tuple = definition.arena.effectValues(definition.events[event_index]).?;
        try std.testing.expectEqual(@as(u32, 123), values[types.idIndex(tuple[2])].toU32());
    }
    const source = definition.arena.effectValues(definition.events[0]).?;
    try std.testing.expectEqual(@as(u32, 1115), values[types.idIndex(source[0])].toU32());
    const header = definition.arena.effectValues(definition.events[6]).?;
    try std.testing.expectEqual(@as(u32, 1102), values[types.idIndex(header[0])].toU32());
    try std.testing.expectEqual(@as(u32, 94), values[types.idIndex(header[1])].toU32());
}
