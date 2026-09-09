const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("vm_public_claim_hash.zig");
const air = @import("ethereum_publication_hash_v1.zig");
const binding = @import("universal_relation_binding.zig");
const types = @import("../../air/lang/types.zig");
const support = @import("test_support.zig");

test "ethereum publication hash identity preserves legacy seal" {
    const original = try legacy.identity(std.testing.allocator);
    try std.testing.expectEqualDeep(legacy.SEMANTIC_DIGEST, original.bytes);
    const identity = try air.semanticIdentity(std.testing.allocator);
    std.debug.print("ETHEREUM_PUBLICATION_HASH_SEMANTIC_DIGEST={s}\n", .{std.fmt.bytesToHex(identity.bytes, .lower)});
    try std.testing.expectEqualDeep(air.SEMANTIC_DIGEST, identity.bytes);
    try std.testing.expect(!std.meta.eql(original.bytes, identity.bytes));
}

test "ethereum publication hash preprocessing permutation preserves constraints and tuples" {
    var original = try legacy.build(std.testing.allocator);
    defer original.deinit();
    var routed = try air.build(std.testing.allocator);
    defer routed.deinit();
    const old_plan = try binding.Binding(legacy).authenticate(&original);
    const new_plan = try air.Relation.authenticate(&routed);
    var row: [legacy.LOGICAL_INPUT_COUNT]M31 = undefined;
    for (&row, 0..) |*word, index| word.* = M31.fromU64(index * 23 + 5);
    // Equivalence also holds for hostile values, not just valid hash rows.
    for (0..legacy.LOGICAL_INPUT_COUNT) |mutation| {
        row[mutation] = row[mutation].add(M31.one());
        const new_row = air.fromLegacy(row);
        const old_values = try support.evaluateArena(std.testing.allocator, &original.arena, &row);
        defer std.testing.allocator.free(old_values);
        const new_values = try support.evaluateArena(std.testing.allocator, &routed.arena, &new_row);
        defer std.testing.allocator.free(new_values);
        for (original.arena.constraintsView(), routed.arena.constraintsView()) |old, new|
            try std.testing.expect(old_values[types.idIndex(old.root)].eql(new_values[types.idIndex(new.root)]));
        const old_entries = try old_plan.entries(&original.arena, legacy.SEMANTIC_DIGEST, original.events, row);
        const new_entries = try new_plan.entries(&routed.arena, air.SEMANTIC_DIGEST, routed.events, new_row);
        try std.testing.expectEqualDeep(old_entries, new_entries);
    }
}
