//! Ethereum routing changes exports only; CSP and canonical constraints stay exact.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("vm_public_claim_input.zig");
const air = @import("ethereum_vm_public_claim_input_v1.zig");
const witness = @import("vm_public_claim_input_witness.zig");
const types = @import("../../air/lang/types.zig");
const support = @import("test_support.zig");

test "ethereum row12 routing identity preserves CSP seal" {
    try std.testing.expectEqual(@as(u16, 2), air.PROFILE_VERSION);
    try std.testing.expectEqualStrings("recursion.ethereum_vm_public_claim_input.v2", air.STABLE_NAME);
    const original = try legacy.semanticIdentity(std.testing.allocator);
    try std.testing.expectEqualStrings(legacy.SEMANTIC_DIGEST_HEX, &std.fmt.bytesToHex(original.bytes, .lower));
    const routed = try air.semanticIdentity(std.testing.allocator);
    std.debug.print("ETHEREUM_CLAIM_ROUTING_SEMANTIC_DIGEST={s}\n", .{std.fmt.bytesToHex(routed.bytes, .lower)});
    try std.testing.expectEqualStrings(air.SEMANTIC_DIGEST_HEX, &std.fmt.bytesToHex(routed.bytes, .lower));
    try std.testing.expect(!std.meta.eql(original.bytes, routed.bytes));
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    _ = try air.Relation.authenticate(&definition);
}

test "ethereum row12 removes legacy hash fanout and preserves semantic IO and role routes" {
    var original = try legacy.build(std.testing.allocator);
    defer original.deinit();
    var routed = try air.build(std.testing.allocator);
    defer routed.deinit();
    try std.testing.expectEqual(legacy.LOGICAL_INPUT_COUNT + 3, air.LOGICAL_INPUT_COUNT);
    try std.testing.expectEqual(legacy.INTERACTION_COLUMN_COUNT, air.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(original.arena.constraintsView().len, routed.arena.constraintsView().len);

    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, .{ .max_input_words = 2, .max_output_words = 2 });
    defer preprocessing.deinit();
    const words = try std.testing.allocator.alloc(M31, preprocessing.rows.len);
    defer std.testing.allocator.free(words);
    for (words, preprocessing.rows, 0..) |*word, row, index| word.* = switch (row.kind) {
        .constant => |constant| M31.fromCanonical(constant),
        .boolean => M31.fromCanonical(@intCast(index & 1)),
        .u16 => M31.fromCanonical(@intCast((index * 17 + 3) & 0xffff)),
        .field => M31.fromCanonical(@intCast(index * 101 + 7)),
    };
    const cases = [_]witness.ClaimWitness{ .{ .segment_leaf = words }, .{ .binary_node = {} }, .{ .empty_leaf = {} } };
    for (cases) |claim| {
        var main = try witness.MainWitness.init(std.testing.allocator, &preprocessing, claim);
        defer main.deinit();
        for (main.rows, preprocessing.rows) |main_row, preprocessed| {
            const row = witness.logicalInputs(main_row, preprocessed, claim.proofKind());
            const old_values = try support.evaluateArena(std.testing.allocator, &original.arena, &row);
            defer std.testing.allocator.free(old_values);
            const routed_row = air.logicalRow(row, .{ 0, 0, 0 });
            const new_values = try support.evaluateArena(std.testing.allocator, &routed.arena, &routed_row);
            defer std.testing.allocator.free(new_values);
            for (routed.arena.constraintsView()) |constraint|
                try std.testing.expect(new_values[types.idIndex(constraint.root)].isZero());
            for (original.events, routed.events, 0..) |old_id, new_id, index| {
                const old = original.arena.effect(old_id).?;
                const new = routed.arena.effect(new_id).?;
                try std.testing.expect(std.meta.eql(old.binding, new.binding));
                const old_tuple = original.arena.effectValues(old_id).?;
                const new_tuple = routed.arena.effectValues(new_id).?;
                for (old_tuple, new_tuple) |a, b| try std.testing.expect(old_values[types.idIndex(a)].eql(new_values[types.idIndex(b)]));
                const old_weight = old_values[types.idIndex(old.liveness.?)];
                const new_weight = new_values[types.idIndex(new.liveness.?)];
                if (index == 1 or index == 2 or index == 6 or index == 7)
                    try std.testing.expect(new_weight.isZero())
                else
                    try std.testing.expect(old_weight.eql(new_weight));
            }
        }
    }
}

test "ethereum row12 rejects malformed canonical main columns" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, .{ .max_input_words = 2, .max_output_words = 2 });
    defer preprocessing.deinit();
    // One active u16 row with a correct decomposition; then corrupt each main
    // column. The retained range lookup is checked separately below.
    const metadata = preprocessing.rows[241];
    const main = witness.MainRow{ .value = M31.fromCanonical(0x1234), .low_byte = M31.fromCanonical(0x34), .high_byte = M31.fromCanonical(0x12) };
    const valid = air.logicalRow(witness.logicalInputs(main, metadata, .segment_leaf), .{ 0, 0, 0 });
    for (0..air.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
        var mutated = valid;
        mutated[column] = mutated[column].add(M31.one());
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &mutated);
        defer std.testing.allocator.free(values);
        var rejected = false;
        for (definition.arena.constraintsView()) |constraint|
            rejected = rejected or !values[types.idIndex(constraint.root)].isZero();
        try std.testing.expect(rejected);
    }
    // A decomposition preserving the equation still makes a real range request.
    var wide_byte = valid;
    wide_byte[1] = M31.fromCanonical(256);
    wide_byte[2] = M31.fromCanonical(256);
    wide_byte[3] = M31.zero();
    const plan = try air.Relation.authenticate(&definition);
    const entries = try plan.entries(&definition.arena, air.SEMANTIC_DIGEST, definition.events, wide_byte);
    try std.testing.expectEqual(@import("../../air/lang/relation.zig").Domain.range_check_8_8, entries[5].domain);
    try std.testing.expect(!entries[5].numerator.isZero());
}

test "ethereum row12 enables only exact authenticated role source fanout" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var original = [_]M31{M31.zero()} ** legacy.LOGICAL_INPUT_COUNT;
    original[0] = M31.fromCanonical(0x1234);
    original[1] = M31.fromCanonical(0x34);
    original[2] = M31.fromCanonical(0x12);
    original[3] = M31.one();
    original[4] = M31.one(); // row mask
    original[8] = M31.one(); // u16 mask
    original[14] = M31.one(); // segment parameter
    const row = air.logicalRow(original, .{ 2, 3, 1 });
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for ([_]usize{ 2, 6, 7 }, [_]u32{ 2, 3, 1 }) |event_index, uses| {
        const effect = definition.arena.effect(definition.events[event_index]).?;
        try std.testing.expectEqual(uses, values[types.idIndex(effect.liveness.?)].toU32());
    }
}
