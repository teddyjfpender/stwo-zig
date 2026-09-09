const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ir = @import("../../air/lang/ir.zig");
const types = @import("../../air/lang/types.zig");
const support = @import("test_support.zig");
const state = @import("transcript_state.zig");
const payload = @import("transcript_payload.zig");
const routed_state = @import("ethereum_transcript_state_v1.zig");
const routed_payload = @import("transcript_payload_clocks_v2.zig");
const witness = @import("transcript_payload_witness.zig");
const routing = @import("../ethereum_publication_routing_v1.zig");

test "Ethereum native publication transcript identities preserve legacy seals" {
    try std.testing.expectEqualDeep(state.SEMANTIC_DIGEST, (try state.identity(std.testing.allocator)).bytes);
    try std.testing.expectEqualDeep(payload.SEMANTIC_DIGEST, (try payload.identity(std.testing.allocator)).bytes);
    const state_identity = try routed_state.semanticIdentity(std.testing.allocator);
    const payload_identity = try routed_payload.semanticIdentity(std.testing.allocator);
    // Print both before either assertion so the serialized build can pin both.
    std.debug.print("ETHEREUM_TRANSCRIPT_STATE_SEMANTIC_DIGEST={s}\nETHEREUM_TRANSCRIPT_PAYLOAD_SEMANTIC_DIGEST={s}\n", .{
        std.fmt.bytesToHex(state_identity.bytes, .lower),
        std.fmt.bytesToHex(payload_identity.bytes, .lower),
    });
    try std.testing.expectEqualDeep(routed_state.SEMANTIC_DIGEST, state_identity.bytes);
    try std.testing.expectEqualDeep(routed_payload.SEMANTIC_DIGEST, payload_identity.bytes);
}

test "Ethereum native publication retains every legacy constraint and relation" {
    var old_state = try state.build(std.testing.allocator);
    defer old_state.deinit();
    var new_state = try routed_state.build(std.testing.allocator);
    defer new_state.deinit();
    var state_row: [state.LOGICAL_INPUT_COUNT]M31 = undefined;
    for (&state_row, 0..) |*value, index| value.* = M31.fromU64(index * 13 + 9);
    for (0..state.LOGICAL_INPUT_COUNT) |mutation| {
        state_row[mutation] = state_row[mutation].add(M31.one());
        const converted = routed_state.logicalRow(state_row, true);
        try expectLegacyParity(&old_state.arena, &new_state.arena, &state_row, &converted);
    }
    var old_payload = try payload.build(std.testing.allocator);
    defer old_payload.deinit();
    var new_payload = try routed_payload.build(std.testing.allocator);
    defer new_payload.deinit();
    var payload_row: [payload.LOGICAL_INPUT_COUNT]M31 = undefined;
    for (&payload_row, 0..) |*value, index| value.* = M31.fromU64(index * 29 + 7);
    const at = payload.PHYSICAL_MAIN_COLUMN_COUNT + payload.PREPROCESSED_COLUMN_COUNT;
    for (0..payload.LOGICAL_INPUT_COUNT) |mutation| {
        payload_row[mutation] = payload_row[mutation].add(M31.one());
        const converted = payload_row[0..at].* ++ .{ M31.one(), M31.fromCanonical(1114), M31.fromCanonical(32), M31.one() } ++ payload_row[at..].*;
        try expectLegacyParity(&old_payload.arena, &new_payload.arena, &payload_row, &converted);
    }
}

test "Ethereum native publication terminal exports input digest rather than draw output" {
    var definition = try routed_state.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try routed_state.Relation.authenticate(&definition);
    var original = [_]M31{M31.zero()} ** state.LOGICAL_INPUT_COUNT;
    original[0] = M31.one();
    original[17] = M31.one(); // row mask
    original[18] = M31.one(); // segment lane
    original[34] = M31.one(); // segment parameter
    for (0..8) |limb| {
        original[1 + limb] = M31.fromU64(100 + limb);
        original[9 + limb] = M31.fromU64(900 + limb);
    }
    const row = routed_state.logicalRow(original, true);
    const entries = try plan.entries(&definition.arena, routed_state.SEMANTIC_DIGEST, definition.events, row);
    for (entries[state.RELATION_EVENT_COUNT..], 0..) |entry, limb| {
        try std.testing.expectEqual(@import("../../air/lang/relation.zig").Domain.recursion_vm_public_claim_word, entry.domain);
        try std.testing.expect(!entry.numerator.isZero());
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        const tuple = definition.arena.effectValues(definition.events[state.RELATION_EVENT_COUNT + limb]).?;
        try std.testing.expectEqual(@as(u32, 1114), values[types.idIndex(tuple[0])].toU32());
        try std.testing.expectEqual(routing.terminalIndex(@intCast(limb)).?, values[types.idIndex(tuple[1])].toU32());
        try std.testing.expect(values[types.idIndex(tuple[2])].eql(original[1 + limb]));
    }
    const disabled = try plan.entries(&definition.arena, routed_state.SEMANTIC_DIGEST, definition.events, routed_state.logicalRow(original, false));
    for (disabled[state.RELATION_EVENT_COUNT..]) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "Ethereum native publication payload exports source values without fixed-value fallback" {
    var definition = try routed_payload.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try routed_payload.Relation.authenticate(&definition);
    var metadata: witness.Row = .{ .row_mask = 0, .segment_mask = 0, .binary_mask = 0, .verifier_id = 0, .sequence = 0, .tag = 0, .args = .{0} ** 4, .payload_index = 0, .source_kind = .statement, .item_index = 0, .limb_index = 0, .constant_mask = 0, .input_use_count = 0, .constant_value = 0, .source_hash_id = 0, .source_word_index = 0 };
    metadata.row_mask = 1;
    metadata.segment_mask = 1;
    metadata.verifier_id = witness.SEGMENT_VERIFIER_ID;
    metadata.source_kind = .statement;
    metadata.item_index = routing.STATEMENT_SCOPE;
    metadata.limb_index = routing.rawIndex(.statement_authority, 0).?;
    metadata.source_word_index = @import("../poseidon2_channel.zig").RATE;
    for ([_]u32{ 3, 65535 }) |word| {
        const row = try routed_payload.logicalRow(metadata, M31.fromCanonical(word));
        const entries = try plan.entries(&definition.arena, routed_payload.SEMANTIC_DIGEST, definition.events, row);
        try std.testing.expect(entries[1].numerator.isZero()); // No duplicate verifier input.
        try std.testing.expect(entries[2].numerator.isZero()); // No clock alias.
        try std.testing.expect(!entries[3].numerator.isZero());
        try std.testing.expectEqual(@import("../../air/lang/relation.zig").Domain.recursion_vm_public_claim_word, entries[3].domain);
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        const tuple = definition.arena.effectValues(definition.events[3]).?;
        try std.testing.expectEqual(word, values[types.idIndex(tuple[2])].toU32());
        for (definition.arena.constraintsView()) |constraint| try std.testing.expect(values[types.idIndex(constraint.root)].isZero());
    }
    try std.testing.expectError(error.InvalidTraceRow, witness.logicalRowForRecordedFrame(metadata, M31.one(), .segment_leaf));
    metadata.constant_mask = 1;
    try std.testing.expectError(error.InvalidTraceRow, routed_payload.logicalRow(metadata, M31.one()));
    metadata.constant_mask = 0;
    metadata.limb_index = 81; // Reserved gap, not a payload source.
    try std.testing.expectError(error.InvalidTraceRow, routed_payload.logicalRow(metadata, M31.one()));
}

fn expectLegacyParity(old: *const ir.Arena, new: *const ir.Arena, old_row: []const M31, new_row: []const M31) !void {
    const old_values = try support.evaluateArena(std.testing.allocator, old, old_row);
    defer std.testing.allocator.free(old_values);
    const new_values = try support.evaluateArena(std.testing.allocator, new, new_row);
    defer std.testing.allocator.free(new_values);
    try std.testing.expectEqual(old.constraintsView().len, new.constraintsView().len);
    for (old.constraintsView(), new.constraintsView()) |a, b|
        try std.testing.expect(old_values[types.idIndex(a.root)].eql(new_values[types.idIndex(b.root)]));
    for (0..old.effectsView().len) |index| {
        const effect_id: types.EffectId = @enumFromInt(index);
        const a = old.effect(effect_id).?;
        const b = new.effect(effect_id).?;
        try std.testing.expectEqualDeep(a.binding, b.binding);
        try std.testing.expect(old_values[types.idIndex(a.liveness.?)].eql(new_values[types.idIndex(b.liveness.?)]));
        for (old.effectValues(effect_id).?, new.effectValues(effect_id).?) |x, y|
            try std.testing.expect(old_values[types.idIndex(x)].eql(new_values[types.idIndex(y)]));
    }
}
