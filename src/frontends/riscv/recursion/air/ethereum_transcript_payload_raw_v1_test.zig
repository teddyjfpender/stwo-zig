const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const legacy = @import("transcript_payload.zig");
const clocks = @import("transcript_payload_clocks_v2.zig");
const raw = @import("ethereum_transcript_payload_raw_v1.zig");
const hash_air = @import("ethereum_publication_hash_v1.zig");
const hash_witness = @import("vm_public_claim_hash_witness.zig");
const interaction = @import("relation_interaction.zig");
const relation = @import("../../air/lang/relation.zig");
const types = @import("../../air/lang/types.zig");
const support = @import("test_support.zig");
const channel = @import("../poseidon2_channel.zig");

test "Ethereum raw transcript export preserves legacy seals and pins opt-in identity" {
    try std.testing.expectEqualDeep(legacy.SEMANTIC_DIGEST, (try legacy.identity(std.testing.allocator)).bytes);
    try std.testing.expectEqualDeep(clocks.SEMANTIC_DIGEST, (try clocks.semanticIdentity(std.testing.allocator)).bytes);
    const identity = try raw.semanticIdentity(std.testing.allocator);
    std.debug.print("ETHEREUM_RAW_TRANSCRIPT_PAYLOAD_SEMANTIC_DIGEST={s}\n", .{std.fmt.bytesToHex(identity.bytes, .lower)});
    try std.testing.expectEqualDeep(raw.SEMANTIC_DIGEST, identity.bytes);
    try std.testing.expectEqual(@as(usize, 23), raw.PREPROCESSED_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 27), raw.LOGICAL_INPUT_COUNT);
    var definition = try raw.build(std.testing.allocator);
    defer definition.deinit();
    _ = try raw.Relation.authenticate(&definition);
}

test "Ethereum raw transcript export preserves constraints clock routing and disabled events" {
    var old = try clocks.build(std.testing.allocator);
    defer old.deinit();
    var new = try raw.build(std.testing.allocator);
    defer new.deinit();
    var row: clocks.Relation.Row = undefined;
    for (&row, 0..) |*value, index| value.* = M31.fromU64(index * 19 + 7);
    // Retain parity even for hostile inputs, independently of row validation.
    for (0..row.len) |index| {
        row[index] = row[index].add(M31.one());
        const converted = raw.logicalRow(row, true);
        const before = try support.evaluateArena(std.testing.allocator, &old.arena, &row);
        defer std.testing.allocator.free(before);
        const after = try support.evaluateArena(std.testing.allocator, &new.arena, &converted);
        defer std.testing.allocator.free(after);
        for (old.arena.constraintsView(), new.arena.constraintsView()) |a, b|
            try std.testing.expect(before[types.idIndex(a.root)].eql(after[types.idIndex(b.root)]));
        for (old.events, new.events[0..old.events.len]) |old_id, new_id| {
            const a = old.arena.effect(old_id).?;
            const b = new.arena.effect(new_id).?;
            try std.testing.expectEqualDeep(a.binding, b.binding);
            try std.testing.expect(before[types.idIndex(a.liveness.?)].eql(after[types.idIndex(b.liveness.?)]));
            for (old.arena.effectValues(old_id).?, new.arena.effectValues(new_id).?) |x, y|
                try std.testing.expect(before[types.idIndex(x)].eql(after[types.idIndex(y)]));
        }
    }
    const active = payloadRow(516, M31.fromCanonical(65535), true);
    const plan = try raw.Relation.authenticate(&new);
    const enabled = try plan.entries(&new.arena, raw.SEMANTIC_DIGEST, new.events, raw.logicalRow(active, true));
    // Existing clock consumer needs exactly its original one source; the hash
    // uses the added event, so no clock fan-out or node-use count changes.
    try std.testing.expect(enabled[2].numerator.eql(core.fields.qm31.QM31.one()));
    try std.testing.expect(enabled[4].numerator.eql(core.fields.qm31.QM31.one()));
    const disabled = try plan.entries(&new.arena, raw.SEMANTIC_DIGEST, new.events, raw.logicalRow(active, false));
    try std.testing.expect(disabled[4].numerator.isZero());
    const padding = [_]M31{M31.zero()} ** clocks.LOGICAL_INPUT_COUNT;
    const padded = try plan.entries(&new.arena, raw.SEMANTIC_DIGEST, new.events, raw.logicalRow(padding, true));
    for (padded) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "Ethereum raw transcript and native wire hash require identical payload words" {
    const words = [_]M31{ M31.fromCanonical(75), M31.fromCanonical(65535), M31.fromCanonical(917) };
    const domain = @import("../segment_statement_v2.zig").WIRE_ID_DOMAIN;
    const metadata = try hash_witness.expectedRow(words.len, 1, 0);
    var state = [_]M31{M31.zero()} ** hash_witness.STATE_WIDTH;
    state[state.len - 1] = M31.fromCanonical(domain);
    const main = hash_witness.materialize(metadata, &words, state);
    const digest = channel.hashCanonicalWords(&words, domain);
    for (digest, main.output[0..digest.len]) |a, b| try std.testing.expectEqual(a, b.toU32());
    const hash_row = hash_air.fromLegacy(main.values() ++ metadata.values() ++ [_]M31{
        M31.one(),                             M31.fromCanonical(domain), M31.fromCanonical(raw.RAW_WIRE_SCOPE),
        M31.fromCanonical(raw.RAW_WIRE_SCOPE), M31.fromCanonical(11),
    });
    var hash_definition = try hash_air.build(std.testing.allocator);
    defer hash_definition.deinit();
    const hash_plan = try hash_air.Relation.authenticate(&hash_definition);
    var definition = try raw.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try raw.Relation.authenticate(&definition);
    const domain_mask = @as(u64, 1) << @intFromEnum(relation.Domain.recursion_vm_public_claim_word);
    var rows: [words.len]raw.Relation.Row = undefined;
    for (words, &rows, 0..) |word, *row, index| row.* = raw.logicalRow(payloadRow(@intCast(index), word, false), true);
    var exact = interaction.TupleLedger.init(std.testing.allocator);
    defer exact.deinit();
    try plan.appendPreparedTupleContributions(&exact, 5, &rows, domain_mask);
    try hash_plan.appendPreparedTupleContributions(&exact, 13, &.{hash_row}, domain_mask);
    try std.testing.expect(exact.classify().isClosed());
    for (0..rows.len) |index| {
        var changed = rows;
        changed[index][1] = changed[index][1].add(M31.one());
        var ledger = interaction.TupleLedger.init(std.testing.allocator);
        defer ledger.deinit();
        try plan.appendPreparedTupleContributions(&ledger, 5, &changed, domain_mask);
        try hash_plan.appendPreparedTupleContributions(&ledger, 13, &.{hash_row}, domain_mask);
        try std.testing.expectEqual(@as(usize, 2), ledger.classify().unmatched_tuple_count);
        // The original FS payload event and new raw hash event share the same
        // main value. A prover cannot supply independent values to the two.
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &changed[index]);
        defer std.testing.allocator.free(values);
        const fs_tuple = definition.arena.effectValues(definition.events[0]).?;
        const hash_tuple = definition.arena.effectValues(definition.events[4]).?;
        try std.testing.expect(values[types.idIndex(fs_tuple[8])].eql(values[types.idIndex(hash_tuple[2])]));
    }
    var duplicate = interaction.TupleLedger.init(std.testing.allocator);
    defer duplicate.deinit();
    try plan.appendPreparedTupleContributions(&duplicate, 5, &rows, domain_mask);
    try plan.appendPreparedTupleContributions(&duplicate, 5, rows[0..1], domain_mask);
    try hash_plan.appendPreparedTupleContributions(&duplicate, 13, &.{hash_row}, domain_mask);
    try std.testing.expect(!duplicate.classify().isClosed());
}

test "Ethereum raw transcript root topology closes two raw uses without duplicate hash publishers" {
    const router_air = @import("ethereum_publication_control_v1.zig");
    const allocator = std.testing.allocator;
    // A bounded contiguous preimage includes both canonical root coordinates.
    // The actual hash AIR consumes every word; this is only its input boundary,
    // not a claim that this synthetic preimage is a valid V2 document.
    var words = [_]M31{M31.zero()} ** 496;
    words[482] = M31.fromCanonical(10);
    words[483] = M31.one();
    words[494] = M31.fromCanonical(20);
    words[495] = M31.fromCanonical(2);
    var rows: [words.len]raw.Relation.Row = undefined;
    for (words, &rows, 0..) |value, *row, index| row.* = raw.logicalRow(payloadRow(@intCast(index), value, false), true);
    var definition = try raw.build(allocator);
    defer definition.deinit();
    const plan = try raw.Relation.authenticate(&definition);
    var hash_definition = try hash_air.build(allocator);
    defer hash_definition.deinit();
    const hash_plan = try hash_air.Relation.authenticate(&hash_definition);
    var router_definition = try router_air.build(allocator);
    defer router_definition.deinit();
    const router_plan = try router_air.Relation.authenticate(&router_definition);
    const hash_count = (words.len + 1 + hash_witness.RATE - 1) / hash_witness.RATE;
    var hashes: [hash_count]hash_air.Relation.Row = undefined;
    const domain = @import("../segment_statement_v2.zig").WIRE_ID_DOMAIN;
    var state = [_]M31{M31.zero()} ** hash_witness.STATE_WIDTH;
    state[state.len - 1] = M31.fromCanonical(domain);
    for (&hashes, 0..) |*row, index| {
        const metadata = try hash_witness.expectedRow(words.len, hash_count, index);
        const main = hash_witness.materialize(metadata, &words, state);
        row.* = hash_air.fromLegacy(main.values() ++ metadata.values() ++ [_]M31{
            M31.one(),                             M31.fromCanonical(domain), M31.fromCanonical(raw.RAW_WIRE_SCOPE),
            M31.fromCanonical(raw.RAW_WIRE_SCOPE), M31.fromCanonical(11),
        });
        state = main.output;
    }
    var routed: [6]router_air.Relation.Row = undefined;
    for ([_]u32{ 482, 483, 494, 495 }, routed[0..4]) |index, *row| {
        const source = raw.exportForRawWord(index);
        try std.testing.expectEqual(@as(u32, 1114), source.scope);
        try std.testing.expectEqual(index + 256, source.index);
        try std.testing.expectEqual(@as(u32, 2), source.uses);
        var pp = [_]u32{0} ** router_air.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[13] = 1;
        pp[14] = raw.RAW_WIRE_SCOPE;
        pp[15] = index;
        row.* = try router_air.rawWordRow(words[index], words[index], M31.zero(), false, source.index, pp);
    }
    for ([_]u32{ 482, 494 }, [_]u32{ 295, 378 }, routed[4..]) |index, statement_index, *row| {
        var pp = [_]u32{0} ** router_air.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[10] = 1;
        pp[11] = 0;
        pp[12] = statement_index;
        const joined = words[index].add(words[index + 1].mul(M31.fromCanonical(65536)));
        row.* = try router_air.rawWordRow(joined, words[index], words[index + 1], true, raw.ROOT_SOURCE_BASE + index, pp);
    }
    const mask = @as(u64, 1) << @intFromEnum(relation.Domain.recursion_vm_public_claim_word);
    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 5, &rows, mask);
    try hash_plan.appendPreparedTupleContributions(&ledger, 13, &hashes, mask);
    try router_plan.appendPreparedTupleContributions(&ledger, 17, &routed, mask);
    try std.testing.expect(ledger.classify().isClosed());
    for ([_]usize{ 0, 482, 483, 494, 495 }) |index| {
        const original = rows[index];
        rows[index][1] = rows[index][1].add(M31.one());
        var changed = interaction.TupleLedger.init(allocator);
        defer changed.deinit();
        try plan.appendPreparedTupleContributions(&changed, 5, &rows, mask);
        try hash_plan.appendPreparedTupleContributions(&changed, 13, &hashes, mask);
        try router_plan.appendPreparedTupleContributions(&changed, 17, &routed, mask);
        try std.testing.expect(!changed.classify().isClosed());
        rows[index] = original;
    }
    // Repeating an old root hash publisher is rejected by exact multiplicity.
    try router_plan.appendPreparedTupleContributions(&ledger, 17, routed[0..1], mask);
    try std.testing.expect(!ledger.classify().isClosed());
    for ([_]u32{ 0, 60, 472, 484, 516, 644, 652, 1000 }) |index| {
        const source = raw.exportForRawWord(index);
        try std.testing.expectEqual(raw.RAW_WIRE_SCOPE, source.scope);
        try std.testing.expectEqual(index, source.index);
        try std.testing.expectEqual(@as(u32, 1), source.uses);
    }
}

fn payloadRow(index: u32, value: M31, clock: bool) clocks.Relation.Row {
    var row = [_]M31{M31.zero()} ** clocks.LOGICAL_INPUT_COUNT;
    row[0] = M31.one(); // main enabler
    row[1] = value;
    row[2] = M31.one(); // row mask
    row[3] = M31.one(); // segment mask
    row[2 + 10] = M31.fromCanonical(index); // authenticated payload coordinate
    if (clock) {
        row[2 + 17] = M31.one(); // original clock route, one use
        row[2 + 18] = M31.fromCanonical(5);
        row[2 + 19] = M31.fromCanonical(index - 516);
    }
    row[clocks.LOGICAL_INPUT_COUNT - 2] = M31.one();
    return row;
}
