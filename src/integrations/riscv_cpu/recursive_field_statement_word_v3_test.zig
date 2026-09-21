const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const air = recursion.air;
const Air = air.field_statement_word_v3;
const Binding = air.universal_relation_binding.Binding(Air);
const direct = air.direct_constraint_program;
const M31 = core.fields.m31.M31;
const Ledger = air.relation_interaction.TupleLedger;
const Row = [Air.LOGICAL_INPUT_COUNT]M31;
const transcript = @import("recursive_secure_transcript_rows_v1.zig");
const public = @import("recursive_field_node_public_v2.zig");
const hashes = @import("recursive_common_fold_public_hash_v3.zig");

test "field statement bridge rejects noncanonical limb aliases" {
    const identity = try Air.computeSemanticDigest(std.testing.allocator);
    std.debug.print("FIELD_STATEMENT_BRIDGE_DIGEST={s}\n", .{std.fmt.bytesToHex(identity, .lower)});
    try std.testing.expectEqualDeep(Air.SEMANTIC_DIGEST, identity);
    var logs = [_]u32{4} ** 36;
    logs[34] = 10;
    logs[35] = 16;
    const frozen = try air.universal_manifest.build(logs);
    const selected = try air.universal_manifest.buildForCatalog(transcript.catalog, logs);
    try std.testing.expect(!std.mem.eql(u8, &frozen.seal, &selected.seal));
    for (frozen.placements, selected.placements, 0..) |old, current, index| {
        if (index == 10) {
            try std.testing.expectEqualDeep(air.fixed_wire_v3.SEMANTIC_DIGEST, current.?.geometry.semantic_digest);
        } else if (index == 12) {
            try std.testing.expectEqualDeep(Air.SEMANTIC_DIGEST, current.?.geometry.semantic_digest);
            try std.testing.expectEqual(3, current.?.geometry.protocol_constraint_degree);
        } else if (index >= 13 and index <= 16) {
            try std.testing.expectEqualDeep(air.vm_public_claim_hash.SEMANTIC_DIGEST, current.?.geometry.semantic_digest);
        } else if (index == 17) {
            try std.testing.expectEqualDeep(air.field_public_word_v3.SEMANTIC_DIGEST, current.?.geometry.semantic_digest);
        } else try std.testing.expectEqualDeep(old.?.geometry, current.?.geometry);
    }
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try Binding.authenticate(&definition);
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    for ([_]u32{ 0, 1, 65535, 65536, core.fields.m31.Modulus - 1 }) |value| {
        const row = try logical(value);
        try check(&compiled, &plan, &row, &ledger);
    }
    // Nonces use all 64 bits: each u32 half keeps its original two limbs,
    // including the values that would alias a canonical field word.
    for ([_]u32{ 0, core.fields.m31.Modulus, 0x80000000, 0xffffffff }) |value| {
        var nonce = (try Air.nonceRow(value)) ++ (try logical(0))[Air.PHYSICAL_MAIN_COLUMN_COUNT..].*;
        nonce[21] = M31.zero();
        nonce[22] = M31.zero();
        try check(&compiled, &plan, &nonce, &ledger);
        nonce[2] = nonce[2].add(M31.one());
        try std.testing.expectError(error.FieldStatementConstraintMismatch, check(&compiled, &plan, &nonce, &ledger));
    }
    try std.testing.expectError(error.NonCanonicalFieldStatementWord, Air.mainRow(core.fields.m31.Modulus));
    var row = try logical(0);
    row[2] = felt(65535);
    row[3] = felt(32767);
    row[4] = felt(255);
    row[5] = felt(255);
    row[6] = felt(255);
    row[7] = felt(127);
    row[8] = M31.one();
    row[9] = felt(254);
    try std.testing.expectError(error.FieldStatementConstraintMismatch, check(&compiled, &plan, &row, &ledger));
    // 0x80000000 reduces to one, but its high limb exceeds fifteen bits.
    row = try logical(1);
    row[2] = M31.zero();
    row[3] = felt(32768);
    row[4] = M31.zero();
    row[5] = M31.zero();
    row[6] = M31.zero();
    row[7] = felt(128);
    row[8] = try felt(65534).inv();
    row[9] = felt(256);
    try std.testing.expectError(error.FieldStatementRangeMismatch, check(&compiled, &plan, &row, &ledger));
    // Checking only 2*high_byte would admit the modular inverse of two.
    row = try logical(8388608);
    row[6] = M31.zero();
    row[7] = felt(1073741824);
    row[9] = M31.one();
    try std.testing.expectError(error.FieldStatementRangeMismatch, check(&compiled, &plan, &row, &ledger));
}

fn logical(value: u32) !Row {
    return (try Air.mainRow(value)) ++ [_]M31{ M31.one(), M31.one(), felt(7), felt(3), M31.zero(), felt(900), M31.zero(), M31.zero(), felt(12), M31.one(), M31.zero(), M31.one(), M31.one() };
}

/// Check the committed profile rows against independently reconstructed child
/// words and the actual composition inputs. The full proof checks the provider.
pub fn exerciseCaptured(views: [2]transcript.View, prefix: *const transcript.Prepared, source: anytype, statements: [2]*const public.NodePublicV2) !void {
    try checkCaptured(views, prefix, source, statements);
    const composition = source.composition_rows.?;
    var first_statement: ?usize = null;
    var statement_count: usize = 0;
    for (composition.input_preprocessing.rows, 0..) |metadata, index| {
        const input = switch (metadata.classification) {
            .recursion_input => |input| input,
            else => continue,
        };
        if (input.source != .statement_word) continue;
        // All slots remain in the input AIR after removing their literal
        // comparisons from the arithmetic graph.
        try std.testing.expect(metadata.use_count > 0);
        statement_count += 1;
        if (first_statement == null) first_statement = index;
    }
    try std.testing.expectEqual(2 * public.STATEMENT_WORD_COUNT, statement_count);
    const index = first_statement orelse return error.MissingCompositionStatementInput;
    const values = @constCast(composition.schedule_values);
    const original = values[index];
    values[index] = original.add(M31.one());
    defer values[index] = original;
    try std.testing.expectError(error.FieldStatementJoinMismatch, checkCaptured(views, prefix, source, statements));
    std.debug.print("COMPOSITION_STATEMENT_BINDING words={d} literal_graph_checks=false changed_input_rejected=true\n", .{statement_count});
}

fn checkCaptured(views: [2]transcript.View, prefix: *const transcript.Prepared, source: anytype, statements: [2]*const public.NodePublicV2) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try Binding.authenticate(&definition);
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    try std.testing.expectEqual(2 * public.AIR_WORD_COUNT + 8, prefix.logical[10].len);
    const scopes = [_]u32{ recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE, recursion.binary_fri_outer_source.RIGHT_COMPOSITION_STATEMENT_SCOPE };
    for (views, statements, 0..) |view, statement, lane| {
        try view.program.validateRecording(view.execution);
        const words = try statement.canonicalAirWords();
        var found = false;
        for (view.program.operations, view.execution.operations, 0..) |operation, recorded, sequence| {
            if (operation.source != .statement) continue;
            try std.testing.expect(!found);
            found = true;
            const limbs = view.execution.hash_frames[recorded.first_hash_id].words[recursion.recording_poseidon_channel_v4.RATE..];
            try std.testing.expectEqual(2 * words.len, limbs.len);
            var control: ?[7]M31 = null;
            for (prefix.logical[0]) |row| {
                if (row[2].toU32() == lane + 1 and row[3].toU32() == sequence and row[4].toU32() > 28) {
                    try std.testing.expect(control == null);
                    control = row[2..9].*;
                }
            }
            const coordinates = control orelse return error.MissingStatementControl;
            for (words, 0..) |expected, word_index| {
                const combined = @as(u64, limbs[2 * word_index].toU32()) + 65536 * @as(u64, limbs[2 * word_index + 1].toU32());
                const value = std.math.cast(u32, combined) orelse return error.NonCanonicalFieldStatementWord;
                try std.testing.expectEqual(expected, value);
                const body = word_index >= public.HEADER_WORD_COUNT and word_index < public.HEADER_WORD_COUNT + public.STATEMENT_WORD_COUNT;
                const extra = !body;
                const existing = body or word_index >= hashes.CHILD_HASH_START;
                const uses: u32 = if (body and prefix.logical[12].len != 0) 2 else 1;
                const pp = [_]M31{M31.one()} ++ coordinates ++ [_]M31{ felt(@intCast(2 * word_index)), felt(scopes[lane]), felt(hashes.nodeWordIndex(word_index)), felt(@intFromBool(existing or extra)), felt(uses + @intFromBool(existing and extra)) };
                const row = (try Air.mainRow(value)) ++ pp;
                const actual = prefix.logical[10][lane * (words.len + 4) + word_index];
                try std.testing.expectEqualDeep(row, actual);
                try check(&compiled, &plan, &actual, &ledger);
            }
        }
        try std.testing.expect(found);
        var nonce_at = lane * (words.len + 4) + words.len;
        for (view.program.operations, view.execution.operations, 0..) |operation, recorded, sequence| {
            if (operation.source != .nonce) continue;
            const limbs = view.execution.hash_frames[recorded.first_hash_id].words[recursion.recording_poseidon_channel_v4.RATE..];
            try std.testing.expectEqual(@as(usize, 4), limbs.len);
            for (0..2) |index| {
                const value = limbs[2 * index].toU32() + 65536 * limbs[2 * index + 1].toU32();
                const tag = air.pow_frame.controlTag(if (operation.context == .interaction_pow) .interaction else .pcs);
                const pp = [_]M31{ M31.one(), felt(@intCast(lane + 1)), felt(@intCast(sequence)), felt(tag), felt(operation.pow_bits), felt(4), M31.zero(), felt(operation.item), felt(@intCast(2 * index)), M31.zero(), M31.zero(), M31.zero(), M31.zero() };
                const expected = (try Air.nonceRow(value)) ++ pp;
                try std.testing.expectEqualDeep(expected, prefix.logical[10][nonce_at]);
                try check(&compiled, &plan, &expected, &ledger);
                nonce_at += 1;
            }
        }
        try std.testing.expectEqual((lane + 1) * (words.len + 4), nonce_at);
    }
    var word_definition = try air.transcript_word.build(std.testing.allocator);
    defer word_definition.deinit();
    const word_plan = try air.universal_relation_binding.Binding(air.transcript_word).authenticate(&word_definition);
    for (prefix.logical[4]) |row| for (word_plan.preparedEntries(row)) |entry| {
        if (entry.domain != .recursion_transcript_payload_word or entry.numerator.isZero()) continue;
        const verifier = (try entry.values[0].tryIntoM31()).toU32();
        const sequence = (try entry.values[1].tryIntoM31()).toU32();
        if (verifier < 1 or verifier > 2) continue;
        const kind = views[verifier - 1].program.operations[sequence].source;
        if (kind != .statement and kind != .nonce) continue;
        try ledger.append(entry.domain, 4, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    };
    const composition = source.composition_rows.?;
    for (composition.input_preprocessing.rows, composition.schedule_values) |metadata, value| {
        const row = try air.vm_air_composition_input_witness.logicalRow(metadata, value, .binary_node);
        for (composition.input_relation.preparedEntries(row)) |entry| {
            if (entry.domain != .recursion_statement_word) continue;
            try ledger.append(entry.domain, 18, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
        }
    }
    inline for (.{ 10, 11, 17 }, .{ 11, 12, 17 }) |index, slot| {
        const Component = transcript.catalog.LOGICAL_ROWS[index].Air;
        var component_definition = try Component.build(std.testing.allocator);
        defer component_definition.deinit();
        const component_plan = try air.universal_relation_binding.Binding(Component).authenticate(&component_definition);
        for (prefix.logical[slot]) |row| for (component_plan.preparedEntries(row)) |entry| {
            if (entry.domain == .recursion_statement_word)
                try ledger.append(entry.domain, index, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
        };
    }
    const parent_words = try source.pair.live.input.outputNodePublic().canonicalAirWords();
    for (parent_words, 0..) |word, index| {
        const Q = core.fields.qm31.QM31;
        try ledger.append(.recursion_statement_word, 17, 0, .consume, Q.one().neg(), &.{ Q.fromBase(felt(air.field_public_word_v3.PUBLIC_SCOPE)), Q.fromBase(felt(@intCast(index))), Q.fromBase(felt(word)) });
    }
    const report = ledger.classify();
    std.debug.print("FIELD_STATEMENT_BRIDGE_JOIN contributions={d} unmatched={d} canonical_words=900 nonce_limbs=16\n", .{ report.contribution_count, report.unmatched_tuple_count });
    if (!report.isClosed()) return error.FieldStatementJoinMismatch;
}

fn check(compiled: *const direct.Program, plan: *const Binding.Plan, row: *const Row, ledger: *Ledger) !void {
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try compiled.evaluateBaseInto(row, &scratch, &roots);
    for (roots) |root| if (!root.isZero()) return error.FieldStatementConstraintMismatch;
    for (plan.preparedEntries(row.*)) |entry| {
        if (entry.numerator.isZero()) continue;
        if (entry.domain == .range_check_8_8) {
            for (entry.values[0..entry.arity]) |value|
                if ((try value.tryIntoM31()).toU32() > 255) return error.FieldStatementRangeMismatch;
        } else try ledger.append(entry.domain, 12, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    }
}

fn felt(value: u32) M31 {
    return M31.fromCanonical(value);
}
