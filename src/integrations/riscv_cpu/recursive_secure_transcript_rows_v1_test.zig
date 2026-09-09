const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const recursion = frontend.recursion;
const air = recursion.air;
const direct = air.direct_constraint_program;
const Ledger = air.relation_interaction.TupleLedger;
const Program = @import("recursive_secure_transcript_program_v1.zig").Program;
const rows_mod = @import("recursive_secure_transcript_rows_v1.zig");
const Rows = rows_mod.Rows;
const PayloadRow = std.meta.Child(@FieldType(Rows, "payload"));

pub fn exerciseSharedRecording(comptime Kernel: type, cohort: anytype, session: anytype, artifact: anytype, expected: anytype) !void {
    const allocator = std.testing.allocator;
    var verified = try Kernel.verifyColdWithReplay(allocator, cohort, session, artifact);
    defer verified.deinit();
    const cache_before = Kernel.preprocessedCacheSnapshot();
    var timer = try std.time.Timer.start();
    var recorded = try Kernel.recordColdReplayWithCohort(allocator, cohort, session, &verified);
    const record_ns = timer.read();
    defer recorded.deinit();
    try std.testing.expectEqualDeep(cache_before, Kernel.preprocessedCacheSnapshot());
    try std.testing.expectEqualDeep(expected.replay, recorded.replay);
    try std.testing.expectEqualDeep(expected.execution.identity_sha256, recorded.execution.identity_sha256);
    try std.testing.expectEqualDeep(expected.program.identity, recorded.program.identity);
    {
        const original = verified.cohort_ptr;
        verified.cohort_ptr = 0;
        defer verified.cohort_ptr = original;
        try std.testing.expectError(error.InvalidSecureTemporalParentSharedReplay, Kernel.recordColdReplayWithCohort(allocator, cohort, session, &verified));
    }
    {
        const original = verified.replay.relations.elements[0].z;
        verified.replay.relations.elements[0].z = original.add(QM31.one());
        defer verified.replay.relations.elements[0].z = original;
        try std.testing.expectError(error.InvalidSecureTemporalParentSharedReplay, Kernel.recordColdReplayWithCohort(allocator, cohort, session, &verified));
    }
    std.debug.print("SECURE_TRANSCRIPT_SHARED_RECORDING record_ns={d} extra_preprocessed_lookups=0\n", .{record_ns});
}

pub fn exercise(first: anytype, second: anytype) !void {
    try exercisePrepared(first, second);
    const allocator = std.testing.allocator;
    var left = try first.prepareTranscriptRows(allocator, 1);
    defer left.deinit();
    var changed_child = try second.prepareTranscriptRows(allocator, 1);
    defer changed_child.deinit();
    try std.testing.expectEqualDeep(left.control, changed_child.control);
    for (left.binding, changed_child.binding) |a, b| try std.testing.expectEqualDeep(a.preprocessing, b.preprocessing);
    for (left.state, changed_child.state) |a, b| try std.testing.expectEqualDeep(a.preprocessing, b.preprocessing);
    for (left.word, changed_child.word) |a, b| try std.testing.expectEqualDeep(a.preprocessing, b.preprocessing);
    for (left.payload, changed_child.payload) |a, b| try std.testing.expectEqualDeep(a.preprocessing, b.preprocessing);
    for (left.challenges, changed_child.challenges) |a, b| try std.testing.expectEqualDeep(a.preprocessing, b.preprocessing);
    for (left.randomness, changed_child.randomness) |a, b| try std.testing.expectEqualDeep(a.preprocessing, b.preprocessing);
    try validate(&left, &first.program, &first.execution);
    try validate(&changed_child, &second.program, &second.execution);
    var right = try second.prepareTranscriptRows(allocator, 2);
    defer right.deinit();
    try validate(&right, &second.program, &second.execution);
    if (first.program.kind == .canonical_empty) {
        const root = @import("recursive_common_canonical_empty_universal_manifest_v2.zig").PREPROCESSED_ROOT;
        var root_words: usize = 0;
        for (left.payload) |row| {
            const pp = row.preprocessing;
            if (pp.source_kind != .commitment or pp.item_index != 0) continue;
            try std.testing.expectEqual(@as(u32, 1), pp.constant_mask);
            try std.testing.expectEqual(@as(u32, 1), pp.input_use_count);
            try std.testing.expectEqual(root[pp.limb_index], row.value.toU32());
            root_words += 1;
        }
        try std.testing.expectEqual(@as(usize, 8), root_words);
        std.debug.print("CANONICAL_CHILD_KEY_BINDING root_words=8 fixed_in_air=true\n", .{});
        const manifest = @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
        try exerciseSessionKeys(&left, &first.program, &first.execution, .{ try manifest.verificationKeyId(), try manifest.nextParentVkId(), try manifest.airProgramId() });
        try exerciseProviderPartials(left.payload, .{ QM31.zero(), first.replay.claims.values[34] });
    }
    var fixed_payload_checked = false;
    for (left.payload) |*row| {
        if (row.preprocessing.constant_mask == 0) continue;
        const original = row.value;
        row.value = original.add(M31.one());
        defer row.value = original;
        try std.testing.expectError(error.TranscriptConstraintMismatch, validate(&left, &first.program, &first.execution));
        fixed_payload_checked = true;
        break;
    }
    try std.testing.expect(fixed_payload_checked);
    try std.testing.expectError(error.InvalidRecursiveTranscriptLane, first.prepareTranscriptRows(allocator, 0));
    try std.testing.expectError(error.InvalidRecursiveTranscriptLane, first.prepareTranscriptRows(allocator, 3));
    const old_randomness = left.randomness[0].main.outputs[0];
    left.randomness[0].main.outputs[0] = old_randomness.add(M31.one());
    try std.testing.expectError(error.TranscriptLookupMismatch, validate(&left, &first.program, &first.execution));
    left.randomness[0].main.outputs[0] = old_randomness;
    // Even a self-consistent weakened PoW witness must fail the lookup to
    // the verifier-owned difficulty in row 2's frame tuple.
    const original_check = left.pow_check[0];
    const original_frame = left.pow_frame[0];
    var weakened = first.execution.pow_checks[0];
    weakened.bits = 0;
    left.pow_check[0] = try air.pow_check_witness.mainRow(.{ .verifier_id = 1, .kind = .interaction, .check = weakened });
    left.pow_frame[0][6] = M31.zero();
    try std.testing.expectError(error.TranscriptLookupMismatch, validate(&left, &first.program, &first.execution));
    left.pow_check[0] = original_check;
    left.pow_frame[0] = original_frame;
    const old_pow_word = left.pow_check[0][5];
    left.pow_check[0][5] = M31.one();
    try std.testing.expectError(error.TranscriptConstraintMismatch, validate(&left, &first.program, &first.execution));
    left.pow_check[0][5] = old_pow_word;
    const old_word = left.word[0].value;
    left.word[0].value = old_word.add(M31.one());
    try std.testing.expectError(error.TranscriptLookupMismatch, validate(&left, &first.program, &first.execution));
    left.word[0].value = old_word;
    left.state[0].main.inputs[0] = M31.one();
    try std.testing.expectError(error.TranscriptConstraintMismatch, validate(&left, &first.program, &first.execution));
    std.debug.print("SECURE_TRANSCRIPT_AIR_ROWS control={d} sponge={d} binding={d} state={d} word={d} pow={d} challenges={d} randomness={d} lanes=2\n", .{ left.control.len, left.sponge.len, left.binding.len, left.state.len, left.word.len, left.pow_check.len, left.challenges.len, left.randomness.len });
}

pub fn validate(rows: *const Rows, program: *const Program, execution: *const recursion.recording_poseidon_channel_v4.ExecutionV4) !void {
    const allocator = std.testing.allocator;
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();
    try checkRows(0, air.control, rows.control, &ledger);
    try checkRows(1, air.transcript_air, rows.sponge, &ledger);
    try checkRows(2, air.transcript_binding, rows.binding, &ledger);
    try checkRows(3, air.transcript_state, rows.state, &ledger);
    try checkRows(4, air.transcript_word, rows.word, &ledger);
    try checkRows(5, air.transcript_payload, rows.payload, &ledger);
    try checkRows(6, air.pow_check, rows.pow_check, &ledger);
    try checkRows(7, air.pow_frame, rows.pow_frame, &ledger);
    try checkRows(8, air.relation_challenge, rows.challenges, &ledger);
    try checkRows(9, air.verifier_randomness, rows.randomness, &ledger);
    // Explicit native boundary oracles, not residual compensation: the
    // permutation provider, payload row 5 and verifier suffix must discharge these tuples
    // inside the complete parent AIR. No arbitrary unmatched tuple is allowed.
    for (execution.poseidon_calls, rows.provider) |call, provider| {
        for (call.input, provider.input) |word, actual| try std.testing.expectEqual(word.toU32(), actual);
        try std.testing.expect(provider.io and !provider.wide and provider.narrow_output == null);
        var values: [32]QM31 = undefined;
        for (call.input ++ call.output, &values) |word, *value| value.* = QM31.fromBase(word);
        try ledger.append(.poseidon2_io, 34, 0, .emit, QM31.one(), &values);
    }
    for (execution.operations, rows.control, program.operations) |operation, control, instruction| {
        const header = [_]QM31{ felt(control.verifier_id), felt(control.sequence), felt(control.tag), felt(control.args[0]), felt(control.args[1]), felt(control.args[2]), felt(control.args[3]) };
        for (0..operation.hash_count) |part| {
            const frame = execution.hash_frames[operation.first_hash_id + part];
            if (frame.purpose == .mix) {
                for (frame.words[8..], 0..) |word, index| {
                    const tuple = header ++ .{ felt(@intCast(index)), QM31.fromBase(word) };
                    if (rows_mod.payloadKind(instruction.source) == null)
                        try ledger.append(.recursion_transcript_payload_word, 5, 0, .emit, QM31.one(), &tuple);
                }
            } else if (operation.effect == .draw) {
                if (instruction.draw == .relation) {
                    for (frame.output[0..8], 0..) |word, index| {
                        const tuple = [_]QM31{ felt(control.verifier_id), felt(1), felt(instruction.item), felt(@intCast(index)), QM31.fromBase(word) };
                        try ledger.append(.recursion_relation_challenge_word, 18, 0, .consume, QM31.one().neg(), &tuple);
                    }
                } else {
                    const kind: u32 = switch (instruction.draw) {
                        .composition => 1,
                        .oods => 2,
                        .deep => 3,
                        .fri_alpha => 4,
                        .queries => 5,
                        else => unreachable,
                    };
                    const count: u32 = if (instruction.draw == .oods) 2 else 1;
                    for (frame.output[0..instruction.draw_word_count], 0..) |word, index| {
                        const item = instruction.item + if (instruction.draw == .queries) @as(u32, @intCast(index)) else 0;
                        const limb: u32 = if (instruction.draw == .queries) 0 else @intCast(index);
                        const tuple = [_]QM31{ felt(control.verifier_id), felt(kind), felt(item), felt(limb), QM31.fromBase(word) };
                        try ledger.append(.recursion_verifier_randomness_word, 18, 0, .consume, felt(count).neg(), &tuple);
                    }
                }
            }
        }
    }
    // Independent full-source joins below test the semantic coordinates;
    // this local component exercise supplies the explicit outside consumer.
    for (rows.payload) |row| {
        const pp = row.preprocessing;
        const tuple = [_]QM31{ felt(pp.verifier_id), felt(@intFromEnum(pp.source_kind)), felt(pp.item_index), felt(pp.limb_index), QM31.fromBase(row.value) };
        try ledger.append(.recursion_verifier_input_word, 18, 0, .consume, felt(pp.input_use_count).neg(), &tuple);
    }
    if (!ledger.classify().isClosed()) return error.TranscriptLookupMismatch;
}

pub fn checkRows(comptime component: u8, comptime Air: type, rows: anytype, ledger: *Ledger) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const Binding = air.universal_relation_binding.Binding(Air);
    const relations = try Binding.authenticate(&definition);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        const values = try rows_mod.logicalRow(component, row);
        try compiled.evaluateBaseInto(&values, &scratch, &roots);
        for (roots) |root| if (!root.isZero()) return error.TranscriptConstraintMismatch;
        const entries = try relations.entries(&definition.arena, Air.SEMANTIC_DIGEST, Binding.events(&definition), values);
        for (entries) |entry| try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    }
}
fn felt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

pub fn exerciseProviderPartials(payload: []const PayloadRow, partials: [2]QM31) !void {
    try checkProviderPartials(payload, partials);
    // An equal-and-opposite change preserves the roster total but must not
    // change the two provider evaluations admitted by the transcript.
    const changed = [2]QM31{ partials[0].add(QM31.one()), partials[1].sub(QM31.one()) };
    try std.testing.expect(changed[0].add(changed[1]).eql(partials[0].add(partials[1])));
    try std.testing.expectError(error.ProviderPartialTranscriptMismatch, checkProviderPartials(payload, changed));
    std.debug.print("COMMON_FOLD_PROVIDER_PARTIAL_JOIN limbs=8 preserving_total_mutation_rejected=true\n", .{});
}

pub fn exerciseProviderPartialFixture() !void {
    const partials = [2]QM31{ QM31.fromU32Unchecked(1, 2, 3, 4), QM31.fromU32Unchecked(5, 6, 7, 8) };
    var payload: [8]PayloadRow = undefined;
    for (partials, 0..) |partial, item| for (partial.toM31Array(), 0..) |value, limb| {
        const index = 4 * item + limb;
        payload[index] = .{ .preprocessing = .{
            .row_mask = 1,
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = 1,
            .sequence = 0,
            .tag = 0,
            .args = .{0} ** 4,
            .payload_index = @intCast(index),
            .source_kind = .claimed_sum,
            .item_index = @intCast(recursion.recursion_air_composition_circuit_v3.POSEIDON_AUX_START + item),
            .limb_index = @intCast(limb),
            .constant_mask = 0,
            .input_use_count = 1,
            .constant_value = 0,
            .source_hash_id = 0,
            .source_word_index = @intCast(8 + index),
        }, .value = value };
    };
    try exerciseProviderPartials(&payload, partials);
}

fn checkProviderPartials(payload: []const PayloadRow, partials: [2]QM31) !void {
    const start = recursion.recursion_air_composition_circuit_v3.POSEIDON_AUX_START;
    const Air = air.transcript_payload;
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try air.universal_relation_binding.Binding(Air).authenticate(&definition);
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    var count: usize = 0;
    for (payload) |row| {
        const pp = row.preprocessing;
        if (pp.source_kind != .claimed_sum or pp.item_index < start or pp.item_index >= start + 2) continue;
        count += 1;
        for (plan.preparedEntries(try rows_mod.logicalRow(5, row))) |entry| {
            if (entry.domain != .recursion_verifier_input_word) continue;
            try ledger.append(entry.domain, 5, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
        }
    }
    if (count != 8) return error.ProviderPartialTranscriptMismatch;
    for (partials, 0..) |claim, index| for (claim.toM31Array(), 0..) |limb, limb_index| {
        try ledger.append(.recursion_verifier_input_word, 18, 0, .consume, QM31.one().neg(), &.{
            felt(1), felt(@intFromEnum(Air.VerifierInputKind.claimed_sum)), felt(@intCast(start + index)), felt(@intCast(limb_index)), QM31.fromBase(limb),
        });
    };
    if (!ledger.classify().isClosed()) return error.ProviderPartialTranscriptMismatch;
}

fn exercisePrepared(first: anytype, second: anytype) !void {
    const allocator = std.testing.allocator;
    var prepared = try rows_mod.Prepared.init(allocator, .{
        .{ .program = &first.program, .execution = &first.execution },
        .{ .program = &second.program, .execution = &second.execution },
    });
    defer prepared.deinit();
    try prepared.validate();
    const claim_kind = @intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum);
    const partial_start = recursion.recursion_air_composition_circuit_v3.POSEIDON_AUX_START;
    for (1..3) |lane| {
        for (partial_start..partial_start + 2) |item|
            try std.testing.expect(try prepared.bindsVerifierInputForLane(@intCast(lane), claim_kind, @intCast(item)));
        try std.testing.expect(!try prepared.bindsVerifierInputForLane(@intCast(lane), claim_kind, partial_start + 3));
    }
    try std.testing.expectEqual(first.execution.poseidon_calls.len + second.execution.poseidon_calls.len, prepared.provider.len);
    try validatePrepared(&prepared);
}

pub fn validatePrepared(prepared: *const rows_mod.Prepared) !void {
    const allocator = std.testing.allocator;
    try prepared.validate();
    const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
    const support = @import("recursive_binary_outer_cohort_support.zig");
    var logs = [_]u32{4} ** 36;
    logs[34] = @import("recursive_common_fold_field_public_v2.zig").MINIMUM_POSEIDON_LOG_SIZE;
    logs[35] = 16;
    try prepared.installLogSizes(&logs);
    const manifest = try manifest_mod.buildForDerivedLogSizes(logs);
    for (0..2) |tree| {
        var scratch = try support.TreeScratch.init(allocator, &manifest, tree);
        defer scratch.deinit();
        try prepared.writePhysicalInto(&manifest, tree, scratch.columns);
        inline for (rows_mod.ACTIVE_ROWS, 0..) |index, slot| {
            const Air = rows_mod.catalog.LOGICAL_ROWS[index].Air;
            const placement = try manifest.placement(@enumFromInt(index));
            const offset = if (tree == 0) placement.preprocessed_offset else placement.main_offset;
            const width = if (tree == 0) Air.PREPROCESSED_COLUMN_COUNT else Air.PHYSICAL_MAIN_COLUMN_COUNT;
            const start = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
            for (0..(@as(usize, 1) << @intCast(logs[index]))) |row| {
                const physical = air.framework_interaction.committedRow(row, logs[index]);
                for (0..width) |column| {
                    const expected = if (row < prepared.logical[slot].len) prepared.logical[slot][row][start + column] else M31.zero();
                    try std.testing.expectEqualDeep(expected, scratch.columns[offset + column][physical]);
                }
            }
        }
        if (tree == 1) {
            const placement = try manifest.placement(.control);
            const original = scratch.columns[placement.main_offset];
            scratch.columns[placement.main_offset] = @as([*]M31, @ptrCast(@constCast(prepared.logical[0].ptr)))[0..original.len];
            defer scratch.columns[placement.main_offset] = original;
            try std.testing.expectError(error.DestinationAlias, prepared.writePhysicalInto(&manifest, tree, scratch.columns));
        }
    }
    // A valid but undersized late component must fail before touching an
    // earlier destination. Geometry validation is a whole-tree transaction.
    logs[9] -= 1;
    const small_manifest = try manifest_mod.buildForDerivedLogSizes(logs);
    var small = try support.TreeScratch.init(allocator, &small_manifest, 1);
    defer small.deinit();
    small.columns[0][0] = M31.one();
    try std.testing.expectError(error.DestinationLogSizeMismatch, prepared.writePhysicalInto(&small_manifest, 1, small.columns));
    try std.testing.expect(small.columns[0][0].eql(M31.one()));
    const original = prepared.provider[0].input[0];
    prepared.provider[0].input[0] = (original + 1) % core.fields.m31.Modulus;
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, prepared.validate());
    prepared.provider[0].input[0] = original;
    try prepared.validate();
    std.debug.print("SECURE_TRANSCRIPT_PHYSICAL_ROWS lanes=2 components={d} provider_calls={d} alias_rejected=true undersized_rejected=true\n", .{ rows_mod.ACTIVE_ROWS.len, prepared.provider.len });
}

/// Exact proof-input/challenge/randomness join to the real composition, query,
/// root, PCS and FRI consumers. No native compensation enters this ledger.
pub fn validateSemanticJoin(prepared: *const rows_mod.Prepared, source: anytype) !void {
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    inline for (rows_mod.ACTIVE_ROWS, 0..) |index, slot| {
        if (index != 0 and index != 5 and index != 8 and index != 9 and index != 10) continue;
        const Air = rows_mod.catalog.LOGICAL_ROWS[index].Air;
        var definition = try Air.build(std.testing.allocator);
        defer definition.deinit();
        const plan = try air.universal_relation_binding.Binding(Air).authenticate(&definition);
        try appendSemantic(prepared, &ledger, &plan, @intCast(index), prepared.logical[slot]);
    }
    const composition = source.composition_rows.?;
    try appendControlConsumers(19, &ledger, &composition.control_relation, composition.control_preprocessing.rows);
    try appendControlConsumers(23, &ledger, &source.fri_rows.trace_merkle_relation, source.fri_rows.trace_merkle_preprocessing.rows);
    try appendControlConsumers(27, &ledger, &source.fri_rows.fri_anchor_relation, source.fri_rows.fri_anchor_preprocessing.rows);
    try appendControlConsumers(28, &ledger, &source.fri_rows.control_relation, source.fri_rows.control_preprocessing.rows);
    for (composition.input_preprocessing.rows, composition.schedule_values) |row, value| {
        const logical = try air.vm_air_composition_input_witness.logicalRow(row, value, .binary_node);
        try appendSemantic(prepared, &ledger, &composition.input_relation, 18, &[_]@TypeOf(logical){logical});
    }
    const query_witness = air.query_bits_witness.QueryWitness{ .binary_node = .{
        .left = source.query_words[0],
        .right = source.query_words[1],
    } };
    const query_parameters = try air.query_bits_witness.parameterValues(source.fri_rows.query_bits_reference, .binary_node);
    for (source.fri_rows.query_bits_preprocessing.rows) |row| {
        const logical = try air.query_bits_witness.logicalRow(row, query_witness, query_parameters);
        try appendSemantic(prepared, &ledger, &source.fri_rows.query_bits_relation, 20, &[_]@TypeOf(logical){logical});
    }
    const roots = air.merkle_root_witness.RootWitness{ .binary_node = .{
        .left = .{ .trace = source.children[0].capture.trace_roots, .fri = source.children[0].capture.fri_roots },
        .right = .{ .trace = source.children[1].capture.trace_roots, .fri = source.children[1].capture.fri_roots },
    } };
    for (source.fri_rows.merkle_root_preprocessing.rows) |row| {
        const logical = try air.merkle_root_witness.logicalRow(row, roots);
        try appendSemantic(prepared, &ledger, &source.fri_rows.merkle_root_relation, 22, &[_]@TypeOf(logical){logical});
    }
    const pcs = air.pcs_deep_input_witness;
    for (source.fri_rows.pcs_preprocessing.rows) |row| {
        const value = source.fri_rows.pcs_inputs.lanes[row.lane].input_values[row.binding];
        const logical = pcs.logicalInputs((pcs.MainRow{ .enabler = M31.one(), .value = value }).values(), row.values(), .binary_node);
        try appendSemantic(prepared, &ledger, &source.fri_rows.pcs_relation, 24, &[_]@TypeOf(logical){logical});
    }
    const fri = air.fri_verifier_input_witness;
    const evaluations = fri.Evaluations{
        .segment = &source.fri_rows.inactive_fri_evaluation,
        .left = &source.children[0].capture.evaluation,
        .right = &source.children[1].capture.evaluation,
    };
    for (source.fri_rows.input_preprocessing.rows) |row| {
        const value = try evaluations.at(row.lane).values[row.node_id].tryIntoM31();
        const logical = fri.logicalInputs((fri.MainRow{ .enabler = M31.one(), .value = value }).values(), row.values(), .binary_node);
        try appendSemantic(prepared, &ledger, &source.fri_rows.input_relation, 29, &[_]@TypeOf(logical){logical});
    }
    const Domain = @TypeOf(recursion.binary_global_closure_outer_source.PROVIDER_DOMAIN);
    const report = ledger.classify();
    std.debug.print("SECURE_TRANSCRIPT_SEMANTIC_JOIN tuples={d} unmatched_challenges={d} unmatched_randomness={d} unmatched_proof_inputs={d} unmatched_control={d}\n", .{
        report.contribution_count,
        report.unmatched_by_domain[@intFromEnum(Domain.recursion_relation_challenge_word)],
        report.unmatched_by_domain[@intFromEnum(Domain.recursion_verifier_randomness_word)],
        report.unmatched_by_domain[@intFromEnum(Domain.recursion_verifier_input_word)],
        report.unmatched_by_domain[@intFromEnum(Domain.recursion_step)],
    });
    if (!report.isClosed()) return error.RecursiveTranscriptSemanticJoinMismatch;
}

pub fn exerciseCanonicalWireBoundary(prepared: *const rows_mod.Prepared, source: anytype) !void {
    const composition = source.composition_rows.?;
    var words: usize = 0;
    for (composition.input_preprocessing.rows, 0..) |row, index| {
        const input = switch (row.classification) {
            .recursion_input => |input| input,
            else => continue,
        };
        if (input.source != .public_wire_boundary) continue;
        try std.testing.expect(try prepared.bindsVerifierInputForLane(input.verifier_id, @intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum), input.source.public_wire_boundary.item_index));
        words += 1;
        if (words == 1) {
            const values = @constCast(composition.schedule_values);
            const original = values[index];
            values[index] = original.add(M31.one());
            defer values[index] = original;
            try std.testing.expectError(error.RecursiveTranscriptSemanticJoinMismatch, validateSemanticJoin(prepared, source));
        }
    }
    try std.testing.expectEqual(@as(usize, 8), words);
    std.debug.print("CANONICAL_CHILD_WIRE_BOUNDARY limbs=8 transcript_join=true changed_input_rejected=true\n", .{});
}

fn appendControlConsumers(comptime index: usize, ledger: *Ledger, plan: anytype, rows: anytype) !void {
    const Air = rows_mod.catalog.LOGICAL_ROWS[index].Air;
    for (rows) |row| {
        // These AIR control events depend only on preprocessing and proof-kind
        // selectors. Other events and witness constraints are not audited here.
        var logical = [_]M31{M31.zero()} ** Air.LOGICAL_INPUT_COUNT;
        const main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT;
        @memcpy(logical[main_count..][0..Air.PREPROCESSED_COLUMN_COUNT], &row.values());
        logical[main_count + Air.PREPROCESSED_COLUMN_COUNT + 1] = M31.one();
        for (plan.preparedEntries(logical)) |entry| {
            if (entry.domain != .recursion_step) continue;
            try ledger.append(entry.domain, @intCast(index), entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
        }
    }
}

fn appendSemantic(prepared: *const rows_mod.Prepared, ledger: *Ledger, plan: anytype, component: u8, rows: anytype) !void {
    for (rows) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.numerator.isZero()) continue;
        if (entry.domain == .recursion_step) {
            if (!rows_mod.bindsControlTag((try entry.values[2].tryIntoM31()).toU32())) continue;
        } else if (entry.domain == .recursion_verifier_input_word) {
            if (!try prepared.bindsVerifierInputForLane((try entry.values[0].tryIntoM31()).toU32(), (try entry.values[1].tryIntoM31()).toU32(), (try entry.values[2].tryIntoM31()).toU32())) continue;
        } else if (entry.domain != .recursion_relation_challenge_word and entry.domain != .recursion_verifier_randomness_word) continue;
        try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    };
}

pub fn exerciseFold(cold: anytype) !void {
    const allocator = std.testing.allocator;
    const recorded = cold.transcript;
    const before_rows = cold.performanceSnapshot();
    try recorded.program.validateRecording(&recorded.execution);
    var transcript_rows = try recorded.prepareTranscriptRows(allocator, 1);
    defer transcript_rows.deinit();
    try validate(&transcript_rows, &recorded.program, &recorded.execution);
    try std.testing.expectEqual(.common_fold, recorded.program.kind);
    try exercisePublicBoundary(cold, &transcript_rows);
    const keys = [_]recursion.poseidon2_channel.Digest{ cold.session.verification_key_id, cold.session.next_parent_vk_id, cold.session.air_program_id };
    try exerciseSessionKeys(&transcript_rows, &recorded.program, &recorded.execution, keys);
    const partial_start = recursion.recursion_air_composition_circuit_v3.POSEIDON_AUX_START;
    try exerciseProviderPartials(transcript_rows.payload, cold.composition_capture.claim_inputs.values[partial_start..][0..2].*);
    try std.testing.expectEqualDeep(
        cold.query_authority.query_words,
        recorded.replay.query_words,
    );
    try std.testing.expectEqualDeep(
        cold.query_authority.final_transcript_digest,
        recorded.execution.final_digest,
    );
    try std.testing.expectEqualDeep(before_rows, cold.performanceSnapshot());
    {
        cold.transcript.execution.identity_sha256[0] ^= 1;
        defer cold.transcript.execution.identity_sha256[0] ^= 1;
        try std.testing.expectError(error.InvalidProcessLocalValidationToken, cold.validate());
    }
    std.debug.print(
        "COMMON_FOLD_TRANSCRIPT_PROGRAM operations={d} frames={d} permutations={d} queries={d}\n",
        .{ recorded.program.operations.len, recorded.execution.hash_frames.len, recorded.execution.poseidon_calls.len, recorded.replay.query_words.len },
    );
}

fn exercisePublicBoundary(cold: anytype, transcript_rows: *const Rows) !void {
    const public = @import("recursive_field_node_public_v2.zig");
    const hashes = @import("recursive_common_fold_public_hash_v3.zig");
    const capture = &cold.composition_capture;
    const composition = air.composition_circuit;
    const allocator = std.testing.allocator;
    var definition = try air.field_statement_word_v3.build(allocator);
    defer definition.deinit();
    const plan = try air.universal_relation_binding.Binding(air.field_statement_word_v3).authenticate(&definition);
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();
    for (transcript_rows.statement) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain == .recursion_statement_word and !entry.numerator.isZero())
            try ledger.append(entry.domain, 12, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    };
    const inputs = try allocator.dupe(QM31, capture.input_values);
    defer allocator.free(inputs);
    const values = try allocator.alloc(QM31, capture.circuit.nodes.len);
    defer allocator.free(values);
    try capture.circuit.evaluateInto(inputs, values);
    const scope = recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE;
    var count: usize = 0;
    var extras: usize = 0;
    for (capture.bindings, inputs, 0..) |binding, value, input_index| {
        const node_index: usize = switch (binding.source) {
            .statement_word => |index| public.HEADER_WORD_COUNT + index,
            .field_public_word => |index| blk: {
                extras += 1;
                break :blk index;
            },
            else => continue,
        };
        count += 1;
        const tuple = [_]QM31{ felt(scope), felt(composition.recursionSourceIndices(binding.source)[0]), value };
        try ledger.append(.recursion_statement_word, 18, 0, .consume, QM31.one().neg(), &tuple);
        // These sixteen words also feed the parent source-hash AIR.
        if (node_index >= hashes.CHILD_HASH_START)
            try ledger.append(.recursion_statement_word, 17, 0, .consume, QM31.one().neg(), &tuple);
        if (node_index == 0 or node_index == public.HEADER_WORD_COUNT or
            node_index == hashes.DIGEST_START or node_index == public.AIR_WORD_COUNT - 1)
        {
            inputs[input_index] = value.add(QM31.one());
            try std.testing.expectError(error.UnsatisfiedCircuit, capture.circuit.evaluateInto(inputs, values));
            inputs[input_index] = value;
        }
    }
    try std.testing.expectEqual(public.AIR_WORD_COUNT, count);
    try std.testing.expectEqual(@as(usize, 38), extras);
    try std.testing.expect(ledger.classify().isClosed());
    std.debug.print("COMMON_FOLD_PUBLIC_BOUNDARY_AIR words=450 extra_inputs=38 source_join=true changed_public_input_rejected=true native_public_sum_literal=false\n", .{});
}

fn exerciseSessionKeys(rows: *Rows, program: *const Program, execution: *const recursion.recording_poseidon_channel_v4.ExecutionV4, keys: [3]recursion.poseidon2_channel.Digest) !void {
    var key_count: usize = 0;
    var key_rows: usize = 0;
    for (program.operations, 0..) |operation, sequence| {
        try std.testing.expect(operation.source != .claim_seal and operation.source != .session_seal);
        if (operation.source != .session_key) continue;
        try std.testing.expectEqual(key_count, operation.item);
        for (keys[key_count], 0..) |word, index| {
            try std.testing.expectEqual(word & 0xffff, operation.constant_words[2 * index]);
            try std.testing.expectEqual(word >> 16, operation.constant_words[2 * index + 1]);
        }
        for (rows.payload) |*row| {
            if (row.preprocessing.sequence != sequence) continue;
            key_rows += 1;
            try std.testing.expectEqual(@as(u32, 1), row.preprocessing.constant_mask);
            if (key_rows == 1) {
                const original = row.value;
                row.value = original.add(M31.one());
                defer row.value = original;
                try std.testing.expectError(error.TranscriptConstraintMismatch, validate(rows, program, execution));
            }
        }
        key_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), key_count);
    try std.testing.expectEqual(@as(usize, 48), key_rows);
    std.debug.print("FIELD_SESSION_KEY_AIR kind={s} limbs=48 changed_value_rejected=true native_session_seal=false\n", .{@tagName(program.kind)});
}
