//! Proof-boundary, mutation, schedule, and allocation tests for rows 15--17.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const semantics = @import("vm_public_semantics_circuit.zig");
const vm_claim = @import("vm_public_claim.zig");
const statement = @import("span_statement.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");
const fixed_profile = @import("fixed_profile.zig");
const public_data = @import("../air/public_data.zig");
const public_logup = @import("../air/public_logup.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const row16 = @import("air/vm_public_logup_input_witness.zig");
const schedule = @import("air/verifier_schedule.zig");

const SHAPE = vm_claim.Shape{ .max_input_words = 2, .max_output_words = 2 };
const CLAIM_CIRCUIT_ID: u32 = 40;
const LOGUP_CIRCUIT_ID: u32 = 41;

test "Ethereum statement arithmetic owns admitted graphs and rejects stale evaluations" {
    const admission = @import("ethereum_statement_arithmetic_v4.zig");
    const statement_circuit = @import("statement_semantics_circuit.zig");
    const allocator = std.testing.allocator;
    var owned: ?*admission.Prepared = null;
    defer if (owned) |value| value.deinit();
    var expected: QM31 = undefined;
    {
        const data = testPublicData();
        var encoded = try vm_claim.encode(allocator, &data, SHAPE);
        defer encoded.deinit();
        const leaf = try statement.SegmentLeaf.init(&data, &encoded, protocol.protocolId());
        var circuit = try statement_circuit.build(allocator);
        defer circuit.deinit();
        var evaluation = try circuit.evaluate(allocator, statement_circuit.Witness.forSegment(&leaf.words));
        defer evaluation.deinit();
        var reference = try semantics.ClaimReference.initForSegmentV2(allocator, SHAPE, CLAIM_CIRCUIT_ID);
        defer reference.deinit();
        var prepared = try reference.prepare(allocator, claimWitness(&encoded, &leaf));
        defer prepared.deinit();
        owned = try admission.Prepared.init(allocator, &circuit, &evaluation, &reference, &prepared);
        expected = prepared.evaluation.values[0];
        const saved = prepared.input_values[0];
        prepared.input_values[0] = saved.add(QM31.one());
        try std.testing.expectError(error.PreparedAuthorityMismatch, admission.Prepared.init(allocator, &circuit, &evaluation, &reference, &prepared));
        prepared.input_values[0] = saved;
        var legacy = try semantics.ClaimReference.init(allocator, SHAPE, CLAIM_CIRCUIT_ID);
        defer legacy.deinit();
        var legacy_prepared = try legacy.prepare(allocator, claimWitness(&encoded, &leaf));
        defer legacy_prepared.deinit();
        try std.testing.expectError(error.EthereumStatementArithmeticMismatch, admission.Prepared.init(allocator, &circuit, &evaluation, &legacy, &legacy_prepared));
        const Factory = struct {
            fn call(a: std.mem.Allocator, c: *const statement_circuit.Circuit, e: *const statement_circuit.Evaluation, r: *const semantics.ClaimReference, p: *const semantics.ClaimPrepared) !void {
                const value = try admission.Prepared.init(a, c, e, r, p);
                defer value.deinit();
            }
        };
        try std.testing.checkAllAllocationFailures(allocator, Factory.call, .{ &circuit, &evaluation, &reference, &prepared });
        prepared.evaluation.values[0] = expected.add(QM31.one());
    }
    // Every producer allocation above is gone. Views remain owned and sealed.
    const lanes = owned.?.lanes();
    const evaluations = owned.?.evaluations();
    try std.testing.expect(!std.mem.allEqual(u8, &owned.?.identity(), 0));
    try std.testing.expectEqual(@as(usize, 2), lanes.len);
    try std.testing.expect(evaluations[1].values[0].eql(expected));
    for (lanes, evaluations) |lane, evaluation| {
        try lane.graph.validate();
        try std.testing.expectEqual(lane.graph.nodes.len, evaluation.values.len);
        for (lane.graph.outputs) |output| try std.testing.expect(evaluation.values[output].isZero());
    }
}

test "R-012 claim semantics graph is deterministic sealed and row-15 exact" {
    var first = try semantics.ClaimReference.init(
        std.testing.allocator,
        SHAPE,
        CLAIM_CIRCUIT_ID,
    );
    defer first.deinit();
    var second = try semantics.ClaimReference.init(
        std.testing.allocator,
        SHAPE,
        CLAIM_CIRCUIT_ID,
    );
    defer second.deinit();
    try first.validate();
    try second.validate();
    try std.testing.expectEqual(first.authority_digest, second.authority_digest);
    try std.testing.expectEqualSlices(
        semantics.ClaimInputBinding,
        first.inputs,
        second.inputs,
    );
    try std.testing.expect(first.circuit.nodes().len > first.inputs.len);
    try std.testing.expect(first.circuit.outputs().len > 1_000);
    for (first.inputs, first.row_bindings, 0..) |binding, row_binding, index| {
        try std.testing.expectEqual(binding.node_id, row_binding.node_id);
        try std.testing.expectEqual(binding.use_count, row_binding.use_count);
        try std.testing.expectEqual(
            binding.use_count,
            try first.circuit.inputUseCount(@intCast(index)),
        );
    }
}

test "R-012 claim semantics SegmentV2 keeps continuation IO in statement relations" {
    const allocator = std.testing.allocator;
    const row10 = @import("air/statement_input.zig");
    const row10_witness = @import("air/statement_input_witness.zig");
    const row10_relation = @import("air/statement_input_relation.zig");
    const row15 = @import("air/vm_public_claim_semantics_input.zig");
    const row15_witness = @import("air/vm_public_claim_semantics_input_witness.zig");
    const row15_relation = @import("air/vm_public_claim_semantics_input_relation.zig");
    const relations = @import("air/universal_challenges.zig").UniversalRelations.dummy();
    const data = testPublicData();
    var claim = try vm_claim.encode(allocator, &data, SHAPE);
    defer claim.deinit();
    var leaf = try statement.SegmentLeaf.init(&data, &claim, protocol.protocolId());
    // The first limb is the actual saved Stage101 failure. Cover every limb
    // at both boundaries without changing the genuine saved proof inputs.
    for ([_]usize{ statement.canonical_layout.entry_state_start, statement.canonical_layout.exit_state_start }) |start| {
        for (0..8) |limb| leaf.words[start + statement.canonical_layout.machine_state_io_digest_start_offset + limb] =
            M31.fromCanonical(1991068772 + @as(u32, @intCast(limb)));
    }
    var legacy = try semantics.ClaimReference.init(allocator, SHAPE, CLAIM_CIRCUIT_ID);
    defer legacy.deinit();
    var reference = try semantics.ClaimReference.initForSegmentV2(allocator, SHAPE, CLAIM_CIRCUIT_ID);
    defer reference.deinit();
    try reference.validate();
    try std.testing.expect(!std.mem.eql(u8, &legacy.authority_digest, &reference.authority_digest));
    try std.testing.expectError(error.SemanticConstraintViolation, legacy.prepare(allocator, claimWitness(&claim, &leaf)));
    var prepared = try reference.prepare(allocator, claimWitness(&claim, &leaf));
    defer prepared.deinit();
    try prepared.validateAgainst(&reference);

    var statement_preprocessing = try row10_witness.Preprocessed.init(allocator);
    defer statement_preprocessing.deinit();
    var statement_definition = try row10.build(allocator);
    defer statement_definition.deinit();
    const statement_plan = try row10_relation.authenticate(&statement_definition);
    var claim_definition = try row15.build(allocator);
    defer claim_definition.deinit();
    const claim_plan = try row15_relation.authenticate(&claim_definition);
    var checked: usize = 0;
    for (reference.inputs, reference.row_preprocessing.rows, prepared.row_witness.rows) |binding, metadata, main| {
        const index = switch (binding.source) {
            .statement_word => |index| index,
            else => continue,
        };
        const is_io = for ([_]usize{ statement.canonical_layout.entry_state_start, statement.canonical_layout.exit_state_start }) |start| {
            const first = start + statement.canonical_layout.machine_state_io_digest_start_offset;
            if (index >= first and index < first + 8) break true;
        } else false;
        if (!is_io) continue;
        checked += 1;
        const source = try statement_plan.entries(
            &statement_definition.arena,
            row10.SEMANTIC_DIGEST,
            statement_definition.events.ordered(),
            try row10_witness.logicalRow(statement_preprocessing.rows[index], .{ .segment_leaf = &leaf.words }),
        );
        const logical = row15_witness.logicalInputs(
            main,
            metadata,
            .segment_leaf,
            M31.fromCanonical(17),
            M31.fromCanonical(row10.VM_CLAIM_STATEMENT_SCOPE),
        );
        const destination = try claim_plan.entries(
            &claim_definition.arena,
            row15.SEMANTIC_DIGEST,
            claim_definition.events,
            logical,
        );
        // Graph use count may be zero, but row 15 must still consume the exact
        // authenticated statement word with unit multiplicity.
        try std.testing.expect(source[3].numerator.eql(QM31.one()));
        try std.testing.expect(destination[1].numerator.eql(QM31.one().neg()));
        try std.testing.expect((try source[3].denominator(&relations)).eql(try destination[1].denominator(&relations)));
        var forged = logical;
        forged[1] = forged[1].add(M31.one());
        const changed = try claim_plan.entries(
            &claim_definition.arena,
            row15.SEMANTIC_DIGEST,
            claim_definition.events,
            forged,
        );
        try std.testing.expect(!(try source[3].denominator(&relations)).eql(try changed[1].denominator(&relations)));
    }
    try std.testing.expectEqual(@as(usize, 16), checked);
}

test "R-012 claim semantics accepts an honest leaf and rejects algebraic mutations" {
    const allocator = std.testing.allocator;
    const data = testPublicData();
    var claim = try vm_claim.encode(allocator, &data, SHAPE);
    defer claim.deinit();
    const leaf = try statement.SegmentLeaf.init(&data, &claim, protocol.protocolId());
    var reference = try semantics.ClaimReference.init(
        allocator,
        SHAPE,
        CLAIM_CIRCUIT_ID,
    );
    defer reference.deinit();

    var prepared = try reference.prepare(allocator, claimWitness(&claim, &leaf));
    defer prepared.deinit();
    try prepared.validateAgainst(&reference);
    try std.testing.expectEqual(reference.inputs.len, prepared.row_witness.rows.len);

    const forged_words = try allocator.dupe(M31, claim.words);
    defer allocator.free(forged_words);
    forged_words[vm_claim.canonical_layout.program_root_start] = M31.fromCanonical(99);
    var forged = claimWitness(&claim, &leaf);
    forged.claim_words = forged_words;
    try std.testing.expectError(
        error.SemanticConstraintViolation,
        reference.prepare(allocator, forged),
    );

    forged = claimWitness(&claim, &leaf);
    forged.input_digest[0] += 1;
    try std.testing.expectError(
        error.SemanticConstraintViolation,
        reference.prepare(allocator, forged),
    );

    // The legacy claim has zero continuation I/O state. The genuine V4
    // statement's nonzero digest needs its own authenticated policy.
    for ([_]usize{
        statement.canonical_layout.entry_state_start,
        statement.canonical_layout.exit_state_start,
    }) |state_start| {
        var changed_statement = leaf.words;
        changed_statement[state_start + statement.canonical_layout.machine_state_io_digest_start_offset] =
            M31.fromCanonical(1991068772);
        forged = claimWitness(&claim, &leaf);
        forged.statement_words = &changed_statement;
        try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, forged));
    }

    // Access clocks use the frontend's four-wide strict subclock authority:
    // residues 1--3 are valid and floor(clock / 4) must precede the retired
    // instruction count.  A register may additionally be untouched (zero),
    // whereas a present output may not.
    const register_clock_start =
        vm_claim.canonical_layout.register_last_clocks_start + 3 * 2;
    const first_output_clock_start =
        vm_claim.canonical_layout.outputSlotsStart(SHAPE) + 5;
    for ([_]struct { start: usize, value: u32 }{
        .{ .start = register_clock_start, .value = 4 },
        .{ .start = register_clock_start, .value = 33 },
        .{ .start = first_output_clock_start, .value = 0 },
        .{ .start = first_output_clock_start, .value = 4 },
    }) |mutation| {
        const mutated_words = try allocator.dupe(M31, claim.words);
        defer allocator.free(mutated_words);
        writeClaimU32(mutated_words, mutation.start, mutation.value);
        forged = claimWitness(&claim, &leaf);
        forged.claim_words = mutated_words;
        try std.testing.expectError(
            error.SemanticConstraintViolation,
            reference.prepare(allocator, forged),
        );
    }

    const boundary_words = try allocator.dupe(M31, claim.words);
    defer allocator.free(boundary_words);
    writeClaimU32(boundary_words, register_clock_start, 31);
    var boundary = claimWitness(&claim, &leaf);
    boundary.claim_words = boundary_words;
    var boundary_prepared = try reference.prepare(allocator, boundary);
    defer boundary_prepared.deinit();
    try boundary_prepared.validateAgainst(&reference);

    var inactive = claimWitness(&claim, &leaf);
    inactive.segment_selected = false;
    var inactive_prepared = try reference.prepare(allocator, inactive);
    defer inactive_prepared.deinit();
    for (inactive_prepared.row_witness.rows) |row|
        try std.testing.expect(row.value.isZero());
}

test "R-012 four-domain public LogUp matches native and rejects sum or program mutations" {
    const allocator = std.testing.allocator;
    const data = testPublicData();
    var claim = try vm_claim.encode(allocator, &data, SHAPE);
    defer claim.deinit();
    const relations = relation_challenges.Relations.dummy();
    const claimed_sums = [_]QM31{try semantics.expectedClaimedSum(&data, &relations)};
    var reference = try semantics.LogupReference.init(
        allocator,
        SHAPE,
        LOGUP_CIRCUIT_ID,
        claimed_sums.len,
    );
    defer reference.deinit();
    try reference.validate();
    try std.testing.expectEqual(@as(u32, 74), reference.public_term_count);
    try std.testing.expectEqual(
        (try public_logup.sum(&data, &relations)).neg(),
        claimed_sums[0],
    );
    const witness = semantics.LogupWitness{
        .segment_selected = true,
        .claim_words = claim.words,
        .relation_words = semantics.LogupChallengeWords.fromRelations(&relations),
        .claimed_sums = &claimed_sums,
    };
    var prepared = try reference.prepare(allocator, witness);
    defer prepared.deinit();
    var input_rows = try reference.prepareRow16(allocator, &prepared);
    defer input_rows.deinit();
    try input_rows.main.validateAgainst(&input_rows.preprocessing);
    try std.testing.expectEqual(reference.inputs.len, input_rows.main.rows.len);

    var wrong_sums = claimed_sums;
    wrong_sums[0] = wrong_sums[0].add(QM31.one());
    var forged = witness;
    forged.claimed_sums = &wrong_sums;
    try std.testing.expectError(
        error.SemanticConstraintViolation,
        reference.prepare(allocator, forged),
    );

    forged = witness;
    forged.relation_words.program_access[0] =
        forged.relation_words.program_access[0].add(M31.one());
    try std.testing.expectError(
        error.SemanticConstraintViolation,
        reference.prepare(allocator, forged),
    );

    var saw_program_challenge = false;
    for (reference.inputs) |binding| switch (binding.source) {
        .relation_challenge_word => |coordinate| {
            if (coordinate.challenge == 2) saw_program_challenge = true;
        },
        else => {},
    };
    try std.testing.expect(saw_program_challenge);
    try std.testing.expectEqualSlices(
        u32,
        &semantics.REQUIRED_LOGUP_CHALLENGES,
        &row16.CHALLENGES,
    );
}

test "R-012 row-17 control consumes exactly one step per public inverse" {
    const allocator = std.testing.allocator;
    var reference = try semantics.LogupReference.init(
        allocator,
        SHAPE,
        LOGUP_CIRCUIT_ID,
        1,
    );
    defer reference.deinit();
    const shape = try scheduleShape();
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(SHAPE.max_input_words, SHAPE.max_output_words),
        shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(.recursion, 3, 0, 2, 3),
        shape,
    );
    defer recursion_plan.deinit();
    var control = try reference.prepareRow17(allocator, &vm_plan, &recursion_plan);
    defer control.deinit();
    try control.validateAgainst(&vm_plan, &recursion_plan);
    try std.testing.expectEqual(
        @as(usize, reference.public_term_count + 1),
        control.activeStepCount(.segment_leaf),
    );

    var stale_vm = try schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(.vm, 12, 5, 101, 12),
        shape,
    );
    defer stale_vm.deinit();
    try std.testing.expectError(
        error.PublicTermCountMismatch,
        reference.prepareRow17(allocator, &stale_vm, &recursion_plan),
    );
}

test "R-012 semantic references and hot instances release every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        claimReferenceFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        logupReferenceFailureCase,
        .{},
    );

    const data = testPublicData();
    var claim = try vm_claim.encode(std.testing.allocator, &data, SHAPE);
    defer claim.deinit();
    const leaf = try statement.SegmentLeaf.init(&data, &claim, protocol.protocolId());
    var claim_reference = try semantics.ClaimReference.init(
        std.testing.allocator,
        SHAPE,
        CLAIM_CIRCUIT_ID,
    );
    defer claim_reference.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        claimPrepareFailureCase,
        .{ &claim_reference, claimWitness(&claim, &leaf) },
    );

    const relations = relation_challenges.Relations.dummy();
    const sums = [_]QM31{try semantics.expectedClaimedSum(&data, &relations)};
    var logup_reference = try semantics.LogupReference.init(
        std.testing.allocator,
        SHAPE,
        LOGUP_CIRCUIT_ID,
        1,
    );
    defer logup_reference.deinit();
    const logup_witness = semantics.LogupWitness{
        .segment_selected = true,
        .claim_words = claim.words,
        .relation_words = semantics.LogupChallengeWords.fromRelations(&relations),
        .claimed_sums = &sums,
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        logupPrepareFailureCase,
        .{ &logup_reference, logup_witness },
    );
}

fn claimWitness(
    claim: *const vm_claim.Encoded,
    leaf: *const statement.SegmentLeaf,
) semantics.ClaimWitness {
    return .{
        .segment_selected = true,
        .claim_words = claim.words,
        .statement_words = &leaf.words,
        .input_digest = claim.public_input_digest,
        .output_digest = claim.public_output_digest,
    };
}

fn scheduleShape() !schedule.ScheduleShape {
    return .{
        .protocol_id = channel.hashBytes("vm-public-semantics-test-protocol", 0x5343),
        .shape_id = channel.hashBytes("vm-public-semantics-test-shape", 0x5348),
        .interaction_pow_bits = 0,
        .pcs_pow_bits = 0,
        .query_count = 2,
        .table_count = 4,
        .claimed_sum_count = 1,
        .sampled_value_count = 4,
        .tree_heights = .{ 5, 5, 5, 5 },
        .fri = try fixed_profile.FriSchedule.init(4, protocol.PCS_CONFIG.fri_config),
    };
}

fn claimReferenceFailureCase(allocator: std.mem.Allocator) !void {
    var reference = try semantics.ClaimReference.init(allocator, SHAPE, CLAIM_CIRCUIT_ID);
    defer reference.deinit();
}

fn logupReferenceFailureCase(allocator: std.mem.Allocator) !void {
    var reference = try semantics.LogupReference.init(allocator, SHAPE, LOGUP_CIRCUIT_ID, 1);
    defer reference.deinit();
}

fn claimPrepareFailureCase(
    allocator: std.mem.Allocator,
    reference: *const semantics.ClaimReference,
    witness: semantics.ClaimWitness,
) !void {
    var prepared = try reference.prepare(allocator, witness);
    defer prepared.deinit();
}

fn logupPrepareFailureCase(
    allocator: std.mem.Allocator,
    reference: *const semantics.LogupReference,
    witness: semantics.LogupWitness,
) !void {
    var prepared = try reference.prepare(allocator, witness);
    defer prepared.deinit();
}

const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
const test_output_words = [_]public_data.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

fn testPublicData() public_data.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 0x8000_0001;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = 0x20_0000,
            .input_len = 5,
            .input_words = &test_input_words,
            .output_len = 4,
            .output_len_addr = 0x10_0004,
            .output_data_addr = 0x10_0008,
            .output_words = &test_output_words,
        },
    };
}

fn writeClaimU32(words: []M31, start: usize, value: u32) void {
    words[start] = M31.fromCanonical(value & 0xffff);
    words[start + 1] = M31.fromCanonical(value >> 16);
}

test "Ethereum native root claim semantics separates snapshot digests and requires row11 wires" {
    const allocator = std.testing.allocator;
    const row15 = @import("air/vm_public_claim_semantics_input.zig");
    const row15_witness = @import("air/vm_public_claim_semantics_input_witness.zig");
    const row15_relation = @import("air/vm_public_claim_semantics_input_relation.zig");
    const row11 = @import("air/statement_semantics_bytes_v2.zig");
    const data = testPublicData();
    var claim = try vm_claim.encode(allocator, &data, SHAPE);
    defer claim.deinit();
    var leaf = try statement.SegmentLeaf.init(&data, &claim, protocol.protocolId());
    const root_starts = [_]usize{ vm_claim.canonical_layout.initial_rw_root_start, vm_claim.canonical_layout.final_rw_root_start };
    const roots = [_]M31{ claim.words[root_starts[0]], claim.words[root_starts[1]] };
    for ([_]usize{ statement.canonical_layout.entry_state_start, statement.canonical_layout.exit_state_start }, 0..) |start, side| {
        for (0..8) |limb| leaf.words[start + statement.canonical_layout.machine_state_rw_digest_start_offset + limb] = M31.fromU64(1000 + side * 8 + limb);
    }
    var old = try semantics.ClaimReference.initForSegmentV2(allocator, SHAPE, CLAIM_CIRCUIT_ID);
    defer old.deinit();
    try std.testing.expectError(error.SemanticConstraintViolation, old.prepare(allocator, claimWitness(&claim, &leaf)));
    try std.testing.expectEqual(@as(usize, 0), old.nativeRootConsumerCount());
    var reference = try semantics.ClaimReference.initForEthereumNativeRoots(allocator, SHAPE, CLAIM_CIRCUIT_ID);
    defer reference.deinit();
    try reference.validate();
    try std.testing.expectEqual(@as(usize, 2), reference.nativeRootConsumerCount());
    try std.testing.expectError(error.InputLayoutMismatch, reference.prepare(allocator, claimWitness(&claim, &leaf)));
    var witness = claimWitness(&claim, &leaf);
    witness.native_continuation_roots = roots;
    var prepared = try reference.prepare(allocator, witness);
    defer prepared.deinit();
    try prepared.validateAgainst(&reference);
    var definition15 = try row15.build(allocator);
    defer definition15.deinit();
    const relation15 = try row15_relation.authenticate(&definition15);
    var definition11 = try row11.build(allocator);
    defer definition11.deinit();
    const relation11 = try row11.Relation.authenticate(&definition11);
    for (reference.inputs, reference.row_preprocessing.rows, prepared.row_witness.rows, 0..) |binding, metadata, main, index| {
        if (binding.source != .native_continuation_root) continue;
        const side = binding.source.native_continuation_root;
        const row = reference.nativeRootConsumerRow(side).?;
        try std.testing.expectEqual(@as(u32, 6), row.statement_scope);
        try std.testing.expectEqual(@as(u32, side), row.word_index);
        try std.testing.expectEqual(binding.node_id, row.node_id);
        try std.testing.expectEqual(try reference.circuit.inputUseCount(@intCast(index)), row.use_count);
        try std.testing.expect(row.use_count > 0);
        try std.testing.expectEqual(@as(u32, 1), reference.nativeRootSourceUses(side));
        const entries15 = try relation15.entries(&definition15.arena, row15.SEMANTIC_DIGEST, definition15.events, row15_witness.logicalInputs(main, metadata, .segment_leaf, M31.zero(), M31.zero()));
        // Row15 provides neither source tuples nor graph wires for roots.
        // Therefore omitting the row11 contribution leaves the positive graph
        // fanout entirely missing, even with a valid row15 witness.
        for (entries15) |entry| try std.testing.expect(entry.numerator.isZero());
        const entries11 = relation11.preparedEntries(try row11.logicalRow(row, roots[side], .segment_leaf, .{M31.zero()} ** 4));
        try std.testing.expectEqual(row.use_count, entries11[1].numerator.toM31Array()[0].toU32());
        try std.testing.expectEqual(roots[side].toU32(), entries11[1].values[2].toM31Array()[0].toU32());
        const changed11 = relation11.preparedEntries(try row11.logicalRow(row, roots[side].add(M31.one()), .segment_leaf, .{M31.zero()} ** 4));
        try std.testing.expect(!std.meta.eql(entries11[1].values, changed11[1].values));
        for (0..3) |mode| {
            var ledger = @import("air/relation_interaction.zig").TupleLedger.init(allocator);
            defer ledger.deinit();
            // The consuming coefficient comes from the authenticated graph,
            // independently of either row owner's preprocessing.
            const graph_uses = try reference.circuit.inputUseCount(@intCast(index));
            const needed = [_]QM31{ QM31.fromBase(M31.fromCanonical(CLAIM_CIRCUIT_ID)), QM31.fromBase(M31.fromCanonical(binding.node_id)), prepared.input_values[index], QM31.zero(), QM31.zero(), QM31.zero() };
            try ledger.append(.recursion_wire, 40, 0, .consume, QM31.fromBase(M31.fromCanonical(graph_uses)).neg(), &needed);
            for (entries15) |entry| if (entry.domain == .recursion_wire) try ledger.append(entry.domain, 15, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
            if (mode != 1) {
                const entry = if (mode == 0) entries11[1] else changed11[1];
                try ledger.append(entry.domain, 11, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
            }
            try std.testing.expectEqual(mode == 0, ledger.classify().isClosed());
        }
        const saved = prepared.input_values[index];
        prepared.input_values[index] = saved.add(QM31.one());
        var changed_graph = try reference.circuit.evaluate(allocator, prepared.input_values);
        defer changed_graph.deinit();
        try std.testing.expect(!try reference.circuit.outputsAreZero(changed_graph.values));
        prepared.input_values[index] = saved;
        const saved_use = reference.row_bindings[index].use_count;
        reference.row_bindings[index].use_count = 1;
        try std.testing.expectError(error.InputLayoutMismatch, reference.validate());
        reference.row_bindings[index].use_count = saved_use;
    }
    // All seven non-scalar lanes are constrained, not merely ignored.
    for (root_starts) |start| for (1..8) |limb| {
        const source_word = start + limb;
        const input_index = for (reference.inputs, 0..) |binding, index| {
            if (binding.source == .claim_word and binding.source.claim_word == source_word) break index;
        } else unreachable;
        const saved = prepared.input_values[input_index];
        prepared.input_values[input_index] = QM31.one();
        var changed_graph = try reference.circuit.evaluate(allocator, prepared.input_values);
        defer changed_graph.deinit();
        try std.testing.expect(!try reference.circuit.outputsAreZero(changed_graph.values));
        prepared.input_values[input_index] = saved;
    };
    var changed_witness = witness;
    changed_witness.native_continuation_roots = .{ roots[0].add(M31.one()), roots[1] };
    try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, changed_witness));
}

test "Ethereum initial claim policy keeps exact canonical shape with bounded graph inputs" {
    const allocator = std.testing.allocator;
    var small_nodes: usize = 0;
    var small_inputs: usize = 0;
    var small_digest: [32]u8 = undefined;
    for ([_]u32{ 40, 675173 }) |count| {
        const shape = vm_claim.Shape{ .max_input_words = count, .max_output_words = 12 };
        var reference = try semantics.ClaimReference.initForEthereumInitialInputs(allocator, shape, CLAIM_CIRCUIT_ID);
        defer reference.deinit();
        try reference.validate();
        try std.testing.expectEqual(try shape.wordCount(), reference.claim_preprocessing.rows.len);
        try std.testing.expectEqual(@as(usize, 2), reference.nativeRootConsumerCount());
        var canonical_count: usize = 0;
        var found_suffix = false;
        for (reference.inputs) |binding| if (binding.source == .claim_word) {
            const index = binding.source.claim_word;
            try std.testing.expect(index < vm_claim.canonical_layout.input_slots_start or index >= vm_claim.canonical_layout.outputWordsTag(shape));
            if (index == vm_claim.canonical_layout.outputWordsTag(shape)) found_suffix = true;
            canonical_count += 1;
        };
        try std.testing.expect(found_suffix);
        try std.testing.expectEqual(@as(usize, 343), canonical_count);
        if (count == 40) {
            small_nodes = reference.circuit.nodes().len;
            small_inputs = reference.inputs.len;
            small_digest = reference.authority_digest;
        } else {
            // Constant interning may reuse the small count in another equation.
            try std.testing.expect(reference.circuit.nodes().len <= small_nodes + 1);
            try std.testing.expectEqual(small_inputs, reference.inputs.len);
            try std.testing.expect(!std.mem.eql(u8, &small_digest, &reference.authority_digest));
        }
        reference.initial_input_policy = false;
        try std.testing.expectError(error.AuthoritySealMismatch, reference.validate());
        reference.initial_input_policy = true;
    }
    try std.testing.expectError(error.InputLayoutMismatch, semantics.ClaimReference.initForEthereumInitialInputs(allocator, .{ .max_input_words = 0, .max_output_words = 12 }, CLAIM_CIRCUIT_ID));
}

test "Ethereum initial claim policy constrains headers native roots and input edge" {
    const allocator = std.testing.allocator;
    const shape = vm_claim.Shape{ .max_input_words = 40, .max_output_words = 12 };
    const input_words = [_]u32{0x1234} ** 40;
    var data = testPublicData();
    data.io_entries.input_words = &input_words;
    data.io_entries.input_len = 160;
    data.io_entries.output_words = &.{};
    data.io_entries.output_len = 0;
    var claim = try vm_claim.encode(allocator, &data, shape);
    defer claim.deinit();
    var leaf = try statement.SegmentLeaf.init(&data, &claim, protocol.protocolId());
    // This is the first of two segments, so its output edge is absent.
    var complete = leaf.root.statement.job.complete;
    complete.total_cycles = data.clock * 2;
    const job = try statement.JobContext.init(complete, 2);
    var executed = leaf.root.statement.body.executed;
    executed.output = statement.EdgeClaim.absent();
    const first_span = try statement.SpanStatement.segmentLeaf(job, 0, executed);
    leaf.words = try first_span.canonicalWords();
    var reference = try semantics.ClaimReference.initForEthereumInitialInputs(allocator, shape, CLAIM_CIRCUIT_ID);
    defer reference.deinit();
    var witness = claimWitness(&claim, &leaf);
    witness.native_continuation_roots = .{ M31.fromCanonical(data.initial_rw_root.?), M31.fromCanonical(data.final_rw_root.?) };
    var prepared = try reference.prepare(allocator, witness);
    defer prepared.deinit();
    try prepared.validateAgainst(&reference);
    const statement_circuit = @import("statement_semantics_circuit.zig");
    const admission = @import("ethereum_statement_arithmetic_v4.zig");
    var circuit = try statement_circuit.build(allocator);
    defer circuit.deinit();
    var evaluation = try circuit.evaluate(allocator, statement_circuit.Witness.forSegment(&leaf.words));
    defer evaluation.deinit();
    const owned = try admission.Prepared.initForEthereumInitialInputs(allocator, &circuit, &evaluation, &reference, &prepared);
    defer owned.deinit();
    try std.testing.expectError(error.EthereumStatementArithmeticMismatch, admission.Prepared.initForEthereumNativeRoots(allocator, &circuit, &evaluation, &reference, &prepared));
    for ([_]usize{
        vm_claim.canonical_layout.input_word_count_start,
        vm_claim.canonical_layout.input_length_start,
        vm_claim.canonical_layout.outputWordCountStart(shape),
        vm_claim.canonical_layout.initial_rw_root_start,
        vm_claim.canonical_layout.final_rw_root_start + 1,
    }) |index| {
        const saved = claim.words[index];
        claim.words[index] = saved.add(M31.one());
        defer claim.words[index] = saved;
        try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, witness));
    }
    const saved_tag = leaf.words[statement.canonical_layout.input_edge_tag];
    leaf.words[statement.canonical_layout.input_edge_tag] = M31.zero();
    try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, witness));
    leaf.words[statement.canonical_layout.input_edge_tag] = saved_tag;
    witness.input_digest[0] = (witness.input_digest[0] + 1) % stwo_core.fields.m31.Modulus;
    try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, witness));
}
