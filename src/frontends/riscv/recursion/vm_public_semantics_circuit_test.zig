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
