//! Cold retained-witness construction for the Segment public cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const semantics = @import("vm_public_semantics_circuit.zig");
const air = @import("air/mod.zig");
const binding = air.universal_relation_binding;
const claim_input_witness = air.vm_public_claim_input_witness;
const claim_hash_witness = air.vm_public_claim_hash_witness;
const io_hash_witness = air.vm_public_io_hash_witness;
const claim_semantics_witness = air.vm_public_claim_semantics_input_witness;
const public_logup_witness = air.vm_public_logup_input_witness;
const ClaimInputRelation = binding.Binding(air.vm_public_claim_input);
const ClaimHashRelation = binding.Binding(air.vm_public_claim_hash);
const IoHashRelation = binding.Binding(air.vm_public_io_hash);
const ClaimSemanticsRelation = binding.Binding(air.vm_public_claim_semantics_input);
const PublicLogupRelation = binding.Binding(air.vm_public_logup_input);

pub fn init(
    comptime PreparedType: type,
    allocator: std.mem.Allocator,
    source: anytype,
    preprocessing: anytype,
    leaf: anytype,
    data: anytype,
    native_relations: anytype,
    claimed_sums: []const QM31,
    baseValueFn: anytype,
) !PreparedType {
    try source.validateLeaf(preprocessing);
    try leaf.validateAgainst(preprocessing, data);
    if (claimed_sums.len != source.claimed_sum_count)
        return error.ClaimedSumCountMismatch;

    var claim_semantics = source.claim_reference.prepare(allocator, .{
        .segment_selected = true,
        .claim_words = leaf.claim.words,
        .statement_words = &leaf.statement.words,
        .input_digest = leaf.claim.public_input_digest,
        .output_digest = leaf.claim.public_output_digest,
    }) catch |err| switch (err) {
        error.SemanticConstraintViolation => return error.ClaimSemanticConstraintViolation,
        else => return err,
    };
    errdefer claim_semantics.deinit();
    var public_logup = source.logup_reference.prepare(allocator, .{
        .segment_selected = true,
        .claim_words = leaf.claim.words,
        .relation_words = semantics.LogupChallengeWords.fromRelations(native_relations),
        .claimed_sums = claimed_sums,
    }) catch |err| switch (err) {
        error.SemanticConstraintViolation => return error.PublicLogupSemanticConstraintViolation,
        else => return err,
    };
    errdefer public_logup.deinit();

    const logup_values = try allocator.alloc(M31, public_logup.input_values.len);
    defer allocator.free(logup_values);
    for (logup_values, public_logup.input_values) |*destination, value|
        destination.* = try baseValueFn(value);
    const row16_reference = try source.logupRowReference();
    var public_logup_main = try public_logup_witness.MainWitness.init(
        allocator,
        &source.public_logup_preprocessing,
        row16_reference,
        logup_values,
        .segment_leaf,
    );
    errdefer public_logup_main.deinit();

    const claim_input_rows = try allocator.alloc(
        ClaimInputRelation.Row,
        preprocessing.claim_input.rows.len,
    );
    errdefer allocator.free(claim_input_rows);
    for (
        claim_input_rows,
        leaf.claim_input.rows,
        preprocessing.claim_input.rows,
    ) |*destination, main, pp| destination.* = claim_input_witness.logicalInputs(
        main,
        pp,
        .segment_leaf,
    );

    const claim_hash_rows = try allocator.alloc(
        ClaimHashRelation.Row,
        preprocessing.claim_hash.rows.len,
    );
    errdefer allocator.free(claim_hash_rows);
    for (
        claim_hash_rows,
        leaf.claim_hash.rows,
        preprocessing.claim_hash.rows,
    ) |*destination, main, pp| destination.* = claim_hash_witness.logicalInputs(
        main,
        pp,
        .segment_leaf,
    );

    const io_hash_rows = try allocator.alloc(
        IoHashRelation.Row,
        preprocessing.io_hash.rows.len,
    );
    errdefer allocator.free(io_hash_rows);
    for (
        io_hash_rows,
        leaf.io_hash.rows,
        preprocessing.io_hash.rows,
    ) |*destination, main, pp| destination.* = io_hash_witness.logicalInputs(
        main,
        pp,
        .segment_leaf,
    );

    const claim_semantics_rows = try allocator.alloc(
        ClaimSemanticsRelation.Row,
        source.claim_reference.row_preprocessing.rows.len,
    );
    errdefer allocator.free(claim_semantics_rows);
    for (
        claim_semantics_rows,
        claim_semantics.row_witness.rows,
        source.claim_reference.row_preprocessing.rows,
    ) |*destination, main, pp| destination.* =
        claim_semantics_witness.logicalInputs(
            main,
            pp,
            .segment_leaf,
            source.parameters.claim_semantics[1],
            source.parameters.claim_semantics[2],
        );

    const public_logup_rows = try allocator.alloc(
        PublicLogupRelation.Row,
        source.public_logup_preprocessing.rows.len,
    );
    errdefer allocator.free(public_logup_rows);
    for (
        public_logup_rows,
        public_logup_main.rows,
        source.public_logup_preprocessing.rows,
    ) |*destination, main, pp| destination.* = public_logup_witness.logicalInputs(
        main,
        pp,
        .segment_leaf,
        source.parameters.public_logup[1],
        source.parameters.public_logup[2],
        source.parameters.public_logup[3],
        source.parameters.public_logup[4],
    );

    const result = PreparedType{
        .allocator = allocator,
        .claim_semantics = claim_semantics,
        .public_logup = public_logup,
        .public_logup_main = public_logup_main,
        .claim_input_rows = claim_input_rows,
        .claim_hash_rows = claim_hash_rows,
        .io_hash_rows = io_hash_rows,
        .claim_semantics_rows = claim_semantics_rows,
        .public_logup_rows = public_logup_rows,
        .authority_seal = undefined,
    };
    return result;
}
