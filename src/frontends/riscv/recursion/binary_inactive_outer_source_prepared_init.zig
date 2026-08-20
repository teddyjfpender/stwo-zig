//! Cold retained-witness construction for the binary inactive cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
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
    typed: anytype,
    vm_plan: anytype,
    recursion_plan: anytype,
    preprocessing: anytype,
) !PreparedType {
    try source.validateAgainst(typed, vm_plan, recursion_plan, preprocessing);

    var claim_input = try claim_input_witness.MainWitness.init(
        allocator,
        &preprocessing.claim_input,
        .{ .binary_node = {} },
    );
    errdefer claim_input.deinit();
    var claim_hash = try claim_hash_witness.MainWitness.init(
        allocator,
        &preprocessing.claim_hash,
        .{ .binary_node = {} },
    );
    errdefer claim_hash.deinit();
    var io_hash = try io_hash_witness.MainWitness.init(
        allocator,
        &preprocessing.io_hash,
        .{ .binary_node = {} },
    );
    errdefer io_hash.deinit();

    const claim_reference = try source.claimSemanticsReference(typed);
    const logup_reference = try source.publicLogupReference(typed);
    const maximum_input_count = @max(
        typed.claim_reference.row_preprocessing.rows.len,
        typed.public_logup_preprocessing.rows.len,
    );
    const zero_values = try allocator.alloc(M31, maximum_input_count);
    defer allocator.free(zero_values);
    @memset(zero_values, M31.zero());
    var claim_semantics = try claim_semantics_witness.MainWitness.init(
        allocator,
        &typed.claim_reference.row_preprocessing,
        claim_reference,
        zero_values[0..typed.claim_reference.row_preprocessing.rows.len],
        .binary_node,
    );
    errdefer claim_semantics.deinit();
    var public_logup = try public_logup_witness.MainWitness.init(
        allocator,
        &typed.public_logup_preprocessing,
        logup_reference,
        zero_values[0..typed.public_logup_preprocessing.rows.len],
        .binary_node,
    );
    errdefer public_logup.deinit();

    const claim_input_rows = try allocator.alloc(
        ClaimInputRelation.Row,
        preprocessing.claim_input.rows.len,
    );
    errdefer allocator.free(claim_input_rows);
    const claim_hash_rows = try allocator.alloc(
        ClaimHashRelation.Row,
        preprocessing.claim_hash.rows.len,
    );
    errdefer allocator.free(claim_hash_rows);
    const io_hash_rows = try allocator.alloc(
        IoHashRelation.Row,
        preprocessing.io_hash.rows.len,
    );
    errdefer allocator.free(io_hash_rows);
    const claim_semantics_rows = try allocator.alloc(
        ClaimSemanticsRelation.Row,
        typed.claim_reference.row_preprocessing.rows.len,
    );
    errdefer allocator.free(claim_semantics_rows);
    const public_logup_rows = try allocator.alloc(
        PublicLogupRelation.Row,
        typed.public_logup_preprocessing.rows.len,
    );
    errdefer allocator.free(public_logup_rows);

    for (
        claim_input_rows,
        claim_input.rows,
        preprocessing.claim_input.rows,
    ) |*destination, main, pp| destination.* = claim_input_witness.logicalInputs(
        main,
        pp,
        .binary_node,
    );
    for (
        claim_hash_rows,
        claim_hash.rows,
        preprocessing.claim_hash.rows,
    ) |*destination, main, pp| destination.* = claim_hash_witness.logicalInputs(
        main,
        pp,
        .binary_node,
    );
    for (
        io_hash_rows,
        io_hash.rows,
        preprocessing.io_hash.rows,
    ) |*destination, main, pp| destination.* = io_hash_witness.logicalInputs(
        main,
        pp,
        .binary_node,
    );
    for (
        claim_semantics_rows,
        claim_semantics.rows,
        typed.claim_reference.row_preprocessing.rows,
    ) |*destination, main, pp| destination.* =
        claim_semantics_witness.logicalInputs(
            main,
            pp,
            .binary_node,
            source.parameters.claim_semantics[1],
            source.parameters.claim_semantics[2],
        );
    for (
        public_logup_rows,
        public_logup.rows,
        typed.public_logup_preprocessing.rows,
    ) |*destination, main, pp| destination.* =
        public_logup_witness.logicalInputs(
            main,
            pp,
            .binary_node,
            source.parameters.public_logup[1],
            source.parameters.public_logup[2],
            source.parameters.public_logup[3],
            source.parameters.public_logup[4],
        );

    const result = PreparedType{
        .allocator = allocator,
        .claim_input = claim_input,
        .claim_hash = claim_hash,
        .io_hash = io_hash,
        .claim_semantics = claim_semantics,
        .public_logup = public_logup,
        .claim_input_rows = claim_input_rows,
        .claim_hash_rows = claim_hash_rows,
        .io_hash_rows = io_hash_rows,
        .claim_semantics_rows = claim_semantics_rows,
        .public_logup_rows = public_logup_rows,
        .authority_seal = undefined,
    };
    return result;
}
