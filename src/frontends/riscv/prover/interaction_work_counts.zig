//! Exact base and guest Tree-2 work accounting, independent of generator ownership.
const std = @import("std");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const guest_interaction = @import("../air/guest_precompile/interaction.zig");
const guest_components = @import("../air/guest_precompile/component_registry.zig");
const guest_relations = @import("../air/guest_precompile/relation_challenges.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const BaseScalar = @import("../air/lookups/base_scalar.zig").Scalar;
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const interaction_witness_work = @import("interaction_witness_work.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_mod = @import("../air/statement.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const OpcodeBaseEntries = opcode_entries.Entries(BaseScalar);

/// Exact work of the allocation-safe sequential base generator selected by
/// the current guest profile. Projection arithmetic is owned by the separate
/// main-witness site; this authority covers every relation combine and LogUp
/// normalization, inversion, and prefix operation performed by Tree 2.
pub fn sequentialBaseWorkCounts(
    statement: *const statement_mod.RiscVStatement,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_v2: ?*const lookup_physical_v2.Manifest,
) !interaction_witness_work.Counts {
    var counts = interaction_witness_work.Counts{};

    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        const size = try workDomainSize(descriptor.log_size);
        var zeros = [_]BaseScalar{BaseScalar.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
        const list = try OpcodeBaseEntries.fromMain(
            descriptor.family,
            zeros[0..trace_mod.nColumnsForFamily(descriptor.family)],
        );
        var relation_inputs: usize = 0;
        for (list.entries[0..list.len]) |entry| {
            relation_inputs = try workAddUsize(relation_inputs, entry.arity);
        }
        try interaction_witness_work.observeRelationRows(
            &counts,
            size,
            list.len,
            relation_inputs,
        );
        const n_batches, const paired_batches = if (lookup_v2) |manifest| blk: {
            const physical = manifest.entryForFamily(descriptor.family);
            try lookup_physical_v2.validatePinnedEntry(physical);
            if (physical.lookup_authority.entry_count != list.len)
                return error.InteractionWorkSourceMismatch;
            var paired: usize = 0;
            for (physical.activeBatches()) |batch| {
                paired += @intFromBool(batch.entry_count == 2);
            }
            break :blk .{ physical.activeBatches().len, paired };
        } else .{
            list.batchCount(),
            if (list.batch_size == 1) 0 else list.len - list.batchCount(),
        };
        try observeSequentialBatchLogup(
            &counts,
            size,
            n_batches,
            paired_batches,
            opcode_interaction.CHUNK_ROWS,
        );
    }

    try interaction_witness_work.observeRelationRows(
        &counts,
        witness.program.rows.len,
        7,
        24,
    );
    try observeDirectLogup(
        &counts,
        try workDomainSize(geometry.program_log_size),
        program_interaction.N_SUMS,
    );

    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        if (descriptor.kind != .memory) continue;
        try interaction_witness_work.observeRelationRows(
            &counts,
            descriptor.n_rows,
            7,
            27,
        );
        try observeDirectLogup(
            &counts,
            try workDomainSize(descriptor.log_size),
            memory_interaction.N_SUMS,
        );
    }

    try interaction_witness_work.observeRelationRows(
        &counts,
        witness.merkleRows().len,
        5,
        44,
    );
    try observeDirectLogup(
        &counts,
        try workDomainSize(geometry.merkle_log_size),
        merkle_node.N_SUMS,
    );

    try interaction_witness_work.observeRelationRows(
        &counts,
        witness.poseidonCalls().len,
        4,
        80,
    );
    try observeDirectLogup(
        &counts,
        try workDomainSize(geometry.poseidon_log_size),
        poseidon2_air.N_SUMS,
    );

    // The live clock generator loops over each sum and reconstructs both
    // pairs inside that loop, so its four denominator combines execute twice.
    const clock_size = try workDomainSize(geometry.clock_update_log);
    try interaction_witness_work.observeRelationRows(
        &counts,
        try workMulUsize(clock_size, clock_update_interaction.N_SUMS),
        4,
        17,
    );
    for (0..clock_update_interaction.N_SUMS) |_| {
        try observeSequentialBatchLogup(
            &counts,
            clock_size,
            1,
            1,
            clock_update_interaction.CHUNK_ROWS,
        );
    }

    // `generateInto` first proves every denominator non-zero, then rebuilds
    // each denominator during its bounded generation pass.
    for (component_order.lookupTables()) |kind| {
        const size = lookup_table_schema.size(kind);
        try interaction_witness_work.observeRelationRows(
            &counts,
            try workMulUsize(size, 2),
            1,
            lookup_table_schema.arity(kind),
        );
        try observeSequentialBatchLogup(
            &counts,
            size,
            1,
            0,
            lookup_table_interaction.CHUNK_ROWS,
        );
    }
    return counts;
}

pub fn guestInteractionWorkCounts(
    active_rows: u32,
) !interaction_witness_work.Counts {
    var counts = interaction_witness_work.Counts{};
    var caller_inputs: usize = 0;
    for (guest_components.caller_events) |event| {
        if (event.numerator == .zero_in_guest_mode)
            return error.InteractionWorkSourceMismatch;
        caller_inputs = try workAddUsize(caller_inputs, event.arity);
    }
    var paired_batches: usize = 0;
    for (guest_components.caller_batches) |batch| {
        paired_batches += @intFromBool(batch.second_event != null);
    }
    const provider_event = guest_components.provider_events[3];
    if (provider_event.arity != guest_relations.guest_relation_arity or
        paired_batches + 1 != guest_interaction.caller_batch_count)
    {
        return error.InteractionWorkSourceMismatch;
    }
    const rows: usize = @intCast(active_rows);
    try interaction_witness_work.observeRelationRows(
        &counts,
        rows,
        guest_interaction.caller_event_count + 1,
        try workAddUsize(caller_inputs, provider_event.arity),
    );
    try interaction_witness_work.observeLogupTerms(
        &counts,
        try workMulUsize(rows, paired_batches),
        try workMulUsize(rows, guest_interaction.total_batch_count),
        0,
    );
    var row_start: usize = 0;
    while (row_start < rows) {
        const chunk_len = @min(guest_interaction.chunk_rows, rows - row_start);
        try interaction_witness_work.observeBatchInverse(
            &counts,
            try workMulUsize(guest_interaction.total_batch_count, chunk_len),
        );
        row_start += chunk_len;
    }
    return counts;
}

fn observeDirectLogup(
    counts: *interaction_witness_work.Counts,
    rows: usize,
    n_sums: usize,
) !void {
    const terms = try workMulUsize(rows, n_sums);
    try interaction_witness_work.observeLogupTerms(
        counts,
        terms,
        terms,
        terms,
    );
}

fn observeSequentialBatchLogup(
    counts: *interaction_witness_work.Counts,
    rows: usize,
    n_batches: usize,
    paired_batches: usize,
    chunk_rows: usize,
) !void {
    try interaction_witness_work.observeLogupTerms(
        counts,
        try workMulUsize(rows, paired_batches),
        try workMulUsize(rows, n_batches),
        0,
    );
    var row_start: usize = 0;
    while (row_start < rows) {
        const chunk_len = @min(chunk_rows, rows - row_start);
        try interaction_witness_work.observeBatchInverse(
            counts,
            try workMulUsize(n_batches, chunk_len),
        );
        row_start += chunk_len;
    }
}

fn workDomainSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InteractionWorkOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn workAddUsize(lhs: usize, rhs: usize) !usize {
    return std.math.add(usize, lhs, rhs) catch error.InteractionWorkOverflow;
}

fn workMulUsize(lhs: usize, rhs: usize) !usize {
    return std.math.mul(usize, lhs, rhs) catch error.InteractionWorkOverflow;
}
