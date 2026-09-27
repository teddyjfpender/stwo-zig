//! Proof-independent inspection of the exact production statement geometry.
//!
//! This module deliberately calls the same commitment-witness and statement
//! builders as proving. It never estimates geometry from cycles and never
//! constructs trace columns, commitments, or a proof. The resulting facts are
//! suitable for rejecting an incompatible fixed recursion profile before a
//! benchmark cohort starts.

const std = @import("std");
const public_data_mod = @import("../air/public_data.zig");
const trace_mod = @import("../runner/trace.zig");
const memory_state = @import("../runner/memory_state.zig");
const state_chain = @import("../runner/state_chain.zig");
const segment_profile = @import("../recursion/segment_profile.zig");
const commitment_witness = @import("commitment_witness.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");

pub const Admission = enum {
    admitted,
    column_counts_mismatch,
    column_log_degree_mismatch,
    column_counts_and_log_degree_mismatch,
};

pub const Facts = struct {
    component_count: u32,
    infrastructure_count: u32,
    preprocessed_column_count: u32,
    main_column_count: u32,
    interaction_column_count: u32,
    maximum_column_log_degree: u32,
    expected_preprocessed_column_count: u32,
    expected_main_column_count: u32,
    expected_interaction_column_count: u32,
    expected_maximum_column_log_degree: u32,
    admission: Admission,
    fixed_profile_admissible: bool,
};

pub fn inspect(
    allocator: std.mem.Allocator,
    execution_trace: *const trace_mod.Trace,
    state_chain_tracker: ?*const state_chain.StateChainTracker,
    memory: ?*const memory_state.Snapshot,
    public_data: public_data_mod.PublicData,
) !Facts {
    var bound_public_data = public_data;
    try commitment_witness.bindCompletion(
        &bound_public_data,
        execution_trace.final_pc,
        memory,
    );
    var witness = try commitment_witness.CommitmentWitness.build(
        allocator,
        execution_trace,
        memory,
        bound_public_data.completion.?,
    );
    defer witness.deinit(allocator);

    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    _ = try statement_geometry.build(
        allocator,
        workspace,
        execution_trace,
        &witness,
        state_chain_tracker,
        bound_public_data,
        .proof,
    );
    const statement = &workspace.statement;

    var maximum_log: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor|
        maximum_log = @max(maximum_log, descriptor.log_size);
    for (statement.infra_descs[0..statement.n_infra]) |descriptor|
        maximum_log = @max(maximum_log, descriptor.log_size);

    const preprocessed = statement.nPreprocessedColumns();
    const main = statement.nMainColumns();
    const interaction = statement.nInteractionColumns();
    const counts_match =
        preprocessed == segment_profile.PREPROCESSED_COLUMN_COUNT and
        main == segment_profile.MAIN_COLUMN_COUNT and
        interaction == segment_profile.INTERACTION_COLUMN_COUNT;
    const log_matches = maximum_log == segment_profile.COLUMN_LOG_DEGREE;
    const expected_admitted = counts_match and log_matches;
    const profile_admitted = blk: {
        segment_profile.validateStatement(statement) catch |err| switch (err) {
            error.StatementGeometryMismatch => break :blk false,
            else => return err,
        };
        break :blk true;
    };
    if (profile_admitted != expected_admitted)
        return error.ProfileAdmissionPredicateDrift;

    return .{
        .component_count = statement.n_components,
        .infrastructure_count = statement.n_infra,
        .preprocessed_column_count = preprocessed,
        .main_column_count = main,
        .interaction_column_count = interaction,
        .maximum_column_log_degree = maximum_log,
        .expected_preprocessed_column_count = segment_profile.PREPROCESSED_COLUMN_COUNT,
        .expected_main_column_count = segment_profile.MAIN_COLUMN_COUNT,
        .expected_interaction_column_count = segment_profile.INTERACTION_COLUMN_COUNT,
        .expected_maximum_column_log_degree = segment_profile.COLUMN_LOG_DEGREE,
        .admission = if (counts_match and log_matches)
            .admitted
        else if (!counts_match and !log_matches)
            .column_counts_and_log_degree_mismatch
        else if (!counts_match)
            .column_counts_mismatch
        else
            .column_log_degree_mismatch,
        .fixed_profile_admissible = profile_admitted,
    };
}
