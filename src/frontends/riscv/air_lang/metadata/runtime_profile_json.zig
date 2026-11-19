//! Canonical JSON encoding for authenticated runtime profiles.

const std = @import("std");

pub fn write(
    writer: *std.Io.Writer,
    profile: anytype,
    schema: []const u8,
) !void {
    const profile_hex = std.fmt.bytesToHex(profile.profile_digest, .lower);
    const static_hex = std.fmt.bytesToHex(profile.static_report_digest, .lower);
    const runtime_hex = std.fmt.bytesToHex(profile.runtime_digest, .lower);
    const example_hex = std.fmt.bytesToHex(profile.example_digest, .lower);
    const implementation_hex = std.fmt.bytesToHex(
        profile.identity.implementation,
        .lower,
    );
    const workload_hex = std.fmt.bytesToHex(profile.identity.workload, .lower);
    const protocol_hex = std.fmt.bytesToHex(profile.identity.protocol, .lower);
    const proof_hex = std.fmt.bytesToHex(profile.identity.proof, .lower);
    const stage_hex = std.fmt.bytesToHex(profile.stages.source_digest, .lower);
    const task_hex = std.fmt.bytesToHex(profile.tasks.source_digest, .lower);

    try writer.print(
        "{{\"schema\":\"{s}\",\"schema_version\":{d}" ++
            ",\"profile_sha256\":\"{s}\",\"static_schema_version\":{d}" ++
            ",\"static_report_sha256\":\"{s}\",\"runtime_sha256\":\"{s}\"" ++
            ",\"example_sha256\":\"{s}\",\"implementation_sha256\":\"{s}\"" ++
            ",\"workload_sha256\":\"{s}\",\"protocol_sha256\":\"{s}\"" ++
            ",\"proof_sha256\":\"{s}\",\"backend\":\"{s}\"" ++
            ",\"optimize\":\"{s}\",\"configured_workers\":{d}" ++
            ",\"independently_verified\":{},\"input_and_execution_ns\":{d}" ++
            ",\"prove_ns\":{d},\"encode_ns\":{d},\"verify_ns\":{d}" ++
            ",\"request_ns\":{d},\"proof_bytes\":{d},\"committed_trace_cells\":{d}",
        .{
            schema,
            profile.schema_version,
            &profile_hex,
            profile.static_schema_version,
            &static_hex,
            &runtime_hex,
            &example_hex,
            &implementation_hex,
            &workload_hex,
            &protocol_hex,
            &proof_hex,
            @tagName(profile.backend),
            @tagName(profile.optimize),
            profile.configured_workers,
            profile.independently_verified,
            profile.timings.input_and_execution_ns,
            profile.timings.prove_ns,
            profile.timings.encode_ns,
            profile.timings.verify_ns,
            profile.timings.request_ns,
            profile.proof_bytes,
            profile.committed_trace_cells,
        },
    );
    try writer.writeAll(",\"peak_rss_bytes\":");
    try writeOptional(writer, profile.resources.peak_rss_bytes);
    try writer.writeAll(",\"instructions\":");
    try writeOptional(writer, profile.resources.instructions);
    try writer.writeAll(",\"cycles\":");
    try writeOptional(writer, profile.resources.cycles);
    try writer.writeAll(",\"energy_nanojoules\":");
    try writeOptional(writer, profile.resources.energy_nanojoules);
    try writer.print(
        ",\"counter_authority\":\"{s}\"",
        .{@tagName(profile.work.authority)},
    );
    inline for (.{
        .{ "field_additions", profile.work.field_additions },
        .{ "field_multiplications", profile.work.field_multiplications },
        .{ "field_inversions", profile.work.field_inversions },
        .{ "fft_butterflies", profile.work.fft_butterflies },
        .{ "fri_folds", profile.work.fri_folds },
        .{ "merkle_compressions", profile.work.merkle_compressions },
    }) |entry| {
        try writer.print(",\"{s}\":", .{entry[0]});
        try writeOptional(writer, entry[1]);
    }
    try writer.print(
        ",\"static_physical_main_columns\":{d}" ++
            ",\"static_logical_input_nodes\":{d},\"static_constraint_roots\":{d}" ++
            ",\"static_effects\":{d},\"static_lookup_events\":{d}" ++
            ",\"static_lookup_batches\":{d},\"static_interaction_columns\":{d}" ++
            ",\"static_expression_dag_nodes\":{d},\"static_expression_dag_edges\":{d}" ++
            ",\"static_expression_dag_shared_nodes\":{d}" ++
            ",\"static_constraint_effect_reachable_nodes\":{d}" ++
            ",\"static_nodes_outside_constraint_effect_closure\":{d}" ++
            ",\"static_maximum_constraint_degree\":{d}" ++
            ",\"static_maximum_lookup_numerator_degree\":{d}" ++
            ",\"static_maximum_lookup_denominator_degree\":{d}" ++
            ",\"static_maximum_interaction_degree\":{d}" ++
            ",\"stage_source_schema_version\":{d}" ++
            ",\"stage_source_sha256\":\"{s}\",\"stage_count\":{d}" ++
            ",\"maximum_stage_depth\":{d},\"root_stage_ns\":{d}" ++
            ",\"nested_stage_ns\":{d},\"task_source_schema_version\":{d}" ++
            ",\"task_source_sha256\":\"{s}\"" ++
            ",\"graph_count\":{d},\"task_count\":{d},\"contribution_count\":{d}" ++
            ",\"component_work_count\":{d},\"useful_task_work_ns\":{d}" ++
            ",\"critical_path_ns\":",
        .{
            profile.static_totals.physical_main_columns,
            profile.static_totals.logical_input_nodes,
            profile.static_totals.constraint_roots,
            profile.static_totals.effects,
            profile.static_totals.lookup_events,
            profile.static_totals.lookup_batches,
            profile.static_totals.interaction_columns,
            profile.static_totals.expression_dag_nodes,
            profile.static_totals.expression_dag_edges,
            profile.static_totals.expression_dag_shared_nodes,
            profile.static_totals.constraint_effect_reachable_nodes,
            profile.static_totals.nodes_outside_constraint_effect_closure,
            profile.static_totals.maximum_logical_constraint_degree,
            profile.static_totals.maximum_lookup_numerator_degree,
            profile.static_totals.maximum_lookup_denominator_degree,
            profile.static_totals.maximum_modeled_interaction_degree,
            profile.stages.source_schema_version,
            &stage_hex,
            profile.stages.stage_count,
            profile.stages.maximum_depth,
            profile.stages.root_elapsed_ns,
            profile.stages.nested_node_elapsed_ns,
            profile.tasks.source_schema_version,
            &task_hex,
            profile.tasks.graph_count,
            profile.tasks.task_count,
            profile.tasks.contribution_count,
            profile.tasks.component_work_count,
            profile.tasks.useful_task_work_ns,
        },
    );
    try writeOptional(writer, profile.tasks.critical_path_ns);
    try writer.print(
        ",\"admission_wait_ns\":{d},\"queue_wait_ns\":{d}" ++
            ",\"resource_wait_ns\":{d},\"task_run_ns\":{d}" ++
            ",\"worker_busy_ns\":",
        .{
            profile.tasks.admission_wait_ns,
            profile.tasks.queue_wait_ns,
            profile.tasks.resource_wait_ns,
            profile.tasks.task_run_ns,
        },
    );
    try writeOptional(writer, profile.tasks.worker_busy_ns);
    try writer.print(
        ",\"worker_capacity_ns\":{d},\"graph_elapsed_ns\":{d}" ++
            ",\"parallel_eligible_ns\":{d},\"peak_reserved_bytes\":{d}" ++
            ",\"total_work_estimate\":{d},\"completed_rows\":{d}" ++
            ",\"completed_tiles\":{d},\"maximum_active_tasks\":{d}" ++
            ",\"maximum_active_workers\":",
        .{
            profile.tasks.worker_capacity_ns,
            profile.tasks.graph_elapsed_ns,
            profile.tasks.parallel_eligible_ns,
            profile.tasks.peak_reserved_bytes,
            profile.tasks.total_work_estimate,
            profile.tasks.completed_rows,
            profile.tasks.completed_tiles,
            profile.tasks.maximum_active_tasks,
        },
    );
    try writeOptional(writer, profile.tasks.maximum_active_workers);
    try writer.print(
        ",\"all_graphs_completed\":{},\"evidence_complete\":{}}}\n",
        .{ profile.tasks.all_graphs_completed, profile.evidenceComplete() },
    );
}

fn writeOptional(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    if (value) |present| {
        try writer.print("{d}", .{present});
    } else {
        try writer.writeAll("null");
    }
}
