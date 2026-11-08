const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const ExecutionMetrics = @import("execution_metrics.zig").ExecutionMetrics;
const nanosecondsToSeconds = @import("timing.zig").nanosecondsToSeconds;

const prove_timing_scope_name = "recorded_witness_start_to_verified_proof";
const pow_timing_scope_name = "cpu_nonce_search_or_fixture_validation_only";

const SpillPurposeStat = struct {
    purpose: []const u8,
    buffers: usize = 0,
    bytes: u64 = 0,
};

pub fn write(ctx: anytype, execution_metrics: *const ExecutionMetrics) !void {
    const allocator = ctx.allocator;
    const missing_components = ctx.missing_components;
    const missing_lookup_components = ctx.missing_lookup_components;
    const plan = ctx.plan;
    const schedule = ctx.schedule;
    const runner_wall_timer = ctx.runner_wall_timer;
    const runner_phase_timing = ctx.runner_phase_timing;
    const recipe_preparation_timing = ctx.recipe_preparation_timing;
    const args = ctx.args;
    const input_sha256 = ctx.input_sha256;
    const canonical_protocol = ctx.canonical_protocol;
    const component_count = ctx.component_count;
    const witness_bundle = ctx.witness_bundle;
    const feed_bundle = ctx.feed_bundle;
    const native_destination_count = ctx.native_destination_count;
    const relation_bundle = ctx.relation_bundle;
    const relation_coverage = ctx.relation_coverage;
    const fixed_table_bundle = ctx.fixed_table_bundle;
    const fixed_table_coverage = ctx.fixed_table_coverage;
    const ec_op_coverage = ctx.ec_op_coverage;
    const composition_bundle = ctx.composition_bundle;
    const composition_coverage = ctx.composition_coverage;
    const proof_bindings = ctx.proof_bindings;
    const proof_plan = ctx.proof_plan;
    const arena_plan_cache_hit = ctx.arena_plan_cache_hit;
    const native_recipe_buffers = ctx.native_recipe_buffers;
    const native_recipe_bytes = ctx.native_recipe_bytes;
    const zero_recipe_buffers = ctx.zero_recipe_buffers;
    const zero_recipe_bytes = ctx.zero_recipe_bytes;
    const witness_recipe_buffers = ctx.witness_recipe_buffers;
    const witness_recipe_bytes = ctx.witness_recipe_bytes;
    const witness_missing_buffers = ctx.witness_missing_buffers;
    const bound_recipe_buffers = ctx.bound_recipe_buffers;
    const bound_recipe_bytes = ctx.bound_recipe_bytes;
    const circle_recipe_buffers = ctx.circle_recipe_buffers;
    const circle_recipe_bytes = ctx.circle_recipe_bytes;
    const preprocessed_recipe_buffers = ctx.preprocessed_recipe_buffers;
    const preprocessed_recipe_bytes = ctx.preprocessed_recipe_bytes;
    const merkle_parent_coverage = ctx.merkle_parent_coverage;
    const merkle_commit_coverage = ctx.merkle_commit_coverage;
    const peak_tick = ctx.peak_tick;
    const diagnostic_peak_logical_bytes = ctx.diagnostic_peak_logical_bytes;
    const diagnostic_base_peak_bytes = ctx.diagnostic_base_peak_bytes;
    const diagnostic_base_peak_tick = ctx.diagnostic_base_peak_tick;
    const diagnostic_interaction_peak_bytes = ctx.diagnostic_interaction_peak_bytes;
    const diagnostic_interaction_peak_tick = ctx.diagnostic_interaction_peak_tick;
    const interaction_peak_purposes = ctx.interaction_peak_purposes;
    const base_peak_purposes = ctx.base_peak_purposes;
    const peak_purposes = ctx.peak_purposes;
    const budget_bytes = ctx.budget_bytes;
    const budget_gib = ctx.budget_gib;
    const report_writer = ctx.report_writer;

    const missing_names = try allocator.alloc([]const u8, missing_components.count());
    defer allocator.free(missing_names);
    var missing_iterator = missing_components.keyIterator();
    var missing_index: usize = 0;
    while (missing_iterator.next()) |name| : (missing_index += 1) missing_names[missing_index] = name.*;
    std.mem.sortUnstable([]const u8, missing_names, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    const missing_lookup_names = try allocator.alloc([]const u8, missing_lookup_components.count());
    defer allocator.free(missing_lookup_names);
    var missing_lookup_iterator = missing_lookup_components.keyIterator();
    var missing_lookup_index: usize = 0;
    while (missing_lookup_iterator.next()) |name| : (missing_lookup_index += 1) missing_lookup_names[missing_lookup_index] = name.*;
    std.mem.sortUnstable([]const u8, missing_lookup_names, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    var resident: usize = 0;
    var spilled: usize = 0;
    var recomputed: usize = 0;
    var spill_snapshot_bytes: u64 = 0;
    var recompute_snapshot_bytes: u64 = 0;
    var spill_by_purpose = std.ArrayList(SpillPurposeStat).empty;
    defer spill_by_purpose.deinit(allocator);
    for (plan.bindings) |binding| switch (binding.materialization) {
        .resident => resident += 1,
        .spill => {
            spilled += 1;
            spill_snapshot_bytes += binding.size_bytes;
            const purpose = schedule[binding.logical_id].object.get("purpose").?.string;
            var stat: ?*SpillPurposeStat = null;
            for (spill_by_purpose.items) |*candidate| {
                if (std.mem.eql(u8, candidate.purpose, purpose)) {
                    stat = candidate;
                    break;
                }
            }
            if (stat == null) {
                try spill_by_purpose.append(allocator, .{ .purpose = purpose });
                stat = &spill_by_purpose.items[spill_by_purpose.items.len - 1];
            }
            stat.?.buffers += 1;
            stat.?.bytes += binding.size_bytes;
        },
        .recompute => {
            recomputed += 1;
            recompute_snapshot_bytes += binding.size_bytes;
        },
    };
    std.mem.sortUnstable(SpillPurposeStat, spill_by_purpose.items, {}, struct {
        fn lessThan(_: void, lhs: SpillPurposeStat, rhs: SpillPurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.order(u8, lhs.purpose, rhs.purpose) == .lt;
        }
    }.lessThan);
    const runner_before_report_wall_s = nanosecondsToSeconds(runner_wall_timer.read());
    const runner_phase_report = runner_phase_timing.report(
        runner_before_report_wall_s,
        execution_metrics.prove_started_wall_s,
        execution_metrics.proof_verified_wall_s,
        execution_metrics.prove_wall_s,
    );
    const recipe_preparation_report = recipe_preparation_timing.report(execution_metrics.prove_wall_s);
    const result = .{
        .schema_version = 1,
        .protocol = canonical_protocol,
        .protocol_complete = true,
        .planner = "zig-metal-sparse-epochs-v1",
        .schedule_policy = "protocol-purpose-v1-global-phase-conservative",
        .source = args[1],
        .source_sha256 = input_sha256,
        .logical_buffers = plan.bindings.len,
        .component_subepochs = component_count,
        .canonical_witness_programs = if (witness_bundle) |bundle| bundle.entries.len else 0,
        .native_feed_producers = if (feed_bundle) |bundle| bundle.feeds.len else 0,
        .native_feed_destinations = native_destination_count,
        .relation_graph_hash = if (relation_bundle) |bundle| bundle.graph_hash else 0,
        .relation_instances = if (relation_coverage) |coverage| coverage.instances else 0,
        .relation_output_buffers = if (relation_coverage) |coverage| coverage.output_buffers else 0,
        .relation_output_bytes = if (relation_coverage) |coverage| coverage.output_bytes else 0,
        .fixed_table_graph_hash = if (fixed_table_bundle) |bundle| bundle.graph_hash else 0,
        .fixed_table_components = if (fixed_table_coverage) |coverage| coverage.components else 0,
        .fixed_table_lookup_buffers = if (fixed_table_coverage) |coverage| coverage.lookup_buffers else 0,
        .fixed_table_lookup_bytes = if (fixed_table_coverage) |coverage| coverage.lookup_bytes else 0,
        .ec_op_rows = ec_op_coverage.rows,
        .ec_op_output_buffers = ec_op_coverage.output_buffers,
        .ec_op_output_bytes = ec_op_coverage.output_bytes,
        .composition_plan_hash = if (composition_bundle) |bundle| bundle.plan_hash else 0,
        .composition_recipe_components = if (composition_coverage) |coverage| coverage.components else 0,
        .composition_recipe_parts = if (composition_coverage) |coverage| coverage.parts else 0,
        .composition_recipe_buffers = if (composition_coverage) |coverage| coverage.output_buffers else 0,
        .composition_recipe_bytes = if (composition_coverage) |coverage| coverage.output_bytes else 0,
        .composition_radix4 = (try metal_runtime.compositionLdeOptionsFromEnvironment()).radix4,
        .prepared_proof_bindings = if (proof_bindings) |bindings| bindings.assembly.len else 0,
        .prepared_proof_copy_ranges = if (proof_bindings) |bindings| bindings.proof_copies.len else 0,
        .prepared_proof_words = if (proof_bindings) |bindings| bindings.proof_bytes.size_bytes / 4 else 0,
        .cairo_proof_plan_components = if (proof_plan) |value| value.components.len else 0,
        .cairo_witness_levels = if (proof_plan) |value| value.levels.len else 0,
        .resident_prepare_gate = execution_metrics.resident_prepare_gate,
        .populated_direct_witness_lanes = execution_metrics.populated_direct_witness_lanes,
        .execution_table_split_gpu_ms = execution_metrics.execution_table_split_gpu_ms,
        .executed_witness_programs = execution_metrics.executed_witness_programs,
        .witness_graph_gpu_ms = execution_metrics.witness_graph_gpu_ms,
        .multiplicity_feed_gpu_ms = execution_metrics.multiplicity_feed_gpu_ms,
        .memory_public_seed_gpu_ms = execution_metrics.memory_public_seed_gpu_ms,
        .memory_trace_gpu_ms = execution_metrics.memory_trace_gpu_ms,
        .memory_rc99_gpu_ms = execution_metrics.memory_rc99_gpu_ms,
        .populated_preprocessed_coefficients = execution_metrics.populated_preprocessed_coefficients,
        .preprocessed_gpu_ms = execution_metrics.preprocessed_gpu_ms,
        .base_interpolation_gpu_ms = execution_metrics.base_interpolation_gpu_ms,
        .interaction_witness_gpu_ms = execution_metrics.interaction_witness_gpu_ms,
        .relation_gpu_ms = execution_metrics.relation_gpu_ms,
        .interaction_interpolation_gpu_ms = execution_metrics.interaction_interpolation_gpu_ms,
        .composition_gpu_ms = execution_metrics.composition_gpu_ms,
        .quotient_gpu_ms = execution_metrics.quotient_gpu_ms,
        .quotient_executed = execution_metrics.quotient_executed,
        .quotient_reference_parity = execution_metrics.quotient_reference_parity,
        .fri_gpu_ms = execution_metrics.fri_gpu_ms,
        .fri_executed = execution_metrics.fri_executed,
        .fri_reference_parity = execution_metrics.fri_reference_parity,
        .fri_final_degree_valid = execution_metrics.fri_final_degree_valid,
        .interaction_pow_nonce = execution_metrics.interaction_pow_nonce,
        .interaction_pow_wall_s = execution_metrics.interaction_pow_wall_s,
        .interaction_pow_mode = execution_metrics.interaction_pow_mode,
        .interaction_pow_bits = execution_metrics.interaction_pow_bits,
        .interaction_pow_invocations = execution_metrics.interaction_pow_invocations,
        .query_pow_nonce = execution_metrics.query_pow_nonce,
        .query_pow_wall_s = execution_metrics.query_pow_wall_s,
        .query_pow_mode = execution_metrics.query_pow_mode,
        .query_pow_bits = execution_metrics.query_pow_bits,
        .query_pow_invocations = execution_metrics.query_pow_invocations,
        .pow_timing_scope = if (execution_metrics.interaction_pow_wall_s != null or execution_metrics.query_pow_wall_s != null)
            pow_timing_scope_name
        else
            null,
        .decommit_lde_gpu_ms = execution_metrics.decommit_lde_gpu_ms,
        .decommit_gpu_ms = execution_metrics.decommit_gpu_ms,
        .decommit_executed = execution_metrics.decommit_executed,
        .proof_assembly_gpu_ms = execution_metrics.proof_assembly_gpu_ms,
        .proof_assembled = execution_metrics.proof_assembled,
        .proof_bundle_valid = execution_metrics.proof_bundle_valid,
        .proof_verified = execution_metrics.proof_verified,
        .proof_layout = execution_metrics.proof_layout,
        .statement_self_derived = execution_metrics.statement_self_derived,
        .legacy_transcript_bootstrap_used = execution_metrics.legacy_transcript_bootstrap_used,
        .parity_fixture_used = execution_metrics.parity_fixture_used,
        .proof_derived_artifact_used = true,
        .self_contained = false,
        .proof_output_bytes = execution_metrics.proof_output_bytes,
        .prove_wall_s = execution_metrics.prove_wall_s,
        .prove_timing_scope = if (execution_metrics.prove_wall_s != null) prove_timing_scope_name else null,
        .runner_phase_timing = runner_phase_report,
        .recipe_preparation_timing = recipe_preparation_report,
        .proof_serialization = if (execution_metrics.proof_assembled) "resident_sn2_bundle_v1" else null,
        .transcript_gpu_ms = execution_metrics.transcript_gpu_ms,
        .commitment_gpu_ms = execution_metrics.commitment_gpu_ms,
        .commitment_lde_gpu_ms = execution_metrics.commitment_lde_gpu_ms,
        .commitment_leaf_gpu_ms = execution_metrics.commitment_leaf_gpu_ms,
        .commitment_parent_gpu_ms = execution_metrics.commitment_parent_gpu_ms,
        .resident_arena_bytes = execution_metrics.resident_arena_bytes,
        .arena_plan_cache_hit = arena_plan_cache_hit,
        .prepared_state_cache_hit = execution_metrics.prepared_state_cache_hit,
        .fixed_table_recipe_cache_hit = execution_metrics.fixed_table_recipe_cache_hit,
        .multiplicity_feed_recipe_cache_hit = execution_metrics.multiplicity_feed_recipe_cache_hit,
        .base_aot_witness_cache_hit = execution_metrics.base_aot_witness_cache_hit,
        .interaction_aot_witness_cache_hit = execution_metrics.interaction_aot_witness_cache_hit,
        .compact_verify_recipe_cache_hit = execution_metrics.compact_verify_recipe_cache_hit,
        .compact_pedersen_recipe_cache_hit = execution_metrics.compact_pedersen_recipe_cache_hit,
        .compact_poseidon_recipe_cache_hit = execution_metrics.compact_poseidon_recipe_cache_hit,
        .recorded_base_interpolation_cache_hit = execution_metrics.recorded_base_interpolation_cache_hit,
        .native_base_interpolation_cache_hit = execution_metrics.native_base_interpolation_cache_hit,
        .prepared_state_snapshot_bytes = execution_metrics.prepared_state_snapshot_bytes,
        .prepared_state_clear_bytes = execution_metrics.prepared_state_clear_bytes,
        .prepared_state_capture_gpu_ms = execution_metrics.prepared_state_capture_gpu_ms,
        .prepared_state_restore_gpu_ms = execution_metrics.prepared_state_restore_gpu_ms,
        .preprocessed_coefficients_loaded_bytes = execution_metrics.preprocessed_coefficients_loaded_bytes,
        .preprocessed_coefficients_reconstructed_bytes = execution_metrics.preprocessed_coefficients_reconstructed_bytes,
        .commitment_roots = execution_metrics.commitment_roots,
        .fri_roots = execution_metrics.fri_roots,
        .prepared_quotient_partials = if (proof_bindings) |bindings| bindings.quotient_partials.len else 0,
        .prepared_fri_layers = if (proof_bindings) |bindings| bindings.fri_merkle_layers.len else 0,
        .native_recipe_buffers = native_recipe_buffers,
        .native_recipe_bytes = native_recipe_bytes,
        .zero_recipe_buffers = zero_recipe_buffers,
        .zero_recipe_bytes = zero_recipe_bytes,
        .witness_recipe_buffers = witness_recipe_buffers,
        .witness_recipe_bytes = witness_recipe_bytes,
        .witness_missing_buffers = witness_missing_buffers,
        .witness_missing_components = missing_names,
        .lookup_missing_components = missing_lookup_names,
        .bound_recompute_recipe_buffers = bound_recipe_buffers,
        .bound_recompute_recipe_bytes = bound_recipe_bytes,
        .metal_circle_recipe_buffers = circle_recipe_buffers,
        .metal_circle_recipe_bytes = circle_recipe_bytes,
        .preprocessed_ifft_recipe_buffers = preprocessed_recipe_buffers,
        .preprocessed_ifft_recipe_bytes = preprocessed_recipe_bytes,
        .merkle_parent_recipe_chains = merkle_parent_coverage.chains,
        .merkle_parent_recipe_buffers = merkle_parent_coverage.buffers,
        .merkle_parent_recipe_bytes = merkle_parent_coverage.bytes,
        .merkle_commit_recipe_commitments = merkle_commit_coverage.commitments,
        .merkle_commit_recipe_buffers = merkle_commit_coverage.buffers,
        .merkle_commit_recipe_bytes = merkle_commit_coverage.bytes,
        .physical_slots = plan.slots.len,
        .actions = plan.actions.len,
        .resident_buffers = resident,
        .spilled_buffers = spilled,
        .spill_snapshot_bytes = spill_snapshot_bytes,
        .spill_by_purpose = spill_by_purpose.items,
        .recomputed_buffers = recomputed,
        .recompute_snapshot_bytes = recompute_snapshot_bytes,
        .total_bytes = plan.total_bytes,
        .total_gib = @as(f64, @floatFromInt(plan.total_bytes)) / (1024.0 * 1024.0 * 1024.0),
        .base_epoch_arena_bytes = arena.bytesThroughTick(plan, 2 * 65),
        .peak_live_bytes = plan.peak_live_bytes,
        .peak_logical_bytes = arena.peakLogicalBytes(plan.bindings),
        .diagnostic_peak_tick = peak_tick,
        .diagnostic_peak_logical_bytes = diagnostic_peak_logical_bytes,
        .diagnostic_base_peak_bytes = diagnostic_base_peak_bytes,
        .diagnostic_base_peak_tick = diagnostic_base_peak_tick,
        .diagnostic_interaction_peak_bytes = diagnostic_interaction_peak_bytes,
        .diagnostic_interaction_peak_tick = diagnostic_interaction_peak_tick,
        .diagnostic_interaction_peak_purposes = interaction_peak_purposes,
        .diagnostic_base_peak_purposes = base_peak_purposes,
        .diagnostic_peak_purposes = peak_purposes,
        .budget_bytes = budget_bytes,
        .budget_gib = budget_gib,
        .fits = true,
        .alias_validation = "passed",
        .recovery_gate = "passed_no_unbound_recompute",
        .plan_hash = plan.plan_hash,
    };
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, report_writer);
    try report_writer.writeByte('\n');
}
