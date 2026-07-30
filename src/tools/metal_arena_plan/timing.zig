pub const PreparedStateTelemetry = struct {
    cache_hit: bool = false,
    arena_bytes: u64 = 0,
    snapshot_bytes: u64 = 0,
    clear_bytes: u64 = 0,
    capture_gpu_ms: f64 = 0,
    restore_gpu_ms: f64 = 0,
};

pub const RunnerPhaseTiming = struct {
    schedule_read_and_hash_wall_s: f64 = 0,
    schedule_json_parse_wall_s: f64 = 0,
    bundle_read_and_validate_wall_s: f64 = 0,
    statement_and_proof_plan_wall_s: f64 = 0,
    schedule_liveness_analysis_wall_s: f64 = 0,
    arena_plan_and_bindings_wall_s: f64 = 0,
    resident_acquire_reset_restore_wall_s: f64 = 0,
    input_materialization_wall_s: f64 = 0,
    immutable_host_restore_wall_s: f64 = 0,
    recipe_preparation_wall_s: f64 = 0,

    pub fn addInterval(destination: *f64, timer: *std.time.Timer, started_ns: u64) void {
        destination.* += nanosecondsToSeconds(timer.read() - started_ns);
    }

    pub fn instrumentedPreProveWallSeconds(self: RunnerPhaseTiming) f64 {
        return self.schedule_read_and_hash_wall_s +
            self.schedule_json_parse_wall_s +
            self.bundle_read_and_validate_wall_s +
            self.statement_and_proof_plan_wall_s +
            self.schedule_liveness_analysis_wall_s +
            self.arena_plan_and_bindings_wall_s +
            self.resident_acquire_reset_restore_wall_s +
            self.input_materialization_wall_s +
            self.immutable_host_restore_wall_s +
            self.recipe_preparation_wall_s;
    }

    pub fn report(
        self: RunnerPhaseTiming,
        runner_before_report_wall_s: f64,
        prove_started_wall_s: ?f64,
        proof_verified_wall_s: ?f64,
        prove_wall_s: ?f64,
    ) RunnerPhaseTimingReport {
        const instrumented = self.instrumentedPreProveWallSeconds();
        const observed = prove_started_wall_s;
        return .{
            .schedule_read_and_hash_wall_s = self.schedule_read_and_hash_wall_s,
            .schedule_json_parse_wall_s = self.schedule_json_parse_wall_s,
            .bundle_read_and_validate_wall_s = self.bundle_read_and_validate_wall_s,
            .statement_and_proof_plan_wall_s = self.statement_and_proof_plan_wall_s,
            .schedule_liveness_analysis_wall_s = self.schedule_liveness_analysis_wall_s,
            .arena_plan_and_bindings_wall_s = self.arena_plan_and_bindings_wall_s,
            .resident_acquire_reset_restore_wall_s = self.resident_acquire_reset_restore_wall_s,
            .input_materialization_wall_s = self.input_materialization_wall_s,
            .immutable_host_restore_wall_s = self.immutable_host_restore_wall_s,
            .recipe_preparation_wall_s = self.recipe_preparation_wall_s,
            .pre_prove_observed_wall_s = observed,
            .pre_prove_instrumented_wall_s = instrumented,
            .pre_prove_unattributed_wall_s = if (observed) |value| @max(0, value - instrumented) else null,
            .post_prove_pre_report_wall_s = if (proof_verified_wall_s) |verified|
                @max(0, runner_before_report_wall_s - verified)
            else
                null,
            .runner_minus_prove_before_report_wall_s = if (prove_wall_s) |proved|
                @max(0, runner_before_report_wall_s - proved)
            else
                null,
            .runner_before_report_wall_s = runner_before_report_wall_s,
        };
    }
};

pub const RunnerPhaseTimingReport = struct {
    schema_version: u32 = 1,
    scope: []const u8 = "run_one_entry_to_report_serialization_start",
    schedule_read_and_hash_wall_s: f64,
    schedule_json_parse_wall_s: f64,
    bundle_read_and_validate_wall_s: f64,
    statement_and_proof_plan_wall_s: f64,
    schedule_liveness_analysis_wall_s: f64,
    arena_plan_and_bindings_wall_s: f64,
    resident_acquire_reset_restore_wall_s: f64,
    input_materialization_wall_s: f64,
    immutable_host_restore_wall_s: f64,
    recipe_preparation_wall_s: f64,
    pre_prove_observed_wall_s: ?f64,
    pre_prove_instrumented_wall_s: f64,
    pre_prove_unattributed_wall_s: ?f64,
    post_prove_pre_report_wall_s: ?f64,
    runner_minus_prove_before_report_wall_s: ?f64,
    runner_before_report_wall_s: f64,
};

pub const RecipePreparationTiming = struct {
    fixed_tables_wall_s: f64 = 0,
    multiplicity_feeds_wall_s: f64 = 0,
    base_aot_witness_acquire_wall_s: f64 = 0,
    compact_verify_wall_s: f64 = 0,
    compact_pedersen_wall_s: f64 = 0,
    compact_poseidon_wall_s: f64 = 0,
    ec_op_base_wall_s: f64 = 0,
    recorded_base_interpolation_wall_s: f64 = 0,
    native_base_interpolation_wall_s: f64 = 0,
    transcript_wall_s: f64 = 0,
    interaction_aot_witness_wall_s: f64 = 0,
    ec_op_interaction_wall_s: f64 = 0,
    relation_components_wall_s: f64 = 0,
    interaction_native_interpolation_wall_s: f64 = 0,
    composition_wall_s: f64 = 0,
    quotient_wall_s: f64 = 0,
    fri_wall_s: f64 = 0,
    decommit_queries_wall_s: f64 = 0,
    proof_assembly_wall_s: f64 = 0,

    pub fn preProveWallSeconds(self: RecipePreparationTiming) f64 {
        return self.fixed_tables_wall_s +
            self.multiplicity_feeds_wall_s +
            self.base_aot_witness_acquire_wall_s +
            self.compact_verify_wall_s +
            self.compact_pedersen_wall_s +
            self.compact_poseidon_wall_s +
            self.ec_op_base_wall_s +
            self.recorded_base_interpolation_wall_s +
            self.native_base_interpolation_wall_s;
    }

    pub fn recordedProveWallSeconds(self: RecipePreparationTiming) f64 {
        return self.transcript_wall_s +
            self.interaction_aot_witness_wall_s +
            self.ec_op_interaction_wall_s +
            self.relation_components_wall_s +
            self.interaction_native_interpolation_wall_s +
            self.composition_wall_s +
            self.quotient_wall_s +
            self.fri_wall_s +
            self.decommit_queries_wall_s +
            self.proof_assembly_wall_s;
    }

    pub fn report(
        self: RecipePreparationTiming,
        prove_wall_s: ?f64,
    ) RecipePreparationTimingReport {
        const pre_prove_wall_s = self.preProveWallSeconds();
        const recorded_prove_wall_s = self.recordedProveWallSeconds();
        return .{
            .pre_prove = .{
                .fixed_tables_wall_s = self.fixed_tables_wall_s,
                .multiplicity_feeds_wall_s = self.multiplicity_feeds_wall_s,
                .base_aot_witness_acquire_wall_s = self.base_aot_witness_acquire_wall_s,
                .compact_verify_wall_s = self.compact_verify_wall_s,
                .compact_pedersen_wall_s = self.compact_pedersen_wall_s,
                .compact_poseidon_wall_s = self.compact_poseidon_wall_s,
                .ec_op_base_wall_s = self.ec_op_base_wall_s,
                .recorded_base_interpolation_wall_s = self.recorded_base_interpolation_wall_s,
                .native_base_interpolation_wall_s = self.native_base_interpolation_wall_s,
                .total_wall_s = pre_prove_wall_s,
            },
            .recorded_prove = .{
                .transcript_wall_s = self.transcript_wall_s,
                .interaction_aot_witness_wall_s = self.interaction_aot_witness_wall_s,
                .ec_op_interaction_wall_s = self.ec_op_interaction_wall_s,
                .relation_components_wall_s = self.relation_components_wall_s,
                .interaction_native_interpolation_wall_s = self.interaction_native_interpolation_wall_s,
                .composition_wall_s = self.composition_wall_s,
                .quotient_wall_s = self.quotient_wall_s,
                .fri_wall_s = self.fri_wall_s,
                .decommit_queries_wall_s = self.decommit_queries_wall_s,
                .proof_assembly_wall_s = self.proof_assembly_wall_s,
                .total_wall_s = recorded_prove_wall_s,
            },
            .total_wall_s = pre_prove_wall_s + recorded_prove_wall_s,
            .recorded_prove_non_recipe_wall_s = if (prove_wall_s) |proved|
                @max(0, proved - recorded_prove_wall_s)
            else
                null,
        };
    }
};

pub const PreProveRecipePreparationTimingReport = struct {
    fixed_tables_wall_s: f64,
    multiplicity_feeds_wall_s: f64,
    base_aot_witness_acquire_wall_s: f64,
    compact_verify_wall_s: f64,
    compact_pedersen_wall_s: f64,
    compact_poseidon_wall_s: f64,
    ec_op_base_wall_s: f64,
    recorded_base_interpolation_wall_s: f64,
    native_base_interpolation_wall_s: f64,
    total_wall_s: f64,
};

pub const RecordedProveRecipePreparationTimingReport = struct {
    transcript_wall_s: f64,
    interaction_aot_witness_wall_s: f64,
    ec_op_interaction_wall_s: f64,
    relation_components_wall_s: f64,
    interaction_native_interpolation_wall_s: f64,
    composition_wall_s: f64,
    quotient_wall_s: f64,
    fri_wall_s: f64,
    decommit_queries_wall_s: f64,
    proof_assembly_wall_s: f64,
    total_wall_s: f64,
};

pub const RecipePreparationTimingReport = struct {
    schema_version: u32 = 1,
    scope: []const u8 = "run_one_recipe_acquisition_wall_time",
    pre_prove: PreProveRecipePreparationTimingReport,
    recorded_prove: RecordedProveRecipePreparationTimingReport,
    total_wall_s: f64,
    recorded_prove_non_recipe_wall_s: ?f64,
};

pub fn nanosecondsToSeconds(value: u64) f64 {
    return @as(f64, @floatFromInt(value)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

pub const CanonicalFullProofPlanMode = struct {
    execute_proof: bool,
    no_projection: bool,
    prepare_metal: bool,
    execute_preprocessed: bool,
    execute_witness: bool,
    execute_base_interpolation: bool,
    execute_commitments: bool,
    execute_relations: bool,
    execute_oods: bool,
    verify_proof: bool,

    pub fn eligible(self: CanonicalFullProofPlanMode) bool {
        return self.execute_proof and self.no_projection and self.prepare_metal and
            self.execute_preprocessed and self.execute_witness and
            self.execute_base_interpolation and self.execute_commitments and
            self.execute_relations and self.execute_oods and self.verify_proof;
    }
};
const std = @import("std");
