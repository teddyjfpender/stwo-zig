const std = @import("std");

pub const ProofLayoutEvidence = struct {
    interaction_claim_words: usize,
    sampled_value_words: usize,
    decommitment_capacity_words: usize,
};

pub const ExecutionMetrics = struct {
    resident_prepare_gate: []const u8 = "not_requested",
    populated_direct_witness_lanes: usize = 0,
    execution_table_split_gpu_ms: f64 = 0,
    executed_witness_programs: usize = 0,
    witness_graph_gpu_ms: f64 = 0,
    multiplicity_feed_gpu_ms: f64 = 0,
    memory_public_seed_gpu_ms: f64 = 0,
    memory_trace_gpu_ms: f64 = 0,
    memory_rc99_gpu_ms: f64 = 0,
    populated_preprocessed_coefficients: usize = 0,
    resident_preprocessed_coefficients: bool = false,
    preprocessed_gpu_ms: f64 = 0,
    base_interpolation_gpu_ms: f64 = 0,
    relation_gpu_ms: f64 = 0,
    interaction_witness_gpu_ms: f64 = 0,
    interaction_interpolation_gpu_ms: f64 = 0,
    composition_gpu_ms: f64 = 0,
    quotient_gpu_ms: f64 = 0,
    quotient_executed: bool = false,
    quotient_reference_parity: bool = false,
    fri_gpu_ms: f64 = 0,
    fri_executed: bool = false,
    fri_reference_parity: bool = false,
    fri_final_degree_valid: bool = false,
    interaction_pow_nonce: ?u64 = null,
    interaction_pow_wall_s: ?f64 = null,
    interaction_pow_mode: ?[]const u8 = null,
    interaction_pow_bits: ?u32 = null,
    interaction_pow_invocations: u32 = 0,
    query_pow_nonce: ?u64 = null,
    query_pow_wall_s: ?f64 = null,
    query_pow_mode: ?[]const u8 = null,
    query_pow_bits: ?u32 = null,
    query_pow_invocations: u32 = 0,
    decommit_lde_gpu_ms: f64 = 0,
    decommit_gpu_ms: f64 = 0,
    decommit_executed: bool = false,
    proof_assembly_gpu_ms: f64 = 0,
    proof_assembled: bool = false,
    proof_bundle_valid: bool = false,
    proof_verified: bool = false,
    proof_layout: ?ProofLayoutEvidence = null,
    statement_self_derived: bool = false,
    legacy_transcript_bootstrap_used: bool = false,
    parity_fixture_used: bool,
    proof_output_bytes: u64 = 0,
    prove_timer: ?std.time.Timer = null,
    prove_started_wall_s: ?f64 = null,
    proof_verified_wall_s: ?f64 = null,
    prove_wall_s: ?f64 = null,
    transcript_gpu_ms: f64 = 0,
    commitment_gpu_ms: f64 = 0,
    commitment_lde_gpu_ms: f64 = 0,
    commitment_leaf_gpu_ms: f64 = 0,
    commitment_parent_gpu_ms: f64 = 0,
    resident_arena_bytes: u64 = 0,
    prepared_state_cache_hit: bool = false,
    fixed_table_recipe_cache_hit: bool = false,
    multiplicity_feed_recipe_cache_hit: bool = false,
    base_aot_witness_cache_hit: bool = false,
    interaction_aot_witness_cache_hit: bool = false,
    compact_verify_recipe_cache_hit: bool = false,
    compact_pedersen_recipe_cache_hit: bool = false,
    compact_poseidon_recipe_cache_hit: bool = false,
    recorded_base_interpolation_cache_hit: bool = false,
    native_base_interpolation_cache_hit: bool = false,
    prepared_state_snapshot_bytes: u64 = 0,
    prepared_state_clear_bytes: u64 = 0,
    prepared_state_capture_gpu_ms: f64 = 0,
    prepared_state_restore_gpu_ms: f64 = 0,
    preprocessed_coefficients_loaded_bytes: u64 = 0,
    preprocessed_coefficients_reconstructed_bytes: u64 = 0,
    commitment_roots: [4]?[32]u8 = .{ null, null, null, null },
    fri_roots: []?[32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        fri_root_count: usize,
        parity_fixture_used: bool,
    ) !ExecutionMetrics {
        const fri_roots = try allocator.alloc(?[32]u8, fri_root_count);
        @memset(fri_roots, null);
        return .{
            .parity_fixture_used = parity_fixture_used,
            .fri_roots = fri_roots,
        };
    }

    pub fn deinit(self: *ExecutionMetrics, allocator: std.mem.Allocator) void {
        allocator.free(self.fri_roots);
        self.* = undefined;
    }
};
