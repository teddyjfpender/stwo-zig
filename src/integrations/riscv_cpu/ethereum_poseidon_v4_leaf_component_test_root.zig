//! Diagnostic-only Debug compile root for the Poseidon v4 leaf surface.
//!
//! This intentionally excludes the production multiplexer, source
//! materializer, mutation harness, external ELF fixture, and proof runtime.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const compact_replay = @import("ethereum_block_compact_replay.zig");
const compact_replay_receipt = @import("ethereum_block_compact_replay_receipt.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const incremental_boundary_artifact = @import("ethereum_incremental_boundary_artifact_v2.zig");
const incremental_boundary_capture = @import("ethereum_incremental_boundary_capture_v2.zig");
const incremental_boundary = @import("ethereum_incremental_boundary_authority_v1.zig");
const snapshot_batch = @import("ethereum_block_snapshot_batch.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const guest_pc_profile = @import("ethereum_guest_pc_profile.zig");
const geometry_command = @import("ethereum_poseidon_leaf_geometry_command.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const provider_resource_plan =
    @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const provider_call_artifact =
    @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const provider_stage_a_checkpoint =
    @import("ethereum_poseidon_provider_stage_a_checkpoint_v1.zig");
const provider_proof_artifact =
    @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const provider_proof_artifact_v2 =
    @import("ethereum_poseidon_provider_proof_artifact_v2.zig");
const provider_hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const provider_hpc_receipt =
    @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const provider_raw_pair_receipt =
    @import("ethereum_poseidon_provider_raw_pair_receipt_v1.zig");
const provider_raw_pair_benchmark =
    @import("ethereum_poseidon_provider_raw_pair_benchmark_v1.zig");
const provider_raw_batch_receipt =
    @import("ethereum_poseidon_provider_raw_batch_receipt_v2.zig");
const provider_raw_batch_benchmark =
    @import("ethereum_poseidon_provider_raw_batch_benchmark_v2.zig");
const provider_topology_sweep_receipt =
    @import("ethereum_poseidon_provider_topology_sweep_receipt_v1.zig");
const provider_topology_sweep =
    @import("ethereum_poseidon_provider_topology_sweep_v1.zig");
const provider_retention_sweep_receipt =
    @import("ethereum_poseidon_provider_retention_sweep_receipt_v1.zig");
const provider_retention_sweep =
    @import("ethereum_poseidon_provider_retention_sweep_v1.zig");
const provider_retention_admission =
    @import("ethereum_poseidon_provider_retention_admission_v2.zig");
const provider_retained_batch_receipt =
    @import("ethereum_poseidon_provider_retained_batch_receipt_v3.zig");
const provider_retained_batch =
    @import("ethereum_poseidon_provider_retained_batch_v3.zig");
const provider_prepared_capture =
    @import("ethereum_poseidon_provider_prepared_capture_v1.zig");
const provider_prepared_capture_receipt =
    @import("ethereum_poseidon_provider_prepared_capture_receipt_v1.zig");
const provider_fused =
    @import("ethereum_poseidon_provider_fused_v1.zig");
const provider_stage_b_lifecycle =
    @import("ethereum_poseidon_provider_stage_b_lifecycle_v1.zig");
const provider_stage_b_prefix =
    @import("ethereum_poseidon_provider_stage_b_prefix_v2.zig");
const bulk_memcpy_retained_microproof =
    @import("bulk_memcpy_retained_microproof_v1.zig");
const bulk_memcpy_retained_replay =
    @import("bulk_memcpy_retained_replay_v1.zig");
const bulk_memcpy_current_selected_segment_authority =
    @import("bulk_memcpy_current_selected_segment_authority_v1.zig");
const bulk_memcpy_retained_microproof_receipt =
    @import("bulk_memcpy_retained_microproof_receipt_v1.zig");
const bulk_memcpy_retained_microproof_receipt_v2 =
    @import("bulk_memcpy_retained_microproof_receipt_v2.zig");
const bulk_memcpy_tape_artifact =
    @import("bulk_memcpy_tape_artifact_v1.zig");
const bulk_memcpy_statement_artifact =
    @import("bulk_memcpy_statement_artifact_v1.zig");
const ethereum_candidate_combined_execution_capture_receipt =
    @import("ethereum_candidate_combined_execution_capture_receipt_v1.zig");
const ethereum_candidate_combined_execution_capture =
    @import("ethereum_candidate_combined_execution_capture_v1.zig");
const ethereum_candidate_combined_execution_capture_command =
    @import("ethereum_candidate_combined_execution_capture_command_v1.zig");
const ethereum_candidate_combined_execution_replay_receipt =
    @import("ethereum_candidate_combined_execution_replay_receipt_v1.zig");
const ethereum_candidate_combined_execution_replay =
    @import("ethereum_candidate_combined_execution_replay_v1.zig");
const ethereum_candidate_combined_execution_replay_command =
    @import("ethereum_candidate_combined_execution_replay_command_v1.zig");
const matched_ab_rematerialization_authority =
    @import("ethereum_matched_ab_rematerialization_authority_v1.zig");
const matched_ab_leaf_request =
    @import("ethereum_matched_ab_leaf_request_v1.zig");
const matched_ab_rematerialization_controller =
    @import("ethereum_matched_ab_rematerialization_controller_v1.zig");
const matched_ab_rematerialization_command =
    @import("ethereum_matched_ab_rematerialization_command_v1.zig");
const matched_ab_geometry_audit =
    @import("ethereum_matched_ab_geometry_audit_v1.zig");
const leaf_contract = @import("ethereum_block_leaf_contract.zig");
const materializer_options = @import("ethereum_block_leaf_materializer_options.zig");
const contract = @import("ethereum_poseidon_leaf_product_contract.zig");
const profile_receipt = @import("ethereum_poseidon_leaf_profile_receipt.zig");
const request = @import("ethereum_poseidon_leaf_product_request.zig");
const producer = @import("ethereum_poseidon_leaf_product_producer.zig");
const matched_ab_result =
    @import("ethereum_poseidon_leaf_matched_ab_result_v1.zig");
const matched_ab_command =
    @import("ethereum_poseidon_leaf_matched_ab_baseline_command_v1.zig");
const leaf_support = @import("ethereum_block_leaf_support.zig");
const verifier = @import("ethereum_poseidon_leaf_product_verifier.zig");
const baseline_admission_receipt =
    @import("ethereum_unoptimized_baseline_admission_receipt_v1.zig");
const baseline_admission =
    @import("ethereum_unoptimized_baseline_admission_v1.zig");
const candidate_leaf_verifier = @import("stwo_riscv_frontend").prover_mod
    .guest_precompile.ethereum_candidate_leaf_verifier_v1;
const candidate_leaf_orchestration = @import("stwo_riscv_frontend").prover_mod
    .guest_precompile.ethereum_candidate_leaf_orchestration_v1;
const matched_ab_execution = @import("stwo_riscv_frontend").prover_mod
    .guest_precompile.ethereum_leaf_matched_ab_execution_profile_v1;

test {
    _ = @import("bulk_memcpy_candidate_proof_test.zig");
}

test "diagnostic-only Poseidon v4 leaf component surface compiles" {
    std.testing.refAllDecls(contract);
    std.testing.refAllDecls(compact_replay);
    std.testing.refAllDecls(compact_replay_receipt);
    std.testing.refAllDecls(compact_manifest);
    std.testing.refAllDecls(incremental_boundary_artifact);
    std.testing.refAllDecls(incremental_boundary_capture);
    std.testing.refAllDecls(incremental_boundary);
    std.testing.refAllDecls(snapshot_batch);
    std.testing.refAllDecls(profile_receipt);
    std.testing.refAllDecls(guest_pc_profile);
    std.testing.refAllDecls(geometry_command);
    std.testing.refAllDecls(geometry_snapshot);
    std.testing.refAllDecls(provider_resource_plan);
    std.testing.refAllDecls(provider_call_artifact);
    std.testing.refAllDecls(provider_stage_a_checkpoint);
    std.testing.refAllDecls(provider_proof_artifact);
    std.testing.refAllDecls(provider_proof_artifact_v2);
    std.testing.refAllDecls(provider_hpc);
    std.testing.refAllDecls(provider_hpc_receipt);
    std.testing.refAllDecls(provider_raw_pair_receipt);
    std.testing.refAllDecls(provider_raw_pair_benchmark);
    std.testing.refAllDecls(provider_raw_batch_receipt);
    std.testing.refAllDecls(provider_raw_batch_benchmark);
    std.testing.refAllDecls(provider_topology_sweep_receipt);
    std.testing.refAllDecls(provider_topology_sweep);
    std.testing.refAllDecls(provider_retention_sweep_receipt);
    std.testing.refAllDecls(provider_retention_sweep);
    std.testing.refAllDecls(provider_retention_admission);
    std.testing.refAllDecls(provider_retained_batch_receipt);
    std.testing.refAllDecls(provider_retained_batch);
    std.testing.refAllDecls(provider_prepared_capture);
    std.testing.refAllDecls(provider_prepared_capture_receipt);
    std.testing.refAllDecls(provider_fused);
    std.testing.refAllDecls(provider_stage_b_lifecycle);
    std.testing.refAllDecls(provider_stage_b_prefix);
    std.testing.refAllDecls(bulk_memcpy_retained_microproof);
    std.testing.refAllDecls(bulk_memcpy_retained_replay);
    std.testing.refAllDecls(bulk_memcpy_current_selected_segment_authority);
    std.testing.refAllDecls(bulk_memcpy_retained_microproof_receipt);
    std.testing.refAllDecls(bulk_memcpy_retained_microproof_receipt_v2);
    std.testing.refAllDecls(bulk_memcpy_tape_artifact);
    std.testing.refAllDecls(bulk_memcpy_statement_artifact);
    std.testing.refAllDecls(ethereum_candidate_combined_execution_capture_receipt);
    std.testing.refAllDecls(ethereum_candidate_combined_execution_capture);
    std.testing.refAllDecls(ethereum_candidate_combined_execution_capture_command);
    std.testing.refAllDecls(ethereum_candidate_combined_execution_replay_receipt);
    std.testing.refAllDecls(ethereum_candidate_combined_execution_replay);
    std.testing.refAllDecls(ethereum_candidate_combined_execution_replay_command);
    std.testing.refAllDecls(matched_ab_rematerialization_authority);
    std.testing.refAllDecls(matched_ab_leaf_request);
    std.testing.refAllDecls(matched_ab_rematerialization_controller);
    std.testing.refAllDecls(matched_ab_rematerialization_command);
    std.testing.refAllDecls(matched_ab_geometry_audit);
    std.testing.refAllDecls(request);
    std.testing.refAllDecls(producer);
    std.testing.refAllDecls(matched_ab_result);
    std.testing.refAllDecls(matched_ab_command);
    std.testing.refAllDecls(verifier);
    std.testing.refAllDecls(baseline_admission_receipt);
    std.testing.refAllDecls(baseline_admission);
    std.testing.refAllDecls(candidate_leaf_verifier);
    std.testing.refAllDecls(candidate_leaf_orchestration);
    std.testing.refAllDecls(matched_ab_execution);
    std.testing.refAllDecls(materializer_options);
}

test "unoptimized baseline receipt cold reopens exact files and rejects mutations" {
    try baseline_admission_receipt.testing.coldReopenAndMutationGate(
        std.testing.allocator,
    );
}

test "provider Stage-B proof metadata round-trips exact frozen statements" {
    try provider_proof_artifact.testing.statementRoundTrip(
        std.testing.allocator,
    );
}

test "provider V2 proof metadata binds ordered-call Tree2 authority" {
    try provider_proof_artifact_v2.testing.statementRoundTrip(
        std.testing.allocator,
    );
}

test "provider HPC receipt seals bounded worker and fresh-verifier custody" {
    try provider_hpc_receipt.testing.canonicalRoundTrip(
        std.testing.allocator,
    );
}

test "provider raw-pair benchmark requires disjoint absolute outputs" {
    try provider_raw_pair_benchmark.testing.parseOptions(
        std.testing.allocator,
        &.{
            "--call-artifact",
            "/retained/calls.json",
            "--serial-proof-0",
            "/fresh/serial-0.stw",
            "--serial-proof-1",
            "/fresh/serial-1.stw",
            "--parallel-proof-0",
            "/fresh/parallel-0.stw",
            "--parallel-proof-1",
            "/fresh/parallel-1.stw",
            "--receipt",
            "/fresh/receipt.json",
            "--power-classification",
            "battery-diagnostic",
            "--per-job-engine-workers",
            "4",
        },
    );
}

test "provider raw-batch V2 accepts only explicit N one through four" {
    try provider_raw_batch_benchmark.testing.parseOptions(
        std.testing.allocator,
        &.{
            "--call-artifact",
            "/retained/calls.json",
            "--output-root",
            "/fresh/raw-batch-v2",
            "--power-classification",
            "battery-diagnostic",
            "--batch-size",
            "4",
            "--per-job-engine-workers",
            "4",
        },
    );
    try std.testing.expectError(
        error.InvalidArguments,
        provider_raw_batch_benchmark.testing.parseOptions(
            std.testing.allocator,
            &.{
                "--call-artifact",
                "/retained/calls.json",
                "--output-root",
                "/fresh/raw-batch-v2",
                "--power-classification",
                "battery-diagnostic",
                "--batch-size",
                "5",
            },
        ),
    );
}

test "provider topology sweep seals only the canonical 18-core configurations" {
    try provider_topology_sweep.testing.parseOptions(
        std.testing.allocator,
        &.{
            "--call-artifact",
            "/retained/calls.json",
            "--output-root",
            "/fresh/topology-sweep-v1",
            "--power-classification",
            "battery-diagnostic",
            "--log-size",
            "15",
            "--arm-hard-cap-seconds",
            "35",
            "--total-hard-cap-seconds",
            "118",
        },
    );
    try provider_topology_sweep_receipt.testing.canonicalRoundTrip(
        std.testing.allocator,
    );
}

test "provider retention sweep requires bounded four-way create-only custody" {
    try provider_retention_sweep.testing.parseOptions(
        std.testing.allocator,
        &.{
            "--call-artifact",
            "/retained/calls.json",
            "--output-root",
            "/fresh/retention-sweep-v1",
            "--power-classification",
            "battery-diagnostic",
            "--log-size",
            "16",
            "--arm-hard-cap-seconds",
            "50",
            "--total-hard-cap-seconds",
            "118",
        },
    );
}

test "provider prepared capture seals single-pass custody telemetry" {
    try provider_prepared_capture.testing.callCustodyParity();
    try provider_prepared_capture_receipt.testing.canonicalRoundTrip(
        std.testing.allocator,
    );
    try provider_fused.testing.parseOptions(std.testing.allocator);
}

test "provider retained batch binds preferred retention into sealed admission" {
    try provider_retained_batch.testing.parseOptions(std.testing.allocator);
    try provider_retained_batch_receipt.testing.canonicalRoundTrip(
        std.testing.allocator,
    );
}

test "provider call custody wire round-trips only canonical narrow calls" {
    try provider_call_artifact.testing.rawRoundTrip(std.testing.allocator);
}

test "provider Stage-B journal accepts only a strict immutable prefix" {
    try provider_stage_b_prefix.testing.structuralPrefixChain(
        std.testing.allocator,
    );
}

test "pre-Engine geometry command is an explicit create-only diagnostic" {
    try geometry_command.testing.parse(&.{
        "--request",
        "/retained/request.json",
        "--snapshot",
        "/retained/geometry.json",
    });
    try std.testing.expectError(
        error.InvalidArguments,
        geometry_command.testing.parse(&.{
            "--request",
            "/retained/request.json",
            "--proof",
            "/forbidden/proof.bin",
        }),
    );
}

test "pre-Engine geometry snapshot seals a canonical round trip" {
    try geometry_snapshot.testing.canonicalRoundTrip(std.testing.allocator);
}

test "Poseidon v4 product rejects unsafe Tree1 PCS residency before proving" {
    const orchestration = leaf_support.prover.guest_precompile
        .ethereum_segment_orchestration;
    const execution = leaf_support.executionOptions().cpu;
    try std.testing.expectEqual(
        @as(usize, 48 * 1024 * 1024 * 1024),
        leaf_support.product_host_byte_budget,
    );
    try std.testing.expectEqual(
        leaf_support.product_host_byte_budget,
        execution.host_byte_budget,
    );
    try std.testing.expectEqual(
        @import("stwo_prover_api").CpuCompositionContentionPolicy.strict,
        execution.contention_policy,
    );

    const unsafe_provider_logs = [_]u32{24} ** 445;
    try std.testing.expectError(
        error.PcsResidentBudgetExceeded,
        orchestration.requireTree1Residency(
            &unsafe_provider_logs,
            leaf_support.recursive_pcs_config.fri_config.log_blowup_factor,
            execution.host_byte_budget,
        ),
    );

    const sharded_provider_logs = [_]u32{20} ** 445;
    const accepted = try orchestration.requireTree1Residency(
        &sharded_provider_logs,
        leaf_support.recursive_pcs_config.fri_config.log_blowup_factor,
        execution.host_byte_budget,
    );
    try std.testing.expectEqual(@as(u64, 5_599_395_840), accepted.minimum_resident_bytes);
    try std.testing.expectEqual(
        orchestration.tree1_coefficient_retention_policy,
        accepted.retention_policy,
    );
}

test "compact Ethereum materialization manifest seals ordered leaf custody and timings" {
    const allocator = std.testing.allocator;
    const sha_a = [_]u8{0x11} ** 32;
    const sha_b = [_]u8{0x22} ** 32;
    const sha_c = [_]u8{0x33} ** 32;
    const identity_a = evidence.FileIdentity{
        .bytes = 12,
        .path = "/retained/a",
        .sha256 = sha_a,
    };
    const identity_b = evidence.FileIdentity{
        .bytes = 13,
        .path = "/retained/b",
        .sha256 = sha_b,
    };
    const artifacts = [_]compact_manifest.ArtifactInput{
        .{
            .artifact = identity_a,
            .capture_wall_ns = 1,
            .completion = null,
            .core_cycle_count = 8,
            .cycle_count = 10,
            .encode_wall_ns = 2,
            .entry_boundary = sha_a,
            .entry_cpu = sha_a,
            .entry_memory = sha_a,
            .exit_boundary = sha_b,
            .exit_cpu = sha_b,
            .exit_memory = sha_b,
            .global_first_cycle = 1,
            .keccak_calls = 1,
            .leaf_seal = sha_c,
            .publish_wall_ns = 3,
            .recovery_calls = 1,
            .segment_index = 0,
        },
        .{
            .artifact = identity_b,
            .capture_wall_ns = 4,
            .completion = .{
                .kind = 1,
                .address = 0x1000,
                .value = 1,
                .clock = 9,
            },
            .core_cycle_count = 7,
            .cycle_count = 9,
            .encode_wall_ns = 5,
            .entry_boundary = sha_b,
            .entry_cpu = sha_b,
            .entry_memory = sha_b,
            .exit_boundary = sha_c,
            .exit_cpu = sha_c,
            .exit_memory = sha_c,
            .global_first_cycle = 11,
            .keccak_calls = 2,
            .leaf_seal = sha_a,
            .publish_wall_ns = 6,
            .recovery_calls = 0,
            .segment_index = 1,
        },
    };
    const session = compact_manifest.sessionIdentity(
        sha_a,
        sha_b,
        sha_c,
        @import("stwo_riscv_frontend").isa.execution_profile.ethereum_semantic_digest,
        2,
        10,
    );
    const bytes = try compact_manifest.encode(allocator, .{
        .artifacts = &artifacts,
        .elf = identity_a,
        .execution_journal = identity_b,
        .execution_profile_abi_version = @import("stwo_riscv_frontend").isa
            .execution_profile.ethereum_abi_version,
        .execution_profile_receipt = identity_a,
        .execution_profile_semantic_sha256 = @import("stwo_riscv_frontend").isa
            .execution_profile.ethereum_semantic_digest,
        .expected_output = identity_b,
        .input = .{ .bytes = 0, .path = "/retained/input", .sha256 = sha_b },
        .materialization_result = identity_a,
        .materializer_executable_sha256 = sha_c,
        .program_sha256 = sha_a,
        .segment_step_budget = 10,
        .session_sha256 = session,
        .source_request = identity_b,
        .stage_timings = .{
            .capture_wall_ns = 5,
            .encode_wall_ns = 7,
            .observer_wall_ns = 40,
            .pc_attribution_wall_ns = 11,
            .post_execution_authority_wall_ns = 20,
            .publish_wall_ns = 9,
            .stream_observed_wall_ns = 100,
            .pre_manifest_materialization_wall_ns = 150,
        },
    });
    defer allocator.free(bytes);
    var parsed = try compact_manifest.parse(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.artifacts.len);
    try std.testing.expectEqual(@as(u64, 25), parsed.value.total_artifact_bytes);
    try std.testing.expectEqual(@as(u64, 19), parsed.value.total_cycles);
    try std.testing.expect(parsed.value.artifacts[0].completion == null);
    try std.testing.expectEqual(
        @as(u8, 1),
        parsed.value.artifacts[1].completion.?.kind,
    );

    const mutable_artifacts = @constCast(parsed.value.artifacts);
    const final_completion = mutable_artifacts[1].completion;
    mutable_artifacts[1].completion = null;
    try std.testing.expectError(
        error.InvalidCompactArtifactRecord,
        parsed.value.validate(),
    );
    mutable_artifacts[1].completion = final_completion;
    mutable_artifacts[0].completion = final_completion;
    try std.testing.expectError(
        error.InvalidCompactArtifactRecord,
        parsed.value.validate(),
    );
    mutable_artifacts[0].completion = null;

    const retained_entry_cpu = mutable_artifacts[1].entry_cpu_sha256;
    mutable_artifacts[1].entry_cpu_sha256 =
        mutable_artifacts[0].entry_cpu_sha256;
    try std.testing.expectError(
        error.InvalidCompactCpuContinuation,
        parsed.value.validate(),
    );
    mutable_artifacts[1].entry_cpu_sha256 = retained_entry_cpu;

    const artifact_sha = @constCast(parsed.value.artifacts[0].artifact.sha256);
    artifact_sha[0] = if (artifact_sha[0] == '0') '1' else '0';
    try std.testing.expectError(
        error.InvalidCompactArtifactChain,
        parsed.value.validate(),
    );
}

test "compact Ethereum parallel replay receipt seals ordered witness authorities" {
    const allocator = std.testing.allocator;
    const sha_a = [_]u8{0x11} ** 32;
    const sha_b = [_]u8{0x22} ** 32;
    const sha_c = [_]u8{0x33} ** 32;
    const file_a = evidence.FileIdentity{
        .bytes = 12,
        .path = "/retained/a",
        .sha256 = sha_a,
    };
    const file_b = evidence.FileIdentity{
        .bytes = 13,
        .path = "/retained/b",
        .sha256 = sha_b,
    };
    var leaves = [_]compact_replay_receipt.LeafAuthorityInput{
        .{
            .core_trace_rows = 8,
            .core_trace_sha256 = sha_a,
            .entry_cpu_sha256 = sha_a,
            .exit_cpu_sha256 = sha_b,
            .keccak_call_count = 1,
            .keccak_calls_sha256 = sha_b,
            .keccak_execution_rows = 1,
            .keccak_rows_sha256 = sha_c,
            .recovery_call_count = 1,
            .recovery_calls_sha256 = sha_c,
            .recovery_execution_rows = 1,
            .recovery_rows_sha256 = sha_a,
            .segment_index = 0,
            .state_chain_access_count = 20,
            .state_chain_memory_clock_updates = 2,
            .state_chain_register_clock_updates = 3,
            .state_chain_sha256 = sha_b,
            .touched_memory_sha256 = sha_c,
            .touched_memory_words = 4,
            .witness_sha256 = undefined,
        },
        .{
            .core_trace_rows = 7,
            .core_trace_sha256 = sha_b,
            .entry_cpu_sha256 = sha_b,
            .exit_cpu_sha256 = sha_c,
            .keccak_call_count = 2,
            .keccak_calls_sha256 = sha_c,
            .keccak_execution_rows = 2,
            .keccak_rows_sha256 = sha_a,
            .recovery_call_count = 0,
            .recovery_calls_sha256 = sha_a,
            .recovery_execution_rows = 0,
            .recovery_rows_sha256 = sha_b,
            .segment_index = 1,
            .state_chain_access_count = 21,
            .state_chain_memory_clock_updates = 4,
            .state_chain_register_clock_updates = 5,
            .state_chain_sha256 = sha_c,
            .touched_memory_sha256 = sha_a,
            .touched_memory_words = 6,
            .witness_sha256 = undefined,
        },
    };
    for (&leaves) |*leaf|
        leaf.witness_sha256 = compact_replay_receipt.witnessIdentity(leaf.*);
    const encoded = try compact_replay_receipt.encode(allocator, .{
        .artifact_chain_sha256 = sha_a,
        .artifacts_manifest = file_a,
        .elf = file_a,
        .execution_journal = file_b,
        .execution_profile_abi_version = @import("stwo_riscv_frontend").isa
            .execution_profile.ethereum_abi_version,
        .execution_profile_receipt = file_a,
        .execution_profile_semantic_sha256 = @import("stwo_riscv_frontend").isa
            .execution_profile.ethereum_semantic_digest,
        .expected_output = file_b,
        .input = .{ .bytes = 0, .path = "/retained/input", .sha256 = sha_b },
        .leaf_authorities = &leaves,
        .manifest_content_sha256 = sha_b,
        .materialization_result = file_a,
        .program_sha256 = sha_c,
        .replay_executable = file_b,
        .replay_receipt = .{
            .admitted_workers = 2,
            .core_cycles = 15,
            .keccak_calls = 3,
            .leaf_count = 2,
            .recovery_calls = 1,
            .total_cycles = 19,
        },
        .replay_timing = .{ .wall_ns = 10, .user_ns = 11, .system_ns = 12 },
        .requested_workers = 4,
        .segment_step_budget = 10,
        .session_sha256 = sha_c,
        .source_request = file_b,
    });
    defer allocator.free(encoded);
    var parsed = try compact_replay_receipt.parse(allocator, encoded);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.leaf_authorities.len);
    try std.testing.expectEqual(@as(u16, 2), parsed.value.replay_receipt.admitted_workers);

    const mutable_leaves = @constCast(parsed.value.leaf_authorities);
    mutable_leaves[1].segment_index = 0;
    try std.testing.expectError(
        error.InvalidReplayLeafAuthority,
        parsed.value.validate(),
    );
    mutable_leaves[1].segment_index = 1;
    const witness = @constCast(mutable_leaves[1].witness_sha256);
    witness[0] = if (witness[0] == '0') '1' else '0';
    try std.testing.expectError(
        error.InvalidReplayWitnessIdentity,
        parsed.value.validate(),
    );
}

test "compact tape materializer options are additive and paired" {
    const base = [_][]const u8{
        "--elf",                 "/retained/elf",
        "--expected-output",     "/retained/output",
        "--input",               "/retained/input",
        "--journal",             "/retained/journal",
        "--proof-profile",       leaf_contract.recursive_proof_profile_name,
        "--result",              "/retained/result",
        "--segment-count",       "2",
        "--segment-step-budget", "10",
        "--source-request",      "/retained/source",
        "--source-root",         "/retained/sources",
    };
    _ = try materializer_options.Options.parse(&base);
    const full = base ++ [_][]const u8{
        "--execution-profile-receipt",
        "/retained/profile",
        "--compact-tape-root",
        "/retained/tapes",
        "--compact-tape-manifest",
        "/retained/tapes.json",
    };
    const parsed = try materializer_options.Options.parse(&full);
    try std.testing.expectEqualStrings(
        "/retained/tapes",
        parsed.compact_tape_root.?,
    );
    const incomplete = base ++ [_][]const u8{
        "--execution-profile-receipt",
        "/retained/profile",
        "--compact-tape-root",
        "/retained/tapes",
    };
    try std.testing.expectError(
        error.InvalidArguments,
        materializer_options.Options.parse(&incomplete),
    );
}

test "fresh verifier ProgramV2 instance binds program root and capture" {
    const air = [_]u8{0x11} ** 32;
    const verifier_program = [_]u8{0x22} ** 32;
    const tree0 = [_]u32{0x3333_3333} ** 8;
    const proof_capture = [_]u8{0x44} ** 32;
    const capture = [_]u8{0x55} ** 32;
    const expected = leaf_support.testing.freshProgramInstanceSha256(
        air,
        verifier_program,
        tree0,
        proof_capture,
        capture,
    );

    var changed_air = air;
    changed_air[0] ^= 1;
    var changed_program = verifier_program;
    changed_program[0] ^= 1;
    var changed_tree0 = tree0;
    changed_tree0[0] ^= 1;
    var changed_proof = proof_capture;
    changed_proof[0] ^= 1;
    var changed_capture = capture;
    changed_capture[0] ^= 1;
    inline for (.{
        leaf_support.testing.freshProgramInstanceSha256(
            changed_air,
            verifier_program,
            tree0,
            proof_capture,
            capture,
        ),
        leaf_support.testing.freshProgramInstanceSha256(
            air,
            changed_program,
            tree0,
            proof_capture,
            capture,
        ),
        leaf_support.testing.freshProgramInstanceSha256(
            air,
            verifier_program,
            changed_tree0,
            proof_capture,
            capture,
        ),
        leaf_support.testing.freshProgramInstanceSha256(
            air,
            verifier_program,
            tree0,
            changed_proof,
            capture,
        ),
        leaf_support.testing.freshProgramInstanceSha256(
            air,
            verifier_program,
            tree0,
            proof_capture,
            changed_capture,
        ),
    }) |mutated| try std.testing.expect(!std.mem.eql(u8, &expected, &mutated));
}

test "Ethereum guest PC profile resolves exact ELF functions and native calls" {
    const allocator = std.testing.allocator;
    var elf = @import("stwo_riscv_frontend").testing
        .guest_precompile_test_elf.buildEthereum();
    const symbol_strings = "\x00__text_start\x00__text_len\x00";
    const function_name = "guest_main\x00";
    @memcpy(
        elf[480 + symbol_strings.len ..][0..function_name.len],
        function_name,
    );
    put(u32, &elf, 308, symbol_strings.len + function_name.len);
    put(u32, &elf, 268, 4 * 16);
    const function_symbol = 560 + 3 * 16;
    put(u32, &elf, function_symbol, symbol_strings.len);
    put(u32, &elf, function_symbol + 4, 0x1000);
    put(u32, &elf, function_symbol + 8, 24);
    elf[function_symbol + 12] = 0x12;
    put(u16, &elf, function_symbol + 14, 1);

    var profiler = try guest_pc_profile.Profiler.init(allocator, &elf);
    defer profiler.deinit();
    for (0..5) |_| try profiler.observeCorePc(0x1000);
    for (0..2) |_| try profiler.observeCorePc(0x1004);
    try profiler.observeCorePc(0x2000);
    const keccak = [_]struct { pc: u32 }{.{ .pc = 0x1008 }};
    try profiler.observeExternalRecords(.keccakf, &keccak, 24);
    const recovery = [_]struct { pc: u32 }{
        .{ .pc = 0x1008 },
        .{ .pc = 0x2000 },
    };
    try profiler.observeExternalRecords(.secp256k1_recover, &recovery, 2);

    const identity_bytes = "retained-authority";
    const identity_value = evidence.identity(
        "/retained/authority.bin",
        identity_bytes,
    );
    const bytes = try profiler.encodeReceipt(allocator, .{
        .elf = identity_value,
        .execution_journal = identity_value,
        .materialization_result = identity_value,
        .source_request = identity_value,
    });
    defer allocator.free(bytes);
    var parsed = try guest_pc_profile.parseReceipt(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u64, 8), parsed.value.core_rows);
    try std.testing.expectEqual(@as(u64, 3), parsed.value.external_calls);
    try std.testing.expectEqual(@as(u64, 26), parsed.value.external_execution_rows);
    try std.testing.expectEqual(@as(u64, 7), parsed.value.attributed_core_rows);
    try std.testing.expectEqual(@as(u64, 2), parsed.value.attributed_external_calls);
    try std.testing.expectEqualStrings(
        "guest_main",
        parsed.value.top_functions[0].name,
    );
    try std.testing.expectEqual(@as(u64, 9), parsed.value.top_functions[0].total_retirements);
    try std.testing.expectEqual(@as(u32, 0x1000), parsed.value.top_pcs[0].pc);
}

test "Poseidon v4 proof profile receipt is additive sealed evidence" {
    const allocator = std.testing.allocator;
    const sha = [_]u8{'a'} ** 64;
    var stages = [_]@import("stwo_prover_api").stage_profile.StageNode{.{
        .id = "prove",
        .label = "Prove",
        .seconds = 1.0,
    }};
    var base_components = [_]profile_receipt.BaseComponent{.{
        .active = true,
        .claimed_sum_count = 1,
        .claimed_sum_offset = 0,
        .composition_log_split = 1,
        .constraint_count = 1,
        .interaction = .{
            .declared_columns = 1,
            .offset = 0,
            .sampled_columns = 1,
        },
        .interaction_batch_count = 1,
        .kind = "load_store",
        .log_size = 1,
        .main = .{
            .declared_columns = 1,
            .offset = 0,
            .sampled_columns = 1,
        },
        .max_constraint_log_degree_bound = 2,
        .n_rows = 1,
        .physical_index = 0,
        .preprocessed = .{
            .declared_columns = 1,
            .offset = 0,
            .sampled_columns = 1,
        },
        .relation_event_count = 1,
        .role = "opcode_lookup",
        .shard_ordinal = 0,
    }};
    var extension_components =
        [_]profile_receipt.ExtensionComponent{.{
            .direct_constraint_count = 1,
            .interaction_batch_count = 1,
            .interaction_columns = 1,
            .interaction_offset = 1,
            .kind = "keccak_caller",
            .log_size = 1,
            .main_columns = 1,
            .main_offset = 1,
            .n_rows = 0,
            .preprocessed_columns = 1,
            .preprocessed_offset = 1,
        }} ** 14;
    const execution_policy = try profile_receipt.executionPolicy(
        leaf_support.worker_count,
        leaf_support.product_host_byte_budget,
    );
    const bytes = try profile_receipt.encode(allocator, .{
        .base_geometry = .{
            .air_instruction_count = 1,
            .claimed_sum_count = 1,
            .component_count = 1,
            .components = &base_components,
            .composition_log_degree_bound = 2,
            .composition_log_split = 1,
            .interaction_column_count = 1,
            .lookup_activation_sha256 = &sha,
            .lookup_manifest_sha256 = &sha,
            .lookup_statement_sha256 = &sha,
            .main_column_count = 1,
            .max_log_degree_bound = 1,
            .preprocessed_column_count = 1,
            .profile_sha256 = &sha,
            .relation_challenge_count = 1,
            .sampled_value_count = 1,
            .transcript_claimed_sum_count = 1,
        },
        .execution_policy = execution_policy,
        .extension_geometry = .{
            .claim_sha256 = &sha,
            .component_count = 14,
            .components = &extension_components,
            .context_sha256 = &sha,
            .full_component_count = 15,
            .statement_sha256 = &sha,
        },
        .producer_result = fixedIdentity("/retained/result.json", &sha),
        .producer_sha256 = &sha,
        .proof = fixedIdentity("/retained/proof.stw", &sha),
        .prove_timing = .{ .system_ns = 1, .user_ns = 2, .wall_ns = 3 },
        .request = fixedIdentity("/retained/request.json", &sha),
        .request_content_sha256 = &sha,
        .segment_index = 7,
        .stage_profile = .{
            .runtime = profile_receipt.runtime,
            .example = profile_receipt.example,
            .stages = &stages,
        },
        .task_profile = .{
            .runtime = profile_receipt.runtime,
            .example = profile_receipt.example,
            .graphs = &.{},
        },
        .work_complete_exact = false,
        .work_profile = @import("stwo_prover_api").work_profile.Profile
            .unavailable(),
    });
    defer allocator.free(bytes);
    var parsed = try profile_receipt.parse(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u32, 8), parsed.value.execution_policy.worker_count);
    try std.testing.expectEqual(
        @as(u64, @intCast(leaf_support.product_host_byte_budget)),
        parsed.value.execution_policy.host_byte_budget,
    );
    try std.testing.expect(!parsed.value.execution_policy.host_byte_budget_unbounded);
    try std.testing.expectEqual(@as(usize, 14), parsed.value.extension_geometry.components.len);

    const mutated = try allocator.dupe(u8, bytes);
    defer allocator.free(mutated);
    const prefix = "{\"content_sha256\":\"";
    mutated[prefix.len] = if (mutated[prefix.len] == '0') '1' else '0';
    try std.testing.expectError(
        error.InvalidContentSha256,
        profile_receipt.parse(allocator, mutated),
    );

    try std.testing.expect(!(try producer.testing.parseHasProfileReceipt(&.{
        "--proof",   "/retained/proof.stw",
        "--request", "/retained/request.json",
        "--result",  "/retained/result.json",
    })));
    try std.testing.expect(try producer.testing.parseHasProfileReceipt(&.{
        "--profile-receipt", "/retained/profile.json",
        "--proof",           "/retained/proof.stw",
        "--request",         "/retained/request.json",
        "--result",          "/retained/result.json",
    }));
}

test "Poseidon v4 verifier timing receipt binds exact retained custody" {
    const allocator = std.testing.allocator;
    const sha = [_]u8{'a'} ** 64;
    const zero_m31 = [_]u8{'0'} ** 64;
    const request_bytes = try contract.encodeRequest(allocator, .{
        .expected_recursive_statement_sha256 = &sha,
        .expected_source_public_statement_sha256 = &sha,
        .producer_sha256 = &sha,
        .segment_index = 7,
        .session_id = &sha,
        .source_request = .{
            .bytes = 1,
            .path = "/retained/source-v2.json",
            .schema = leaf_contract.recursive_source_schema,
            .sha256 = &sha,
        },
        .source_segment = fixedIdentity(
            "/retained/segment-000007.stwesg31",
            &sha,
        ),
        .verifier_sha256 = &sha,
    });
    defer allocator.free(request_bytes);
    var parsed_request = try contract.parseRequest(allocator, request_bytes);
    defer parsed_request.deinit();

    const proof_bytes = "canonical-proof";
    const proof_sha = shaHex(proof_bytes);
    const result_bytes = try contract.encodeVerifierResult(allocator, .{
        .proof_bytes = proof_bytes.len,
        .proof_sha256 = &proof_sha,
        .recursive_statement_sha256 = &sha,
        .request_sha256 = parsed_request.value.content_sha256,
        .root_sha256 = &sha,
        .security_identity_sha256 = &sha,
        .segment_index = 7,
        .source_public_statement_sha256 = &sha,
        .transcript_state_sha256 = &sha,
        .verified_capture_sha256 = &sha,
        .verified_link_id_m31_le = &zero_m31,
        .verifier_sha256 = &sha,
    });
    defer allocator.free(result_bytes);
    var result = try contract.parseVerifierResult(allocator, result_bytes);
    defer result.deinit();

    const request_sha = shaHex(request_bytes);
    const result_sha = shaHex(result_bytes);
    const request_identity = fixedIdentity(
        "/retained/request.json",
        &request_sha,
    );
    const proof_identity = leaf_contract.Identity{
        .bytes = proof_bytes.len,
        .path = "/retained/proof.stw",
        .sha256 = &proof_sha,
    };
    const result_identity = leaf_contract.Identity{
        .bytes = result_bytes.len,
        .path = "/retained/verifier-result.json",
        .sha256 = &result_sha,
    };
    const receipt_bytes = try contract.encodeVerifierTimingReceipt(
        allocator,
        .{
            .proof = proof_identity,
            .request = .{
                .bytes = request_bytes.len,
                .path = request_identity.path,
                .sha256 = request_identity.sha256,
            },
            .request_content_sha256 = parsed_request.value.content_sha256,
            .segment_index = 7,
            .verifier_result = result_identity,
            .verifier_sha256 = &sha,
            .verify_timing = .{
                .system_ns = 11,
                .user_ns = 22,
                .wall_ns = 33,
            },
        },
    );
    defer allocator.free(receipt_bytes);
    var receipt = try contract.parseVerifierTimingReceipt(
        allocator,
        receipt_bytes,
    );
    defer receipt.deinit();
    try receipt.value.validateAgainst(
        parsed_request.value,
        result.value,
        .{
            .bytes = request_bytes.len,
            .path = request_identity.path,
            .sha256 = request_identity.sha256,
        },
        proof_identity,
        result_identity,
    );
    try std.testing.expectEqual(
        contract.VerifierEvidenceStatus.complete,
        try contract.verifierEvidenceStatus(true, true),
    );
    try std.testing.expectEqual(
        contract.VerifierEvidenceStatus.nonpromotable_missing_verifier_timing,
        try contract.verifierEvidenceStatus(true, false),
    );
    try std.testing.expectError(
        error.OrphanVerifierTimingReceipt,
        contract.verifierEvidenceStatus(false, true),
    );

    var wrong_proof = proof_identity;
    wrong_proof.sha256 = &sha;
    try std.testing.expectError(
        error.VerifierTimingCustodyMismatch,
        receipt.value.validateAgainst(
            parsed_request.value,
            result.value,
            .{
                .bytes = request_bytes.len,
                .path = request_identity.path,
                .sha256 = request_identity.sha256,
            },
            wrong_proof,
            result_identity,
        ),
    );
    const mutated = try allocator.dupe(u8, receipt_bytes);
    defer allocator.free(mutated);
    const content_prefix = "{\"content_sha256\":\"";
    mutated[content_prefix.len] = if (mutated[content_prefix.len] == '0')
        '1'
    else
        '0';
    try std.testing.expectError(
        error.InvalidContentSha256,
        contract.parseVerifierTimingReceipt(allocator, mutated),
    );
    try std.testing.expectError(
        error.VerifierTimingReceiptMismatch,
        contract.encodeVerifierTimingReceipt(allocator, .{
            .proof = proof_identity,
            .request = .{
                .bytes = request_bytes.len,
                .path = request_identity.path,
                .sha256 = request_identity.sha256,
            },
            .request_content_sha256 = parsed_request.value.content_sha256,
            .segment_index = 7,
            .timing_scope = "wrong-verification-scope",
            .verifier_result = result_identity,
            .verifier_sha256 = &sha,
            .verify_timing = .{ .system_ns = 0, .user_ns = 0, .wall_ns = 33 },
        }),
    );
    try std.testing.expectError(
        error.VerifierTimingReceiptMismatch,
        contract.encodeVerifierTimingReceipt(allocator, .{
            .proof = proof_identity,
            .request = .{
                .bytes = request_bytes.len,
                .path = request_identity.path,
                .sha256 = request_identity.sha256,
            },
            .request_content_sha256 = parsed_request.value.content_sha256,
            .segment_index = 7,
            .verifier_result = result_identity,
            .verifier_sha256 = &sha,
            .verify_timing = .{ .system_ns = 0, .user_ns = 0, .wall_ns = 0 },
        }),
    );
}

test "Poseidon v4 verifier V1 bytes and default CLI remain frozen" {
    const allocator = std.testing.allocator;
    const sha = [_]u8{'a'} ** 64;
    const zero_m31 = [_]u8{'0'} ** 64;
    const bytes = try contract.encodeVerifierResult(allocator, .{
        .proof_bytes = 1,
        .proof_sha256 = &sha,
        .recursive_statement_sha256 = &sha,
        .request_sha256 = &sha,
        .root_sha256 = &sha,
        .security_identity_sha256 = &sha,
        .segment_index = 0,
        .source_public_statement_sha256 = &sha,
        .transcript_state_sha256 = &sha,
        .verified_capture_sha256 = &sha,
        .verified_link_id_m31_le = &zero_m31,
        .verifier_sha256 = &sha,
    });
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 1228), bytes.len);
    const digest = shaHex(bytes);
    try std.testing.expectEqualStrings(
        "a292b25c2a793dd814083944922d0e21f737e4f239d73e354652081cf7162756",
        &digest,
    );
    try std.testing.expect(!(try verifier.testing.parseHasTimingReceipt(&.{
        "--proof",   "/retained/proof.stw",
        "--request", "/retained/request.json",
        "--result",  "/retained/result.json",
    })));
    try std.testing.expect(try verifier.testing.parseHasTimingReceipt(&.{
        "--proof",          "/retained/proof.stw",
        "--request",        "/retained/request.json",
        "--result",         "/retained/result.json",
        "--timing-receipt", "/retained/timing.json",
    }));
}

test "Poseidon v4 timing publication is create-only and partial is nonpromotable" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const result = try std.fs.path.join(allocator, &.{ root, "result.json" });
    defer allocator.free(result);
    const receipt = try std.fs.path.join(allocator, &.{ root, "timing.json" });
    defer allocator.free(receipt);
    try verifier.testing.publishPair(result, "v1-result\n", receipt, "timing\n");
    const retained_result = try artifact_io.readFileBounded(allocator, result, 32);
    defer allocator.free(retained_result);
    const retained_receipt = try artifact_io.readFileBounded(allocator, receipt, 32);
    defer allocator.free(retained_receipt);
    try std.testing.expectEqualStrings("v1-result\n", retained_result);
    try std.testing.expectEqualStrings("timing\n", retained_receipt);
    try std.testing.expectError(
        error.PathAlreadyExists,
        verifier.testing.publishPair(result, "replacement\n", null, null),
    );

    const partial_result = try std.fs.path.join(
        allocator,
        &.{ root, "partial-result.json" },
    );
    defer allocator.free(partial_result);
    const missing_receipt = try std.fs.path.join(
        allocator,
        &.{ root, "missing-parent", "timing.json" },
    );
    defer allocator.free(missing_receipt);
    try std.testing.expectError(
        error.FileNotFound,
        verifier.testing.publishPair(
            partial_result,
            "valid-v1\n",
            missing_receipt,
            "timing\n",
        ),
    );
    const retained_partial = try artifact_io.readFileBounded(
        allocator,
        partial_result,
        32,
    );
    defer allocator.free(retained_partial);
    try std.testing.expectEqualStrings("valid-v1\n", retained_partial);
    try expectAbsent(missing_receipt);
    try std.testing.expectEqual(
        contract.VerifierEvidenceStatus.nonpromotable_missing_verifier_timing,
        try contract.verifierEvidenceStatus(true, false),
    );

    try temporary.dir.symLink("result.json", "timing-link", .{});
    const symlink_result = try std.fs.path.join(
        allocator,
        &.{ root, "symlink-result.json" },
    );
    defer allocator.free(symlink_result);
    const symlink_receipt = try std.fs.path.join(
        allocator,
        &.{ root, "timing-link" },
    );
    defer allocator.free(symlink_receipt);
    if (verifier.testing.publishPair(
        symlink_result,
        "valid-v1\n",
        symlink_receipt,
        "forbidden\n",
    )) |_| {
        return error.SymlinkWasAccepted;
    } else |_| {}
    const original = try artifact_io.readFileBounded(allocator, result, 32);
    defer allocator.free(original);
    try std.testing.expectEqualStrings("v1-result\n", original);
}

test "Poseidon v4 timer failure precedes every publication" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const result = try std.fs.path.join(allocator, &.{ root, "result.json" });
    defer allocator.free(result);
    const receipt = try std.fs.path.join(allocator, &.{ root, "timing.json" });
    defer allocator.free(receipt);
    var clock = FailingClock{};
    try std.testing.expectError(
        error.ProcessClockRegressed,
        verifier.testing.finishThenPublish(
            &clock,
            result,
            "must-not-publish\n",
            receipt,
            "must-not-publish\n",
        ),
    );
    try expectAbsent(result);
    try expectAbsent(receipt);
}

const FailingClock = struct {
    pub fn finish(_: *@This()) error{ProcessClockRegressed}!evidence.Timing {
        return error.ProcessClockRegressed;
    }
};

fn fixedIdentity(path: []const u8, sha256: []const u8) leaf_contract.Identity {
    return .{ .bytes = 1, .path = path, .sha256 = sha256 };
}

fn shaHex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn expectAbsent(path: []const u8) !void {
    if (std.fs.openFileAbsolute(path, .{})) |file| {
        file.close();
        return error.UnexpectedPublication;
    } else |err| try std.testing.expectEqual(error.FileNotFound, err);
}

fn put(comptime T: type, bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], @intCast(value), .little);
}
