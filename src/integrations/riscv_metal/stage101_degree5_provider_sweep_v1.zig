//! Retained Stage101 degree-five provider throughput experiment.
//!
//! This command is deliberately not a complete leaf proof and is not a
//! production route. It cold-opens the sealed V4 campaign through the normal
//! Stage101 replay command, borrows the exact prepared Poseidon call list,
//! proves its ordered D5 shards with the authenticated-AOT recursion Metal
//! engine, destroys producer proofs after canonical encoding, and freshly
//! decodes/verifies every shard with the CPU recursion engine.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const metal = @import("stwo_metal_backend");
const cpu = @import("stwo_riscv_cpu_stage101_degree5_metal");

const aot = @import("aot_bundle_admission.zig");
const artifact_io = cpu.ethereum_precompile_artifact_io;
const replay_command = cpu.ethereum_incremental_full_leaf_replay_command_v4;
const execution_mod = cpu.ethereum_candidate_degree5_provider_batch_execution_v1;
const prepared_batch = cpu.ethereum_candidate_degree5_provider_prepared_batch_v1;
const order_batch = cpu.ethereum_candidate_degree5_provider_order_batch_v1;
const throughput = cpu.ethereum_incremental_full_leaf_throughput_execution_v1;

const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider =
    frontend.testing.narrow_memory_provider_degree5_order_proof_v2;
const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVE = false;
pub const COMPLETE_LEAF_PROOF = false;
pub const command_name = "stage101-degree5-provider-sweep-v1";
pub const expected_segment_index: u32 = 1;
pub const expected_incremental_memory_call_count: u64 = 3_784_119;
pub const expected_elf_byte_count: u64 = 3_352_364;
pub const expected_elf_sha256 = hexDigest(
    "b751305c0e350918a4a1e692fcfd620a54f5bce6c50322230e156faca95328fa",
);
pub const expected_program_base: u32 = 0x400;
pub const expected_program_end: u32 = 0x2c11fc;
pub const expected_declared_program_word_count: u64 = 721_791;
pub const expected_committed_program_word_count: u64 = 721_791;
pub const expected_program_leaf_count: u64 = 2_887_164;
pub const expected_program_call_count: u64 = contiguousTreeNodeCount(
    expected_program_base,
    expected_program_leaf_count,
    sparse_merkle.LEAF_DEPTH,
);
pub const expected_full_call_count: u64 =
    expected_program_call_count + expected_incremental_memory_call_count;
pub const expected_reference_byte_count: u64 = 240;
pub const expected_reference_sha256 = hexDigest(
    "3220855bccc805bf9a9846aa5c3f3286cacafe26cdc38c6144e5f6c53fb88724",
);
pub const expected_payload_byte_count: u64 = 48_058_224;
pub const expected_payload_sha256 = hexDigest(
    "0d0272475946a4bd668d52e2e3b178806ea07df391344031855e5893285134bd",
);
pub const expected_manifest_sha256 = hexDigest(
    "996f039fa10092a5de3dc01b983208366123a8d9c232999130d136751563320d",
);
pub const expected_metallib_sha256 = hexDigest(
    "2def25929db324acd76bb5fc4f480977eae6651798b40284f5f027de64961d3e",
);
pub const expected_source_sha256 = hexDigest(
    "be2525ebfad6b8d9eef947507cb34196cedc1fdc6a4d7ab6d8da6ba3e2afe56b",
);
pub const expected_air_sha256 = hexDigest(
    "634eca518912f29699578303d308eb42a007e3dcdc5af960754589f9735aafb8",
);
pub const expected_native_export_count: u32 = 164;

pub const MetalEngine = frontend.recursion.engine.ProverEngineForBackend(
    metal.MetalCommitBackend,
);
pub const CpuVerifierEngine = replay_command.CpuEngine;

pub const EnvironmentV1 = struct {
    bundle_path: []const u8,
    shard_log_size: u32,
    concurrent_owners: usize,
    engine_workers_per_owner: usize,
    total_host_byte_budget: u64,
    host_byte_limit: usize,
    controller_reserve_bytes: u64,
    non_column_reserve_per_owner: u64,
};

pub const TelemetryReceiptV1 = struct {
    metal_dispatch_total: u64,
    cpu_fallback_total: u64,
    resident_merkle_commits: u64,
    poseidon_merkle_commits: u64,
    sampled_value_dispatches: u64,
    quotient_dispatches: u64,
    circle_transform_dispatches: u64,
    circle_lde_dispatches: u64,
    fri_circle_dispatches: u64,
    fri_line_dispatches: u64,
    base_eligible_components: u64,
    lookup_eligible_components: u64,
    base_batch_dispatches: u64,
    lookup_batch_dispatches: u64,
    polynomial_declines: u64,
    host_merkle_commits: u64,
    cpu_small_merkle_commits: u64,
    cpu_streaming_merkle_commits: u64,
    cpu_sampled_value_evaluations: u64,
    cpu_small_circle_interpolations: u64,
    cpu_small_circle_evaluations: u64,
    cpu_small_circle_ldes: u64,
    cpu_composition_evaluations: u64,
};

pub const ReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema: []const u8 = "stwo.stage101.degree5-provider-sweep.v1",
    production_active: bool = PRODUCTION_ACTIVE,
    complete_leaf_proof: bool = COMPLETE_LEAF_PROOF,
    build_mode: []const u8,
    segment_index: u32,
    elf_byte_count: u64,
    elf_sha256: [32]u8,
    program_source_identity_sha256: [32]u8,
    stwipr04_reference_byte_count: u64,
    stwipr04_reference_sha256: [32]u8,
    stwipw04_payload_byte_count: u64,
    stwipw04_payload_sha256: [32]u8,
    retained_source_byte_count: u64,
    retained_source_sha256: [32]u8,
    prepared_source_identity_sha256: [32]u8,
    prepared_profile_identity_sha256: [32]u8,
    program_base: u32,
    program_end: u32,
    declared_program_word_count: u64,
    committed_program_word_count: u64,
    program_leaf_count: u64,
    program_call_count: u64,
    program_commitment_root: u32,
    incremental_memory_call_count: u64,
    call_count: u64,
    ordered_call_commitment: [32]u8,
    topology: execution_mod.TopologyReceiptV1,
    aot_manifest_sha256: [32]u8 = expected_manifest_sha256,
    aot_metallib_sha256: [32]u8 = expected_metallib_sha256,
    aot_source_sha256: [32]u8 = expected_source_sha256,
    aot_air_sha256: [32]u8 = expected_air_sha256,
    aot_native_export_count: u32 = expected_native_export_count,
    backend_identity_sha256: [32]u8,
    pow_bits: u32,
    query_count: u32,
    fri_log_blowup_factor: u32,
    quotient_expansion_bits: u32,
    producer_proofs_destroyed_before_cpu_decode: bool,
    cpu_fresh_verified: bool,
    ordered_call_air_verified_count: u32,
    ordered_call_claim_recomputed_count: u32,
    relation_context_intentionally_unshared_count: u32,
    plan_construction_full_validations: u8,
    producer_call_authority_full_validations: u8,
    fresh_call_authority_full_validations: u8,
    internal_full_call_revalidations: u8,
    producer_call_authority_fast_checks: u64,
    fresh_call_authority_fast_checks: u64,
    legacy_internal_full_call_revalidations_avoided: u64,
    proof_count: u32,
    total_canonical_proof_bytes: u64,
    ordered_proof_identity_sha256: [32]u8,
    ordered_fresh_identity_sha256: [32]u8,
    runtime_initialization_ns: u64,
    input_admission_ns: u64,
    compact_replay_ns: u64,
    snapshot_ns: u64,
    witness_prepare_ns: u64,
    statement_profile_prepare_ns: u64,
    source_preparation_resources: throughput.ResourceReceiptV1,
    stage_a_resources: throughput.ResourceReceiptV1,
    metal_prove_resources: throughput.ResourceReceiptV1,
    cpu_fresh_verify_resources: throughput.ResourceReceiptV1,
    total_resources: throughput.ResourceReceiptV1,
    telemetry: TelemetryReceiptV1,
    validation_identity_sha256: [32]u8,

    pub fn validate(self: ReceiptV1, allocator: std.mem.Allocator) !void {
        try requireFirstArm(self.topology);
        try self.source_preparation_resources.validate();
        try self.stage_a_resources.validate();
        try self.metal_prove_resources.validate();
        try self.cpu_fresh_verify_resources.validate();
        try self.total_resources.validate();
        const recomposed_call_count = std.math.add(
            u64,
            self.program_call_count,
            self.incremental_memory_call_count,
        ) catch return error.InvalidStage101Degree5ProviderSweepReceipt;
        const observed_fast_checks = std.math.add(
            u64,
            self.producer_call_authority_fast_checks,
            self.fresh_call_authority_fast_checks,
        ) catch return error.InvalidStage101Degree5ProviderSweepReceipt;
        if (self.format_version != FORMAT_VERSION or
            !std.mem.eql(u8, self.schema, "stwo.stage101.degree5-provider-sweep.v1") or
            self.production_active or self.complete_leaf_proof or
            !std.mem.eql(u8, self.build_mode, "ReleaseFast") or
            self.segment_index != expected_segment_index or
            self.elf_byte_count != expected_elf_byte_count or
            !std.mem.eql(u8, &self.elf_sha256, &expected_elf_sha256) or
            std.mem.allEqual(u8, &self.program_source_identity_sha256, 0) or
            self.stwipr04_reference_byte_count != expected_reference_byte_count or
            !std.mem.eql(
                u8,
                &self.stwipr04_reference_sha256,
                &expected_reference_sha256,
            ) or
            self.stwipw04_payload_byte_count != expected_payload_byte_count or
            !std.mem.eql(
                u8,
                &self.stwipw04_payload_sha256,
                &expected_payload_sha256,
            ) or self.retained_source_byte_count == 0 or
            std.mem.allEqual(u8, &self.retained_source_sha256, 0) or
            std.mem.allEqual(u8, &self.prepared_source_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.prepared_profile_identity_sha256, 0) or
            self.program_base != expected_program_base or
            self.program_end != expected_program_end or
            self.declared_program_word_count !=
                expected_declared_program_word_count or
            self.committed_program_word_count !=
                expected_committed_program_word_count or
            self.program_leaf_count != expected_program_leaf_count or
            self.program_call_count != expected_program_call_count or
            self.incremental_memory_call_count !=
                expected_incremental_memory_call_count or
            self.call_count != expected_full_call_count or
            self.call_count != recomposed_call_count or
            self.call_count != self.topology.total_call_count or
            std.mem.allEqual(u8, &self.ordered_call_commitment, 0) or
            self.pow_bits != execution_mod.Q193_POW_BITS or
            self.query_count != execution_mod.Q193_QUERY_COUNT or
            self.query_count != 193 or
            self.fri_log_blowup_factor !=
                execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR or
            self.quotient_expansion_bits !=
                execution_mod.D5_QUOTIENT_EXPANSION_BITS or
            !self.producer_proofs_destroyed_before_cpu_decode or
            !self.cpu_fresh_verified or self.proof_count == 0 or
            self.proof_count != self.topology.shard_count or
            self.ordered_call_air_verified_count != self.proof_count or
            self.ordered_call_claim_recomputed_count != self.proof_count or
            self.relation_context_intentionally_unshared_count != self.proof_count or
            self.plan_construction_full_validations != 1 or
            self.producer_call_authority_full_validations != 1 or
            self.fresh_call_authority_full_validations != 1 or
            self.internal_full_call_revalidations != 0 or
            self.producer_call_authority_fast_checks !=
                expectedProducerFastChecks(self.proof_count) or
            self.fresh_call_authority_fast_checks !=
                expectedFreshFastChecks(self.proof_count) or
            self.legacy_internal_full_call_revalidations_avoided !=
                observed_fast_checks or
            self.total_canonical_proof_bytes == 0 or
            self.total_canonical_proof_bytes >
                self.topology.encoded_proof_reservation_bytes or
            self.telemetry.cpu_fallback_total != 0 or
            self.telemetry.metal_dispatch_total == 0 or
            self.telemetry.base_eligible_components != 4 * self.proof_count or
            self.telemetry.lookup_eligible_components != self.proof_count or
            self.telemetry.base_batch_dispatches != self.proof_count or
            self.telemetry.lookup_batch_dispatches != self.proof_count or
            self.telemetry.polynomial_declines != 0 or
            !std.mem.eql(
                u8,
                &self.aot_manifest_sha256,
                &expected_manifest_sha256,
            ) or !std.mem.eql(
            u8,
            &self.aot_metallib_sha256,
            &expected_metallib_sha256,
        ) or !std.mem.eql(
            u8,
            &self.aot_source_sha256,
            &expected_source_sha256,
        ) or !std.mem.eql(
            u8,
            &self.aot_air_sha256,
            &expected_air_sha256,
        ) or self.aot_native_export_count != expected_native_export_count or
            !std.mem.eql(
                u8,
                &self.backend_identity_sha256,
                &backendIdentity(),
            )) return error.InvalidStage101Degree5ProviderSweepReceipt;
        var unsigned = self;
        unsigned.validation_identity_sha256 = [_]u8{0} ** 32;
        const canonical = try std.json.Stringify.valueAlloc(
            allocator,
            unsigned,
            .{},
        );
        defer allocator.free(canonical);
        if (!std.mem.eql(
            u8,
            &self.validation_identity_sha256,
            &sha256(canonical),
        )) return error.InvalidStage101Degree5ProviderSweepReceipt;
    }
};

const StateV1 = struct {
    allocator: std.mem.Allocator,
    output_path: []const u8,
    environment: EnvironmentV1,
    runtime_initialization_ns: u64,
    lifecycle_before: metal.MetalCommitBackend.RuntimeLifecycleSnapshot,
    telemetry_before: metal.MetalCommitBackend.TelemetrySnapshot,
    source_measurement: throughput.MeasurementV1,
    total_measurement: throughput.MeasurementV1,

    fn visitOpaque(
        context: *anyopaque,
        custody: replay_command.PreparedVisitorCustodyV1,
        transaction: *const replay_command.PreparedProofTransactionV4,
        call_view: replay_command.PreparedProviderCallViewV1,
        evidence: replay_command.PreparedVisitorEvidenceV1,
    ) anyerror!void {
        const self: *StateV1 = @ptrCast(@alignCast(context));
        return self.visit(custody, transaction, call_view, evidence);
    }

    fn visit(
        self: *StateV1,
        custody: replay_command.PreparedVisitorCustodyV1,
        transaction: *const replay_command.PreparedProofTransactionV4,
        call_view: replay_command.PreparedProviderCallViewV1,
        evidence: replay_command.PreparedVisitorEvidenceV1,
    ) !void {
        try custody.validateAgainst(call_view);
        try call_view.validateAgainst(transaction);
        try evidence.validate();
        const inventory = call_view.inventory;
        if (custody.segment_index != expected_segment_index or
            custody.elf.byte_count != expected_elf_byte_count or
            !std.mem.eql(u8, &custody.elf.sha256, &expected_elf_sha256) or
            inventory.program_base != expected_program_base or
            inventory.program_end != expected_program_end or
            inventory.declared_program_word_count !=
                expected_declared_program_word_count or
            inventory.committed_program_word_count !=
                expected_committed_program_word_count or
            inventory.program_leaf_count != expected_program_leaf_count or
            inventory.program_call_count != expected_program_call_count or
            inventory.incremental_memory_call_count !=
                expected_incremental_memory_call_count or
            inventory.total_call_count != expected_full_call_count or
            @as(u64, @intCast(call_view.calls.len)) !=
                inventory.total_call_count or
            custody.public_wire.reference.byte_count !=
                expected_reference_byte_count or !std.mem.eql(
            u8,
            &custody.public_wire.reference.sha256,
            &expected_reference_sha256,
        ) or
            custody.public_wire.segment.wire_artifact.byte_count !=
                expected_payload_byte_count or !std.mem.eql(
            u8,
            &custody.public_wire.segment.wire_artifact.sha256,
            &expected_payload_sha256,
        )) {
            printRetainedSourceMismatch(custody, call_view);
            return error.Stage101Degree5RetainedSourceMismatch;
        }

        const source_resources = try self.source_measurement.finish(1);
        var planning_measurement = try throughput.MeasurementV1.begin();
        var plan = try provider_authority.ProviderShardPlanV1.create(
            self.allocator,
            call_view.source_identity_sha256,
            call_view.calls,
            .{
                .logical_row_count = inventory.total_call_count,
                .column_count = provider_authority.main_column_count,
                .min_shard_log_size = self.environment.shard_log_size,
                .max_shard_log_size = self.environment.shard_log_size,
                .log_blowup_factor = execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR,
                .retention_policy = .always,
                .host_byte_budget = self.environment.total_host_byte_budget,
                .reserved_host_bytes = self.environment.controller_reserve_bytes,
                .requested_parallel_shards = @intCast(
                    self.environment.concurrent_owners,
                ),
            },
        );
        defer plan.deinit(self.allocator);
        const host = try execution_mod.HostCapacityV1.detect(
            self.environment.host_byte_limit,
        );
        const execution = try execution_mod.AuthorityV1.initAgainstPlan(
            host,
            &plan,
            .{
                .concurrent_owners = self.environment.concurrent_owners,
                .engine_workers_per_owner = self.environment.engine_workers_per_owner,
                .total_host_byte_budget = self.environment.total_host_byte_budget,
                .controller_reserve_bytes = self.environment.controller_reserve_bytes,
                .non_column_reserve_per_owner = self.environment.non_column_reserve_per_owner,
            },
        );
        const topology = try execution_mod.TopologyReceiptV1.init(
            &plan,
            &execution,
        );
        const program = try provider.VerifierProgramAuthorityV2.coldCompile(
            self.allocator,
        );
        const profile = try execution.executionProfile(program);
        _ = try planning_measurement.finish(1);
        try requireFirstArm(topology);

        const pcs_config = cpu.ethereum_block_leaf_support.recursive_pcs_config;
        var producer_calls = try provider_authority
            .OwnedValidatedPlanCallAuthorityV1.init(
            self.allocator,
            &plan,
            call_view.calls,
        );
        defer producer_calls.deinit();
        var stage_a_measurement = try throughput.MeasurementV1.begin();
        var prepared = try prepared_batch.prepareParallelValidated(
            MetalEngine,
            self.allocator,
            pcs_config,
            program,
            &plan,
            call_view.calls,
            &producer_calls,
            &execution,
        );
        defer prepared.deinit();
        const stage_a_resources = try stage_a_measurement.finish(1);

        var prove_measurement = try throughput.MeasurementV1.begin();
        var encoded = try order_batch.provePreparedParallelValidated(
            MetalEngine,
            self.allocator,
            pcs_config,
            program,
            profile,
            &plan,
            call_view.calls,
            &producer_calls,
            &prepared,
            &execution,
        );
        defer encoded.deinit();
        const prove_resources = try prove_measurement.finish(1);
        const producer_call_work = producer_calls.workReceipt();
        try producer_call_work.validate();

        var verify_measurement = try throughput.MeasurementV1.begin();
        var fresh_calls = try provider_authority
            .OwnedValidatedPlanCallAuthorityV1.init(
            self.allocator,
            &plan,
            call_view.calls,
        );
        defer fresh_calls.deinit();
        var fresh = try order_batch.verifyFreshParallelValidated(
            MetalEngine,
            CpuVerifierEngine,
            self.allocator,
            pcs_config,
            program,
            profile,
            &plan,
            call_view.calls,
            &fresh_calls,
            &encoded,
            &execution,
        );
        defer fresh.deinit();
        const verify_resources = try verify_measurement.finish(1);
        const fresh_call_work = fresh_calls.workReceipt();
        try fresh_call_work.validate();

        const lifecycle_after = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
        try validateLifecycle(lifecycle_after);
        if (!std.meta.eql(self.lifecycle_before.identity, lifecycle_after.identity))
            return error.Stage101Degree5MetalRuntimeIdentityChanged;
        const telemetry_after = try metal.MetalCommitBackend.telemetrySnapshot();
        const delta = telemetry_after.delta(self.telemetry_before);
        printTelemetry(delta.counters);
        try delta.requireResidentRiscPolynomialExecution();
        const telemetry = telemetryReceipt(delta.counters);

        var proof_bytes: u64 = 0;
        for (encoded.shards) |shard| proof_bytes = std.math.add(
            u64,
            proof_bytes,
            shard.canonical_proof_bytes.len,
        ) catch return error.Stage101Degree5ProviderSweepOverflow;
        var ordered_air: u32 = 0;
        var ordered_recomputed: u32 = 0;
        var unshared_relation: u32 = 0;
        for (fresh.claims) |claim| {
            try claim.validate();
            ordered_air += @intFromBool(claim.ordered_call_air_verified);
            ordered_recomputed += @intFromBool(
                claim.ordered_call_claim_recomputed,
            );
            unshared_relation += @intFromBool(
                !claim.shared_core_relation_context_verified,
            );
        }
        const total_resources = try self.total_measurement.finish(1);
        var receipt = ReceiptV1{
            .build_mode = @tagName(builtin.mode),
            .segment_index = custody.segment_index,
            .elf_byte_count = custody.elf.byte_count,
            .elf_sha256 = custody.elf.sha256,
            .program_source_identity_sha256 = custody.program_source_identity_sha256,
            .stwipr04_reference_byte_count = custody.public_wire.reference.byte_count,
            .stwipr04_reference_sha256 = custody.public_wire.reference.sha256,
            .stwipw04_payload_byte_count = custody.public_wire.segment.wire_artifact.byte_count,
            .stwipw04_payload_sha256 = custody.public_wire.segment.wire_artifact.sha256,
            .retained_source_byte_count = custody.public_wire.segment.source.byte_count,
            .retained_source_sha256 = custody.public_wire.segment.source.sha256,
            .prepared_source_identity_sha256 = call_view.source_identity_sha256,
            .prepared_profile_identity_sha256 = call_view.profile_identity_sha256,
            .program_base = inventory.program_base,
            .program_end = inventory.program_end,
            .declared_program_word_count = inventory.declared_program_word_count,
            .committed_program_word_count = inventory.committed_program_word_count,
            .program_leaf_count = inventory.program_leaf_count,
            .program_call_count = inventory.program_call_count,
            .program_commitment_root = inventory.program_commitment_root,
            .incremental_memory_call_count = inventory.incremental_memory_call_count,
            .call_count = @intCast(call_view.calls.len),
            .ordered_call_commitment = plan.call_list_commitment,
            .topology = topology,
            .backend_identity_sha256 = backendIdentity(),
            .pow_bits = execution_mod.Q193_POW_BITS,
            .query_count = execution_mod.Q193_QUERY_COUNT,
            .fri_log_blowup_factor = execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR,
            .quotient_expansion_bits = execution_mod.D5_QUOTIENT_EXPANSION_BITS,
            .producer_proofs_destroyed_before_cpu_decode = true,
            .cpu_fresh_verified = true,
            .ordered_call_air_verified_count = ordered_air,
            .ordered_call_claim_recomputed_count = ordered_recomputed,
            .relation_context_intentionally_unshared_count = unshared_relation,
            .plan_construction_full_validations = 1,
            .producer_call_authority_full_validations = @intCast(
                producer_call_work.full_corpus_validations,
            ),
            .fresh_call_authority_full_validations = @intCast(
                fresh_call_work.full_corpus_validations,
            ),
            .internal_full_call_revalidations = 0,
            .producer_call_authority_fast_checks = producer_call_work.fast_pointer_checks,
            .fresh_call_authority_fast_checks = fresh_call_work.fast_pointer_checks,
            .legacy_internal_full_call_revalidations_avoided = producer_call_work.fast_pointer_checks +
                fresh_call_work.fast_pointer_checks,
            .proof_count = @intCast(encoded.shards.len),
            .total_canonical_proof_bytes = proof_bytes,
            .ordered_proof_identity_sha256 = proofBatchIdentity(&encoded),
            .ordered_fresh_identity_sha256 = freshBatchIdentity(&fresh),
            .runtime_initialization_ns = self.runtime_initialization_ns,
            .input_admission_ns = evidence.input_admission_ns,
            .compact_replay_ns = evidence.compact_replay_ns,
            .snapshot_ns = evidence.snapshot_ns,
            .witness_prepare_ns = evidence.preparation.phase_timing.witness_prepare_ns,
            .statement_profile_prepare_ns = evidence.preparation.phase_timing.statement_profile_prepare_ns,
            .source_preparation_resources = source_resources,
            .stage_a_resources = stage_a_resources,
            .metal_prove_resources = prove_resources,
            .cpu_fresh_verify_resources = verify_resources,
            .total_resources = total_resources,
            .telemetry = telemetry,
            .validation_identity_sha256 = [_]u8{0} ** 32,
        };
        const encoded_receipt = try sealReceiptAlloc(self.allocator, &receipt);
        defer self.allocator.free(encoded_receipt);
        try artifact_io.publishCreateOnlyDurable(
            self.output_path,
            encoded_receipt,
        );
        const receipt_hex = std.fmt.bytesToHex(
            receipt.validation_identity_sha256,
            .lower,
        );
        std.debug.print(
            "STAGE101_D5_PROVIDER_BATCH=verified calls={} shards={} " ++
                "log={} waves={} proof_bytes={} receipt={s}\n",
            .{
                receipt.call_count,
                receipt.proof_count,
                receipt.topology.planner_shard_log_size,
                receipt.topology.wave_count,
                receipt.total_canonical_proof_bytes,
                &receipt_hex,
            },
        );
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed = try replay_command.Options.parse(arguments);
    if (parsed.segment_index != expected_segment_index)
        return error.Stage101Degree5RetainedSourceMismatch;
    const output_path = try artifact_io.resolveAbsolute(allocator, parsed.output);
    defer allocator.free(output_path);
    const environment = try environmentFromProcess(allocator);
    try aot.validate(
        allocator,
        environment.bundle_path,
        expected_manifest_sha256,
    );
    defer allocator.free(environment.bundle_path);
    const initial = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
    if (initial.initialized)
        return error.Stage101Degree5MetalRuntimeAlreadyInitialized;
    var initialization_timer = try std.time.Timer.start();
    try metal.MetalCommitBackend.initializeRuntime(allocator, .{
        .authenticated_aot = .{
            .bundle_path = environment.bundle_path,
            .manifest_sha256 = expected_manifest_sha256,
        },
    });
    const initialization_ns = initialization_timer.read();
    defer metal.MetalCommitBackend.shutdown() catch unreachable;
    const lifecycle = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
    try validateLifecycle(lifecycle);
    var state = StateV1{
        .allocator = allocator,
        .output_path = output_path,
        .environment = environment,
        .runtime_initialization_ns = initialization_ns,
        .lifecycle_before = lifecycle,
        .telemetry_before = try metal.MetalCommitBackend.telemetrySnapshot(),
        .source_measurement = try throughput.MeasurementV1.begin(),
        .total_measurement = try throughput.MeasurementV1.begin(),
    };
    try replay_command.runPreparedVisitor(
        allocator,
        arguments,
        .{ .context = &state, .visit_fn = StateV1.visitOpaque },
    );
}

fn environmentFromProcess(allocator: std.mem.Allocator) !EnvironmentV1 {
    return .{
        .bundle_path = try environmentOwned(
            allocator,
            "STWO_RISCV_METAL_AOT_BUNDLE",
        ),
        .shard_log_size = try environmentInt(
            allocator,
            u32,
            "STWO_ZIG_D5_PROVIDER_SHARD_LOG",
        ),
        .concurrent_owners = try environmentInt(
            allocator,
            usize,
            "STWO_ZIG_D5_PROVIDER_CONCURRENT_OWNERS",
        ),
        .engine_workers_per_owner = try environmentInt(
            allocator,
            usize,
            "STWO_ZIG_D5_PROVIDER_ENGINE_WORKERS",
        ),
        .total_host_byte_budget = try environmentInt(
            allocator,
            u64,
            "STWO_ZIG_D5_PROVIDER_HOST_BYTE_BUDGET",
        ),
        .host_byte_limit = try environmentInt(
            allocator,
            usize,
            "STWO_ZIG_D5_PROVIDER_HOST_BYTE_LIMIT",
        ),
        .controller_reserve_bytes = try environmentInt(
            allocator,
            u64,
            "STWO_ZIG_D5_PROVIDER_CONTROLLER_RESERVE_BYTES",
        ),
        .non_column_reserve_per_owner = try environmentInt(
            allocator,
            u64,
            "STWO_ZIG_D5_PROVIDER_NON_COLUMN_RESERVE_BYTES",
        ),
    };
}

fn environmentOwned(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch
        return error.MissingStage101Degree5ProviderEnvironment;
}

fn environmentInt(
    allocator: std.mem.Allocator,
    comptime T: type,
    name: []const u8,
) !T {
    const bytes = try environmentOwned(allocator, name);
    defer allocator.free(bytes);
    return std.fmt.parseInt(T, bytes, 10) catch
        return error.InvalidStage101Degree5ProviderEnvironment;
}

fn requireFirstArm(topology: execution_mod.TopologyReceiptV1) !void {
    if (topology.planner_shard_log_size != 18 or
        topology.shard_count != 26 or topology.concurrent_owners != 18 or
        topology.wave_count != 2 or topology.minimum_descriptor_log_size != 17 or
        topology.maximum_descriptor_log_size != 18 or
        topology.committed_rows != 6_684_672 or topology.padding_rows != 13_371 or
        topology.max_canonical_proof_bytes_per_shard != 128 * 1024 * 1024 or
        topology.retained_stage_a_column_reservation_bytes != 19_332_071_424 or
        topology.retained_stage_a_non_column_reservation_bytes != 13_958_643_712 or
        topology.active_post_stage_a_column_reservation_bytes != 1_585_446_912 or
        topology.composition_domain_scratch_concurrent_owners != 1 or
        topology.composition_domain_scratch_reservation_bytes != 1_044_381_696 or
        topology.encoded_proof_reservation_bytes != 3_489_660_928 or
        topology.aggregate_owner_reservation_bytes != 39_410_204_672 or
        topology.controller_reserve_bytes != 8 * 1024 * 1024 * 1024 or
        topology.total_reservation_bytes != 48_000_139_264)
    {
        return error.Stage101Degree5FirstArmTopologyMismatch;
    }
}

/// Every legacy call site replaced by the producer token previously invoked
/// `ProviderShardPlanV1.validate` over the complete corpus. The constant term
/// is the four batch-boundary checks; each shard has seven O(1) pointer and
/// descriptor checks across Stage-A construction, validation, and proving.
fn expectedProducerFastChecks(proof_count: u32) u64 {
    return 4 + 7 * @as(u64, proof_count);
}

/// Fresh CPU admission validates the complete corpus once when it mints its
/// independent token, then performs one batch-boundary and one per-shard
/// pointer/descriptor check.
fn expectedFreshFastChecks(proof_count: u32) u64 {
    return 1 + @as(u64, proof_count);
}

/// Source-level legacy `ProviderShardPlanV1.validate` invocation counts. One
/// invocation performs five full-corpus-equivalent passes: outer canonical
/// validation, global validation+hash, and aggregate shard validation+hash.
/// `ProviderShardPlanV1.create` is separate: its construction work plus final
/// validation performs ten passes and remains unchanged.
fn legacyPrepareFullValidationCalls(proof_count: u32) u64 {
    return 2 + 3 * @as(u64, proof_count);
}

fn legacyProveFullValidationCalls(proof_count: u32) u64 {
    return 2 + 4 * @as(u64, proof_count);
}

fn legacyFreshFullValidationCalls(proof_count: u32) u64 {
    return expectedFreshFastChecks(proof_count);
}

fn printRetainedSourceMismatch(
    custody: replay_command.PreparedVisitorCustodyV1,
    call_view: replay_command.PreparedProviderCallViewV1,
) void {
    const reference_observed = std.fmt.bytesToHex(
        custody.public_wire.reference.sha256,
        .lower,
    );
    const reference_expected = std.fmt.bytesToHex(
        expected_reference_sha256,
        .lower,
    );
    const payload_observed = std.fmt.bytesToHex(
        custody.public_wire.segment.wire_artifact.sha256,
        .lower,
    );
    const payload_expected = std.fmt.bytesToHex(
        expected_payload_sha256,
        .lower,
    );
    const elf_observed = std.fmt.bytesToHex(custody.elf.sha256, .lower);
    const elf_expected = std.fmt.bytesToHex(expected_elf_sha256, .lower);
    const program_source = std.fmt.bytesToHex(
        custody.program_source_identity_sha256,
        .lower,
    );
    const inventory = call_view.inventory;
    std.debug.print(
        "STAGE101_D5_RETAINED_SOURCE=mismatch " ++
            "segment_observed={} segment_expected={} " ++
            "calls_observed={} calls_expected={} program_calls={}/{} " ++
            "incremental_calls={}/{} program_words={}/{} " ++
            "program_leaves={}/{} program_range=0x{x}..0x{x}/0x{x}..0x{x} " ++
            "elf_bytes_observed={} elf_bytes_expected={} " ++
            "elf_sha_observed={s} elf_sha_expected={s} program_source={s} " ++
            "stwipr_bytes_observed={} stwipr_bytes_expected={} " ++
            "stwipr_sha_observed={s} stwipr_sha_expected={s} " ++
            "stwipw_bytes_observed={} stwipw_bytes_expected={} " ++
            "stwipw_sha_observed={s} stwipw_sha_expected={s}\n",
        .{
            custody.segment_index,
            expected_segment_index,
            call_view.calls.len,
            expected_full_call_count,
            inventory.program_call_count,
            expected_program_call_count,
            inventory.incremental_memory_call_count,
            expected_incremental_memory_call_count,
            inventory.declared_program_word_count,
            expected_declared_program_word_count,
            inventory.program_leaf_count,
            expected_program_leaf_count,
            inventory.program_base,
            inventory.program_end,
            expected_program_base,
            expected_program_end,
            custody.elf.byte_count,
            expected_elf_byte_count,
            &elf_observed,
            &elf_expected,
            &program_source,
            custody.public_wire.reference.byte_count,
            expected_reference_byte_count,
            &reference_observed,
            &reference_expected,
            custody.public_wire.segment.wire_artifact.byte_count,
            expected_payload_byte_count,
            &payload_observed,
            &payload_expected,
        },
    );
}

fn validateLifecycle(
    lifecycle: metal.MetalCommitBackend.RuntimeLifecycleSnapshot,
) !void {
    if (!lifecycle.initialized or lifecycle.identity == null)
        return error.Stage101Degree5AuthenticatedMetalRuntimeMissing;
    const identity = lifecycle.identity.?;
    if (identity.origin != .authenticated_core_aot or
        identity.manifest_sha256 == null or
        identity.metallib_sha256 == null or
        identity.metallib_bytes == null or identity.metallib_bytes.? == 0 or
        !std.mem.eql(
            u8,
            &identity.manifest_sha256.?,
            &expected_manifest_sha256,
        ) or !std.mem.eql(
        u8,
        &identity.metallib_sha256.?,
        &expected_metallib_sha256,
    )) return error.Stage101Degree5AuthenticatedMetalRuntimeMismatch;
}

fn telemetryReceipt(counters: metal.telemetry.CounterValues) TelemetryReceiptV1 {
    return .{
        .metal_dispatch_total = counters.metalDispatchTotal(),
        .cpu_fallback_total = counters.cpuFallbackTotal(),
        .resident_merkle_commits = counters.resident_merkle_commits,
        .poseidon_merkle_commits = counters.metal_poseidon2_merkle_commits,
        .sampled_value_dispatches = counters.metal_sampled_value_dispatches,
        .quotient_dispatches = counters.metal_quotient_dispatches,
        .circle_transform_dispatches = counters.metal_circle_transform_dispatches,
        .circle_lde_dispatches = counters.metal_circle_lde_dispatches,
        .fri_circle_dispatches = counters.metal_fri_circle_fold_dispatches,
        .fri_line_dispatches = counters.metal_fri_line_fold_dispatches,
        .base_eligible_components = counters.riscv_base_polynomial_eligible_components,
        .lookup_eligible_components = counters.riscv_lookup_polynomial_eligible_components,
        .base_batch_dispatches = counters.metal_riscv_base_polynomial_batch_dispatches,
        .lookup_batch_dispatches = counters.metal_riscv_lookup_polynomial_batch_dispatches,
        .polynomial_declines = counters.cpu_riscv_polynomial_composition_declines,
        .host_merkle_commits = counters.host_merkle_commits,
        .cpu_small_merkle_commits = counters.cpu_small_merkle_commits,
        .cpu_streaming_merkle_commits = counters.cpu_streaming_merkle_commits,
        .cpu_sampled_value_evaluations = counters.cpu_sampled_value_evaluations,
        .cpu_small_circle_interpolations = counters.cpu_small_circle_interpolations,
        .cpu_small_circle_evaluations = counters.cpu_small_circle_evaluations,
        .cpu_small_circle_ldes = counters.cpu_small_circle_ldes,
        .cpu_composition_evaluations = counters.cpu_composition_evaluations,
    };
}

fn printTelemetry(counters: metal.telemetry.CounterValues) void {
    std.debug.print(
        "STAGE101_D5_METAL_TELEMETRY dispatch={} fallback={} " ++
            "merkle={}/{}/{}/{} sampled={}/{} transform={}/{} " ++
            "composition={}/{}/{}/{}/{} quotient={} fri={}/{}\n",
        .{
            counters.metalDispatchTotal(),
            counters.cpuFallbackTotal(),
            counters.resident_merkle_commits,
            counters.metal_poseidon2_merkle_commits,
            counters.cpu_small_merkle_commits,
            counters.cpu_streaming_merkle_commits,
            counters.metal_sampled_value_dispatches,
            counters.cpu_sampled_value_evaluations,
            counters.metal_circle_transform_dispatches,
            counters.metal_circle_lde_dispatches,
            counters.riscv_base_polynomial_eligible_components,
            counters.riscv_lookup_polynomial_eligible_components,
            counters.metal_riscv_base_polynomial_batch_dispatches,
            counters.metal_riscv_lookup_polynomial_batch_dispatches,
            counters.cpu_riscv_polynomial_composition_declines,
            counters.metal_quotient_dispatches,
            counters.metal_fri_circle_fold_dispatches,
            counters.metal_fri_line_fold_dispatches,
        },
    );
    std.debug.print(
        "STAGE101_D5_HOST_FALLBACK_DETAIL host_merkle={} small_circle={}/{}/{} " ++
            "cpu_composition={}\n",
        .{
            counters.host_merkle_commits,
            counters.cpu_small_circle_interpolations,
            counters.cpu_small_circle_evaluations,
            counters.cpu_small_circle_ldes,
            counters.cpu_composition_evaluations,
        },
    );
}

fn proofBatchIdentity(batch: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-d5-provider-proof-batch/v1\x00");
    hashInt(&hash, u64, batch.shards.len);
    for (batch.shards, 0..) |shard, index| {
        hashInt(&hash, u64, index);
        hash.update(&shard.statement.identity);
        hashInt(&hash, u64, shard.canonical_proof_bytes.len);
        hash.update(&shard.canonical_proof_sha256);
    }
    return hash.finalResult();
}

fn freshBatchIdentity(batch: *const order_batch.OwnedFreshBatchV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-d5-provider-fresh-batch/v1\x00");
    hashInt(&hash, u64, batch.claims.len);
    for (batch.claims, 0..) |claim, index| {
        hashInt(&hash, u64, index);
        hash.update(&claim.identity);
    }
    return hash.finalResult();
}

fn backendIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-d5-provider-metal-backend/v1\x00");
    hash.update(@typeName(MetalEngine));
    hash.update(&expected_manifest_sha256);
    hash.update(&expected_metallib_sha256);
    hash.update(&expected_source_sha256);
    hash.update(&expected_air_sha256);
    hashInt(&hash, u32, expected_native_export_count);
    return hash.finalResult();
}

fn sealReceiptAlloc(
    allocator: std.mem.Allocator,
    receipt: *ReceiptV1,
) ![]u8 {
    receipt.validation_identity_sha256 = [_]u8{0} ** 32;
    const unsigned = try std.json.Stringify.valueAlloc(allocator, receipt.*, .{});
    defer allocator.free(unsigned);
    receipt.validation_identity_sha256 = sha256(unsigned);
    try receipt.validate(allocator);
    const canonical = try std.json.Stringify.valueAlloc(allocator, receipt.*, .{});
    errdefer allocator.free(canonical);
    const result = try allocator.alloc(u8, canonical.len + 1);
    @memcpy(result[0..canonical.len], canonical);
    result[canonical.len] = '\n';
    allocator.free(canonical);
    return result;
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn hexDigest(comptime encoded: *const [64]u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn contiguousTreeNodeCount(
    first_leaf: u64,
    leaf_count: u64,
    depth: u32,
) u64 {
    if (leaf_count == 0) return 0;
    var first = first_leaf;
    var past_last = first_leaf + leaf_count;
    var result: u64 = 0;
    for (0..depth) |_| {
        first /= 2;
        past_last = (past_last + 1) / 2;
        result += past_last - first;
    }
    return result;
}

test "Stage101 D5 retained first arm pins exact q193 log18 topology" {
    try std.testing.expectEqual(@as(u32, 16), execution_mod.Q193_POW_BITS);
    try std.testing.expectEqual(@as(u32, 193), execution_mod.Q193_QUERY_COUNT);
    try std.testing.expectEqual(@as(u32, 1), execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR);
    try std.testing.expectEqual(@as(u32, 2), execution_mod.D5_QUOTIENT_EXPANSION_BITS);
    try std.testing.expectEqual(
        @as(u64, 249),
        execution_mod.D5_COMPOSITION_DOMAIN_SCRATCH_COLUMNS,
    );
    try std.testing.expectEqual(
        @as(u16, 1),
        execution_mod.D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS,
    );
    try std.testing.expectEqual(
        @as(u64, expected_program_end - expected_program_base),
        expected_program_leaf_count,
    );
    try std.testing.expectEqual(
        @as(u64, 2_887_182),
        expected_program_call_count,
    );
    try std.testing.expectEqual(
        @as(u64, 6_671_301),
        expected_full_call_count,
    );
    try std.testing.expectEqual(
        @as(u64, 117_701),
        expected_full_call_count - 25 * (@as(u64, 1) << 18),
    );
    try std.testing.expectEqual(
        @as(u64, 13_371),
        25 * (@as(u64, 1) << 18) + (@as(u64, 1) << 17) -
            expected_full_call_count,
    );
    try std.testing.expectEqual(@as(u64, 186), expectedProducerFastChecks(26));
    try std.testing.expectEqual(@as(u64, 27), expectedFreshFastChecks(26));
    try std.testing.expectEqual(
        @as(u64, 80),
        legacyPrepareFullValidationCalls(26),
    );
    try std.testing.expectEqual(
        @as(u64, 106),
        legacyProveFullValidationCalls(26),
    );
    try std.testing.expectEqual(
        @as(u64, 27),
        legacyFreshFullValidationCalls(26),
    );
    try std.testing.expectEqual(
        @as(u64, 213),
        legacyPrepareFullValidationCalls(26) +
            legacyProveFullValidationCalls(26) +
            legacyFreshFullValidationCalls(26),
    );
    try std.testing.expect(!PRODUCTION_ACTIVE and !COMPLETE_LEAF_PROOF);
}

test "Stage101 D5 backend identity pins authenticated ABI21 custody" {
    try std.testing.expect(!std.mem.allEqual(u8, &backendIdentity(), 0));
    try std.testing.expectEqual(@as(u32, 164), expected_native_export_count);
    try std.testing.expectEqual(@as(u64, 3_352_364), expected_elf_byte_count);
    try std.testing.expect(!std.mem.allEqual(u8, &expected_elf_sha256, 0));
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected_manifest_sha256,
        &expected_metallib_sha256,
    ));
}

comptime {
    if (FORMAT_VERSION != 1 or PRODUCTION_ACTIVE or COMPLETE_LEAF_PROOF or
        expected_incremental_memory_call_count != 3_784_119 or
        expected_program_call_count != 2_887_182 or
        expected_full_call_count != 6_671_301 or
        expected_native_export_count != 164)
    {
        @compileError("Stage101 D5 provider sweep contract drifted");
    }
}
