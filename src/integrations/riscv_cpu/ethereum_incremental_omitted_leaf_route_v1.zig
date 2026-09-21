//! Engine-generic body of the Stage101 `--provider-route degree5-omit-v1`
//! command (Step 9 of the leaf route flip).
//!
//! The Metal command module (`riscv_metal/stage101_leaf_degree5_provider_v1`)
//! owns everything that needs a device: the authenticated-AOT runtime, the
//! lifecycle and telemetry checks, and the backend half of the receipt. It
//! hands the prepared transaction to `RouteV1(ProducerEngine,
//! CpuVerifierEngine).proveAndFreshVerify`, which runs the route's stages 1-6:
//!
//!   1. the sweep prologue (custody, retained-source pins, the pinned shard
//!      plan, the O(1) validated call authority, the execution authority, the
//!      cold-compiled D5 program);
//!   2. Stage A on the producer engine (validated fast path, G1);
//!   3. the omitted-provider core proof under one shared relation draw;
//!   4. the 26 D5 shard proofs under that same draw;
//!   5. the `STWIOL01` envelope, after which every producer proof object is
//!      destroyed and only bytes plus POD authorities survive;
//!   6. the CPU fresh verify from bytes: plan rebuilt from pins + calls,
//!      Stage-A manifest rebuilt from the decoded roots, the core cold
//!      verifier, every shard fresh-verified under the shared context, and
//!      `closeFreshClaimsV2`.
//!
//! and stage 8 (`ReceiptV1`, sealed like the sweep, published create-only, and
//! only THEN the fail-closed `ProviderRouteBudgetV1`). Being generic over the
//! engine pair is what lets the whole body be analysed against the q193 CPU
//! engine in a focused test root instead of a ten-minute Metal product build.
//!
//! Nothing here activates: `PRODUCTION_ACTIVE`, `COMPLETE_LEAF_PROOF` and
//! `RECURSIVE_CAPTURE_AVAILABLE` are false and the receipt refuses a
//! `production_eligible` or `recursive_admissible` closure.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const prover_api = @import("stwo_prover_api");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const block_leaf_support = @import("ethereum_block_leaf_support.zig");
const envelope =
    @import("ethereum_incremental_omitted_leaf_proof_artifact_v1.zig");
const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const prepared_batch =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const replay_command =
    @import("ethereum_incremental_full_leaf_replay_command_v4.zig");
const shared_batch =
    @import("ethereum_candidate_degree5_provider_shared_batch_v1.zig");
const throughput =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");
const transcript_mod =
    @import("ethereum_incremental_omitted_provider_transcript_v1.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const core_pcs = stwo_core.pcs;
const lookup_physical_v2 = frontend.air.lookup_physical_manifest_v2;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;
const public_data_v2 = frontend.air.public_data_v2;
const prover = frontend.prover_mod;
const protocol = prover.ethereum_native_provider_omit_protocol_v1;
const route = prover.guest_precompile.incremental_ethereum_omit_protocol_v4;
const orchestration =
    frontend.testing.incremental_ethereum_omit_orchestration_v4_internal;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider = frontend.testing.narrow_memory_provider_degree5_order_proof_v2;
const degree5 =
    frontend.testing.narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const harness = frontend.testing.narrow_memory_provider_proof_harness;

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVE = false;
pub const COMPLETE_LEAF_PROOF = false;
pub const RECURSIVE_CAPTURE_AVAILABLE = false;
pub const receipt_schema = "stwo.stage101.leaf-degree5-provider-route.v1";
pub const provider_route_flag = "--provider-route";
pub const provider_route_native = "native";
pub const provider_route_degree5_omit_v1 = "degree5-omit-v1";
pub const durable_core_envelope = "STWIOL01";
pub const fresh_calls_source = "producer_process_borrowed";
pub const provider_plan_admission = "pins_v1";
/// Step 0 took option (a): blocker 1's smallest fix landed with steps 0-7, so
/// the route owes no red baseline. A non-empty list here would name the exact
/// step/assertion a gate is allowed to keep failing at.
pub const known_red_baselines: []const []const u8 = &.{};

pub const Digest = provider_authority.Digest;
pub const AuthorityId = route.AuthorityId;
pub const ProviderOmissionPinsV1 = route.ProviderOmissionPinsV1;
pub const CpuVerifierEngine = replay_command.CpuEngine;
/// Stage recorder type of the core prove, re-exported so the Metal command
/// names exactly the type this module's `OptionsV1.recorder` expects.
pub const StageRecorder = prover_api.stage_profile.Recorder;
pub const stage_profile_environment = "STWO_ZIG_STAGE101_STAGE_PROFILE";

/// Recorder configured like the replay command's, for the route's core prove.
pub fn initStageRecorder(allocator: std.mem.Allocator) StageRecorder {
    return StageRecorder.initWithOptions(
        allocator,
        @tagName(builtin.mode),
        "ethereum_incremental_stage101_d5_route_v1",
        .{ .capture_tasks = false, .capture_work = false },
    );
}

/// Every refusal this module owns. Errors raised by the route protocol, the
/// envelope, the shard batches or the D5 closure keep their own names.
pub const Error = error{
    InvalidStage101ProviderRoute,
    Stage101ProviderRouteRetainedSourceMismatch,
    Stage101ProviderRouteFirstArmTopologyMismatch,
    Stage101ProviderRouteRetainedSnapshotsMissing,
    Stage101ProviderRouteValidationBudgetMismatch,
    Stage101ProviderRoutePlanMismatch,
    Stage101ProviderRouteManifestMismatch,
    Stage101ProviderRouteProjectionMismatch,
    Stage101ProviderRouteSharedAuthorityMismatch,
    Stage101ProviderRouteLeafOmissionMismatch,
    Stage101ProviderRouteShardBytesMismatch,
    Stage101ProviderRouteResidualMismatch,
    Stage101ProviderRouteClosureNotZero,
    Stage101ProviderRouteSharedContextCountMismatch,
    Stage101ProviderRouteOverflow,
    Stage101ProviderRouteBudgetExceeded,
    InvalidStage101ProviderRouteReceipt,
};

// ---------------------------------------------------------------------------
// Flag dispatch
// ---------------------------------------------------------------------------

pub const RouteSelectionV1 = enum { native, degree5_omit_v1 };

/// `arguments` with exactly the `--provider-route <value>` pair removed. The
/// forwarded slice is allocator-owned; the strings it points at are borrowed.
pub const ParsedRouteV1 = struct {
    route: RouteSelectionV1,
    forwarded: []const []const u8,

    pub fn deinit(self: *ParsedRouteV1, allocator: std.mem.Allocator) void {
        allocator.free(self.forwarded);
        self.* = undefined;
    }
};

/// Strips the route flag before the arguments reach the replay command, which
/// rejects any key it does not know. `native` and an absent flag both select
/// the unchanged native path; `degree5-omit-v1` selects the route; any other
/// value is an error, as is a repeated flag or a flag with no value.
pub fn stripProviderRoute(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !ParsedRouteV1 {
    var selection: ?RouteSelectionV1 = null;
    var forwarded: std.ArrayList([]const u8) = .empty;
    errdefer forwarded.deinit(allocator);
    var at: usize = 0;
    while (at < arguments.len) : (at += 1) {
        const argument = arguments[at];
        if (!std.mem.eql(u8, argument, provider_route_flag)) {
            try forwarded.append(allocator, argument);
            continue;
        }
        if (at + 1 == arguments.len) return error.InvalidArguments;
        if (selection != null) return error.DuplicateArgument;
        const value = arguments[at + 1];
        at += 1;
        if (std.mem.eql(u8, value, provider_route_native)) {
            selection = .native;
        } else if (std.mem.eql(u8, value, provider_route_degree5_omit_v1)) {
            selection = .degree5_omit_v1;
        } else return error.InvalidStage101ProviderRoute;
    }
    return .{
        .route = selection orelse .native,
        .forwarded = try forwarded.toOwnedSlice(allocator),
    };
}

// ---------------------------------------------------------------------------
// Stage 1: the sweep prologue's retained-source pins (segment 1), verbatim
// ---------------------------------------------------------------------------

pub const RetainedSourcePinsV1 = struct {
    pub const segment_index: u32 = 1;
    pub const incremental_memory_call_count: u64 = 3_784_119;
    pub const elf_byte_count: u64 = 3_352_364;
    pub const elf_sha256 = hexDigest(
        "b751305c0e350918a4a1e692fcfd620a54f5bce6c50322230e156faca95328fa",
    );
    pub const program_base: u32 = 0x400;
    pub const program_end: u32 = 0x2c11fc;
    pub const declared_program_word_count: u64 = 721_791;
    pub const committed_program_word_count: u64 = 721_791;
    pub const program_leaf_count: u64 = 2_887_164;
    pub const program_call_count: u64 = contiguousTreeNodeCount(
        program_base,
        program_leaf_count,
        sparse_merkle.LEAF_DEPTH,
    );
    pub const full_call_count: u64 =
        program_call_count + incremental_memory_call_count;
    pub const reference_byte_count: u64 = 240;
    pub const reference_sha256 = hexDigest(
        "3220855bccc805bf9a9846aa5c3f3286cacafe26cdc38c6144e5f6c53fb88724",
    );
    pub const payload_byte_count: u64 = 48_058_224;
    pub const payload_sha256 = hexDigest(
        "0d0272475946a4bd668d52e2e3b178806ea07df391344031855e5893285134bd",
    );

    /// The sweep's retained-source admission, verbatim.
    pub fn validate(
        custody: replay_command.PreparedVisitorCustodyV1,
        call_view: replay_command.PreparedProviderCallViewV1,
    ) !void {
        const inventory = call_view.inventory;
        if (custody.segment_index != segment_index or
            custody.elf.byte_count != elf_byte_count or
            !std.mem.eql(u8, &custody.elf.sha256, &elf_sha256) or
            inventory.program_base != program_base or
            inventory.program_end != program_end or
            inventory.declared_program_word_count !=
                declared_program_word_count or
            inventory.committed_program_word_count !=
                committed_program_word_count or
            inventory.program_leaf_count != program_leaf_count or
            inventory.program_call_count != program_call_count or
            inventory.incremental_memory_call_count !=
                incremental_memory_call_count or
            inventory.total_call_count != full_call_count or
            @as(u64, @intCast(call_view.calls.len)) !=
                inventory.total_call_count or
            custody.public_wire.reference.byte_count !=
                reference_byte_count or !std.mem.eql(
            u8,
            &custody.public_wire.reference.sha256,
            &reference_sha256,
        ) or
            custody.public_wire.segment.wire_artifact.byte_count !=
                payload_byte_count or !std.mem.eql(
            u8,
            &custody.public_wire.segment.wire_artifact.sha256,
            &payload_sha256,
        )) {
            printRetainedSourceMismatch(custody, call_view);
            return error.Stage101ProviderRouteRetainedSourceMismatch;
        }
    }
};

/// The sweep's first-arm topology pin, verbatim: q193 log18 shards, 26 of
/// them, 17/18 descriptor logs, the exact committed and padding rows.
pub fn requireFirstArm(topology: execution_mod.TopologyReceiptV1) !void {
    if (topology.planner_shard_log_size != 18 or
        topology.shard_count != 26 or topology.concurrent_owners == 0 or
        topology.wave_count == 0 or topology.minimum_descriptor_log_size != 17 or
        topology.maximum_descriptor_log_size != 18 or
        topology.committed_rows != 6_684_672 or topology.padding_rows != 13_371 or
        topology.max_canonical_proof_bytes_per_shard != 128 * 1024 * 1024 or
        topology.composition_domain_scratch_concurrent_owners != 2 or
        topology.composition_domain_scratch_reservation_bytes != 2_088_763_392 or
        topology.controller_reserve_bytes != 8 * 1024 * 1024 * 1024)
    {
        return error.Stage101ProviderRouteFirstArmTopologyMismatch;
    }
}

/// Host execution request derived from the comptime pins and nothing else.
pub fn pinnedExecutionRequest() execution_mod.RequestV1 {
    return .{
        .concurrent_owners = ProviderOmissionPinsV1.execution_owners,
        .engine_workers_per_owner = ProviderOmissionPinsV1.engine_workers_per_owner,
        .total_host_byte_budget = ProviderOmissionPinsV1.host_byte_budget,
        .controller_reserve_bytes = ProviderOmissionPinsV1.reserved_host_bytes,
        .non_column_reserve_per_owner = ProviderOmissionPinsV1.non_column_reserve_per_owner,
    };
}

/// Envelope limits: one core proof plus 26 shard artifacts, each shard capped
/// exactly where the shared batch caps it.
pub const artifact_limits = envelope.Limits{
    .max_artifact_bytes = 1024 * 1024 * 1024,
    .max_proof_bytes = shared_batch.MAX_CANONICAL_SHARD_ARTIFACT_BYTES,
};

// ---------------------------------------------------------------------------
// Timing, budget, telemetry and backend receipts
// ---------------------------------------------------------------------------

/// Per-phase wall time. `total_ns` is the steady-state sum (admission through
/// encode); runtime initialisation and the CPU fresh verify are reported next
/// to it and can never hide inside it.
pub const TimingV1 = struct {
    runtime_init_ns: u64,
    admission_ns: u64,
    replay_ns: u64,
    snapshot_ns: u64,
    witness_ns: u64,
    profile_ns: u64,
    plan_ns: u64,
    stage_a_ns: u64,
    core_prove_ns: u64,
    shard_prove_ns: u64,
    encode_ns: u64,
    core_fresh_verify_ns: u64,
    shard_fresh_verify_ns: u64,
    closure_ns: u64,
    total_ns: u64,

    pub fn steadyStateTotalNs(self: TimingV1) !u64 {
        var total: u64 = 0;
        inline for (.{
            self.admission_ns,
            self.replay_ns,
            self.witness_ns,
            self.profile_ns,
            self.plan_ns,
            self.stage_a_ns,
            self.core_prove_ns,
            self.shard_prove_ns,
            self.encode_ns,
        }) |value| total = try std.math.add(u64, total, value);
        return total;
    }

    pub fn proofCoreWindowNs(self: TimingV1) !u64 {
        var total = try std.math.add(u64, self.plan_ns, self.stage_a_ns);
        total = try std.math.add(u64, total, self.core_prove_ns);
        return std.math.add(u64, total, self.shard_prove_ns);
    }
};

/// Fail-closed steady-state budget of the route. Stage A is mapped into the
/// proof-core window: plan + Stage A + core prove + shard prove share the leaf's
/// 3.8 s, because on this route Stage A is proving work, not preparation.
pub const ProviderRouteBudgetV1 = struct {
    admission_and_replay_ns: u64 = 200 * std.time.ns_per_ms,
    witness_and_profile_ns: u64 = 800 * std.time.ns_per_ms,
    proof_core_ns: u64 = 3_800 * std.time.ns_per_ms,
    encode_ns: u64 = 200 * std.time.ns_per_ms,
    total_ns: u64 = 5 * std.time.ns_per_s,

    pub fn validate(self: ProviderRouteBudgetV1, timing: TimingV1) !void {
        const admission_and_replay = std.math.add(
            u64,
            timing.admission_ns,
            timing.replay_ns,
        ) catch return error.Stage101ProviderRouteOverflow;
        const witness_and_profile = std.math.add(
            u64,
            timing.witness_ns,
            timing.profile_ns,
        ) catch return error.Stage101ProviderRouteOverflow;
        const proof_core = timing.proofCoreWindowNs() catch
            return error.Stage101ProviderRouteOverflow;
        const total = timing.steadyStateTotalNs() catch
            return error.Stage101ProviderRouteOverflow;
        if (admission_and_replay > self.admission_and_replay_ns or
            witness_and_profile > self.witness_and_profile_ns or
            proof_core > self.proof_core_ns or
            timing.encode_ns > self.encode_ns or
            total > self.total_ns or timing.total_ns != total)
        {
            return error.Stage101ProviderRouteBudgetExceeded;
        }
    }
};

/// Backend telemetry, same shape as the sweep receipt's.
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

/// The Metal command's half of the receipt: AOT pins, backend identity, the
/// runtime initialisation cost and the whole-run telemetry delta.
pub const BackendReceiptV1 = struct {
    aot_manifest_sha256: [32]u8,
    aot_metallib_sha256: [32]u8,
    aot_source_sha256: [32]u8,
    aot_air_sha256: [32]u8,
    aot_native_export_count: u32,
    backend_identity_sha256: [32]u8,
    platform_identity_sha256: [32]u8,
    build_identity_sha256: [32]u8,
    runtime_initialization_ns: u64,
    /// Small-circle host placements admitted by the command (recorded, not
    /// pinned, on the first run).
    admitted_host_placements: u64,
    telemetry: TelemetryReceiptV1,
};

// ---------------------------------------------------------------------------
// Outcome of stages 1-6 (POD only: no engine-typed value crosses this line)
// ---------------------------------------------------------------------------

pub const OutcomeV1 = struct {
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
    topology: execution_mod.TopologyReceiptV1,

    full_statement_authority_id: AuthorityId,
    projected_statement_authority_id: AuthorityId,
    projection_identity: Digest,
    pins_identity: Digest,
    frame_v4_identity: Digest,
    leaf_omission_identity: Digest,
    plan_identity: Digest,
    session: Digest,
    call_list_commitment: Digest,
    manifest_identity: Digest,
    shared_relation_identity: Digest,
    relation_context_identity: Digest,
    interaction_pow: u64,
    core_artifact_byte_count: u64,
    core_artifact_sha256: [32]u8,
    core_commitments_identity: Digest,
    prover_residual: [4]u32,
    fresh_residual: [4]u32,
    closure_identity: Digest,
    strategy_identity: Digest,
    shard_count: u32,
    ordered_shard_proof_identity_sha256: [32]u8,
    ordered_fresh_identity_sha256: [32]u8,
    total_canonical_shard_bytes: u64,
    air_program_identity: Digest,
    execution_profile_identity: Digest,

    core_plus_providers_closed: bool,
    closed_sum_is_zero: bool,
    residuals_equal: bool,
    cpu_fresh_verified: bool,
    producer_proofs_destroyed_before_cpu_decode: bool,
    shared_context_verified_count: u32,
    plan_rebuilt_from_pins_matches_decoded: bool,
    manifest_identity_equal_across_engines: bool,
    stage_a_transactions_validated_authority: bool,
    recursive_admissible: bool,
    production_eligible: bool,
    diagnostic_cancellation_ran: bool,
    legacy_full_corpus_validations_producer: u8,
    legacy_full_corpus_validations_verifier: u8,

    timing: TimingV1,
    plan_resources: throughput.ResourceReceiptV1,
    stage_a_resources: throughput.ResourceReceiptV1,
    core_prove_resources: throughput.ResourceReceiptV1,
    shard_prove_resources: throughput.ResourceReceiptV1,
    encode_resources: throughput.ResourceReceiptV1,
    core_fresh_verify_resources: throughput.ResourceReceiptV1,
    shard_fresh_verify_resources: throughput.ResourceReceiptV1,
    closure_resources: throughput.ResourceReceiptV1,
    total_resources: throughput.ResourceReceiptV1,
};

// ---------------------------------------------------------------------------
// Stage 8: the fail-closed receipt
// ---------------------------------------------------------------------------

pub const ReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema: []const u8 = receipt_schema,
    provider_route: []const u8 = provider_route_degree5_omit_v1,
    durable_core_envelope: []const u8 = durable_core_envelope,
    durable_shard_artifacts: bool = true,
    fresh_calls_source: []const u8 = fresh_calls_source,
    provider_plan_admission: []const u8 = provider_plan_admission,
    known_red_baselines: []const []const u8 = known_red_baselines,
    production_active: bool = PRODUCTION_ACTIVE,
    complete_leaf_proof: bool = COMPLETE_LEAF_PROOF,
    recursive_capture_available: bool = RECURSIVE_CAPTURE_AVAILABLE,
    recursive_admissible: bool,
    production_eligible: bool,
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
    topology: execution_mod.TopologyReceiptV1,
    pow_bits: u32 = execution_mod.Q193_POW_BITS,
    query_count: u32 = execution_mod.Q193_QUERY_COUNT,
    fri_log_blowup_factor: u32 = execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR,
    quotient_expansion_bits: u32 = execution_mod.D5_QUOTIENT_EXPANSION_BITS,
    backend: BackendReceiptV1,

    core_plus_providers_closed: bool,
    closed_sum_is_zero: bool,
    residuals_equal: bool,
    cpu_fresh_verified: bool,
    producer_proofs_destroyed_before_cpu_decode: bool,
    shared_context_verified_count: u32,
    plan_rebuilt_from_pins_matches_decoded: bool,
    manifest_identity_equal_across_engines: bool,
    stage_a_transactions_validated_authority: bool,
    diagnostic_cancellation_ran: bool,
    legacy_full_corpus_validations_producer: u8,
    legacy_full_corpus_validations_verifier: u8,

    full_statement_authority_id: AuthorityId,
    projected_statement_authority_id: AuthorityId,
    projection_identity: Digest,
    pins_identity: Digest,
    frame_v4_identity: Digest,
    leaf_omission_identity: Digest,
    plan_identity: Digest,
    session: Digest,
    call_list_commitment: Digest,
    manifest_identity: Digest,
    shared_relation_identity: Digest,
    relation_context_identity: Digest,
    interaction_pow: u64,
    core_artifact_byte_count: u64,
    core_artifact_sha256: [32]u8,
    core_commitments_identity: Digest,
    prover_residual: [4]u32,
    fresh_residual: [4]u32,
    closure_identity: Digest,
    strategy_identity: Digest,
    shard_count: u32,
    ordered_shard_proof_identity_sha256: [32]u8,
    ordered_fresh_identity_sha256: [32]u8,
    total_canonical_shard_bytes: u64,
    air_program_identity: Digest,
    execution_profile_identity: Digest,

    timing: TimingV1,
    budget: ProviderRouteBudgetV1,
    plan_resources: throughput.ResourceReceiptV1,
    stage_a_resources: throughput.ResourceReceiptV1,
    core_prove_resources: throughput.ResourceReceiptV1,
    shard_prove_resources: throughput.ResourceReceiptV1,
    encode_resources: throughput.ResourceReceiptV1,
    core_fresh_verify_resources: throughput.ResourceReceiptV1,
    shard_fresh_verify_resources: throughput.ResourceReceiptV1,
    closure_resources: throughput.ResourceReceiptV1,
    total_resources: throughput.ResourceReceiptV1,
    validation_identity_sha256: [32]u8,

    pub fn init(
        outcome: OutcomeV1,
        backend: BackendReceiptV1,
        budget: ProviderRouteBudgetV1,
    ) ReceiptV1 {
        var timing = outcome.timing;
        timing.runtime_init_ns = backend.runtime_initialization_ns;
        return .{
            .recursive_admissible = outcome.recursive_admissible,
            .production_eligible = outcome.production_eligible,
            .build_mode = @tagName(builtin.mode),
            .segment_index = outcome.segment_index,
            .elf_byte_count = outcome.elf_byte_count,
            .elf_sha256 = outcome.elf_sha256,
            .program_source_identity_sha256 = outcome.program_source_identity_sha256,
            .stwipr04_reference_byte_count = outcome.stwipr04_reference_byte_count,
            .stwipr04_reference_sha256 = outcome.stwipr04_reference_sha256,
            .stwipw04_payload_byte_count = outcome.stwipw04_payload_byte_count,
            .stwipw04_payload_sha256 = outcome.stwipw04_payload_sha256,
            .retained_source_byte_count = outcome.retained_source_byte_count,
            .retained_source_sha256 = outcome.retained_source_sha256,
            .prepared_source_identity_sha256 = outcome.prepared_source_identity_sha256,
            .prepared_profile_identity_sha256 = outcome.prepared_profile_identity_sha256,
            .program_base = outcome.program_base,
            .program_end = outcome.program_end,
            .declared_program_word_count = outcome.declared_program_word_count,
            .committed_program_word_count = outcome.committed_program_word_count,
            .program_leaf_count = outcome.program_leaf_count,
            .program_call_count = outcome.program_call_count,
            .program_commitment_root = outcome.program_commitment_root,
            .incremental_memory_call_count = outcome.incremental_memory_call_count,
            .call_count = outcome.call_count,
            .topology = outcome.topology,
            .backend = backend,
            .core_plus_providers_closed = outcome.core_plus_providers_closed,
            .closed_sum_is_zero = outcome.closed_sum_is_zero,
            .residuals_equal = outcome.residuals_equal,
            .cpu_fresh_verified = outcome.cpu_fresh_verified,
            .producer_proofs_destroyed_before_cpu_decode = outcome.producer_proofs_destroyed_before_cpu_decode,
            .shared_context_verified_count = outcome.shared_context_verified_count,
            .plan_rebuilt_from_pins_matches_decoded = outcome.plan_rebuilt_from_pins_matches_decoded,
            .manifest_identity_equal_across_engines = outcome.manifest_identity_equal_across_engines,
            .stage_a_transactions_validated_authority = outcome.stage_a_transactions_validated_authority,
            .diagnostic_cancellation_ran = outcome.diagnostic_cancellation_ran,
            .legacy_full_corpus_validations_producer = outcome.legacy_full_corpus_validations_producer,
            .legacy_full_corpus_validations_verifier = outcome.legacy_full_corpus_validations_verifier,
            .full_statement_authority_id = outcome.full_statement_authority_id,
            .projected_statement_authority_id = outcome.projected_statement_authority_id,
            .projection_identity = outcome.projection_identity,
            .pins_identity = outcome.pins_identity,
            .frame_v4_identity = outcome.frame_v4_identity,
            .leaf_omission_identity = outcome.leaf_omission_identity,
            .plan_identity = outcome.plan_identity,
            .session = outcome.session,
            .call_list_commitment = outcome.call_list_commitment,
            .manifest_identity = outcome.manifest_identity,
            .shared_relation_identity = outcome.shared_relation_identity,
            .relation_context_identity = outcome.relation_context_identity,
            .interaction_pow = outcome.interaction_pow,
            .core_artifact_byte_count = outcome.core_artifact_byte_count,
            .core_artifact_sha256 = outcome.core_artifact_sha256,
            .core_commitments_identity = outcome.core_commitments_identity,
            .prover_residual = outcome.prover_residual,
            .fresh_residual = outcome.fresh_residual,
            .closure_identity = outcome.closure_identity,
            .strategy_identity = outcome.strategy_identity,
            .shard_count = outcome.shard_count,
            .ordered_shard_proof_identity_sha256 = outcome.ordered_shard_proof_identity_sha256,
            .ordered_fresh_identity_sha256 = outcome.ordered_fresh_identity_sha256,
            .total_canonical_shard_bytes = outcome.total_canonical_shard_bytes,
            .air_program_identity = outcome.air_program_identity,
            .execution_profile_identity = outcome.execution_profile_identity,
            .timing = timing,
            .budget = budget,
            .plan_resources = outcome.plan_resources,
            .stage_a_resources = outcome.stage_a_resources,
            .core_prove_resources = outcome.core_prove_resources,
            .shard_prove_resources = outcome.shard_prove_resources,
            .encode_resources = outcome.encode_resources,
            .core_fresh_verify_resources = outcome.core_fresh_verify_resources,
            .shard_fresh_verify_resources = outcome.shard_fresh_verify_resources,
            .closure_resources = outcome.closure_resources,
            .total_resources = outcome.total_resources,
            .validation_identity_sha256 = [_]u8{0} ** 32,
        };
    }

    /// Every field-level requirement of Section 4, with no seal involved.
    /// Required-true flags, required-false activation guards, provenance
    /// strings with no silent default, the 26-shard pins, and every identity
    /// non-zero.
    pub fn validateFields(self: ReceiptV1) !void {
        try requireFirstArm(self.topology);
        try self.plan_resources.validate();
        try self.stage_a_resources.validate();
        try self.core_prove_resources.validate();
        try self.shard_prove_resources.validate();
        try self.encode_resources.validate();
        try self.core_fresh_verify_resources.validate();
        try self.shard_fresh_verify_resources.validate();
        try self.closure_resources.validate();
        try self.total_resources.validate();
        const recomposed_call_count = std.math.add(
            u64,
            self.program_call_count,
            self.incremental_memory_call_count,
        ) catch return error.InvalidStage101ProviderRouteReceipt;
        const steady_state = self.timing.steadyStateTotalNs() catch
            return error.InvalidStage101ProviderRouteReceipt;
        if (self.format_version != FORMAT_VERSION or
            !std.mem.eql(u8, self.schema, receipt_schema) or
            !std.mem.eql(u8, self.provider_route, provider_route_degree5_omit_v1) or
            !std.mem.eql(u8, self.durable_core_envelope, durable_core_envelope) or
            !self.durable_shard_artifacts or
            !std.mem.eql(u8, self.fresh_calls_source, fresh_calls_source) or
            !std.mem.eql(u8, self.provider_plan_admission, provider_plan_admission) or
            self.known_red_baselines.len != known_red_baselines.len or
            self.production_active or self.complete_leaf_proof or
            self.recursive_capture_available or self.recursive_admissible or
            self.production_eligible or
            !std.mem.eql(u8, self.build_mode, "ReleaseFast") or
            self.segment_index != RetainedSourcePinsV1.segment_index or
            self.elf_byte_count != RetainedSourcePinsV1.elf_byte_count or
            !std.mem.eql(u8, &self.elf_sha256, &RetainedSourcePinsV1.elf_sha256) or
            std.mem.allEqual(u8, &self.program_source_identity_sha256, 0) or
            self.stwipr04_reference_byte_count !=
                RetainedSourcePinsV1.reference_byte_count or
            !std.mem.eql(
                u8,
                &self.stwipr04_reference_sha256,
                &RetainedSourcePinsV1.reference_sha256,
            ) or
            self.stwipw04_payload_byte_count !=
                RetainedSourcePinsV1.payload_byte_count or
            !std.mem.eql(
                u8,
                &self.stwipw04_payload_sha256,
                &RetainedSourcePinsV1.payload_sha256,
            ) or self.retained_source_byte_count == 0 or
            std.mem.allEqual(u8, &self.retained_source_sha256, 0) or
            std.mem.allEqual(u8, &self.prepared_source_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.prepared_profile_identity_sha256, 0) or
            self.program_base != RetainedSourcePinsV1.program_base or
            self.program_end != RetainedSourcePinsV1.program_end or
            self.declared_program_word_count !=
                RetainedSourcePinsV1.declared_program_word_count or
            self.committed_program_word_count !=
                RetainedSourcePinsV1.committed_program_word_count or
            self.program_leaf_count != RetainedSourcePinsV1.program_leaf_count or
            self.program_call_count != RetainedSourcePinsV1.program_call_count or
            self.incremental_memory_call_count !=
                RetainedSourcePinsV1.incremental_memory_call_count or
            self.call_count != RetainedSourcePinsV1.full_call_count or
            self.call_count != recomposed_call_count or
            self.call_count != self.topology.total_call_count or
            self.pow_bits != execution_mod.Q193_POW_BITS or
            self.query_count != execution_mod.Q193_QUERY_COUNT or
            self.query_count != 193 or
            self.fri_log_blowup_factor != execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR or
            self.quotient_expansion_bits != execution_mod.D5_QUOTIENT_EXPANSION_BITS)
        {
            return error.InvalidStage101ProviderRouteReceipt;
        }
        if (!self.core_plus_providers_closed or !self.closed_sum_is_zero or
            !self.residuals_equal or !self.cpu_fresh_verified or
            !self.producer_proofs_destroyed_before_cpu_decode or
            !self.plan_rebuilt_from_pins_matches_decoded or
            !self.manifest_identity_equal_across_engines or
            !self.stage_a_transactions_validated_authority or
            self.shard_count != 26 or
            self.shard_count != self.topology.shard_count or
            self.shared_context_verified_count != self.shard_count or
            self.legacy_full_corpus_validations_producer != 1 or
            self.legacy_full_corpus_validations_verifier != 1 or
            !std.mem.eql(u8, &self.pins_identity, &ProviderOmissionPinsV1.identity()) or
            !std.mem.eql(u8, &self.plan_identity, &self.topology.plan_identity) or
            !std.mem.eql(u32, &self.prover_residual, &self.fresh_residual) or
            self.core_artifact_byte_count == 0 or
            self.total_canonical_shard_bytes == 0 or
            self.total_canonical_shard_bytes >
                self.topology.encoded_proof_reservation_bytes or
            self.interaction_pow == 0 or
            self.timing.total_ns != steady_state or
            isZeroAuthorityId(self.full_statement_authority_id) or
            isZeroAuthorityId(self.projected_statement_authority_id) or
            std.meta.eql(
                self.full_statement_authority_id,
                self.projected_statement_authority_id,
            ))
        {
            return error.InvalidStage101ProviderRouteReceipt;
        }
        inline for (.{
            self.projection_identity,
            self.frame_v4_identity,
            self.leaf_omission_identity,
            self.plan_identity,
            self.session,
            self.call_list_commitment,
            self.manifest_identity,
            self.shared_relation_identity,
            self.relation_context_identity,
            self.core_artifact_sha256,
            self.core_commitments_identity,
            self.closure_identity,
            self.strategy_identity,
            self.ordered_shard_proof_identity_sha256,
            self.ordered_fresh_identity_sha256,
            self.air_program_identity,
            self.execution_profile_identity,
            self.backend.aot_manifest_sha256,
            self.backend.aot_metallib_sha256,
            self.backend.aot_source_sha256,
            self.backend.aot_air_sha256,
            self.backend.backend_identity_sha256,
            self.backend.platform_identity_sha256,
            self.backend.build_identity_sha256,
        }) |digest| {
            if (std.mem.allEqual(u8, &digest, 0))
                return error.InvalidStage101ProviderRouteReceipt;
        }
        if (self.backend.aot_native_export_count == 0 or
            self.backend.telemetry.metal_dispatch_total == 0 or
            self.backend.telemetry.base_batch_dispatches < self.shard_count or
            self.backend.telemetry.lookup_batch_dispatches < self.shard_count or
            self.backend.telemetry.polynomial_declines != 0 or
            self.backend.telemetry.cpu_fallback_total !=
                self.backend.admitted_host_placements)
        {
            return error.InvalidStage101ProviderRouteReceipt;
        }
    }

    /// Field requirements plus the seal: the identity must be the SHA-256 of
    /// the canonical JSON with the identity field zeroed.
    pub fn validate(self: ReceiptV1, allocator: std.mem.Allocator) !void {
        try self.validateFields();
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
        )) return error.InvalidStage101ProviderRouteReceipt;
    }
};

/// Seals the receipt exactly like the sweep: identity over the zero-identity
/// canonical JSON, then the whole value re-validated before it is encoded.
pub fn sealReceiptAlloc(
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

/// Stage 8: seal, publish create-only and durable, print the summary line, and
/// only THEN validate the fail-closed budget -- the leaf's receipt-then-budget
/// order, so a run over budget still leaves its evidence on disk.
pub fn publishReceiptThenValidateBudget(
    allocator: std.mem.Allocator,
    output_path: []const u8,
    receipt: *ReceiptV1,
) !void {
    const encoded = try sealReceiptAlloc(allocator, receipt);
    defer allocator.free(encoded);
    try artifact_io.publishCreateOnlyDurable(output_path, encoded);
    printReceiptSummary(receipt);
    try receipt.budget.validate(receipt.timing);
}

fn printReceiptSummary(receipt: *const ReceiptV1) void {
    const receipt_hex = std.fmt.bytesToHex(
        receipt.validation_identity_sha256,
        .lower,
    );
    const core_hex = std.fmt.bytesToHex(receipt.core_artifact_sha256, .lower);
    const shards_hex = std.fmt.bytesToHex(
        receipt.ordered_shard_proof_identity_sha256,
        .lower,
    );
    const closure_hex = std.fmt.bytesToHex(receipt.closure_identity, .lower);
    const projection_hex = std.fmt.bytesToHex(receipt.projection_identity, .lower);
    const shared_hex = std.fmt.bytesToHex(receipt.shared_relation_identity, .lower);
    const timing = receipt.timing;
    std.debug.print(
        "STAGE101_D5_ROUTE_RECEIPT_V1 closed={} closed_sum_zero={} " ++
            "residuals_equal={} shards={} shared_context_verified={} " ++
            "core_bytes={} core_sha256={s} shard_batch_sha256={s} " ++
            "closure={s} projection={s} shared_relation={s} receipt={s}\n",
        .{
            receipt.core_plus_providers_closed,
            receipt.closed_sum_is_zero,
            receipt.residuals_equal,
            receipt.shard_count,
            receipt.shared_context_verified_count,
            receipt.core_artifact_byte_count,
            &core_hex,
            &shards_hex,
            &closure_hex,
            &projection_hex,
            &shared_hex,
            &receipt_hex,
        },
    );
    std.debug.print(
        "STAGE101_D5_ROUTE_TIMING_V1 runtime_init_ns={} admission_ns={} " ++
            "replay_ns={} snapshot_ns={} witness_ns={} profile_ns={} " ++
            "plan_ns={} stage_a_ns={} core_prove_ns={} shard_prove_ns={} " ++
            "encode_ns={} core_fresh_verify_ns={} shard_fresh_verify_ns={} " ++
            "closure_ns={} total_ns={} budget_total_ns={}\n",
        .{
            timing.runtime_init_ns,
            timing.admission_ns,
            timing.replay_ns,
            timing.snapshot_ns,
            timing.witness_ns,
            timing.profile_ns,
            timing.plan_ns,
            timing.stage_a_ns,
            timing.core_prove_ns,
            timing.shard_prove_ns,
            timing.encode_ns,
            timing.core_fresh_verify_ns,
            timing.shard_fresh_verify_ns,
            timing.closure_ns,
            timing.total_ns,
            receipt.budget.total_ns,
        },
    );
}

// ---------------------------------------------------------------------------
// Stages 1-6
// ---------------------------------------------------------------------------

pub const OptionsV1 = struct {
    /// The leaf's host execution policy (worker count, host byte budget,
    /// detected capacity). It drives the core prove's execution options and
    /// the D5 host capacity; it never enters the plan (the pins do).
    execution_policy: throughput.PolicyV1,
    /// G7: serial Poseidon cancellation diagnostic, off unless asked for.
    diagnostic_cancellation: bool = false,
    /// Optional stage recorder for the core prove (`STWO_ZIG_STAGE101_STAGE_PROFILE`).
    recorder: ?*prover_api.stage_profile.Recorder = null,
    /// Whole-command measurement begun by the caller before the replay
    /// command cold-opened the segment; finished at the end of stage 6.
    total_measurement: *throughput.MeasurementV1,
};

/// The POD authorities the producer keeps after every proof object is gone.
fn RetainedProducerAuthoritiesV1(comptime Engine: type) type {
    return struct {
        statement: frontend.air.statement_v2.RiscVStatementV2,
        extension: frontend.air.guest_precompile.ethereum_statement.Statement,
        projection: prover.guest_precompile.native_provider_omit_v1.ProjectionV1,
        projected_bridge_geometry: prover.incremental_bridge_external_v3.GeometryV3,
        frame_v4: route.IncrementalOmissionFrameV4,
        leaf_omission: route.LeafOmissionAuthorityV4,
        shared_relation: protocol.SharedRelationAuthorityV1(Engine),
        prover_residual: QM31,
        profile_identity_sha256: [32]u8,
        manifest_identity: Digest,
    };
}

pub fn RouteV1(
    comptime ProducerEngine: type,
    comptime CpuEngine: type,
) type {
    comptime {
        if (!transcript_mod.transcriptTypesCompatible(ProducerEngine, CpuEngine)) {
            @compileError(
                "Stage101 D5 route producer and cold verifier transcript types differ",
            );
        }
    }
    return struct {
        pub const Producer = ProducerEngine;
        pub const Verifier = CpuEngine;
        pub const Extension = protocol.Extension(ProducerEngine);
        pub const ProducerManifest = protocol.ProviderStageAManifestV1(ProducerEngine);
        pub const VerifierManifest = protocol.ProviderStageAManifestV1(CpuEngine);

        /// Stages 1-6. Every proof object created here is destroyed here; the
        /// caller receives POD evidence only.
        pub fn proveAndFreshVerify(
            allocator: std.mem.Allocator,
            custody: replay_command.PreparedVisitorCustodyV1,
            transaction: *const replay_command.PreparedProofTransactionV4,
            call_view: replay_command.PreparedProviderCallViewV1,
            evidence: replay_command.PreparedVisitorEvidenceV1,
            options: OptionsV1,
        ) !OutcomeV1 {
            // ---- 1. Sweep prologue --------------------------------------
            try custody.validateAgainst(call_view);
            try call_view.validateAgainst(transaction);
            try evidence.validate();
            try RetainedSourcePinsV1.validate(custody, call_view);
            try options.execution_policy.validate();
            const inventory = call_view.inventory;
            const calls = call_view.calls;

            var plan_measurement = try throughput.MeasurementV1.begin();
            var plan = try provider_authority.ProviderShardPlanV1.create(
                allocator,
                call_view.source_identity_sha256,
                calls,
                ProviderOmissionPinsV1.request(inventory.total_call_count),
            );
            defer plan.deinit(allocator);
            try ProviderOmissionPinsV1.validateRequest(
                plan.residency.request,
                inventory.total_call_count,
            );
            var producer_calls = try provider_authority
                .OwnedValidatedPlanCallAuthorityV1.init(
                allocator,
                &plan,
                calls,
            );
            defer producer_calls.deinit();
            const host = try execution_mod.HostCapacityV1.detect(
                options.execution_policy.host.host_byte_limit,
            );
            const execution = try execution_mod.AuthorityV1.initAgainstPlan(
                host,
                &plan,
                pinnedExecutionRequest(),
            );
            const topology = try execution_mod.TopologyReceiptV1.init(
                &plan,
                &execution,
            );
            try requireFirstArm(topology);
            const program = try provider.VerifierProgramAuthorityV2.coldCompile(
                allocator,
            );
            const exec_profile = try execution.executionProfile(program);
            const pcs_config = block_leaf_support.recursive_pcs_config;
            const plan_resources = try plan_measurement.finish(1);

            // ---- 2. Stage A on the producer engine (validated, G1) -------
            var stage_a_measurement = try throughput.MeasurementV1.begin();
            var prepared = try prepared_batch.prepareParallelValidated(
                ProducerEngine,
                allocator,
                pcs_config,
                program,
                &plan,
                calls,
                &producer_calls,
                &execution,
            );
            var prepared_live = true;
            defer if (prepared_live) prepared.deinit();
            var owned_manifest = try ProducerManifest.createFromRootsValidated(
                allocator,
                &plan,
                calls,
                &producer_calls,
                prepared.roots(),
            );
            var owned_manifest_live = true;
            defer if (owned_manifest_live) owned_manifest.deinit(allocator);
            const stage_a_resources = try stage_a_measurement.finish(1);

            // ---- 3. Omitted-provider core under the shared draw ----------
            var core_measurement = try throughput.MeasurementV1.begin();
            var extension = try Extension.initValidated(
                &plan,
                calls,
                &producer_calls,
                &owned_manifest.manifest,
            );
            var core_channel = ProducerEngine.Channel{};
            var output = try transaction.proveOmittedProviderWithEngineUsingChannel(
                ProducerEngine,
                allocator,
                options.recorder,
                &core_channel,
                try options.execution_policy.executionOptions(),
                &extension,
                .{ .diagnostic_cancellation = options.diagnostic_cancellation },
            );
            var output_live = true;
            defer if (output_live) output.deinit(allocator);
            const core_prove_resources = try core_measurement.finish(1);
            if (options.recorder) |recorder| try printStageProfileSnapshot(
                allocator,
                recorder,
            );
            const retained = RetainedProducerAuthoritiesV1(ProducerEngine){
                .statement = output.statement,
                .extension = output.extension,
                .projection = output.projection,
                .projected_bridge_geometry = output.projected_bridge_geometry,
                .frame_v4 = output.frame_v4,
                .leaf_omission = output.leaf_omission,
                .shared_relation = output.shared_relation,
                .prover_residual = output.prover_residual,
                .profile_identity_sha256 = output.profile_identity_sha256,
                .manifest_identity = owned_manifest.manifest.identity,
            };

            // ---- 4. Shards under the same draw ---------------------------
            var shard_measurement = try throughput.MeasurementV1.begin();
            const view = try transaction.proofView();
            var lookup_manifest = lookup_physical_v2.Manifest.native();
            const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
                &retained.statement.core,
                &lookup_manifest,
            );
            const source_producer = transcript_mod.SourceV1(ProducerEngine){
                .native = &retained.statement,
                .extension = &retained.extension,
                .lookup_manifest = &lookup_manifest,
                .authenticated_lookup = &authenticated,
                .projection = &retained.projection,
                .plan = &plan,
                .calls = calls,
                .validated_calls = &producer_calls,
                .provider_stage_a = &owned_manifest.manifest,
                .shared = retained.shared_relation,
                .profile = view.profile,
                .role_aware_public = view.role_aware_public,
                .projected_bridge = retained.projected_bridge_geometry,
                .frame_v4 = retained.frame_v4,
                .leaf_omission = retained.leaf_omission,
                .pcs_config = pcs_config,
            };
            var shards = try shared_batch.proveSharedPreparedParallelValidated(
                ProducerEngine,
                allocator,
                pcs_config,
                program,
                exec_profile,
                source_producer,
                &producer_calls,
                &prepared,
                &execution,
            );
            defer shards.deinit();
            const shard_prove_resources = try shard_measurement.finish(1);
            const producer_call_work = producer_calls.workReceipt();
            try producer_call_work.validate();

            // ---- 5. STWIOL01, then destroy every producer proof ----------
            var encode_measurement = try throughput.MeasurementV1.begin();
            var omission_section = try envelope.OmissionSectionV1.canonical(
                ProducerEngine,
                allocator,
                &retained.projection,
                &plan,
                &owned_manifest.manifest,
                retained.shared_relation,
                &retained.projected_bridge_geometry,
                &retained.frame_v4,
                &retained.leaf_omission,
                program.air_program_identity,
                exec_profile.identity,
            );
            defer omission_section.deinit(allocator);
            const shard_slices = try allocator.alloc([]const u8, shards.shards.len);
            defer allocator.free(shard_slices);
            var total_shard_bytes: u64 = 0;
            for (shard_slices, shards.shards) |*slice, shard| {
                slice.* = shard.stwd5pr1_bytes;
                total_shard_bytes = std.math.add(
                    u64,
                    total_shard_bytes,
                    shard.stwd5pr1_bytes.len,
                ) catch return error.Stage101ProviderRouteOverflow;
            }
            const artifact_bytes = try envelope.encodeAlloc(
                ProducerEngine,
                allocator,
                .{
                    .statement = &retained.statement,
                    .role_aware_public = view.role_aware_public,
                    .extension = &retained.extension,
                    .profile = view.profile,
                    .projection = &retained.projection,
                    .omission = &omission_section,
                    .base_claim = output.claims.base,
                    .extension_claim = &output.claims.ethereum,
                    .bridge_claim = output.claims.bridge,
                    .proof = &output.proof,
                    .shards = shard_slices,
                },
                artifact_limits,
            );
            defer allocator.free(artifact_bytes);
            // Producer proof objects die here, before any cold decode: the
            // CPU verifier only ever sees bytes and POD authorities.
            output.deinit(allocator);
            output_live = false;
            prepared.deinit();
            prepared_live = false;
            owned_manifest.deinit(allocator);
            owned_manifest_live = false;
            const producer_proofs_destroyed_before_cpu_decode = true;
            const encode_resources = try encode_measurement.finish(1);
            const artifact_sha256 = sha256(artifact_bytes);

            // ---- 6. CPU fresh verify from bytes --------------------------
            var core_verify_measurement = try throughput.MeasurementV1.begin();
            var cold_validation = public_data_v2.PublicDataV2.ValidationCountersV2{};
            const retained_snapshots = view.public_wire.retained_snapshots orelse
                return error.Stage101ProviderRouteRetainedSnapshotsMissing;
            var decoded = try envelope.decodeAllocWithRetainedLease(
                CpuEngine,
                allocator,
                artifact_bytes,
                artifact_limits,
                retained_snapshots,
                &cold_validation,
            );
            var decoded_proof_moved = false;
            defer if (decoded_proof_moved)
                decoded.deinitAfterProofMoved(allocator)
            else
                decoded.deinit(allocator);
            const cold_validation_snapshot = cold_validation.snapshot();
            if (cold_validation_snapshot.retained_root_authentications != 1 or
                cold_validation_snapshot.legacy_full_authentications != 0)
            {
                return error.Stage101ProviderRouteValidationBudgetMismatch;
            }

            // The plan is rebuilt from the pins and the call list, never
            // recovered from the decoded section, and then compared to it.
            var plan_cpu = try provider_authority.ProviderShardPlanV1.create(
                allocator,
                call_view.source_identity_sha256,
                calls,
                ProviderOmissionPinsV1.request(inventory.total_call_count),
            );
            defer plan_cpu.deinit(allocator);
            try requireDecodedPlanMatches(&plan_cpu, &decoded.omission);
            const plan_rebuilt_from_pins_matches_decoded = true;
            var fresh_calls = try provider_authority
                .OwnedValidatedPlanCallAuthorityV1.init(
                allocator,
                &plan_cpu,
                calls,
            );
            defer fresh_calls.deinit();

            // Stage-A manifest rebuilt from the DECODED roots; its identity
            // must be the producer's and the section's.
            const roots_cpu = try allocator.alloc(
                harness.StageACommitment(CpuEngine),
                decoded.omission.shards.len,
            );
            defer allocator.free(roots_cpu);
            for (roots_cpu, decoded.omission.shards) |*root, record| {
                root.* = .{
                    .preprocessed_root = rootFromBytes(
                        CpuEngine,
                        record.preprocessed_root,
                    ),
                    .main_root = rootFromBytes(CpuEngine, record.main_root),
                };
            }
            var manifest_cpu = try VerifierManifest.createFromRootsValidated(
                allocator,
                &plan_cpu,
                calls,
                &fresh_calls,
                roots_cpu,
            );
            defer manifest_cpu.deinit(allocator);
            if (!std.mem.eql(
                u8,
                &manifest_cpu.manifest.identity,
                &retained.manifest_identity,
            ) or !std.mem.eql(
                u8,
                &manifest_cpu.manifest.identity,
                &decoded.omission.manifest_identity,
            )) return error.Stage101ProviderRouteManifestMismatch;
            const manifest_identity_equal_across_engines = true;

            const shared_cpu = transcript_mod.retypeSharedRelation(
                ProducerEngine,
                CpuEngine,
                retained.shared_relation,
            );
            if (!std.mem.eql(
                u8,
                &shared_cpu.identity,
                &decoded.omission.shared_identity,
            )) return error.Stage101ProviderRouteSharedAuthorityMismatch;
            var verify_ext = try protocol.Extension(CpuEngine)
                .initForFreshVerifyValidated(
                &plan_cpu,
                calls,
                &fresh_calls,
                &manifest_cpu.manifest,
                shared_cpu,
            );
            var lookup_manifest_cpu = lookup_physical_v2.Manifest.native();
            const authenticated_cpu = try lookup_physical_v2.AuthenticatedStatement
                .init(&decoded.statement.core, &lookup_manifest_cpu);
            var verifier_core = decoded.statement.core;
            try verify_ext.prepareProjectedVerifierCore(
                &decoded.statement,
                &decoded.extension,
                &lookup_manifest_cpu,
                &authenticated_cpu,
                &verifier_core,
            );
            const projection_cpu = try verify_ext.providerProjection();
            if (!std.mem.eql(
                u8,
                &projection_cpu.identity,
                &decoded.omission.projection_identity,
            )) return error.Stage101ProviderRouteProjectionMismatch;
            var claims = try decoded.decodeClaims(
                allocator,
                &projection_cpu.projected_native.core,
                &decoded.extension,
            );
            defer claims.deinit(allocator);
            const projected_cpu = try orchestration.projectedRouteGeometry(
                &decoded.profile.bridge_geometry,
                &projection_cpu.projected_native.core,
                &decoded.extension,
                &authenticated_cpu,
                &lookup_manifest_cpu,
            );
            const frame_cpu = try route.IncrementalOmissionFrameV4.canonical(
                projection_cpu,
                decoded.profile.bridge_geometry.n_rows,
                projected_cpu.prefix,
            );
            const leaf_omission_cpu = try orchestration.leafOmissionAuthority(
                decoded.profile.identity_sha256,
                &frame_cpu,
                shared_cpu.identity,
                decoded.statement.authority_id,
            );
            try decoded.omission.validateAgainst(
                projection_cpu,
                &plan_cpu,
                &manifest_cpu.manifest,
                shared_cpu,
                &projected_cpu.bridge,
                &frame_cpu,
                &leaf_omission_cpu,
            );
            try decoded.omission.validateDegree5Program(
                program.air_program_identity,
                exec_profile.identity,
            );

            var verify_channel = CpuEngine.Channel{};
            decoded_proof_moved = true;
            const fresh_core_result = try orchestration
                .verifyOmittedProviderWithEngineUsingChannel(
                CpuEngine,
                profile_mod.AuthorityV4,
                allocator,
                &decoded.statement,
                &decoded.extension,
                &decoded.role_aware_public.value,
                &decoded.profile,
                decoded.proof,
                claims.base_claim,
                &claims.extension_claim,
                claims.bridge_claim,
                decoded.omission.toDecodedOmission(),
                &verify_channel,
                &verify_ext,
            );
            if (!std.meta.eql(fresh_core_result.leaf_omission, leaf_omission_cpu))
                return error.Stage101ProviderRouteLeafOmissionMismatch;
            const shared_verified = verify_ext.shared_relation orelse
                return error.Stage101ProviderRouteSharedAuthorityMismatch;
            if (!std.mem.eql(u8, &shared_verified.identity, &shared_cpu.identity))
                return error.Stage101ProviderRouteSharedAuthorityMismatch;
            const core_fresh_verify_resources = try core_verify_measurement.finish(1);

            var shard_verify_measurement = try throughput.MeasurementV1.begin();
            const source_cpu = transcript_mod.SourceV1(CpuEngine){
                .native = &decoded.statement,
                .extension = &decoded.extension,
                .lookup_manifest = &lookup_manifest_cpu,
                .authenticated_lookup = &authenticated_cpu,
                .projection = projection_cpu,
                .plan = &plan_cpu,
                .calls = calls,
                .validated_calls = &fresh_calls,
                .provider_stage_a = &manifest_cpu.manifest,
                .shared = shared_verified,
                .profile = &decoded.profile,
                .role_aware_public = &decoded.role_aware_public.value,
                .projected_bridge = projected_cpu.bridge,
                .frame_v4 = frame_cpu,
                .leaf_omission = fresh_core_result.leaf_omission,
                .pcs_config = pcs_config,
            };
            // The envelope's shard sections must be the very bytes the batch
            // carries: the cold side verifies what was published, not what
            // the producer process still holds.
            if (decoded.shards.len != shards.shards.len)
                return error.Stage101ProviderRouteShardBytesMismatch;
            for (decoded.shards, shards.shards) |cold, produced| {
                if (!std.mem.eql(u8, cold, produced.stwd5pr1_bytes))
                    return error.Stage101ProviderRouteShardBytesMismatch;
            }
            var fresh_shards = try shared_batch.verifySharedFreshParallelValidated(
                ProducerEngine,
                CpuEngine,
                allocator,
                pcs_config,
                program,
                exec_profile,
                source_cpu,
                &fresh_calls,
                &shards,
                &execution,
            );
            defer fresh_shards.deinit();
            const shard_fresh_verify_resources = try shard_verify_measurement.finish(1);
            const shared_context_verified_count =
                fresh_shards.sharedContextVerifiedCount();
            if (shared_context_verified_count != plan_cpu.shards.len)
                return error.Stage101ProviderRouteSharedContextCountMismatch;

            var closure_measurement = try throughput.MeasurementV1.begin();
            const closed = try degree5.closeFreshClaimsV2(
                CpuEngine,
                allocator,
                program,
                exec_profile,
                source_cpu.ordinary(),
                fresh_core_result.fresh_core,
                fresh_shards.claims,
            );
            try closed.closure.validate();
            try closed.strategy.validate();
            if (!closed.closure.closed_sum.isZero())
                return error.Stage101ProviderRouteClosureNotZero;
            if (!retained.prover_residual.eql(
                fresh_core_result.fresh_core.poseidon2_residual,
            )) return error.Stage101ProviderRouteResidualMismatch;
            const closure_resources = try closure_measurement.finish(1);
            const fresh_call_work = fresh_calls.workReceipt();
            try fresh_call_work.validate();
            const total_resources = try options.total_measurement.finish(1);

            var timing = TimingV1{
                .runtime_init_ns = 0,
                .admission_ns = evidence.input_admission_ns,
                .replay_ns = evidence.compact_replay_ns,
                .snapshot_ns = evidence.snapshot_ns,
                .witness_ns = evidence.preparation.phase_timing.witness_prepare_ns,
                .profile_ns = evidence.preparation.phase_timing
                    .statement_profile_prepare_ns,
                .plan_ns = plan_resources.wall_ns,
                .stage_a_ns = stage_a_resources.wall_ns,
                .core_prove_ns = core_prove_resources.wall_ns,
                .shard_prove_ns = shard_prove_resources.wall_ns,
                .encode_ns = encode_resources.wall_ns,
                .core_fresh_verify_ns = core_fresh_verify_resources.wall_ns,
                .shard_fresh_verify_ns = shard_fresh_verify_resources.wall_ns,
                .closure_ns = closure_resources.wall_ns,
                .total_ns = 0,
            };
            timing.total_ns = timing.steadyStateTotalNs() catch
                return error.Stage101ProviderRouteOverflow;

            return .{
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
                .call_count = @intCast(calls.len),
                .topology = topology,
                .full_statement_authority_id = retained.statement.authority_id,
                .projected_statement_authority_id = retained.projection.projected_native.authority_id,
                .projection_identity = retained.projection.identity,
                .pins_identity = ProviderOmissionPinsV1.identity(),
                .frame_v4_identity = retained.frame_v4.identity,
                .leaf_omission_identity = retained.leaf_omission.identity,
                .plan_identity = plan.identity,
                .session = plan.session,
                .call_list_commitment = plan.call_list_commitment,
                .manifest_identity = retained.manifest_identity,
                .shared_relation_identity = retained.shared_relation.identity,
                .relation_context_identity = retained.shared_relation.relation_context.identity,
                .interaction_pow = retained.shared_relation.interaction_pow,
                .core_artifact_byte_count = artifact_bytes.len,
                .core_artifact_sha256 = artifact_sha256,
                .core_commitments_identity = fresh_core_result.fresh_core.proof_commitments_identity,
                .prover_residual = qm31Words(retained.prover_residual),
                .fresh_residual = qm31Words(
                    fresh_core_result.fresh_core.poseidon2_residual,
                ),
                .closure_identity = closed.closure.identity,
                .strategy_identity = closed.strategy.identity,
                .shard_count = @intCast(plan.shards.len),
                .ordered_shard_proof_identity_sha256 = shardBatchIdentity(&shards),
                .ordered_fresh_identity_sha256 = freshBatchIdentity(&fresh_shards),
                .total_canonical_shard_bytes = total_shard_bytes,
                .air_program_identity = program.air_program_identity,
                .execution_profile_identity = exec_profile.identity,
                .core_plus_providers_closed = true,
                .closed_sum_is_zero = closed.closure.closed_sum.isZero(),
                .residuals_equal = true,
                .cpu_fresh_verified = true,
                .producer_proofs_destroyed_before_cpu_decode = producer_proofs_destroyed_before_cpu_decode,
                .shared_context_verified_count = @intCast(shared_context_verified_count),
                .plan_rebuilt_from_pins_matches_decoded = plan_rebuilt_from_pins_matches_decoded,
                .manifest_identity_equal_across_engines = manifest_identity_equal_across_engines,
                .stage_a_transactions_validated_authority = true,
                .recursive_admissible = closed.closure.recursive_admissible,
                .production_eligible = closed.closure.production_eligible,
                .diagnostic_cancellation_ran = options.diagnostic_cancellation,
                .legacy_full_corpus_validations_producer = @intCast(
                    producer_call_work.full_corpus_validations,
                ),
                .legacy_full_corpus_validations_verifier = @intCast(
                    fresh_call_work.full_corpus_validations,
                ),
                .timing = timing,
                .plan_resources = plan_resources,
                .stage_a_resources = stage_a_resources,
                .core_prove_resources = core_prove_resources,
                .shard_prove_resources = shard_prove_resources,
                .encode_resources = encode_resources,
                .core_fresh_verify_resources = core_fresh_verify_resources,
                .shard_fresh_verify_resources = shard_fresh_verify_resources,
                .closure_resources = closure_resources,
                .total_resources = total_resources,
            };
        }
    };
}

/// Every decoded shard record must equal the record the verifier rebuilds
/// from the pinned plan; the plan identity must be the decoded one.
fn requireDecodedPlanMatches(
    plan: *const provider_authority.ProviderShardPlanV1,
    section: *const envelope.OmissionSectionV1,
) !void {
    if (!std.mem.eql(u8, &plan.identity, &section.plan_identity) or
        !std.mem.eql(u8, &plan.session, &section.session) or
        !std.mem.eql(
            u8,
            &plan.call_list_commitment,
            &section.call_list_commitment,
        ) or plan.total_call_count != section.total_call_count or
        plan.shard_count != section.shard_count or
        plan.shards.len != section.shards.len)
    {
        return error.Stage101ProviderRoutePlanMismatch;
    }
    for (plan.shards, section.shards, 0..) |descriptor, record, index| {
        if (descriptor.shard_index != index or
            !std.mem.eql(u8, &descriptor.identity, &record.descriptor_identity) or
            descriptor.first_call != record.first_call or
            descriptor.call_count != record.call_count or
            descriptor.expected_log_size != record.expected_log_size)
        {
            return error.Stage101ProviderRoutePlanMismatch;
        }
    }
}

fn rootFromBytes(
    comptime Engine: type,
    bytes: envelope.RootBytes,
) Engine.Hasher.Hash {
    comptime {
        if (@sizeOf(Engine.Hasher.Hash) != @sizeOf(envelope.RootBytes))
            @compileError("Stage101 D5 route expects a 32-byte engine root");
    }
    return std.mem.bytesToValue(Engine.Hasher.Hash, &bytes);
}

fn printStageProfileSnapshot(
    allocator: std.mem.Allocator,
    recorder: *prover_api.stage_profile.Recorder,
) !void {
    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    printStageProfile(profile.stages, 0);
}

fn printStageProfile(
    stages: []const prover_api.stage_profile.StageNode,
    depth: usize,
) void {
    for (stages) |stage| {
        std.debug.print(
            "STAGE101_PROFILE depth={} id={s} seconds={d:.9}\n",
            .{ depth, stage.id, stage.seconds },
        );
        if (stage.children) |children| printStageProfile(children, depth + 1);
    }
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
        RetainedSourcePinsV1.reference_sha256,
        .lower,
    );
    const payload_observed = std.fmt.bytesToHex(
        custody.public_wire.segment.wire_artifact.sha256,
        .lower,
    );
    const payload_expected = std.fmt.bytesToHex(
        RetainedSourcePinsV1.payload_sha256,
        .lower,
    );
    const elf_observed = std.fmt.bytesToHex(custody.elf.sha256, .lower);
    const elf_expected = std.fmt.bytesToHex(RetainedSourcePinsV1.elf_sha256, .lower);
    const program_source = std.fmt.bytesToHex(
        custody.program_source_identity_sha256,
        .lower,
    );
    const inventory = call_view.inventory;
    std.debug.print(
        "STAGE101_D5_ROUTE_RETAINED_SOURCE=mismatch " ++
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
            RetainedSourcePinsV1.segment_index,
            call_view.calls.len,
            RetainedSourcePinsV1.full_call_count,
            inventory.program_call_count,
            RetainedSourcePinsV1.program_call_count,
            inventory.incremental_memory_call_count,
            RetainedSourcePinsV1.incremental_memory_call_count,
            inventory.declared_program_word_count,
            RetainedSourcePinsV1.declared_program_word_count,
            inventory.program_leaf_count,
            RetainedSourcePinsV1.program_leaf_count,
            inventory.program_base,
            inventory.program_end,
            RetainedSourcePinsV1.program_base,
            RetainedSourcePinsV1.program_end,
            custody.elf.byte_count,
            RetainedSourcePinsV1.elf_byte_count,
            &elf_observed,
            &elf_expected,
            &program_source,
            custody.public_wire.reference.byte_count,
            RetainedSourcePinsV1.reference_byte_count,
            &reference_observed,
            &reference_expected,
            custody.public_wire.segment.wire_artifact.byte_count,
            RetainedSourcePinsV1.payload_byte_count,
            &payload_observed,
            &payload_expected,
        },
    );
}

// ---------------------------------------------------------------------------
// Identities and small helpers
// ---------------------------------------------------------------------------

fn shardBatchIdentity(batch: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-leaf-d5-provider-shard-batch/v1\x00");
    hashInt(&hash, u64, batch.shards.len);
    for (batch.shards, 0..) |shard, index| {
        hashInt(&hash, u64, index);
        hash.update(&shard.statement.identity);
        hashInt(&hash, u64, shard.stwd5pr1_bytes.len);
        hash.update(&shard.sha256);
    }
    return hash.finalResult();
}

fn freshBatchIdentity(batch: *const shared_batch.OwnedFreshSharedBatchV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-leaf-d5-provider-fresh-batch/v1\x00");
    hashInt(&hash, u64, batch.claims.len);
    for (batch.claims, 0..) |claim, index| {
        hashInt(&hash, u64, index);
        hash.update(&claim.identity);
    }
    return hash.finalResult();
}

pub fn qm31Words(value: QM31) [4]u32 {
    const parts = value.toM31Array();
    return .{
        parts[0].toU32(),
        parts[1].toU32(),
        parts[2].toU32(),
        parts[3].toU32(),
    };
}

fn isZeroAuthorityId(value: AuthorityId) bool {
    for (value) |word| if (word != 0) return false;
    return true;
}

pub fn sha256(bytes: []const u8) [32]u8 {
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

// ---------------------------------------------------------------------------
// Comptime pins
// ---------------------------------------------------------------------------

comptime {
    if (PRODUCTION_ACTIVE or COMPLETE_LEAF_PROOF or RECURSIVE_CAPTURE_AVAILABLE or
        FORMAT_VERSION != 1 or
        RetainedSourcePinsV1.incremental_memory_call_count != 3_784_119 or
        RetainedSourcePinsV1.program_call_count != 2_887_182 or
        RetainedSourcePinsV1.full_call_count != 6_671_301)
    {
        @compileError("Stage101 D5 provider route contract drifted");
    }
    if (route.ACTIVATES_PRODUCTION_PROOF or orchestration.ACTIVATES_PRODUCTION_PROOF or
        transcript_mod.ACTIVATES_PRODUCTION_PROOF or
        shared_batch.ACTIVATES_PRODUCTION_PROOF or envelope.ACTIVATES_PRODUCTION_PROOF)
    {
        @compileError("Stage101 D5 provider route activated a research protocol");
    }
    // The route's shard cap is the shared batch's, and the envelope must admit
    // exactly that per shard.
    if (artifact_limits.max_proof_bytes !=
        execution_mod.MAX_CANONICAL_PROOF_BYTES_PER_SHARD)
    {
        @compileError("Stage101 D5 route shard byte cap drifted");
    }
    // Pins and sweep must plan the same first arm.
    if (ProviderOmissionPinsV1.shard_log_size != 18 or
        ProviderOmissionPinsV1.execution_owners != 18 or
        ProviderOmissionPinsV1.engine_workers_per_owner != 1)
    {
        @compileError("Stage101 D5 route pins drifted from the retained first arm");
    }
}
