//! Isolated authenticated-AOT Stage101 throughput experiment.
//!
//! This is not a production route. It instantiates the exact recursive
//! Poseidon2/q193 engine over Metal for proving, retains the CPU recursion
//! engine for the independent cold verifier, and withholds publication unless
//! artifact custody, protocol security, runtime identity, and backend
//! telemetry all close. Timing and backend evidence are process-local only.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const metal = @import("stwo_metal_backend");
// The degree-five facade is a superset of the original Stage101 facade; a
// file may belong to only one module per compilation, and the opt-in D5 route
// (stage101_leaf_degree5_provider_v1.zig) needs the wider surface.
const cpu_stage101 = @import("stwo_riscv_cpu_stage101_degree5_metal");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const aot = @import("aot_bundle_admission.zig");
const throughput_execution = cpu_stage101
    .ethereum_incremental_full_leaf_throughput_execution_v1;
const replay_command = cpu_stage101
    .ethereum_incremental_full_leaf_replay_command_v4;
const degree5_provider_aot = @import("stage101_degree5_provider_aot_v1.zig");
/// Opt-in `--provider-route degree5-omit-v1` command; everything else in this
/// file is the unchanged native leaf path.
const degree5_provider_route = @import("stage101_leaf_degree5_provider_v1.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVE = false;
pub const command_name = "stage101-metal-autoresearch-v1";
pub const aot_bundle_environment = "STWO_RISCV_METAL_AOT_BUNDLE";
pub const worker_count_environment = "STWO_ZIG_STAGE101_WORKER_COUNT";
pub const host_byte_budget_environment =
    "STWO_ZIG_STAGE101_HOST_BYTE_BUDGET";
pub const host_byte_limit_environment = "STWO_ZIG_STAGE101_HOST_BYTE_LIMIT";
pub const reference_artifact_environment =
    "STWO_ZIG_STAGE101_REFERENCE_ARTIFACT";
/// Optional explicit steady-state budget, in milliseconds, as
/// `admission_and_replay,witness_and_profile,proof_core,encode_and_custody`.
/// The budget stays fail-closed; only its value becomes an explicit,
/// receipt-recorded input, so a route that is not yet at the pinned
/// steady state can still produce and independently verify its artifact.
pub const budget_environment = "STWO_ZIG_STAGE101_BUDGET_MS";
/// Benchmark matrix for the current 18-logical-CPU host only. This array is
/// neither an algorithmic maximum nor a protocol/admission field.
pub const current_host_worker_sweep = [_]usize{ 1, 4, 8, 12, 18 };

pub const MetalEngine = frontend.recursion.engine.ProverEngineForBackend(
    metal.MetalCommitBackend,
);
pub const CpuVerifierEngine = replay_command.CpuEngine;

pub const expected_artifact_sha256 = hexDigest(
    "20baa3ae632cf116b94a5e7af36ce084e82c5dc1eeaaafd568684afb61c3effa",
);
pub const expected_artifact_byte_count: usize = 57_928_628;
const max_reference_artifact_bytes: usize = 256 * 1024 * 1024;
pub const expected_manifest_sha256 = hexDigest(
    "fee0bfb90bf705f4ad1b9923183a99123cb2b0d9623d1233ae9f331100dacd12",
);
pub const expected_metallib_sha256 = hexDigest(
    "c9a87203415ab4432116db15a65a210849884db2a923ffe5adda2e88268fdb58",
);

/// Explicit 5.0-second steady-state leaf budget. Cold runtime initialization
/// and independent CPU verification are reported separately and cannot be
/// hidden in an aggregate throughput number.
pub const ThroughputBudgetV1 = struct {
    admission_and_replay_ns: u64 = 200 * std.time.ns_per_ms,
    witness_and_profile_ns: u64 = 800 * std.time.ns_per_ms,
    proof_core_ns: u64 = 3_800 * std.time.ns_per_ms,
    encode_and_custody_ns: u64 = 200 * std.time.ns_per_ms,

    /// Parses `budget_environment` when it is set, otherwise keeps the pinned
    /// five-second steady-state budget.
    pub fn fromEnvironment(allocator: std.mem.Allocator) !ThroughputBudgetV1 {
        const encoded = std.process.getEnvVarOwned(allocator, budget_environment) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return .{},
            else => return err,
        };
        defer allocator.free(encoded);
        var milliseconds: [4]u64 = undefined;
        var fields = std.mem.splitScalar(u8, encoded, ',');
        for (&milliseconds) |*value| {
            const field = fields.next() orelse
                return error.InvalidStage101BudgetEnvironment;
            value.* = std.fmt.parseInt(u64, std.mem.trim(u8, field, " "), 10) catch
                return error.InvalidStage101BudgetEnvironment;
            if (value.* == 0) return error.InvalidStage101BudgetEnvironment;
        }
        if (fields.next() != null) return error.InvalidStage101BudgetEnvironment;
        return .{
            .admission_and_replay_ns = try std.math.mul(u64, milliseconds[0], std.time.ns_per_ms),
            .witness_and_profile_ns = try std.math.mul(u64, milliseconds[1], std.time.ns_per_ms),
            .proof_core_ns = try std.math.mul(u64, milliseconds[2], std.time.ns_per_ms),
            .encode_and_custody_ns = try std.math.mul(u64, milliseconds[3], std.time.ns_per_ms),
        };
    }

    pub fn totalNs(self: ThroughputBudgetV1) !u64 {
        var result = try std.math.add(
            u64,
            self.admission_and_replay_ns,
            self.witness_and_profile_ns,
        );
        result = try std.math.add(u64, result, self.proof_core_ns);
        return std.math.add(u64, result, self.encode_and_custody_ns);
    }

    pub fn validate(
        self: ThroughputBudgetV1,
        timing: replay_command.TimingReceiptV1,
    ) !void {
        const admission_and_replay = try std.math.add(
            u64,
            timing.input_admission_ns,
            timing.compact_replay_ns,
        );
        const witness_and_profile = try std.math.add(
            u64,
            timing.witness_prepare_ns,
            timing.statement_profile_prepare_ns,
        );
        if (admission_and_replay > self.admission_and_replay_ns)
            return error.Stage101AdmissionReplayBudgetExceeded;
        if (witness_and_profile > self.witness_and_profile_ns)
            return error.Stage101WitnessProfileBudgetExceeded;
        if (timing.prove_ns > self.proof_core_ns)
            return error.Stage101ProofCoreBudgetExceeded;
        if (timing.encode_ns > self.encode_and_custody_ns)
            return error.Stage101EncodeCustodyBudgetExceeded;
        if (timing.transaction_ns > try self.totalNs())
            return error.Stage101LeafThroughputBudgetExceeded;
    }
};

const ReleaseStateV1 = struct {
    runtime_initialization_ns: u64,
    lifecycle_before: metal.MetalCommitBackend.RuntimeLifecycleSnapshot,
    telemetry_before: metal.MetalCommitBackend.TelemetrySnapshot,
    platform_identity_sha256: [32]u8,
    build_identity_sha256: [32]u8,
    execution_policy: throughput_execution.PolicyV1,
    reference_artifact_bytes: []const u8,
    budget: ThroughputBudgetV1 = .{},

    fn validateOpaque(
        context: *anyopaque,
        evidence: replay_command.ReleaseEvidenceV1,
    ) !void {
        const self: *ReleaseStateV1 = @ptrCast(@alignCast(context));
        return self.validate(evidence);
    }

    fn validate(
        self: *ReleaseStateV1,
        evidence: replay_command.ReleaseEvidenceV1,
    ) !void {
        const lifecycle_after = metal.MetalCommitBackend
            .runtimeLifecycleSnapshot();
        try validateAuthenticatedLifecycle(lifecycle_after);
        if (!std.meta.eql(
            self.lifecycle_before.identity,
            lifecycle_after.identity,
        )) return error.Stage101MetalRuntimeIdentityChanged;

        const telemetry_after = try metal.MetalCommitBackend
            .telemetrySnapshot();
        const delta = telemetry_after.delta(self.telemetry_before);
        const measured_artifact_sha256 = sha256(evidence.artifact_bytes);
        const budget_total_ns = try self.budget.totalNs();
        const evidence_policy = evidence.execution_policy orelse
            return error.Stage101ExecutionPolicyReceiptMissing;
        const producer_resources = evidence.producer_resources orelse
            return error.Stage101ProducerResourceReceiptMissing;
        const cold_resources = evidence.cold_verifier_resources orelse
            return error.Stage101ColdResourceReceiptMissing;
        const preparation = evidence.preparation orelse
            return error.Stage101PreparationReceiptMissing;
        if (!std.meta.eql(evidence_policy, self.execution_policy))
            return error.Stage101ExecutionPolicyReceiptMismatch;
        try producer_resources.validate();
        try cold_resources.validate();
        try preparation.construction.validate();
        try preparation.phase_timing.validate();
        const artifact_parity = try throughput_execution
            .ArtifactParityReceiptV1.init(
            self.reference_artifact_bytes,
            evidence.artifact_bytes,
        );
        const throughput_receipt = throughput_execution.ThroughputReceiptV1{
            .policy = self.execution_policy,
            .resources = producer_resources,
            .artifact = artifact_parity,
            .fri_query_count = evidence.fri_query_count,
            .independently_cold_verified = true,
        };
        try throughput_receipt.validate();
        if (producer_resources.wall_ns < evidence.producer_elapsed_ns or
            cold_resources.wall_ns < evidence.cold_verify_elapsed_ns or
            preparation.owner_validations != 3 or
            preparation.proof_view_borrows != 2)
        {
            return error.Stage101PreparedExecutionReceiptMismatch;
        }
        printReceipt(
            self,
            evidence,
            measured_artifact_sha256,
            delta,
            budget_total_ns,
        );

        if (!std.mem.eql(
            u8,
            &measured_artifact_sha256,
            &expected_artifact_sha256,
        )) return error.Stage101MetalArtifactByteMismatch;
        if (evidence.fri_query_count != 193)
            return error.Stage101MetalQueryCountMismatch;
        try validateRequiredKernelCoverage(delta.counters);
        try delta.requireResidentRiscPolynomialDispatch();
        try validateStage101HostPlacements(delta.counters);
        try self.budget.validate(evidence.timing);
    }
};

/// Run the retained segment-1 experiment. `arguments` are the Stage101 CPU
/// command arguments plus an optional `--provider-route <value>` pair, which
/// is stripped here before anything else reads them: `degree5-omit-v1`
/// delegates to the opt-in D5 route command, `native` or an absent flag runs
/// the unchanged native leaf below, and any other value is an error. The AOT
/// bundle is supplied only through the named environment variable so it never
/// becomes proof input.
pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var parsed_route = try degree5_provider_route.stripProviderRoute(
        allocator,
        arguments,
    );
    defer parsed_route.deinit(allocator);
    switch (parsed_route.route) {
        .degree5_omit_v1 => return degree5_provider_route.run(
            allocator,
            parsed_route.forwarded,
        ),
        .native => {},
    }
    return runNative(allocator, parsed_route.forwarded);
}

/// The native leaf path, byte-for-byte the command as it was before the route
/// flag existed. `arguments` carry no `--provider-route` pair.
fn runNative(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const execution_policy = try executionPolicyFromEnvironment(allocator);
    const reference_artifact_path = try std.process.getEnvVarOwned(
        allocator,
        reference_artifact_environment,
    );
    defer allocator.free(reference_artifact_path);
    const reference_artifact_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        reference_artifact_path,
        max_reference_artifact_bytes,
    );
    defer allocator.free(reference_artifact_bytes);
    const reference_artifact_sha256 = sha256(reference_artifact_bytes);
    if (reference_artifact_bytes.len != expected_artifact_byte_count or
        !std.mem.eql(
            u8,
            &reference_artifact_sha256,
            &expected_artifact_sha256,
        ))
    {
        return error.Stage101ReferenceArtifactMismatch;
    }
    const bundle_path = try std.process.getEnvVarOwned(
        allocator,
        aot_bundle_environment,
    );
    defer allocator.free(bundle_path);
    try aot.validate(allocator, bundle_path, expected_manifest_sha256);

    const lifecycle_initial = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
    if (lifecycle_initial.initialized)
        return error.Stage101MetalRuntimeAlreadyInitialized;
    var initialization_timer = try std.time.Timer.start();
    try metal.MetalCommitBackend.initializeRuntime(allocator, .{
        .authenticated_aot = .{
            .bundle_path = bundle_path,
            .manifest_sha256 = expected_manifest_sha256,
        },
    });
    const runtime_initialization_ns = initialization_timer.read();
    defer metal.MetalCommitBackend.shutdown() catch unreachable;

    const lifecycle_before = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
    try validateAuthenticatedLifecycle(lifecycle_before);
    try validatePoseidonMerkleParity(allocator);
    const platform_identity = try metal.MetalCommitBackend
        .runtimePlatformIdentityAlloc(allocator);
    defer allocator.free(platform_identity);
    var state = ReleaseStateV1{
        .runtime_initialization_ns = runtime_initialization_ns,
        .lifecycle_before = lifecycle_before,
        .telemetry_before = try metal.MetalCommitBackend.telemetrySnapshot(),
        .platform_identity_sha256 = sha256(platform_identity),
        .build_identity_sha256 = buildIdentity(),
        .execution_policy = execution_policy,
        .reference_artifact_bytes = reference_artifact_bytes,
        .budget = try ThroughputBudgetV1.fromEnvironment(allocator),
    };
    try replay_command.runPreparedWithEnginesAndExecution(
        MetalEngine,
        CpuVerifierEngine,
        allocator,
        arguments,
        .{
            .context = &state,
            .validate_fn = ReleaseStateV1.validateOpaque,
        },
        execution_policy,
    );
}

fn executionPolicyFromEnvironment(
    allocator: std.mem.Allocator,
) !throughput_execution.PolicyV1 {
    const worker_count = try environmentUsize(
        allocator,
        worker_count_environment,
    );
    const host_byte_budget = try environmentUsize(
        allocator,
        host_byte_budget_environment,
    );
    const host_byte_limit = try environmentUsize(
        allocator,
        host_byte_limit_environment,
    );
    return throughput_execution.PolicyV1.init(
        worker_count,
        host_byte_budget,
        try throughput_execution.HostCapacityV1.detect(host_byte_limit),
    );
}

fn environmentUsize(
    allocator: std.mem.Allocator,
    name: []const u8,
) !usize {
    const encoded = try std.process.getEnvVarOwned(allocator, name);
    defer allocator.free(encoded);
    return std.fmt.parseInt(usize, encoded, 10) catch
        error.InvalidStage101ExecutionEnvironment;
}

fn validateAuthenticatedLifecycle(
    lifecycle: metal.MetalCommitBackend.RuntimeLifecycleSnapshot,
) !void {
    if (!lifecycle.initialized or lifecycle.identity == null)
        return error.Stage101AuthenticatedMetalRuntimeMissing;
    const identity = lifecycle.identity.?;
    if (identity.origin != .authenticated_core_aot or
        identity.manifest_sha256 == null or
        identity.metallib_sha256 == null or
        identity.metallib_bytes == null or
        identity.metallib_bytes.? == 0 or
        !std.mem.eql(
            u8,
            &identity.manifest_sha256.?,
            &expected_manifest_sha256,
        ) or
        !std.mem.eql(
            u8,
            &identity.metallib_sha256.?,
            &expected_metallib_sha256,
        ))
    {
        return error.Stage101AuthenticatedMetalRuntimeMismatch;
    }
}

fn validateRequiredKernelCoverage(
    counters: metal.telemetry.CounterValues,
) !void {
    if (counters.resident_merkle_commits == 0)
        return error.Stage101MetalMerkleDispatchMissing;
    if (counters.metal_poseidon2_merkle_commits == 0)
        return error.Stage101MetalPoseidonMerkleDispatchMissing;
    if (counters.metal_sampled_value_dispatches == 0)
        return error.Stage101MetalSampledValueDispatchMissing;
    if (counters.metal_circle_transform_dispatches == 0 or
        counters.metal_circle_lde_dispatches == 0)
    {
        return error.Stage101MetalTransformDispatchMissing;
    }
    if (counters.metal_composition_eval_dispatches == 0 and
        (counters.metal_riscv_base_polynomial_batch_dispatches == 0 or
            counters.metal_riscv_lookup_polynomial_batch_dispatches == 0))
    {
        return error.Stage101MetalCompositionDispatchMissing;
    }
    if (counters.metal_quotient_dispatches == 0)
        return error.Stage101MetalQuotientDispatchMissing;
    if (counters.metal_fri_circle_fold_dispatches == 0 or
        counters.metal_fri_line_fold_dispatches == 0)
    {
        return error.Stage101MetalFriDispatchMissing;
    }
    if (counters.metal_qm31_coordinate_dispatches == 0)
        return error.Stage101MetalQm31DispatchMissing;
}

/// The current Stage101 circuit has three tiny log<3 circle operations.  They
/// are intentionally kept visible in the generic Metal fallback telemetry;
/// this harness admits exactly three such host placements and rejects every
/// other CPU fallback.  Since the batched circle-LDE commit route the three
/// operations are all classified as small LDEs (they were one interpolation,
/// one evaluation and one LDE before), so the pin is on the total, not the
/// per-kind split.  A future tiny-device epoch can remove this exception
/// without changing the proof protocol.
pub const admitted_small_circle_host_placements: u64 = 3;

fn validateStage101HostPlacements(
    counters: metal.telemetry.CounterValues,
) !void {
    const small_circle = counters.cpu_small_circle_interpolations +|
        counters.cpu_small_circle_evaluations +|
        counters.cpu_small_circle_ldes;
    if (small_circle != admitted_small_circle_host_placements)
        return error.Stage101SmallCirclePlacementMismatch;
    const admitted = counters.cpu_small_circle_interpolations +|
        counters.cpu_small_circle_evaluations +|
        counters.cpu_small_circle_ldes;
    if (counters.cpuFallbackTotal() != admitted)
        return error.Stage101UnexpectedHostFallback;
}

/// Device preflight for the exact lifted leaf ordering, rate-boundary marker,
/// heterogeneous column lifting, and every parent level used by Stage101.
/// The end-to-end artifact identity below separately pins combined and FRI
/// commitments; this small preflight localizes a hash-family mismatch before
/// spending minutes on the retained leaf.
fn validatePoseidonMerkleParity(allocator: std.mem.Allocator) !void {
    const H = MetalEngine.Hasher;
    const M31 = core.fields.m31.M31;
    var values: [17][8]M31 = undefined;
    var columns: [17][]const M31 = undefined;
    for (&values, 0..) |*column, column_index| {
        for (column, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(
                1 + column_index * column.len + row,
            ));
        }
        const length: usize = if (column_index < 3)
            2
        else if (column_index < 8)
            4
        else
            8;
        columns[column_index] = column[0..length];
    }

    var reference = try prover.vcs_lifted.prover.MerkleProverLifted(H)
        .commit(allocator, &columns);
    defer reference.deinit(allocator);
    const telemetry_before = try metal.MetalCommitBackend.telemetrySnapshot();
    var candidate = try metal.MetalCommitBackend.commitMerkle(
        H,
        allocator,
        &columns,
    );
    defer candidate.deinit(allocator);
    const telemetry_after = try metal.MetalCommitBackend.telemetrySnapshot();
    const telemetry_delta = telemetry_after.delta(telemetry_before).counters;

    if (candidate.quotientResidencyHandle() == null or
        telemetry_delta.resident_merkle_commits != 1 or
        telemetry_delta.metal_poseidon2_merkle_commits != 1 or
        telemetry_delta.host_merkle_commits != 0)
    {
        return error.Stage101PoseidonMerkleDeviceDispatchMissing;
    }
    if (!std.meta.eql(reference.root(), candidate.root()))
        return error.Stage101PoseidonMerkleRootMismatch;
    if (reference.maxLogSize() != candidate.maxLogSize())
        return error.Stage101PoseidonMerkleHeightMismatch;

    var indices: [8]u32 = undefined;
    var layer_log_size: u32 = 0;
    while (layer_log_size <= reference.maxLogSize()) : (layer_log_size += 1) {
        const count = @as(usize, 1) << @intCast(layer_log_size);
        for (indices[0..count], 0..) |*index, value| index.* = @intCast(value);
        const reference_hashes = try reference.readHashes(
            allocator,
            layer_log_size,
            indices[0..count],
        );
        defer allocator.free(reference_hashes);
        const candidate_hashes = try candidate.readHashes(
            allocator,
            layer_log_size,
            indices[0..count],
        );
        defer allocator.free(candidate_hashes);
        if (reference_hashes.len != candidate_hashes.len)
            return error.Stage101PoseidonMerkleLayerMismatch;
        for (reference_hashes, candidate_hashes) |expected, actual| {
            if (!std.meta.eql(expected, actual))
                return error.Stage101PoseidonMerkleLayerMismatch;
        }
    }

    // Poseidon direct commitments use the same u64 column-offset authority for
    // device queried-value gathering. Compare the complete decommitment shape
    // as well as roots/layers so a wide-offset ABI drift cannot hide behind a
    // host opening fallback.
    const query_positions = [_]usize{ 0, 3, 7 };
    var reference_decommitment = try reference.decommit(
        allocator,
        &query_positions,
        &columns,
    );
    defer reference_decommitment.deinit(allocator);
    var candidate_decommitment = try candidate.decommit(
        allocator,
        &query_positions,
        &columns,
    );
    defer candidate_decommitment.deinit(allocator);
    for (
        reference_decommitment.queried_values,
        candidate_decommitment.queried_values,
    ) |expected, actual| {
        if (expected.len != actual.len)
            return error.Stage101PoseidonMerkleQueriedValueMismatch;
        for (expected, actual) |expected_value, actual_value| {
            if (!expected_value.eql(actual_value))
                return error.Stage101PoseidonMerkleQueriedValueMismatch;
        }
    }
    const expected_witness = reference_decommitment.decommitment
        .decommitment.hash_witness;
    const actual_witness = candidate_decommitment.decommitment
        .decommitment.hash_witness;
    if (expected_witness.len != actual_witness.len)
        return error.Stage101PoseidonMerkleDecommitmentMismatch;
    for (expected_witness, actual_witness) |expected, actual| {
        if (!std.meta.eql(expected, actual))
            return error.Stage101PoseidonMerkleDecommitmentMismatch;
    }

    // Equal bytes and geometry do not grant residency.  Composition may use
    // only the exact extended-evaluation pointers retained by the committed
    // tree; a separately owned coefficient/base arena (represented by this
    // clone) must fail instead of being uploaded or falling back to host work.
    var unowned_values: [17][8]M31 = undefined;
    var unowned_columns: [17][]const M31 = undefined;
    for (&unowned_values, &unowned_columns, columns) |
        *unowned,
        *unowned_column,
        committed_column,
    | {
        @memcpy(unowned[0..committed_column.len], committed_column);
        unowned_column.* = unowned[0..committed_column.len];
    }
    if (candidate.decommit(
        allocator,
        &query_positions,
        &unowned_columns,
    )) |accepted_value| {
        var accepted = accepted_value;
        accepted.deinit(allocator);
        return error.Stage101FalsePoseidonResidencyAccepted;
    } else |err| switch (err) {
        error.InvalidColumnSize => {},
        else => return err,
    }
}

fn printReceipt(
    state: *const ReleaseStateV1,
    evidence: replay_command.ReleaseEvidenceV1,
    artifact_sha256: [32]u8,
    delta: metal.MetalCommitBackend.TelemetryDelta,
    budget_total_ns: u64,
) void {
    const timing = evidence.timing;
    const producer_resources = evidence.producer_resources.?;
    const cold_resources = evidence.cold_verifier_resources.?;
    const preparation = evidence.preparation.?;
    const counters = delta.counters;
    const artifact_hex = std.fmt.bytesToHex(artifact_sha256, .lower);
    const manifest_hex = std.fmt.bytesToHex(expected_manifest_sha256, .lower);
    const metallib_hex = std.fmt.bytesToHex(expected_metallib_sha256, .lower);
    const platform_hex = std.fmt.bytesToHex(state.platform_identity_sha256, .lower);
    const build_hex = std.fmt.bytesToHex(state.build_identity_sha256, .lower);
    std.debug.print(
        "STAGE101_METAL_RECEIPT_V1 artifact_sha256={s} queries={} " ++
            "manifest_sha256={s} metallib_sha256={s} " ++
            "platform_identity_sha256={s} build_identity_sha256={s} " ++
            "runtime_init_ns={} producer_ns={} cold_cpu_verify_ns={} " ++
            "transaction_ns={} admission_ns={} replay_ns={} witness_ns={} " ++
            "profile_ns={} prove_ns={} encode_ns={} budget_ns={}\n",
        .{
            &artifact_hex,
            evidence.fri_query_count,
            &manifest_hex,
            &metallib_hex,
            &platform_hex,
            &build_hex,
            state.runtime_initialization_ns,
            evidence.producer_elapsed_ns,
            evidence.cold_verify_elapsed_ns,
            timing.transaction_ns,
            timing.input_admission_ns,
            timing.compact_replay_ns,
            timing.witness_prepare_ns,
            timing.statement_profile_prepare_ns,
            timing.prove_ns,
            timing.encode_ns,
            budget_total_ns,
        },
    );
    std.debug.print(
        "STAGE101_METAL_KERNELS_V1 resident_merkle={} poseidon_merkle={} host_merkle={} " ++
            "sampled={} circle_transform={} circle_lde={} composition={} " ++
            "quotient={} fri_circle={} fri_line={} fri_epochs={} qm31={} " ++
            "relation={} trace={} base_eligible={} base_dispatch={} " ++
            "lookup_eligible={} lookup_dispatch={} cpu_fallback_total={} " ++
            "small_interp={} small_eval={} small_lde={} " ++
            "pipeline_hits={} pipeline_misses={} direct_compiles={}\n",
        .{
            counters.resident_merkle_commits,
            counters.metal_poseidon2_merkle_commits,
            counters.host_merkle_commits,
            counters.metal_sampled_value_dispatches,
            counters.metal_circle_transform_dispatches,
            counters.metal_circle_lde_dispatches,
            counters.metal_composition_eval_dispatches,
            counters.metal_quotient_dispatches,
            counters.metal_fri_circle_fold_dispatches,
            counters.metal_fri_line_fold_dispatches,
            counters.metal_fri_fold_commit_epochs,
            counters.metal_qm31_coordinate_dispatches,
            counters.metal_relation_epochs,
            counters.metal_trace_generation_dispatches,
            counters.riscv_base_polynomial_eligible_components,
            counters.metal_riscv_base_polynomial_batch_dispatches,
            counters.riscv_lookup_polynomial_eligible_components,
            counters.metal_riscv_lookup_polynomial_batch_dispatches,
            counters.cpuFallbackTotal(),
            counters.cpu_small_circle_interpolations,
            counters.cpu_small_circle_evaluations,
            counters.cpu_small_circle_ldes,
            delta.pipeline_cache.pipeline_cache_hits,
            delta.pipeline_cache.binary_archive_misses,
            delta.pipeline_cache.direct_compiles,
        },
    );
    std.debug.print(
        "STAGE101_HOST_PLACEMENTS_V1 trace_generation=cpu " ++
            "small_circle_interpolation={} small_circle_evaluation={} " ++
            "small_circle_lde={} admitted_cpu_fallbacks={}\n",
        .{
            counters.cpu_small_circle_interpolations,
            counters.cpu_small_circle_evaluations,
            counters.cpu_small_circle_ldes,
            counters.cpuFallbackTotal(),
        },
    );
    std.debug.print(
        "STAGE101_EXECUTION_RECEIPT_V1 workers={} host_budget={} " ++
            "host_logical_cpus={} host_limit={} producer_wall_ns={} " ++
            "producer_cpu_ns={} producer_parallelism_milli={} " ++
            "producer_peak_footprint={} cold_wall_ns={} cold_cpu_ns={} " ++
            "cold_parallelism_milli={} cold_peak_footprint={} " ++
            "prepared_validations={} prepared_borrows={} cold_rebuilds={} " ++
            "statement_builds={} ethereum_witness_builds={} " ++
            "extension_builds={} profile_cold_mints={} " ++
            "profile_transport_mints={}\n",
        .{
            state.execution_policy.worker_count,
            state.execution_policy.host_byte_budget,
            state.execution_policy.host.logical_cpu_count,
            state.execution_policy.host.host_byte_limit,
            producer_resources.wall_ns,
            producer_resources.process_cpu_ns orelse 0,
            producer_resources.average_parallelism_milli orelse 0,
            producer_resources.lifetime_peak_physical_footprint_bytes orelse 0,
            cold_resources.wall_ns,
            cold_resources.process_cpu_ns orelse 0,
            cold_resources.average_parallelism_milli orelse 0,
            cold_resources.lifetime_peak_physical_footprint_bytes orelse 0,
            preparation.owner_validations,
            preparation.proof_view_borrows,
            preparation.construction.cold_reconstructions,
            preparation.construction.statement_geometry_builds,
            preparation.construction.ethereum_witness_builds,
            preparation.construction.extension_builds,
            preparation.construction.profile_mints_from_cold,
            preparation.construction.profile_mints_from_transport,
        },
    );
}

fn buildIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-metal-autoresearch-build/v1\x00");
    hash.update(@tagName(builtin.mode));
    hash.update(@typeName(MetalEngine));
    hash.update(@typeName(CpuVerifierEngine));
    hash.update(&expected_manifest_sha256);
    hash.update(&expected_metallib_sha256);
    return hash.finalResult();
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn hexDigest(comptime encoded: *const [64]u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

test "Stage101 Metal engine preserves the exact q193 Poseidon protocol" {
    try std.testing.expect(MetalEngine.Hasher == CpuVerifierEngine.Hasher);
    try std.testing.expect(MetalEngine.MerkleChannel ==
        CpuVerifierEngine.MerkleChannel);
    try std.testing.expect(MetalEngine.Channel == CpuVerifierEngine.Channel);
    try std.testing.expectEqual(
        @as(usize, 193),
        frontend.recursion.protocol.PCS_CONFIG.fri_config.n_queries,
    );
}

test "Stage101 five-second budget is exact and fail closed by stage" {
    const budget = ThroughputBudgetV1{};
    const exact = replay_command.TimingReceiptV1{
        .transaction_ns = 5 * std.time.ns_per_s,
        .input_admission_ns = 100 * std.time.ns_per_ms,
        .compact_replay_ns = 100 * std.time.ns_per_ms,
        .witness_prepare_ns = 400 * std.time.ns_per_ms,
        .statement_profile_prepare_ns = 400 * std.time.ns_per_ms,
        .prove_ns = 3_800 * std.time.ns_per_ms,
        .encode_ns = 200 * std.time.ns_per_ms,
    };
    try budget.validate(exact);
    var drift = exact;
    drift.prove_ns += 1;
    try std.testing.expectError(
        error.Stage101ProofCoreBudgetExceeded,
        budget.validate(drift),
    );
    drift = exact;
    drift.input_admission_ns += 1;
    try std.testing.expectError(
        error.Stage101AdmissionReplayBudgetExceeded,
        budget.validate(drift),
    );
}

test "Stage101 worker matrix is current-host evidence not a protocol cap" {
    const host18 = try throughput_execution.HostCapacityV1.init(
        18,
        64 * 1024 * 1024 * 1024,
    );
    try throughput_execution.validateWorkerSweep(
        &current_host_worker_sweep,
        host18,
    );
    const host12 = try throughput_execution.HostCapacityV1.init(12, 1024);
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerSweep,
        throughput_execution.validateWorkerSweep(
            &current_host_worker_sweep,
            host12,
        ),
    );
}

test "Stage101 Metal coverage rejects missing and host fallback work" {
    var counters = metal.telemetry.CounterValues{
        .resident_merkle_commits = 1,
        .metal_poseidon2_merkle_commits = 1,
        .metal_sampled_value_dispatches = 1,
        .metal_circle_transform_dispatches = 1,
        .metal_circle_lde_dispatches = 1,
        .riscv_base_polynomial_eligible_components = 78,
        .riscv_lookup_polynomial_eligible_components = 75,
        .metal_riscv_base_polynomial_batch_dispatches = 1,
        .metal_riscv_lookup_polynomial_batch_dispatches = 1,
        .metal_quotient_dispatches = 1,
        .metal_fri_circle_fold_dispatches = 1,
        .metal_fri_line_fold_dispatches = 22,
        .metal_qm31_coordinate_dispatches = 1,
        .cpu_small_circle_interpolations = 1,
        .cpu_small_circle_evaluations = 1,
        .cpu_small_circle_ldes = 1,
    };
    try validateRequiredKernelCoverage(counters);
    try validateStage101HostPlacements(counters);
    const specialized_dispatch = metal.telemetry.Delta{
        .counters = counters,
        .pipeline_cache = .{},
    };
    try specialized_dispatch.requireResidentRiscPolynomialDispatch();
    try std.testing.expectError(
        error.CpuFallbackObserved,
        specialized_dispatch.requireResidentRiscPolynomialExecution(),
    );
    counters.metal_sampled_value_dispatches = 0;
    try std.testing.expectError(
        error.Stage101MetalSampledValueDispatchMissing,
        validateRequiredKernelCoverage(counters),
    );
    counters.metal_sampled_value_dispatches = 1;
    counters.cpu_sampled_value_evaluations = 1;
    try std.testing.expectError(
        error.Stage101UnexpectedHostFallback,
        validateStage101HostPlacements(counters),
    );
    counters.cpu_sampled_value_evaluations = 0;
    counters.metal_riscv_base_polynomial_batch_dispatches = 0;
    try std.testing.expectError(
        error.Stage101MetalCompositionDispatchMissing,
        validateRequiredKernelCoverage(counters),
    );
    counters.metal_riscv_base_polynomial_batch_dispatches = 1;
    counters.cpu_small_circle_ldes = 0;
    try std.testing.expectError(
        error.Stage101SmallCirclePlacementMismatch,
        validateStage101HostPlacements(counters),
    );
}

test "Stage101 Poseidon Merkle device family is typed and seedless" {
    const H = MetalEngine.Hasher;
    try std.testing.expect(metal.hash_domain.blake2sParameters(H) == null);
    const parameters = metal.hash_domain.parameters(H).?;
    try std.testing.expectEqual(
        metal.hash_domain.FamilyV1.poseidon2_m31,
        parameters.family,
    );
    try std.testing.expectEqual(@as(u32, 16), parameters.leaf_state_words);
    try std.testing.expectEqual([_]u32{0} ** 8, parameters.leaf_seed);
    try std.testing.expectEqual([_]u32{0} ** 8, parameters.node_seed);
    try std.testing.expectEqual(@as(u32, 0), parameters.domain_prefix_bytes);
}

test "Stage101 Poseidon polynomial residency accepts exact u64 tree maps" {
    const runtime_source = metal.source_contract.runtime;
    const lifecycle_source = metal.source_contract.lifecycle_and_tree;
    const resolver_authorities = [_][]const u8{
        "tree.residentColumnOffsetWordBytes",
        "offset_word_bytes == sizeof(uint64_t)",
        "wide_offsets[index]",
        "resident_offset > (uint64_t)buffer_words",
    };
    for (resolver_authorities) |authority|
        try std.testing.expect(std.mem.indexOf(u8, runtime_source, authority) != null);
    const preflight_authorities = [_][]const u8{
        "stwo_zig_tree_resident_column(",
        "binding.wordOffset != (size_t)resident_offset",
        "Metal queried-value residency resolver disagrees with the committed tree",
    };
    for (preflight_authorities) |authority|
        try std.testing.expect(std.mem.indexOf(u8, lifecycle_source, authority) != null);
}

comptime {
    _ = degree5_provider_aot;
    _ = degree5_provider_route;
}

comptime {
    if (FORMAT_VERSION != 1 or PRODUCTION_ACTIVE or
        frontend.recursion.protocol.FRI_QUERY_COUNT != 193)
    {
        @compileError("Stage101 Metal autoresearch contract drifted");
    }
}

test "Stage101 budget environment parses an explicit fail-closed budget" {
    const parsed = ThroughputBudgetV1{
        .admission_and_replay_ns = 6_000 * std.time.ns_per_ms,
        .witness_and_profile_ns = 15_000 * std.time.ns_per_ms,
        .proof_core_ns = 200_000 * std.time.ns_per_ms,
        .encode_and_custody_ns = 1_000 * std.time.ns_per_ms,
    };
    try std.testing.expectEqual(
        @as(u64, 222_000 * std.time.ns_per_ms),
        try parsed.totalNs(),
    );
    // An explicit budget is still exact: one nanosecond over any stage fails.
    try std.testing.expectError(error.Stage101ProofCoreBudgetExceeded, parsed.validate(.{
        .transaction_ns = 1,
        .input_admission_ns = 1,
        .compact_replay_ns = 1,
        .witness_prepare_ns = 1,
        .statement_profile_prepare_ns = 1,
        .prove_ns = 200_000 * std.time.ns_per_ms + 1,
        .encode_ns = 1,
    }));
    try parsed.validate(.{
        .transaction_ns = 222_000 * std.time.ns_per_ms,
        .input_admission_ns = 5_000 * std.time.ns_per_ms,
        .compact_replay_ns = 1_000 * std.time.ns_per_ms,
        .witness_prepare_ns = 14_000 * std.time.ns_per_ms,
        .statement_profile_prepare_ns = 1_000 * std.time.ns_per_ms,
        .prove_ns = 200_000 * std.time.ns_per_ms,
        .encode_ns = 1_000 * std.time.ns_per_ms,
    });
    // The default stays the pinned five-second steady state.
    const default_budget = ThroughputBudgetV1{};
    try std.testing.expectEqual(
        @as(u64, 5 * std.time.ns_per_s),
        try default_budget.totalNs(),
    );
}
