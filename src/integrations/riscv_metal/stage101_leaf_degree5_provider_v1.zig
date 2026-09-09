//! Opt-in Stage101 leaf route: `--provider-route degree5-omit-v1`.
//!
//! This is not a production route and not a complete leaf proof. It reuses the
//! Stage101 leaf command's cold admission (`replay_command.runPreparedVisitor`),
//! proves the leaf's V4 core with the native 445-column Poseidon2 provider
//! omitted from Trees 0/1/2, proves the same 6.67M provider calls as 26 D5
//! shards under the core's single relation draw, publishes one `STWIOL01`
//! envelope, destroys every producer proof object, and independently
//! fresh-verifies core, shards and closure on the CPU recursion engine from
//! bytes. The engine-generic body lives in the CPU integration
//! (`ethereum_incremental_omitted_leaf_route_v1`, analysed against the q193
//! CPU engine by `check-ethereum-incremental-omitted-leaf-route-v1`); this
//! file owns only what needs a device: authenticated-AOT runtime lifecycle,
//! telemetry closure, and the backend half of the receipt.
//!
//! Receipt-then-budget order is the leaf's: the sealed receipt is published
//! create-only first and the fail-closed `ProviderRouteBudgetV1` runs after,
//! so a run over budget still leaves its measured evidence on disk.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const metal = @import("stwo_metal_backend");
const cpu = @import("stwo_riscv_cpu_stage101_degree5_metal");

const aot = @import("aot_bundle_admission.zig");
const leaf = @import("stage101_leaf_autoresearch_v1.zig");
const artifact_io = cpu.ethereum_precompile_artifact_io;
const replay_command = cpu.ethereum_incremental_full_leaf_replay_command_v4;
const route_mod = cpu.ethereum_incremental_omitted_leaf_route_v1;
const throughput = cpu.ethereum_incremental_full_leaf_throughput_execution_v1;

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVE = false;
pub const COMPLETE_LEAF_PROOF = false;
pub const command_name = leaf.command_name ++ " --provider-route degree5-omit-v1";
pub const provider_route_flag = route_mod.provider_route_flag;
pub const provider_route_value = route_mod.provider_route_degree5_omit_v1;
/// `=1` runs the serial Merkle/Poseidon cancellation diagnostic (G7).
pub const diagnostic_cancellation_environment =
    "STWO_ZIG_STAGE101_DIAGNOSTIC_CANCELLATION";
/// The route proves 26 shards; each contributes one base and one lookup
/// resident polynomial batch on top of whatever the core dispatches.
pub const minimum_shard_batch_dispatches: u64 = 26;

pub const MetalEngine = leaf.MetalEngine;
pub const CpuVerifierEngine = leaf.CpuVerifierEngine;
pub const Route = route_mod.RouteV1(MetalEngine, CpuVerifierEngine);
pub const RouteSelectionV1 = route_mod.RouteSelectionV1;
pub const ParsedRouteV1 = route_mod.ParsedRouteV1;
pub const stripProviderRoute = route_mod.stripProviderRoute;

pub const expected_manifest_sha256 = leaf.expected_manifest_sha256;
pub const expected_metallib_sha256 = leaf.expected_metallib_sha256;
pub const expected_source_sha256 = hexDigest(
    "c2daaaf7dab998e6c542651dec73323973eafceee6ccf9d56fce6094ccac2786",
);
pub const expected_air_sha256 = hexDigest(
    "bf21cda590c2102f9c0d373ad41294d952672e8757fd7e390e9a865df250dc33",
);
pub const expected_native_export_count: u32 = 166;

pub const Error = error{
    Stage101ProviderRouteMetalRuntimeAlreadyInitialized,
    Stage101ProviderRouteAuthenticatedMetalRuntimeMissing,
    Stage101ProviderRouteAuthenticatedMetalRuntimeMismatch,
    Stage101ProviderRouteMetalRuntimeIdentityChanged,
    Stage101ProviderRouteBundlePinMismatch,
    Stage101ProviderRouteShardBatchDispatchMissing,
    Stage101ProviderRouteUnexpectedHostFallback,
    Stage101ProviderRouteMetalMerkleDispatchMissing,
    Stage101ProviderRouteMetalPoseidonMerkleDispatchMissing,
    Stage101ProviderRouteMetalSampledValueDispatchMissing,
    Stage101ProviderRouteMetalTransformDispatchMissing,
    Stage101ProviderRouteMetalCompositionDispatchMissing,
    Stage101ProviderRouteMetalQuotientDispatchMissing,
    Stage101ProviderRouteMetalFriDispatchMissing,
    Stage101ProviderRouteMetalQm31DispatchMissing,
    InvalidStage101ProviderRouteEnvironment,
};

const StateV1 = struct {
    allocator: std.mem.Allocator,
    output_path: []const u8,
    execution_policy: throughput.PolicyV1,
    diagnostic_cancellation: bool,
    recorder: ?*route_mod.StageRecorder,
    runtime_initialization_ns: u64,
    lifecycle_before: metal.MetalCommitBackend.RuntimeLifecycleSnapshot,
    telemetry_before: metal.MetalCommitBackend.TelemetrySnapshot,
    platform_identity_sha256: [32]u8,
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
        // ---- Stages 1-6: engine-generic body ------------------------------
        const outcome = try Route.proveAndFreshVerify(
            self.allocator,
            custody,
            transaction,
            call_view,
            evidence,
            .{
                .execution_policy = self.execution_policy,
                .diagnostic_cancellation = self.diagnostic_cancellation,
                .recorder = self.recorder,
                .total_measurement = &self.total_measurement,
            },
        );

        // ---- Stage 7: Metal lifecycle and telemetry, as the leaf ---------
        const lifecycle_after = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
        try validateAuthenticatedLifecycle(lifecycle_after);
        if (!std.meta.eql(
            self.lifecycle_before.identity,
            lifecycle_after.identity,
        )) return error.Stage101ProviderRouteMetalRuntimeIdentityChanged;
        const telemetry_after = try metal.MetalCommitBackend.telemetrySnapshot();
        const delta = telemetry_after.delta(self.telemetry_before);
        printTelemetry(delta.counters);
        try delta.requireResidentRiscPolynomialDispatch();
        try validateRequiredKernelCoverage(delta.counters);
        try requireShardBatchDispatches(delta.counters);
        const admitted_host_placements = try admittedHostPlacements(delta.counters);

        // ---- Stage 8: receipt, publish, THEN budget ----------------------
        const backend = route_mod.BackendReceiptV1{
            .aot_manifest_sha256 = expected_manifest_sha256,
            .aot_metallib_sha256 = expected_metallib_sha256,
            .aot_source_sha256 = expected_source_sha256,
            .aot_air_sha256 = expected_air_sha256,
            .aot_native_export_count = expected_native_export_count,
            .backend_identity_sha256 = backendIdentity(),
            .platform_identity_sha256 = self.platform_identity_sha256,
            .build_identity_sha256 = buildIdentity(),
            .runtime_initialization_ns = self.runtime_initialization_ns,
            .admitted_host_placements = admitted_host_placements,
            .telemetry = telemetryReceipt(delta.counters),
        };
        var receipt = route_mod.ReceiptV1.init(outcome, backend, .{});
        try route_mod.publishReceiptThenValidateBudget(
            self.allocator,
            self.output_path,
            &receipt,
        );
    }
};

/// Run the route. `arguments` are the Stage101 CPU command arguments with the
/// `--provider-route` pair already stripped by the leaf command's dispatcher.
/// Host knobs come from the leaf's environment only; the D5 shard plan is
/// pinned at comptime and no `STWO_ZIG_D5_PROVIDER_*` variable is read.
pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed = try replay_command.Options.parse(arguments);
    if (parsed.segment_index != route_mod.RetainedSourcePinsV1.segment_index)
        return error.Stage101ProviderRouteRetainedSourceMismatch;
    const output_path = try artifact_io.resolveAbsolute(allocator, parsed.output);
    defer allocator.free(output_path);
    const execution_policy = try executionPolicyFromEnvironment(allocator);
    const diagnostic_cancellation = try environmentFlag(
        allocator,
        diagnostic_cancellation_environment,
    );
    const profile_stages = std.process.hasEnvVarConstant(
        route_mod.stage_profile_environment,
    );

    const bundle_path = try std.process.getEnvVarOwned(
        allocator,
        leaf.aot_bundle_environment,
    );
    defer allocator.free(bundle_path);
    try aot.validate(allocator, bundle_path, expected_manifest_sha256);
    try validateBundlePins(allocator, bundle_path);

    const lifecycle_initial = metal.MetalCommitBackend.runtimeLifecycleSnapshot();
    if (lifecycle_initial.initialized)
        return error.Stage101ProviderRouteMetalRuntimeAlreadyInitialized;
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
    const platform_identity = try metal.MetalCommitBackend
        .runtimePlatformIdentityAlloc(allocator);
    defer allocator.free(platform_identity);

    var stage_recorder: route_mod.StageRecorder = undefined;
    if (profile_stages) stage_recorder = route_mod.initStageRecorder(allocator);
    defer if (profile_stages) stage_recorder.deinit();

    var state = StateV1{
        .allocator = allocator,
        .output_path = output_path,
        .execution_policy = execution_policy,
        .diagnostic_cancellation = diagnostic_cancellation,
        .recorder = if (profile_stages) &stage_recorder else null,
        .runtime_initialization_ns = runtime_initialization_ns,
        .lifecycle_before = lifecycle_before,
        .telemetry_before = try metal.MetalCommitBackend.telemetrySnapshot(),
        .platform_identity_sha256 = sha256(platform_identity),
        .total_measurement = try throughput.MeasurementV1.begin(),
    };
    try replay_command.runPreparedVisitor(
        allocator,
        arguments,
        .{ .context = &state, .visit_fn = StateV1.visitOpaque },
    );
}

// ---------------------------------------------------------------------------
// Environment (the leaf's three host knobs, nothing D5-specific)
// ---------------------------------------------------------------------------

fn executionPolicyFromEnvironment(
    allocator: std.mem.Allocator,
) !throughput.PolicyV1 {
    const worker_count = try environmentUsize(
        allocator,
        leaf.worker_count_environment,
    );
    const host_byte_budget = try environmentUsize(
        allocator,
        leaf.host_byte_budget_environment,
    );
    const host_byte_limit = try environmentUsize(
        allocator,
        leaf.host_byte_limit_environment,
    );
    return throughput.PolicyV1.init(
        worker_count,
        host_byte_budget,
        try throughput.HostCapacityV1.detect(host_byte_limit),
    );
}

fn environmentUsize(
    allocator: std.mem.Allocator,
    name: []const u8,
) !usize {
    const encoded = try std.process.getEnvVarOwned(allocator, name);
    defer allocator.free(encoded);
    return std.fmt.parseInt(usize, encoded, 10) catch
        error.InvalidStage101ProviderRouteEnvironment;
}

/// Absent -> false; exactly "1" -> true; anything else is a refusal rather
/// than a silently disabled diagnostic.
fn environmentFlag(allocator: std.mem.Allocator, name: []const u8) !bool {
    const encoded = std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer allocator.free(encoded);
    return parseFlag(encoded);
}

fn parseFlag(encoded: []const u8) !bool {
    const trimmed = std.mem.trim(u8, encoded, " ");
    if (std.mem.eql(u8, trimmed, "1")) return true;
    if (std.mem.eql(u8, trimmed, "0")) return false;
    return error.InvalidStage101ProviderRouteEnvironment;
}

// ---------------------------------------------------------------------------
// Bundle pins: the four SHAs and the export count the sweep records
// ---------------------------------------------------------------------------

const ManifestArtifactV1 = struct { sha256: []const u8 };
const ManifestArtifactsV1 = struct {
    air: ManifestArtifactV1,
    metallib: ManifestArtifactV1,
};
const ManifestExportV1 = struct { name: []const u8 };
const ManifestPinsV1 = struct {
    source: ManifestArtifactV1,
    artifacts: ManifestArtifactsV1,
    exports: []const ManifestExportV1,
};

/// Device-free check that the bundle whose manifest digest `aot.validate`
/// just authenticated is the bundle this command was written against: source,
/// AIR and metallib SHAs and the exact native export count.
fn validateBundlePins(allocator: std.mem.Allocator, bundle_path: []const u8) !void {
    var directory = try std.fs.openDirAbsolute(bundle_path, .{});
    defer directory.close();
    const manifest = try directory.readFileAlloc(
        allocator,
        aot.manifest_filename,
        1024 * 1024,
    );
    defer allocator.free(manifest);
    try validateManifestPins(allocator, manifest);
}

fn validateManifestPins(allocator: std.mem.Allocator, manifest: []const u8) !void {
    var parsed = std.json.parseFromSlice(
        ManifestPinsV1,
        allocator,
        manifest,
        .{ .ignore_unknown_fields = true },
    ) catch return error.Stage101ProviderRouteBundlePinMismatch;
    defer parsed.deinit();
    const pins = parsed.value;
    if (!hexEquals(pins.source.sha256, expected_source_sha256) or
        !hexEquals(pins.artifacts.air.sha256, expected_air_sha256) or
        !hexEquals(pins.artifacts.metallib.sha256, expected_metallib_sha256) or
        pins.exports.len != expected_native_export_count)
    {
        return error.Stage101ProviderRouteBundlePinMismatch;
    }
}

fn hexEquals(encoded: []const u8, expected: [32]u8) bool {
    if (encoded.len != 64) return false;
    var decoded: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, encoded) catch return false;
    return std.mem.eql(u8, &decoded, &expected);
}

// ---------------------------------------------------------------------------
// Lifecycle and telemetry closure (the leaf's, with the route's shard floor)
// ---------------------------------------------------------------------------

fn validateAuthenticatedLifecycle(
    lifecycle: metal.MetalCommitBackend.RuntimeLifecycleSnapshot,
) !void {
    if (!lifecycle.initialized or lifecycle.identity == null)
        return error.Stage101ProviderRouteAuthenticatedMetalRuntimeMissing;
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
        return error.Stage101ProviderRouteAuthenticatedMetalRuntimeMismatch;
    }
}

/// The leaf's kernel coverage, over the whole run (core plus 26 shards).
fn validateRequiredKernelCoverage(
    counters: metal.telemetry.CounterValues,
) !void {
    if (counters.resident_merkle_commits == 0)
        return error.Stage101ProviderRouteMetalMerkleDispatchMissing;
    if (counters.metal_poseidon2_merkle_commits == 0)
        return error.Stage101ProviderRouteMetalPoseidonMerkleDispatchMissing;
    if (counters.metal_sampled_value_dispatches == 0)
        return error.Stage101ProviderRouteMetalSampledValueDispatchMissing;
    if (counters.metal_circle_transform_dispatches == 0 or
        counters.metal_circle_lde_dispatches == 0)
    {
        return error.Stage101ProviderRouteMetalTransformDispatchMissing;
    }
    if (counters.metal_composition_eval_dispatches == 0 and
        (counters.metal_riscv_base_polynomial_batch_dispatches == 0 or
            counters.metal_riscv_lookup_polynomial_batch_dispatches == 0))
    {
        return error.Stage101ProviderRouteMetalCompositionDispatchMissing;
    }
    if (counters.metal_quotient_dispatches == 0)
        return error.Stage101ProviderRouteMetalQuotientDispatchMissing;
    if (counters.metal_fri_circle_fold_dispatches == 0 or
        counters.metal_fri_line_fold_dispatches == 0)
    {
        return error.Stage101ProviderRouteMetalFriDispatchMissing;
    }
    if (counters.metal_qm31_coordinate_dispatches == 0)
        return error.Stage101ProviderRouteMetalQm31DispatchMissing;
}

/// Every shard proof is one resident base batch and one resident lookup
/// batch; fewer than 26 of either means a shard proved on the host.
fn requireShardBatchDispatches(counters: metal.telemetry.CounterValues) !void {
    if (counters.metal_riscv_base_polynomial_batch_dispatches <
        minimum_shard_batch_dispatches or
        counters.metal_riscv_lookup_polynomial_batch_dispatches <
            minimum_shard_batch_dispatches)
    {
        return error.Stage101ProviderRouteShardBatchDispatchMissing;
    }
}

/// The leaf admits its tiny log<3 circle operations as host placements and
/// refuses every other CPU fallback. The route inherits that policy but does
/// not pin the count on its first run: the omitted core's small-circle
/// footprint is recorded in the receipt, and the run fails only if any
/// non-small-circle fallback is observed.
fn admittedHostPlacements(counters: metal.telemetry.CounterValues) !u64 {
    const small_circle = counters.cpu_small_circle_interpolations +|
        counters.cpu_small_circle_evaluations +|
        counters.cpu_small_circle_ldes;
    if (counters.cpuFallbackTotal() != small_circle)
        return error.Stage101ProviderRouteUnexpectedHostFallback;
    return small_circle;
}

fn telemetryReceipt(counters: metal.telemetry.CounterValues) route_mod.TelemetryReceiptV1 {
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
        "STAGE101_D5_ROUTE_METAL_TELEMETRY dispatch={} fallback={} " ++
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
        "STAGE101_D5_ROUTE_HOST_PLACEMENTS_V1 trace_generation=cpu " ++
            "small_circle_interpolation={} small_circle_evaluation={} " ++
            "small_circle_lde={} host_merkle={} cpu_composition={} " ++
            "cpu_fallback_total={}\n",
        .{
            counters.cpu_small_circle_interpolations,
            counters.cpu_small_circle_evaluations,
            counters.cpu_small_circle_ldes,
            counters.host_merkle_commits,
            counters.cpu_composition_evaluations,
            counters.cpuFallbackTotal(),
        },
    );
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

fn backendIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-leaf-d5-provider-route-metal-backend/v1\x00");
    hash.update(@typeName(MetalEngine));
    hash.update(@typeName(CpuVerifierEngine));
    hash.update(&expected_manifest_sha256);
    hash.update(&expected_metallib_sha256);
    hash.update(&expected_source_sha256);
    hash.update(&expected_air_sha256);
    hashU32(&hash, expected_native_export_count);
    return hash.finalResult();
}

fn buildIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101-leaf-d5-provider-route-build/v1\x00");
    hash.update(@tagName(builtin.mode));
    hash.update(@typeName(MetalEngine));
    hash.update(@typeName(CpuVerifierEngine));
    hash.update(&expected_manifest_sha256);
    hash.update(&expected_metallib_sha256);
    return hash.finalResult();
}

fn hashU32(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
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

// ---------------------------------------------------------------------------
// Device-free tests (run through `test-stage101-leaf-autoresearch-v1`)
// ---------------------------------------------------------------------------

test "Stage101 D5 route strips only its own flag and rejects unknown route values" {
    const allocator = std.testing.allocator;
    const base = [_][]const u8{
        "--retained-materialization-result", "/r.json",
        "--publication-root",                "/p",
        "--segment-index",                   "1",
        "--output",                          "/o.json",
    };
    const routed = [_][]const u8{
        "--provider-route", provider_route_value,
    } ++ base;
    var parsed = try stripProviderRoute(allocator, &routed);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(RouteSelectionV1.degree5_omit_v1, parsed.route);
    try std.testing.expectEqual(base.len, parsed.forwarded.len);
    for (base, parsed.forwarded) |expected, actual|
        try std.testing.expectEqualStrings(expected, actual);
    // The forwarded arguments are exactly what the replay command parses.
    const options = try replay_command.Options.parse(parsed.forwarded);
    try std.testing.expectEqual(@as(u32, 1), options.segment_index);

    var absent = try stripProviderRoute(allocator, &base);
    defer absent.deinit(allocator);
    try std.testing.expectEqual(RouteSelectionV1.native, absent.route);
    try std.testing.expectEqual(base.len, absent.forwarded.len);

    const unknown = base ++ [_][]const u8{ provider_route_flag, "degree5" };
    try std.testing.expectError(
        error.InvalidStage101ProviderRoute,
        stripProviderRoute(allocator, &unknown),
    );
}

test "Stage101 D5 route Metal coverage admits only small-circle host placements" {
    var counters = metal.telemetry.CounterValues{
        .resident_merkle_commits = 1,
        .metal_poseidon2_merkle_commits = 1,
        .metal_sampled_value_dispatches = 27,
        .metal_circle_transform_dispatches = 1,
        .metal_circle_lde_dispatches = 1,
        .riscv_base_polynomial_eligible_components = 104 + 78,
        .riscv_lookup_polynomial_eligible_components = 26 + 75,
        .metal_riscv_base_polynomial_batch_dispatches = 27,
        .metal_riscv_lookup_polynomial_batch_dispatches = 27,
        .metal_quotient_dispatches = 27,
        .metal_fri_circle_fold_dispatches = 27,
        .metal_fri_line_fold_dispatches = 22,
        .metal_qm31_coordinate_dispatches = 1,
        .cpu_small_circle_interpolations = 1,
        .cpu_small_circle_evaluations = 1,
        .cpu_small_circle_ldes = 1,
    };
    try validateRequiredKernelCoverage(counters);
    try requireShardBatchDispatches(counters);
    try std.testing.expectEqual(@as(u64, 3), try admittedHostPlacements(counters));
    const delta = metal.telemetry.Delta{
        .counters = counters,
        .pipeline_cache = .{},
    };
    try delta.requireResidentRiscPolynomialDispatch();

    counters.metal_riscv_lookup_polynomial_batch_dispatches = 25;
    try std.testing.expectError(
        error.Stage101ProviderRouteShardBatchDispatchMissing,
        requireShardBatchDispatches(counters),
    );
    counters.metal_riscv_lookup_polynomial_batch_dispatches = 27;
    counters.cpu_sampled_value_evaluations = 1;
    try std.testing.expectError(
        error.Stage101ProviderRouteUnexpectedHostFallback,
        admittedHostPlacements(counters),
    );
    counters.cpu_sampled_value_evaluations = 0;
    counters.metal_quotient_dispatches = 0;
    try std.testing.expectError(
        error.Stage101ProviderRouteMetalQuotientDispatchMissing,
        validateRequiredKernelCoverage(counters),
    );
    try std.testing.expect(try parseFlag("1"));
    try std.testing.expect(!try parseFlag("0"));
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteEnvironment,
        parseFlag("yes"),
    );
}

test "Stage101 D5 route bundle pins reject a drifted manifest" {
    const allocator = std.testing.allocator;
    const good =
        \\{"format":"stwo-zig-metal-core-aot-v2","source":{"path":"s.metal","sha256":"c2daaaf7dab998e6c542651dec73323973eafceee6ccf9d56fce6094ccac2786"},
        \\"artifacts":{"air":{"sha256":"bf21cda590c2102f9c0d373ad41294d952672e8757fd7e390e9a865df250dc33"},
        \\"metallib":{"sha256":"c9a87203415ab4432116db15a65a210849884db2a923ffe5adda2e88268fdb58"}},
        \\"exports":[
    ;
    var manifest: std.ArrayList(u8) = .empty;
    defer manifest.deinit(allocator);
    try manifest.appendSlice(allocator, good);
    for (0..expected_native_export_count) |index| {
        if (index != 0) try manifest.append(allocator, ',');
        try manifest.appendSlice(allocator, "{\"name\":\"k\",\"owner\":\"o\"}");
    }
    try manifest.appendSlice(allocator, "]}");
    try validateManifestPins(allocator, manifest.items);

    // One export fewer.
    var short: std.ArrayList(u8) = .empty;
    defer short.deinit(allocator);
    try short.appendSlice(allocator, good);
    for (0..expected_native_export_count - 1) |index| {
        if (index != 0) try short.append(allocator, ',');
        try short.appendSlice(allocator, "{\"name\":\"k\"}");
    }
    try short.appendSlice(allocator, "]}");
    try std.testing.expectError(
        error.Stage101ProviderRouteBundlePinMismatch,
        validateManifestPins(allocator, short.items),
    );
    // One flipped source nibble.
    const flipped = try allocator.dupe(u8, manifest.items);
    defer allocator.free(flipped);
    const at = std.mem.indexOf(u8, flipped, "c2daaaf7").?;
    flipped[at] = 'd';
    try std.testing.expectError(
        error.Stage101ProviderRouteBundlePinMismatch,
        validateManifestPins(allocator, flipped),
    );
}

comptime {
    if (FORMAT_VERSION != 1 or PRODUCTION_ACTIVE or COMPLETE_LEAF_PROOF or
        route_mod.PRODUCTION_ACTIVE or route_mod.COMPLETE_LEAF_PROOF or
        expected_native_export_count != 166 or
        minimum_shard_batch_dispatches != 26)
    {
        @compileError("Stage101 D5 provider route Metal command contract drifted");
    }
    if (MetalEngine.Hasher != CpuVerifierEngine.Hasher or
        MetalEngine.Channel != CpuVerifierEngine.Channel or
        MetalEngine.MerkleChannel != CpuVerifierEngine.MerkleChannel)
    {
        @compileError("Stage101 D5 provider route engines disagree on the transcript");
    }
}
