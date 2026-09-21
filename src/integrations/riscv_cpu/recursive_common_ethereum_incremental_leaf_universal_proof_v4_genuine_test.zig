//! Genuine, isolated role-0 q193 transaction.
//! Two genuine segments; cold-derived role-0 geometry is routable.
//! Other registry entries are test sentinels.
const std = @import("std");
const stwo_core = @import("stwo_core");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const campaign_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const materializer_mod =
    @import("recursive_common_ethereum_incremental_leaf_materializer_v4.zig");
const fixture =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const proof_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");
const runtime_mod =
    @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
const recipe_mod =
    @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const FreshInput = input_mod.FreshInputV4(Engine);
const FixedProgram = @import("ethereum_fixed_program_admission_v1.zig").OwnedV1;
const Campaign = campaign_mod.OwnedCampaignProviderGeometryV4;
const Materialized =
    campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
const Proof = proof_mod.Types(Engine);
const Sha256 = std.crypto.hash.sha2.Sha256;
const STAGE101_FIXTURE_HOST_BYTE_BUDGET: usize = 8 * 1024 * 1024 * 1024;
const WrapperMode = enum { prove, root_prove, materialize, closure, reconstruct, air_preflight, geometry_preflight, failed_replay, candidate_replay, allocator_probe, tree0_compare };
const Stage = enum {
    stage101_build,
    first_cold_open,
    second_cold_open,
    campaign,
    materialize,
    cohort,
    role0_prove,
    producer_destroy,
    verifier_rebuild,
    role0_reopen,
    fixture_registry,
    recursive_artifact,
    neutral_child,
    mutations,
};

test "role0 genuine two-leaf q193 proof cold-opens into neutral real child" {
    const allocator = std.testing.allocator;
    if (try runtime_mod.stopAfterMaterialize(allocator))
        return error.ProofGateCannotStopAfterMaterialize;
    const worker_policy = try runtime_mod.WorkerPolicyV4.fromEnvironment(
        allocator,
        STAGE101_FIXTURE_HOST_BYTE_BUDGET,
    );
    var total_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var stage: Stage = .stage101_build;
    errdefer |err| {
        std.debug.print(
            "ETHEREUM_INCREMENTAL_ROLE0_GENUINE_STAGE={s} error={s}\n",
            .{ @tagName(stage), @errorName(err) },
        );
        if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
    }

    var artifacts = try fixture.buildArtifactsWithExecutionAndClaimAdmission(
        Engine,
        allocator,
        .{ .cpu = try worker_policy.cpuRequest() },
        .field_authority_v4,
    );
    defer artifacts.deinit();
    try finishAndPrintPhase(
        &phase_usage,
        .stage101_build,
        worker_policy,
    );
    const stage101_execution = artifacts.execution_receipt orelse
        return error.InvalidRole0GenuineExecutionReceipt;
    try stage101_execution.validate();
    try std.testing.expectEqual(
        @as(u32, fixture.LEAF_COUNT),
        stage101_execution.proof_count,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(worker_policy.worker_count)),
        stage101_execution.worker_count,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(worker_policy.host_byte_budget)),
        stage101_execution.host_byte_budget,
    );

    const global_metadata_json = try std.json.Stringify.valueAlloc(allocator, GlobalReplayMetadataV1{ .leaves = artifacts.global_metadata }, .{});
    defer allocator.free(global_metadata_json);
    try runWrapper(.prove, allocator, &artifacts.bytes, &fixture.programElf(), null, global_metadata_json, worker_policy, 0, &total_usage, &stage);
}

test "role0 retained corpus records and reopens its whole program admission" {
    const allocator = std.testing.allocator;
    const directory = try replayDirectory(allocator, .base_bound_v3);
    defer allocator.free(directory);
    const elf = fixture.programElf();
    try runtime_mod.exportProgramElf(directory, &elf);
    const path = try std.fs.path.join(allocator, &.{ directory, "program.elf" });
    defer allocator.free(path);
    var digest: [32]u8 = undefined;
    Sha256.hash(&elf, &digest, .{});
    const bytes = try readPinnedStage101(allocator, path, &std.fmt.bytesToHex(digest, .lower));
    defer allocator.free(bytes);
    const admitted = try @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig").ProgramAdmissionV1.createFromElf(allocator, bytes);
    defer admitted.deinit();
    try std.testing.expectEqual(digest, admitted.sourceSha256());
}

const ClaimAdmissionV4 = @import("ethereum_incremental_full_leaf_profile_v4.zig").ClaimAdmissionV4;
const NativeReplayManifestV1 = runtime_mod.NativeReplayManifestV1;

test "role0 schema3 native pair serializes destroys producer and freshly verifies" {
    try produceRetainedNativePair(.selected_detailed_v3);
}

test "role0 field native pair serializes destroys producer and freshly verifies" {
    try produceRetainedNativePair(.field_authority_v4);
}

fn produceRetainedNativePair(comptime admission: ClaimAdmissionV4) !void {
    const allocator = std.testing.allocator;
    const directory = try replayDirectory(allocator, if (admission == .field_authority_v4) .field_bound_v4 else .base_bound_v3);
    defer allocator.free(directory);
    const policy = try runtime_mod.WorkerPolicyV4.fromEnvironment(allocator, STAGE101_FIXTURE_HOST_BYTE_BUDGET);
    var total_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var digests: [fixture.LEAF_COUNT][32]u8 = undefined;
    var program_digest: [32]u8 = undefined;
    var global_metadata_digest: [32]u8 = undefined;
    {
        // All producer allocations, including serialized buffers, die before
        // the independent verifier opens the retained files below.
        var producer = runtime_mod.TrackedSmpAllocatorV4{};
        defer std.debug.assert(producer.isEmpty());
        var artifacts = try fixture.buildArtifactsWithExecutionAndClaimAdmission(
            Engine,
            producer.allocator(),
            .{ .cpu = try policy.cpuRequest() },
            admission,
        );
        defer artifacts.deinit();
        const execution = artifacts.execution_receipt orelse return error.InvalidRole0GenuineExecutionReceipt;
        try execution.validate();
        try std.testing.expectEqual(@as(u32, fixture.LEAF_COUNT), execution.proof_count);
        for (artifacts.bytes, &digests) |bytes, *digest| Sha256.hash(bytes, digest, .{});
        try runtime_mod.exportStage101ToDirectory(allocator, directory, &artifacts.bytes);
        const elf = fixture.programElf();
        Sha256.hash(&elf, &program_digest, .{});
        try runtime_mod.exportProgramElf(directory, &elf);
        const metadata_json = try std.json.Stringify.valueAlloc(allocator, GlobalReplayMetadataV1{ .leaves = artifacts.global_metadata }, .{});
        defer allocator.free(metadata_json);
        Sha256.hash(metadata_json, &global_metadata_digest, .{});
        const manifest_json = try std.json.Stringify.valueAlloc(allocator, NativeReplayManifestV1{
            .claim_admission = admission,
            .native_sha256 = digests,
            .program_sha256 = program_digest,
            .global_metadata_sha256 = global_metadata_digest,
        }, .{});
        defer allocator.free(manifest_json);
        try runtime_mod.exportNativeReplayManifest(directory, manifest_json, metadata_json);
    }
    try finishAndPrintPhase(&phase_usage, .stage101_build, policy);
    std.debug.print("ETHEREUM_BASE_BOUND_NATIVE producer_destroyed=true source=disk profile_schema={d}\n", .{@intFromEnum(admission)});
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    const program_path = try std.fs.path.join(allocator, &.{ directory, "program.elf" });
    defer allocator.free(program_path);
    const program_hex = std.fmt.bytesToHex(program_digest, .lower);
    const retained_elf = try readPinnedStage101(allocator, program_path, &program_hex);
    defer allocator.free(retained_elf);
    const program_admission = try @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig")
        .ProgramAdmissionV1.createFromElf(allocator, retained_elf);
    defer program_admission.deinit();
    const metadata_path = try std.fs.path.join(allocator, &.{ directory, "global-metadata-v1.json" });
    defer allocator.free(metadata_path);
    const metadata_json = try readPinnedStage101(allocator, metadata_path, &std.fmt.bytesToHex(global_metadata_digest, .lower));
    defer allocator.free(metadata_json);
    const metadata = try decodeGlobalReplayMetadata(allocator, metadata_json);
    for (digests, 0..) |digest, index| {
        const hex = std.fmt.bytesToHex(digest, .lower);
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.bin", .{ directory, hex });
        defer allocator.free(path);
        const bytes = try readPinnedStage101(allocator, path, &hex);
        defer allocator.free(bytes);
        var fresh_native = try FreshInput.coldOpen(allocator, bytes, try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, @intCast(index)), .{});
        defer fresh_native.deinit();
        try std.testing.expectEqual(
            admission,
            try fresh_native.stage101.profile.claimAdmission(),
        );
        try fresh_native.admitGlobalMetadata(&metadata.leaves[index]);
        try fresh_native.validate();
        try std.testing.expectEqual(program_admission.programRoot(), fresh_native.stage101.role_aware_public.value.program_root orelse return error.MissingProgramRoot);
        std.debug.print("ETHEREUM_BASE_BOUND_NATIVE leaf={d} sha256={s} bytes={d} freshly_verified=true profile_schema={d} global_metadata_admitted=true\n", .{ index, hex, bytes.len, @intFromEnum(admission) });
    }
    try finishAndPrintPhase(&phase_usage, .cold_open, policy);
    try finishAndPrintPhase(&total_usage, .total, policy);
}

const GlobalReplayMetadataV1 = runtime_mod.GlobalReplayMetadataV1;

fn decodeGlobalReplayMetadata(allocator: std.mem.Allocator, bytes: []const u8) !GlobalReplayMetadataV1 {
    const parsed = try std.json.parseFromSlice(GlobalReplayMetadataV1, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value.version != 1) return error.UnsupportedGlobalReplayMetadata;
    for (&parsed.value.leaves) |*metadata| try metadata.validate();
    return parsed.value;
}

// The comparison authority is a separately pinned ordinary child key, never
// a dimension vector copied from the candidate being inspected.
fn expectedWrapperGeometry(allocator: std.mem.Allocator) !frontend.recursion.fixed_wire.Dimensions {
    const path = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_GEOMETRY_EXPECTED_KEY");
    defer allocator.free(path);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_GEOMETRY_EXPECTED_KEY_SHA256");
    defer allocator.free(pin);
    if (pin.len != 64) return error.InvalidEthereumGeometryKeyPin;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, pin);
    const bytes = try @import("ethereum_precompile_artifact_io.zig").readFileBounded(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(bytes);
    const key = try @import("ethereum_wrapper_root_command_v1.zig").OwnedKeyV1.admit(allocator, bytes, digest);
    defer key.deinit();
    const shape = try @import("ethereum_wrapper_child_shape_v1.zig").OwnedV1.create(allocator, key.key());
    defer shape.deinit();
    std.debug.print("ETHEREUM_WRAPPER_GEOMETRY_EXPECTED key_sha256={s} dimensions={any} key_admitted=true proof_verified=false\n", .{ pin, shape.wireDimensions() });
    return shape.wireDimensions();
}

fn runWrapper(
    comptime mode: WrapperMode,
    allocator: std.mem.Allocator,
    artifact_bytes: []const []const u8,
    program_elf: []const u8,
    fixed_program: ?*const FixedProgram,
    global_metadata_json: ?[]const u8,
    worker_policy: runtime_mod.WorkerPolicyV4,
    pair_slot: u1,
    total_usage: *runtime_mod.PhaseUsageMeasurementV4,
    stage: *Stage,
) !void {
    const proves_wrapper = mode == .prove or mode == .root_prove;
    const expected_geometry = if (mode == .geometry_preflight) try expectedWrapperGeometry(allocator) else undefined;
    errdefer {
        std.debug.print("ETHEREUM_INCREMENTAL_ROLE0_REQUEST outcome=failed\n", .{});
        finishAndPrintPhase(total_usage, .total, worker_policy) catch |err|
            std.debug.print("ETHEREUM_INCREMENTAL_ROLE0_MEASUREMENT_ERROR={s}\n", .{@errorName(err)});
    }
    try std.testing.expectEqual(@as(usize, fixture.LEAF_COUNT), artifact_bytes.len);
    var tracked_allocator = runtime_mod.TrackedSmpAllocatorV4{};
    defer {
        if (!tracked_allocator.isEmpty()) {
            const leak = tracked_allocator.snapshot();
            std.debug.print(
                "ETHEREUM_INCREMENTAL_ROLE0_ALLOCATOR_LEAK " ++
                    "allocations={d} bytes={d} peak={d} allocated={d} " ++
                    "freed={d} untracked={d}\n",
                .{
                    leak.active_allocations,
                    leak.active_bytes,
                    leak.peak_active_bytes,
                    leak.total_allocated_bytes,
                    leak.total_freed_bytes,
                    leak.untracked_active_allocations,
                },
            );
            tracked_allocator.dumpLeaks();
            @panic("role0 genuine runtime allocator leaked");
        }
    }
    const runtime_allocator = tracked_allocator.allocator();
    // The proof route owns native captures through the same tracked runtime
    // lifetime as their materializer, including fresh verifier reconstruction.
    // Register this guard before capture cleanup so every owner dies first.
    // Other development modes retain their existing native allocation policy.
    const native_allocator = if (proves_wrapper) runtime_allocator else allocator;
    var phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    const pair = try coldOpenNativePair(native_allocator, artifact_bytes, global_metadata_json, fixed_program, worker_policy, stage);
    var first = pair[0];
    var first_live = true;
    defer if (first_live) first.deinit();
    var second = pair[1];
    var second_live = true;
    defer if (second_live) second.deinit();
    try finishAndPrintPhase(&phase_usage, .cold_open, worker_policy);
    try runtime_mod.exportStage101(allocator, artifact_bytes);

    stage.* = .campaign;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    const inventory = try fixtureInventory();
    const fresh_inputs = [_]*const FreshInput{ &first, &second };
    var campaign = try Campaign.mintFromBorrowedFreshInputsAt(
        Engine,
        allocator,
        inventory,
        first.coordinate.index,
        &fresh_inputs,
    );
    var campaign_live = true;
    defer if (campaign_live) campaign.deinit();
    try std.testing.expectEqual(@as(u32, fixture.LEAF_COUNT), campaign.view().leaf_count);
    try std.testing.expectEqual(@as(usize, fixture.LEAF_COUNT), campaign.view().active_tuple_counts.len);
    try std.testing.expect(campaign.view().active_tuple_counts[0] > 0);
    if (first.coordinate.index == 0) {
        try std.testing.expectEqual(@as(u32, 0), campaign.view().active_tuple_counts[1]);
        try std.testing.expectEqual(@as(u32, 0), campaign.view().maximum_leaf_index);
    }
    try std.testing.expectEqual(first.coordinate.index, campaign.view().first_leaf_index);
    if (first.coordinate.index != 0) {
        // The old zero-based constructor must not relabel an admitted real
        // subrange. Its native/global coordinates remain proof-bound.
        if (Campaign.mintFromBorrowedFreshInputs(Engine, allocator, inventory, &fresh_inputs)) |unexpected| {
            var owned = unexpected;
            owned.deinit();
            return error.CampaignSubrangeRelabeled;
        } else |err| try std.testing.expectEqual(error.InvalidCampaignProviderGeometryInputV4, err);
    }
    try finishAndPrintPhase(&phase_usage, .campaign, worker_policy);

    stage.* = .materialize;
    var materialization_metrics = materializer_mod.MaterializationMetricsV4{};
    errdefer if (stage.* == .materialize) printMaterializationMetrics(
        materialization_metrics,
        worker_policy.worker_count,
    );
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var materialized = try materializeReplayInput(
        runtime_allocator,
        if (pair_slot == 0) &first else &second,
        &campaign,
        pair_slot,
        program_elf,
        worker_policy,
        &materialization_metrics,
    );
    if (pair_slot == 0) first_live = false else second_live = false;
    std.debug.print("ETHEREUM_WRAPPER_SELECTED pair_slot={d} global_segment={d}\n", .{ pair_slot, materialized.base.input.coordinate.index });
    var materialized_live = true;
    defer if (materialized_live) materialized.deinit();
    try finishAndPrintPhase(&phase_usage, .materialize, worker_policy);
    printMaterializationMetrics(
        materialization_metrics,
        worker_policy.worker_count,
    );
    printAllocatorSnapshot("materialized-live", tracked_allocator.snapshot());
    if (mode == .tree0_compare) {
        stage.* = .cohort;
        try @import("ethereum_wrapper_tree0_probe_v1.zig").compare(Engine, @import("ethereum_tree0_probe_backend").Backend, runtime_allocator, &materialized, worker_policy.worker_count);
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }
    if (mode == .failed_replay) {
        stage.* = .cohort;
        try @import("ethereum_failed_wrapper_replay_v1.zig").replayFromEnvironment(Engine, runtime_allocator, &materialized);
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }
    if (mode == .air_preflight or mode == .geometry_preflight) {
        stage.* = .cohort;
        var admission_scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
        try admission_scope.initInPlace(worker_policy.worker_count);
        defer admission_scope.deinit();
        const preflight = @import("ethereum_typed_air_preflight_v4.zig");
        if (mode == .geometry_preflight)
            try preflight.geometryOnly(Engine, runtime_allocator, &materialized, expected_geometry)
        else
            try preflight.audit(Engine, runtime_allocator, &materialized);
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }
    if (mode == .closure) {
        stage.* = .cohort;
        var admission_scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
        try admission_scope.initInPlace(worker_policy.worker_count);
        defer admission_scope.deinit();
        try @import("ethereum_statement_root_cohort_replay.zig").audit(Engine, runtime_allocator, &materialized);
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }
    if (mode == .materialize) {
        var retained_campaign = try materialized.campaign_authority.clone(allocator);
        defer retained_campaign.deinit();
        campaign.deinit();
        campaign_live = false;
        try exerciseRetainedCampaignMembership(&materialized);
        phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
        var cleanup_timer = try std.time.Timer.start();
        var retained_input = materialized.deinitRetainingInput();
        materialized_live = false;
        defer retained_input.deinit();
        try finishAndPrintPhase(
            &phase_usage,
            .materialize_cleanup,
            worker_policy,
        );
        const after_cleanup = tracked_allocator.snapshot();
        std.debug.print(
            "ETHEREUM_INCREMENTAL_ROLE0_MATERIALIZE_CLEANUP " ++
                "ns={d} allocator_empty={} peak_allocator_bytes={d}\n",
            .{
                cleanup_timer.read(),
                tracked_allocator.isEmpty(),
                tracked_allocator.peakBytes(),
            },
        );
        printAllocatorSnapshot("materialized-deinitialized", after_cleanup);
        if (!tracked_allocator.isEmpty()) tracked_allocator.dumpLeaks();
        try std.testing.expect(tracked_allocator.isEmpty());
        var rollback_timer = try std.time.Timer.start();
        try exerciseMaterializerFailureOwnership(runtime_allocator, &retained_input, &retained_campaign);
        try std.testing.expect(tracked_allocator.isEmpty());
        std.debug.print("ETHEREUM_ROLE0_MATERIALIZER_ROLLBACK ns={d} allocator_empty=true\n", .{rollback_timer.read()});
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }

    const root_command = @import("ethereum_wrapper_root_command_v1.zig");
    const initial_profile = materialized.initial_input_admission != null;
    // The next saved-parent consumer admits the ordinary 36-component profile.
    // Initial38 retains its existing explicitly selected lifecycle below.
    if (mode == .root_prove and initial_profile) return error.EthereumRootProductionRequiresOrdinaryProfile;
    if (initial_profile and mode == .prove) {
        const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return error.EthereumInitialRootCorpusRequired,
            else => return err,
        };
        defer allocator.free(corpus);
        if (corpus.len == 0) return error.EthereumInitialRootCorpusRequired;
    }
    var retained_root_bundle: ?root_command.BundleLocationV1 = null;
    defer if (retained_root_bundle) |*bundle| bundle.deinit();
    const retained: ?[]u8 = if (proves_wrapper) blk: {
        stage.* = .role0_prove;
        phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
        var proved = try Proof.proveCanonical(
            runtime_allocator,
            &materialized,
            .{ .worker_count = worker_policy.worker_count },
        );
        defer proved.deinit();
        try proved.receipt.validate();
        try std.testing.expectEqual(
            @as(u32, @intCast(worker_policy.worker_count)),
            proved.receipt.worker_count,
        );
        const serialized = try allocator.dupe(u8, proved.bytes);
        errdefer allocator.free(serialized);
        if (proved.root_bundle) |bundle| {
            retained_root_bundle = .{ .allocator = allocator, .path = try allocator.dupe(u8, bundle.path), .expected_key_sha256 = bundle.expected_key_sha256 };
            std.debug.print("ETHEREUM_ROOT_CANDIDATE path={s} expected_key_sha256={x} independently_verified=false\n", .{ bundle.path, bundle.expected_key_sha256 });
        } else if (initial_profile) return error.EthereumInitialRootBundleRequired else if (mode == .root_prove) return error.EthereumRootBundleRequired;
        try runtime_mod.exportWrapperReplay(allocator, artifact_bytes, program_elf, serialized, global_metadata_json);
        try finishAndPrintPhase(&phase_usage, .role0_prove, worker_policy);
        break :blk serialized;
    } else null;
    defer if (retained) |bytes| allocator.free(bytes);

    // Only serialized native inputs and wrapper bytes cross this boundary.
    // A cold open against the producer's materializer is not independent.
    stage.* = .producer_destroy;
    const expected_identity = materialized.identity_sha256;
    const expected_public = materialized.schedule.node_public;
    materialized.deinit();
    materialized_live = false;
    campaign.deinit();
    campaign_live = false;
    if (first_live) {
        first.deinit();
        first_live = false;
    }
    if (second_live) {
        second.deinit();
        second_live = false;
    }
    try std.testing.expect(tracked_allocator.isEmpty());
    printAllocatorSnapshot("producer-destroyed", tracked_allocator.snapshot());

    if (initial_profile and mode == .prove) {
        const bundle = retained_root_bundle orelse return error.EthereumInitialRootBundleRequired;
        const receipt = try root_command.Initial38.verifyDirectory(runtime_allocator, bundle.path, bundle.expected_key_sha256);
        try checkExpectedRootPublic(&expected_public, receipt);
        try std.testing.expect(tracked_allocator.isEmpty());
        std.debug.print("ETHEREUM_ROOT_INDEPENDENT profile=initial38 serialized=true producer_destroyed=true native_inputs_used=false verified=true request_ns={d} verify_ns={d} proof_bytes={d}\n", .{ receipt.request_ns, receipt.verify_ns, receipt.proof_bytes });
        try checkInitialRootRejections(runtime_allocator, bundle);
        try std.testing.expect(tracked_allocator.isEmpty());
        // Initial38 uses detached root verification. Its recursive child capture
        // still requires an explicitly admitted 38-component transcript layout.
        std.debug.print("ETHEREUM_INITIAL_ROOT recursive_child_publication=false\n", .{});
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }
    if (retained_root_bundle) |bundle| {
        const receipt = try root_command.verifyDirectory(runtime_allocator, bundle.path, bundle.expected_key_sha256);
        try checkExpectedRootPublic(&expected_public, receipt);
        try std.testing.expect(tracked_allocator.isEmpty());
        std.debug.print("ETHEREUM_ROOT_INDEPENDENT serialized=true producer_destroyed=true native_inputs_used=false verified=true request_ns={d} verify_ns={d} proof_bytes={d}\n", .{ receipt.request_ns, receipt.verify_ns, receipt.proof_bytes });
    }

    if (mode == .root_prove) {
        _ = retained_root_bundle orelse return error.EthereumRootBundleRequired;
        // The detached parent reconstructs its child transcript/composition
        // directly from this independently verified root bundle. Legacy native
        // reconstruction and CaptureV4 publication remain in .prove diagnostics.
        try std.testing.expect(tracked_allocator.isEmpty());
        std.debug.print("ETHEREUM_ROOT_PRODUCTION profile=ordinary36 full_root_verified=true serialized=true producer_destroyed=true native_inputs_used=false legacy_capture_exercised=false\n", .{});
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }

    stage.* = .verifier_rebuild;
    materialized = try rebuildVerifierInputs(native_allocator, runtime_allocator, artifact_bytes, program_elf, fixed_program, global_metadata_json, worker_policy, pair_slot);
    materialized_live = true;
    try std.testing.expectEqual(expected_identity, materialized.identity_sha256);
    try materialized.validate();
    if (mode == .reconstruct) {
        materialized.deinit();
        materialized_live = false;
        try std.testing.expect(tracked_allocator.isEmpty());
        std.debug.print("ETHEREUM_ROLE0_INDEPENDENT_INPUTS producer_destroyed=true rebuilt_from_serialized_native_inputs=true wrapper_verified=false\n", .{});
        try finishAndPrintPhase(total_usage, .total, worker_policy);
        return;
    }

    stage.* = .role0_reopen;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var cold = try Proof.coldOpenWithWorkers(runtime_allocator, &materialized, retained.?, worker_policy.worker_count);
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    try cold.validateBorrowed();
    std.debug.print("ETHEREUM_ROLE0_INDEPENDENT_PROOF serialized=true producer_destroyed=true fresh_verifier=true wrapper_verified=true\n", .{});
    try std.testing.expectEqual(@as(u16, 36), cold.geometryForPaddingTarget().*.component_count);
    try std.testing.expectEqual(@as(u16, 36), cold.geometryForPaddingTarget().*.proof_shape.claimed_sum_count);
    try std.testing.expectEqual(
        @as(u16, 193),
        cold.geometryForPaddingTarget().*.proof_shape.query_count,
    );
    try finishAndPrintPhase(&phase_usage, .role0_reopen, worker_policy);

    cold_live = false; // The shared check owns cleanup even on rejection.
    try checkRecursivePublication(cold, worker_policy, stage);
    std.debug.print(
        "ETHEREUM_INCREMENTAL_ROLE0_RUNTIME peak_allocator_bytes={d}\n",
        .{tracked_allocator.peakBytes()},
    );
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    printAllocatorSnapshot(
        "recursive-owners-deinitialized",
        tracked_allocator.snapshot(),
    );
    materialized.deinit();
    materialized_live = false;
    const final_allocator = tracked_allocator.snapshot();
    printAllocatorSnapshot("all-stage102-deinitialized", final_allocator);
    if (!tracked_allocator.isEmpty()) tracked_allocator.dumpLeaks();
    try std.testing.expect(tracked_allocator.isEmpty());
    try finishAndPrintPhase(
        &phase_usage,
        .stage102_cleanup,
        worker_policy,
    );
    try finishAndPrintPhase(total_usage, .total, worker_policy);
}

fn checkExpectedRootPublic(expected: *const @import("recursive_field_node_public_v2.zig").NodePublicV2, receipt: anytype) !void {
    try std.testing.expectEqualDeep(expected.coordinate, receipt.coordinate);
    try std.testing.expectEqualDeep(expected.statement_words, receipt.statement_words);
    try std.testing.expectEqualDeep(expected.output_digest, receipt.output_digest);
}

fn checkInitialRootRejections(allocator: std.mem.Allocator, bundle: @import("ethereum_wrapper_root_command_v1.zig").BundleLocationV1) !void {
    const command = @import("ethereum_wrapper_root_command_v1.zig").Initial38;
    const verifier = @import("ethereum_wrapper_root_verifier_v1.zig").Initial38;
    var dir = try std.fs.cwd().openDir(bundle.path, .{});
    defer dir.close();
    const key_bytes = try dir.readFileAlloc(allocator, "key.json", 64 * 1024 * 1024);
    defer allocator.free(key_bytes);
    var wrong_pin = bundle.expected_key_sha256;
    wrong_pin[0] ^= 1;
    try runtime_mod.writeReplayFile(dir, "rejected-key-pin.bin", &wrong_pin);
    try std.testing.expectError(error.EthereumRootKeyHashMismatch, command.OwnedKeyV1.admit(allocator, key_bytes, wrong_pin));
    const key = try command.OwnedKeyV1.admit(allocator, key_bytes, bundle.expected_key_sha256);
    defer key.deinit();
    const input_bytes = try dir.readFileAlloc(allocator, "inputs.json", 128 * 1024);
    defer allocator.free(input_bytes);
    const inputs = try command.decodeInputs(allocator, input_bytes);
    const proof = try dir.readFileAlloc(allocator, "proof.bin", inputs.proof_bytes);
    defer allocator.free(proof);

    // Recompute the public hashes so this is a valid alternative public node,
    // not merely a malformed encoding rejected before proof verification.
    var changed_inputs = inputs;
    var changed_source = inputs.node.source_digest;
    changed_source[0] = (changed_source[0] + 1) % stwo_core.fields.m31.Modulus;
    changed_inputs.node = try @import("recursive_field_node_public_v2.zig").NodePublicV2.initLeaf(inputs.node.coordinate, inputs.node.statement_words, changed_source);
    const changed_json = try std.json.Stringify.valueAlloc(allocator, changed_inputs, .{});
    defer allocator.free(changed_json);
    try runtime_mod.writeReplayFile(dir, "rejected-public-inputs.json", changed_json);
    if (verifier.verify(allocator, key.key(), &changed_inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof)) |_| {
        return error.EthereumInitialRootAcceptedChangedPublicInput;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        std.debug.print("ETHEREUM_INITIAL_ROOT_REJECTION case=changed_public_input error={s}\n", .{@errorName(err)});
    }

    proof[proof.len - 1] ^= 1;
    try runtime_mod.writeReplayFile(dir, "rejected-proof.bin", proof);
    if (verifier.verify(allocator, key.key(), &inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof)) |_| {
        return error.EthereumInitialRootAcceptedCorruptProof;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        std.debug.print("ETHEREUM_INITIAL_ROOT_REJECTION case=corrupt_proof error={s}\n", .{@errorName(err)});
    }
    std.debug.print("ETHEREUM_INITIAL_ROOT_REJECTIONS wrong_key=true changed_public_input=true corrupt_proof=true retained=true\n", .{});
}

test "role0 genuine fixture and q193 proof APIs compile separately" {
    const Builder = struct {
        fn call(
            allocator: std.mem.Allocator,
        ) anyerror!fixture.OwnedArtifactsV4(Engine) {
            return fixture.buildArtifacts(Engine, allocator);
        }
    };
    const builder: *const fn (std.mem.Allocator) anyerror!fixture.OwnedArtifactsV4(Engine) = Builder.call;
    _ = builder;
    std.testing.refAllDeclsRecursive(Proof);
    try std.testing.expectEqual(@as(usize, 2), fixture.LEAF_COUNT);
    try std.testing.expect(!proof_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!proof_mod.WRAPPER_PROOF_AVAILABLE);
    try std.testing.expect(!proof_mod.COLD_WRAPPER_CAPTURE_AVAILABLE);
    try std.testing.expect(!proof_mod.FOLD_CHILD_PROJECTION_AVAILABLE);
}

fn printMaterializationMetrics(
    metrics: materializer_mod.MaterializationMetricsV4,
    worker_count: usize,
) void {
    std.debug.print(
        "ETHEREUM_INCREMENTAL_ROLE0_MATERIALIZE " ++
            "input_ns={d} public_ns={d} transcript_ns={d} profile_ns={d} " ++
            "program_ns={d} prepare_ns={d} fri_ns={d} seal_ns={d} total_ns={d} " ++
            "nodes={d} node_bytes={d} output_bytes={d} binding_bytes={d} " ++
            "schedule_bytes={d} evaluation_bytes={d} input_bytes={d} " ++
            "claim_bytes={d} schedule_compiles={d} graph_copies={d} workers={d}\n",
        .{
            metrics.input_validation_ns,
            metrics.public_witness_ns,
            metrics.transcript_ns,
            metrics.base_profile_ns,
            metrics.program_compile_ns,
            metrics.composition_prepare_ns,
            metrics.fri_capture_ns,
            metrics.final_seal_ns,
            metrics.total_ns,
            metrics.graph_node_count,
            metrics.graph_node_bytes,
            metrics.graph_output_bytes,
            metrics.graph_binding_bytes,
            metrics.retained_schedule_bytes,
            metrics.evaluation_bytes,
            metrics.input_value_bytes,
            metrics.detailed_claim_bytes,
            metrics.graph_schedule_compile_count,
            metrics.retained_graph_copy_count,
            metrics.schedule_projection_worker_count,
        },
    );
    std.debug.assert(metrics.schedule_projection_worker_count == worker_count);
}

fn printAllocatorSnapshot(
    comptime phase: []const u8,
    snapshot: runtime_mod.TrackedSmpAllocatorV4.SnapshotV4,
) void {
    std.debug.print(
        "ETHEREUM_INCREMENTAL_ROLE0_ALLOCATOR phase={s} " ++
            "allocations={d} bytes={d} peak={d} allocated={d} " ++
            "freed={d} untracked={d}\n",
        .{
            phase,
            snapshot.active_allocations,
            snapshot.active_bytes,
            snapshot.peak_active_bytes,
            snapshot.total_allocated_bytes,
            snapshot.total_freed_bytes,
            snapshot.untracked_active_allocations,
        },
    );
}

fn finishAndPrintPhase(
    measurement: *runtime_mod.PhaseUsageMeasurementV4,
    phase: runtime_mod.RuntimePhaseV4,
    policy: runtime_mod.WorkerPolicyV4,
) !void {
    const receipt = try measurement.finish(phase, policy);
    try receipt.validate();
    @import("ethereum_wrapper_resources_v1.zig").progress(
        "ETHEREUM_INCREMENTAL_ROLE0_PHASE phase={s} source={s} " ++
            "wall_ns={d} process_cpu_ns={d} parallelism_milli={d} " ++
            "peak_footprint_bytes={d} energy_nj={d} instructions={d} " ++
            "cycles={d} workers={d} host_byte_budget={d}\n",
        .{
            @tagName(receipt.phase),
            @tagName(receipt.source),
            receipt.wall_ns,
            receipt.process_cpu_ns orelse 0,
            receipt.average_parallelism_milli orelse 0,
            receipt.lifetime_peak_physical_footprint_bytes orelse 0,
            receipt.energy_nj orelse 0,
            receipt.instructions orelse 0,
            receipt.cycles orelse 0,
            receipt.worker_count,
            receipt.host_byte_budget,
        },
    );
}

fn UnusedChild(comptime ProofTypes: type) type {
    return struct {
        wrapper: @import("recursive_common_wrapper_authority_v2.zig")
            .FreshWrapperViewV2,
        ingress: ProofTypes.Ingress,
        graph: ProofTypes.Graph,
        query_words: *const [193]M31,
        query_log_size: u32,
        final_transcript_digest: *const frontend.recursion.poseidon2_channel.Digest,
        final_transcript_draw_count: u32,
        query_words_identity_sha256: *const [32]u8,

        pub fn validateBorrowed(_: @This()) !void {
            return error.UnusedRole0GenuineSibling;
        }
    };
}

fn testOnlyRole0Registry(
    role0: *const registry_mod.AuthenticatedGeometryV1,
) !registry_mod.RecursiveCircuitRegistryV1 {
    try role0.validate();
    if (role0.role != .ethereum_incremental_leaf_wrapper_v4)
        return error.InvalidRole0GenuineFixtureRegistry;
    const empty = try sentinelGeometry(role0.*, .canonical_empty_field_v2);
    const common = try sentinelGeometry(role0.*, .common_fold_field_v2);
    return registry_mod.RecursiveCircuitRegistryV1.seal(.{
        try registry_mod.RegistryEntryV1.fromGeometry(role0),
        try registry_mod.RegistryEntryV1.fromGeometry(&empty),
        try registry_mod.RegistryEntryV1.fromGeometry(&common),
    });
}

fn sentinelGeometry(
    role0: registry_mod.AuthenticatedGeometryV1,
    role: registry_mod.CircuitRoleV4,
) !registry_mod.AuthenticatedGeometryV1 {
    var result = role0;
    result.role = role;
    result.circuit_identity_sha256 = sentinelIdentity("circuit", role);
    result.program_identity_sha256 = sentinelIdentity("program", role);
    result.profile_identity_sha256 = sentinelIdentity("profile", role);
    result.padding_layout_identity_sha256 = sentinelIdentity("padding", role);
    result.preprocessed_root = .{@intFromEnum(role) + 41} ++
        ([_]u32{0} ** 7);
    result.authority_identity_sha256 = undefined;
    return registry_mod.AuthenticatedGeometryV1.seal(result);
}

fn expectNoProductionParity(
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
    role0: registry_mod.AuthenticatedGeometryV1,
) !void {
    const empty = try sentinelGeometry(role0, .canonical_empty_field_v2);
    const common = try sentinelGeometry(role0, .common_fold_field_v2);
    _ = registry_mod.PaddingParityV1.derive(
        registry,
        .{ role0, empty, common },
    ) catch return;
    return error.TestOnlyRegistryMintedProductionParity;
}

fn fixtureInventory() !campaign_mod.CampaignInventoryAuthorityV4 {
    const globals = fixtureGlobals();
    var records: [fixture.LEAF_COUNT]table_mod.LeafRecordV4 = undefined;
    for (&records, 0..) |*record, index|
        record.* = fixtureRecord(globals, @intCast(index));
    const table = try table_mod.CampaignTableV4.seal(.{
        .segment_count = fixture.LEAF_COUNT,
        .globals = globals,
        .records = &records,
        .content_sha256 = undefined,
    });
    return campaign_mod.CampaignInventoryAuthorityV4.fromTable(&table);
}

fn fixtureGlobals() table_mod.GlobalRefsV4 {
    return .{
        .capture_manifest = ref(.capture_transport, 4, 13, 1),
        .public_wire_manifest = ref(
            .capture_transport,
            wire_publication.CAS_MANIFEST_SCHEMA_VERSION,
            17,
            2,
        ),
        .compact_manifest = ref(
            .capture_transport,
            table_mod.COMPACT_MANIFEST_CAS_SCHEMA_VERSION,
            19,
            3,
        ),
        .execution_profile_receipt = ref(.profile_receipt, 1, 23, 4),
        .materialization_result = ref(
            .source,
            table_mod.MATERIALIZATION_CAS_SCHEMA_VERSION,
            29,
            5,
        ),
        .source_request = ref(.source, 1, 31, 6),
        .execution_journal = ref(
            .journal,
            table_mod.FULL_JOURNAL_CAS_SCHEMA_VERSION,
            37,
            7,
        ),
        .program = ref(.program, 1, 41, 8),
        .raw_input = ref(.raw, 1, 43, 9),
        .expected_output = ref(.raw, 1, 47, 10),
    };
}

fn fixtureRecord(
    globals: table_mod.GlobalRefsV4,
    index: u32,
) table_mod.LeafRecordV4 {
    const statement = ref(
        .statement,
        1,
        @import("ethereum_block_leaf_support.zig").source_wire.encoded_size,
        @intCast(20 + index),
    );
    const recipe = ref(
        .capture_transport,
        recipe_mod.SCHEMA_VERSION,
        recipe_mod.ENCODED_BYTE_COUNT,
        @intCast(30 + index),
    );
    const compact = ref(.capture_transport, 1, 53 + index, @intCast(40 + index));
    const boundary = ref(.capture_transport, 4, 59 + index, @intCast(50 + index));
    const public_reference = ref(
        .capture_transport,
        wire_publication.CAS_REFERENCE_SCHEMA_VERSION,
        wire_publication.reference_byte_count,
        @intCast(60 + index),
    );
    const journal = ref(.journal, 1, 61 + index, @intCast(70 + index));
    return .{
        .segment_index = index,
        .recipe = recipe,
        .stage_inputs = .{
            input(.statement, 0, statement),
            input(.program, 0, globals.program),
            input(.profile, 0, recipe),
            input(.witness, 0, compact),
            input(.capture, 0, boundary),
            input(.capture, 1, public_reference),
            input(.journal, 0, journal),
        },
    };
}

fn input(
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    blob: artifact_store.BlobRefV1,
) artifact_store.InputRefV1 {
    return .{ .role = role, .ordinal = ordinal, .blob = blob };
}

fn ref(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    byte_count: u64,
    seed: u8,
) artifact_store.BlobRefV1 {
    var identity = [_]u8{seed} ** 32;
    identity[31] +%= 1;
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        byte_count,
        identity,
    ) catch unreachable;
}

fn sentinelIdentity(
    label: []const u8,
    role: registry_mod.CircuitRoleV4,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/role0-genuine-unrouteable-registry/v1\x00");
    hash.update(label);
    hash.update(&.{@intFromEnum(role)});
    return hash.finalResult();
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn expectRejected(result: anytype) !void {
    if (result) |_| return error.Role0GenuineMutationAccepted else |_| {}
}

comptime {
    if (fixture.LEAF_COUNT != 2 or proof_mod.PRODUCTION_ACTIVATION or
        proof_mod.WRAPPER_PROOF_AVAILABLE or
        proof_mod.COLD_WRAPPER_CAPTURE_AVAILABLE or
        proof_mod.FOLD_CHILD_PROJECTION_AVAILABLE)
    {
        @compileError("role0 genuine fixture escalated production authority");
    }
}

test "role0 saved Stage101 proof replays VM composition" {
    try replaySavedStage101(.composition);
}

test "role0 saved Stage101 proof replays transcript geometry" {
    try replaySavedStage101(.transcript_geometry);
}

test "role0 saved Stage101 proof binds dynamic statement roots" {
    try replaySavedStage101(.statement_roots);
}

/// Consumes the cold owner on every path. Both a freshly produced proof and a
/// retained candidate exercise the identical publication and mutation checks.
fn checkRecursivePublication(cold_value: Proof.OwnedColdProofV4, worker_policy: runtime_mod.WorkerPolicyV4, stage: *Stage) !void {
    var measurements = @import("ethereum_wrapper_resources_v1.zig").Measurements.init();
    var cold = cold_value;
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    stage.* = .fixture_registry;
    var phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    const registry = try testOnlyRole0Registry(cold.geometryForPaddingTarget());
    try registry.validate();
    try expectNoProductionParity(&registry, cold.geometryForPaddingTarget().*);
    measurements.mark("publication.registry");

    stage.* = .recursive_artifact;
    cold_live = false; // initOwned consumes cold on success and failure.
    var evidence = try Proof.EvidenceV4.initOwned(
        cold,
        registry,
        sha256("role0-genuine-two-leaf-campaign"),
    );
    defer evidence.deinit();
    measurements.mark("publication.evidence");
    try evidence.validateBorrowed();
    const admitted_graph = try evidence.foldGraphView();
    var caller_graph = admitted_graph;
    caller_graph.lane.circuit_id +%= 1;
    try std.testing.expectEqual(admitted_graph.lane.circuit_id, (try evidence.cold.foldGraphView()).lane.circuit_id);
    try std.testing.expect(caller_graph.lane.circuit_id != admitted_graph.lane.circuit_id);
    const encoded_node = try evidence.node_artifact.encodeCanonical();
    const decoded_node = try @import("recursive_node_artifact_v2.zig")
        .RecursiveNodeArtifactV2.decodeCanonical(&encoded_node);
    try std.testing.expectEqualDeep(evidence.node_artifact, decoded_node);
    measurements.mark("publication.serialization");

    stage.* = .neutral_child;
    const Empty = UnusedChild(Proof);
    const Tagged = proof_mod.TaggedFoldChildV4(
        Proof.EvidenceV4,
        Empty,
        Empty,
    );
    var real = try Proof.FreshFoldChildV4.init(&evidence, &registry);
    const tagged = try Tagged.fromReal(&real, &registry);
    const projection = try tagged.projection(&registry);
    try std.testing.expectEqual(
        registry_mod.CircuitRoleV4.ethereum_incremental_leaf_wrapper_v4,
        projection.role,
    );
    try std.testing.expectEqual(@as(usize, 36), projection.claimed_sums.len);
    try std.testing.expectEqual(@as(usize, 193), projection.query_words.len);
    try std.testing.expect(projection.capture == evidence.proofCapture());
    measurements.mark("publication.child-projection");

    stage.* = .mutations;
    // The outer child owns borrowed copies as well as its checked adapter.
    // Altering only those copies must not bypass the inner owner's admission.
    {
        const saved_graph = real.graph;
        defer real.graph = saved_graph;
        real.graph.lane.circuit_id +%= 1;
        try std.testing.expectError(error.EthereumIncrementalUniversalProofShellMismatchV4, real.validateBorrowed());
        real.graph = saved_graph;
        const foreign_outputs = try evidence.allocator.dupe(u32, saved_graph.lane.graph.outputs);
        defer evidence.allocator.free(foreign_outputs);
        real.graph.lane.graph.outputs = foreign_outputs;
        try std.testing.expectError(error.EthereumIncrementalUniversalProofShellMismatchV4, real.validateBorrowed());
    }
    {
        const saved_ingress = real.ingress;
        defer real.ingress = saved_ingress;
        const foreign_manifest = saved_ingress.manifest.*;
        real.ingress.manifest = &foreign_manifest;
        try std.testing.expectError(error.EthereumIncrementalUniversalProofShellMismatchV4, real.validateBorrowed());
    }
    // The legacy capture adapter still exposes mutable slice contents. This
    // mutation must be rejected at the next external acceptance boundary;
    // the cold owner's full query authority remains private.
    const mutable_capture = evidence.proofCapture();
    const saved_query = mutable_capture.queries.raw[0];
    mutable_capture.queries.raw[0] = saved_query +% 1;
    try expectRejected(real.validateBorrowed());
    mutable_capture.queries.raw[0] = saved_query;
    try real.validateBorrowed();

    // Source checks must also bind the immutable graph's original inputs;
    // merely retaining the graph cannot admit a changed OODS sample.
    const saved_sample = mutable_capture.sampled_values[0];
    mutable_capture.sampled_values[0] = saved_sample.add(@import("stwo_core").fields.qm31.QM31.one());
    try expectRejected(real.validateBorrowed());
    mutable_capture.sampled_values[0] = saved_sample;

    var registry_mutation = registry;
    registry_mutation.identity_sha256[0] ^= 1;
    try expectRejected(tagged.projection(&registry_mutation));
    measurements.mark("publication.mutations");
    try finishAndPrintPhase(
        &phase_usage,
        .role0_postprocess,
        worker_policy,
    );
}

/// Fresh verifier preparation accepts bytes and execution policy only. Every
/// producer-owned capture, campaign, graph and evaluation has already died.
fn rebuildVerifierInputs(
    allocator: std.mem.Allocator,
    runtime_allocator: std.mem.Allocator,
    artifact_bytes: []const []const u8,
    program_elf: []const u8,
    fixed_program: ?*const FixedProgram,
    global_metadata_json: ?[]const u8,
    worker_policy: runtime_mod.WorkerPolicyV4,
    pair_slot: u1,
) !Materialized {
    try std.testing.expectEqual(@as(usize, fixture.LEAF_COUNT), artifact_bytes.len);
    const pair = try coldOpenNativePair(allocator, artifact_bytes, global_metadata_json, fixed_program, worker_policy, null);
    var first = pair[0];
    var first_live = true;
    defer if (first_live) first.deinit();
    var second = pair[1];
    var second_live = true;
    defer if (second_live) second.deinit();
    var campaign = try Campaign.mintFromBorrowedFreshInputsAt(Engine, allocator, try fixtureInventory(), first.coordinate.index, &.{ &first, &second });
    defer campaign.deinit();
    var metrics = materializer_mod.MaterializationMetricsV4{};
    defer printMaterializationMetrics(metrics, worker_policy.worker_count);
    const rebuilt = try materializeReplayInput(runtime_allocator, if (pair_slot == 0) &first else &second, &campaign, pair_slot, program_elf, worker_policy, &metrics);
    if (pair_slot == 0) first_live = false else second_live = false;
    return rebuilt;
}

/// Both producer and fresh verifier independently reopen the pinned initial
/// job admission. Only the materializer's private copy survives this call.
/// Ordinary wrappers retain the existing constructor and default claim shape.
fn materializeReplayInput(
    allocator: std.mem.Allocator,
    fresh_input: *FreshInput,
    campaign: *const Campaign,
    pair_slot: usize,
    program_elf: []const u8,
    policy: runtime_mod.WorkerPolicyV4,
    metrics: *materializer_mod.MaterializationMetricsV4,
) !Materialized {
    const selected = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_INITIAL_INPUT_ADMISSION_V1") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return Materialized.initOwnedMeasuredWithProgram(allocator, fresh_input, campaign, pair_slot, program_elf, .{ .worker_count = policy.worker_count }, metrics),
        else => return err,
    };
    defer allocator.free(selected);
    if (!std.mem.eql(u8, selected, "1")) return error.InvalidEthereumInitialInputAdmissionMode;
    const path = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_REAL_MATERIALIZATION");
    defer allocator.free(path);
    const absolute = try std.fs.cwd().realpathAlloc(allocator, path);
    defer allocator.free(absolute);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_REAL_MATERIALIZATION_SHA256");
    defer allocator.free(pin);
    if (pin.len != 64) return error.InvalidRealMaterializationPin;
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, pin);
    const initial_mod = @import("recursive_common_ethereum_initial_input_admission_v1.zig");
    const shape = try frontend.recursion.vm_public_claim.Shape.init(initial_mod.INPUT_CAPACITY, initial_mod.OUTPUT_CAPACITY);
    const initial = try initial_mod.InitialInputAdmissionV1.open(allocator, absolute, expected, shape);
    defer initial.deinit();
    return Materialized.initOwnedMeasuredWithInitialInputs(allocator, fresh_input, campaign, pair_slot, program_elf, initial, .{ .worker_count = policy.worker_count }, metrics);
}

/// The combined proof gate selects both SHA-pinned case directories from one
/// corpus root. Existing focused commands keep their explicit directory API.
fn replayDirectory(allocator: std.mem.Allocator, kind: enum { canonical, rejected, base_bound_v3, field_bound_v4 }) ![]u8 {
    const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            if (kind == .base_bound_v3 or kind == .field_bound_v4) return err;
            return std.process.getEnvVarOwned(allocator, "STWO_ROLE0_STAGE101_REPLAY_DIR");
        },
        else => return err,
    };
    defer allocator.free(corpus);
    return std.fs.path.join(allocator, &.{ corpus, switch (kind) {
        .canonical => "role0-genuine-stage101-canonical-io",
        .rejected => "role0-genuine-stage101",
        .base_bound_v3 => "base-bound-v3",
        .field_bound_v4 => "field-bound-v4",
    } });
}

fn replaySavedStage101(check: enum { composition, transcript_geometry, statement_roots }) !void {
    errdefer |err| std.debug.print("ETHEREUM_ROLE0_REPLAY_ERROR={s}\n", .{@errorName(err)});
    const allocator = std.testing.allocator;
    const path = try std.process.getEnvVarOwned(allocator, "STWO_ROLE0_STAGE101_REPLAY_PATH");
    defer allocator.free(path);
    const expected_hex = try std.process.getEnvVarOwned(allocator, "STWO_ROLE0_STAGE101_REPLAY_SHA256");
    defer allocator.free(expected_hex);
    const bytes = try readPinnedStage101(allocator, path, expected_hex);
    defer allocator.free(bytes);

    var tracked = runtime_mod.TrackedSmpAllocatorV4{};
    defer std.debug.assert(tracked.isEmpty());
    var input_value = try FreshInput.coldOpen(
        tracked.allocator(),
        bytes,
        try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 0),
        proof_artifact.Limits{},
    );
    var input_live = true;
    defer if (input_live) input_value.deinit();
    var metrics = materializer_mod.MaterializationMetricsV4{};
    defer printMaterializationMetrics(metrics, 1);
    var prepared = try materializer_mod.PreparedCaptureV4(Engine).initOwnedMeasuredWithExecution(
        tracked.allocator(),
        &input_value,
        .{ .worker_count = 1 },
        &metrics,
    );
    input_live = false;
    defer prepared.deinit();
    try prepared.auditDeep();
    if (check == .statement_roots) try @import("ethereum_statement_root_replay.zig").audit(tracked.allocator(), &prepared);
    if (check == .transcript_geometry) {
        const native_core = @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
        const geometry = @import("recursive_common_ethereum_incremental_leaf_transcript_geometry_v4.zig");
        var plans = try native_core.buildPlans(tracked.allocator(), &prepared.captured_fri, prepared.role_aware_io.padded_tuple_capacity);
        defer for (&plans) |*plan| plan.deinit();
        _ = try geometry.AuthorityV4.mint(&prepared.transcript, &plans[0], &plans[1]);
    }
}

test "role0 saved Stage101 label input commitment is rejected" {
    const allocator = std.testing.allocator;
    const directory = try replayDirectory(allocator, .rejected);
    defer allocator.free(directory);
    const digest = "c86f6acde3d4ab6b148f5a02abe37fe0d7af7d1d96f0fffca26c42c2502538cf";
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}.bin", .{ directory, digest });
    defer allocator.free(path);
    const bytes = try readPinnedStage101(allocator, path, digest);
    defer allocator.free(bytes);
    var input_value = try FreshInput.coldOpen(allocator, bytes, try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 0), proof_artifact.Limits{});
    defer input_value.deinit();
    const vm_claim = frontend.recursion.vm_public_claim;
    const semantics = frontend.recursion.vm_public_semantics_circuit;
    const span = frontend.recursion.span_statement;
    const data = &input_value.stage101.role_aware_public.value;
    const shape = try vm_claim.defaultShape();
    var claim = try vm_claim.encodeWithBoundCompletionV4(allocator, data, shape, data.completion.?);
    defer claim.deinit();
    var words: span.StatementWords = undefined;
    for (&words, input_value.statement_words) |*destination, value| destination.* = M31.fromCanonical(value);
    // Pin the exact first nonzero constraint from the real saved replay.
    const difference = M31.fromCanonical(claim.public_input_digest[0]).sub(words[span.canonical_layout.input_edge_digest_start]);
    try std.testing.expectEqual(@as(u32, 939440486), difference.toU32());
    var reference = try semantics.ClaimReference.initForSegmentV2(allocator, shape, 40);
    defer reference.deinit();
    try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, .{
        .segment_selected = true,
        .claim_words = claim.words,
        .statement_words = &words,
        .input_digest = claim.public_input_digest,
        .output_digest = claim.public_output_digest,
    }));
}

const readPinnedStage101 = runtime_mod.readPinnedStage101;

test "Ethereum cohort replay publication preserves absent and present initial claims" {
    try @import("ethereum_statement_root_cohort_replay.zig").exercisePublicationCodec();
}

test "role0 saved Stage101 pair closes the complete statement-root cohort" {
    try replaySavedPair(.closure);
}

test "role0 saved Stage101 pair replays recursive wrapper" {
    try replaySavedPair(.prove);
}

test "role0 saved Stage101 pair produces a durable root and independently verifies after destruction" {
    try replaySavedPair(.root_prove);
}

test "Ethereum retained real claim isolates snapshot and continuation semantics" {
    // A focused regression over the exact already-retained proof envelope.
    // Decoding authenticates transport/statement custody, not the STARK proof.
    const allocator = std.testing.allocator;
    const path = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_CLAIM_REPLAY_PATH");
    defer allocator.free(path);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_CLAIM_REPLAY_SHA256");
    defer allocator.free(pin);
    const bytes = try readPinnedStage101(allocator, path, pin);
    defer allocator.free(bytes);
    var decoded = try proof_artifact.decodeAlloc(Engine, allocator, bytes, .{});
    defer decoded.deinit(allocator);
    const public_value = &decoded.role_aware_public.value;
    const claim_mod = frontend.recursion.vm_public_claim;
    const shape = try claim_mod.defaultShape();
    var claim = try claim_mod.encodeWithBoundCompletionV4(allocator, public_value, shape, public_value.completion.?);
    defer claim.deinit();
    const view = try decoded.statement.public_data.authenticatedView();
    const original_words: frontend.recursion.span_statement.StatementWords = view.statement.base_statement_words;
    var words = original_words;
    var reference = try frontend.recursion.vm_public_semantics_circuit.ClaimReference.initForSegmentV2(allocator, shape, 40);
    defer reference.deinit();
    const witness: frontend.recursion.vm_public_semantics_circuit.ClaimWitness = .{
        .segment_selected = true,
        .claim_words = claim.words,
        .statement_words = &words,
        .input_digest = claim.public_input_digest,
        .output_digest = claim.public_output_digest,
    };
    try std.testing.expectError(error.SemanticConstraintViolation, reference.prepare(allocator, witness));
    const roots = [2]u32{ public_value.initial_rw_root.?, public_value.final_rw_root.? };
    // Counterfactual diagnostic only: preserve the real input above, then
    // isolate whether these two obsolete equalities explain every failure.
    for (frontend.recursion.air.vm_statement_roots.word_indices, roots) |index, root| {
        try std.testing.expect(words[index].toU32() != root);
        @memset(words[index..][0..8], M31.zero());
        words[index] = M31.fromCanonical(root);
    }
    var projected = try reference.prepare(allocator, witness);
    defer projected.deinit();
    words = original_words;
    var admitted = try frontend.recursion.vm_public_semantics_circuit.ClaimReference.initForEthereumNativeRoots(allocator, shape, 40);
    defer admitted.deinit();
    var native_witness = witness;
    native_witness.native_continuation_roots = .{ M31.fromCanonical(roots[0]), M31.fromCanonical(roots[1]) };
    var accepted = try admitted.prepare(allocator, native_witness);
    defer accepted.deinit();
    for (0..2) |side| {
        var changed = native_witness;
        changed.native_continuation_roots.?[side] = changed.native_continuation_roots.?[side].add(M31.one());
        try std.testing.expectError(error.SemanticConstraintViolation, admitted.prepare(allocator, changed));
    }
    std.debug.print("ETHEREUM_REAL_CLAIM_DIAGNOSTIC original_rejected=true only_snapshot_equalities_changed=true projected_constraints_pass=true proof_verified=false\n", .{});
    std.debug.print("ETHEREUM_REAL_CLAIM_NATIVE_ROOTS original_snapshot_words_preserved=true native_policy_pass=true changed_roots_rejected=true proof_verified=false\n", .{});
}

test "role0 retained wrapper verifies from disk without producer state" {
    const allocator = std.testing.allocator;
    const path = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_WRAPPER_REPLAY_DIR");
    defer allocator.free(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const first = try dir.readFileAlloc(allocator, "leaf-0.bin", 512 * 1024 * 1024);
    defer allocator.free(first);
    const second = try dir.readFileAlloc(allocator, "leaf-1.bin", 512 * 1024 * 1024);
    defer allocator.free(second);
    const program_elf = try dir.readFileAlloc(allocator, "program.elf", 64 * 1024 * 1024);
    defer allocator.free(program_elf);
    const global_metadata_json = dir.readFileAlloc(allocator, "global-metadata-v1.json", 128 * 1024) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (global_metadata_json) |bytes| allocator.free(bytes);
    const wrapper = try dir.readFileAlloc(allocator, "wrapper.bin", 512 * 1024 * 1024);
    defer allocator.free(wrapper);
    const worker_policy = try runtime_mod.WorkerPolicyV4.fromEnvironment(allocator, STAGE101_FIXTURE_HOST_BYTE_BUDGET);
    var usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var tracked = runtime_mod.TrackedSmpAllocatorV4{};
    defer std.debug.assert(tracked.isEmpty());
    {
        var verifier_inputs = try rebuildVerifierInputs(allocator, tracked.allocator(), &.{ first, second }, program_elf, null, global_metadata_json, worker_policy, 0);
        defer verifier_inputs.deinit();
        var cold = try Proof.coldOpenWithWorkers(tracked.allocator(), &verifier_inputs, wrapper, worker_policy.worker_count);
        defer cold.deinit();
        try cold.validateBorrowed();
    }
    try std.testing.expect(tracked.isEmpty());
    std.debug.print("ETHEREUM_ROLE0_RETAINED_PROOF source=disk fresh_verifier=true wrapper_verified=true\n", .{});
    try finishAndPrintPhase(&usage, .total, worker_policy);
}

test "role0 saved Stage101 pair destroys producer before rebuilding verifier inputs" {
    try replaySavedPair(.reconstruct);
}

test "role0 saved Stage101 pair validates retained materializer custody" {
    try replaySavedPair(.materialize);
}

test "role0 retained failed wrapper independently reproduces OODS rejection" {
    try replaySavedPair(.failed_replay);
}

test "role0 retained wrapper candidate cold verifies from pinned inputs without proving" {
    try replaySavedPair(.candidate_replay);
}

test "Ethereum wrapper geometry gate rejects every incompatible wire dimension" {
    const preflight = @import("ethereum_typed_air_preflight_v4.zig");
    const WireDimensions = frontend.recursion.fixed_wire.Dimensions;
    const expected = WireDimensions{
        .commitment_count = 4,
        .claimed_sum_count = 36,
        .sampled_value_count = 2453,
        .queried_value_count = 444865,
        .trace_path_count = 772,
        .fri_layer_count = 6,
        .query_count = 193,
        .maximum_fold_width = 16,
        .last_layer_coefficient_count = 1,
        .maximum_merkle_depth = 25,
    };
    try preflight.requireMatchingWireDimensions(expected, expected);
    inline for (std.meta.fields(WireDimensions)) |field| {
        var changed = expected;
        @field(changed, field.name) += 1;
        try std.testing.expectError(error.EthereumWrapperWireGeometryMismatch, preflight.requireMatchingWireDimensions(expected, changed));
    }
}

test "role0 saved Stage101 pair checks wrapper geometry against pinned child key" {
    try replaySavedPair(.geometry_preflight);
}

test "role0 saved Stage101 pair checks typed AIR parameters before PCS" {
    try replaySavedPair(.air_preflight);
}

test "role0 saved Stage101 pair compares CPU and authenticated Metal Tree0 admission" {
    try replaySavedPair(.tree0_compare);
}

test "role0 saved Stage101 pair compares native cold-open allocators" {
    try replaySavedPair(.allocator_probe);
}

/// The captures own their storage; the joined native worker scope can end
/// before the caller starts a separate materialization/proving session.
fn coldOpenNativePair(
    allocator: std.mem.Allocator,
    bytes: []const []const u8,
    metadata_json: ?[]const u8,
    fixed_program: ?*const FixedProgram,
    policy: runtime_mod.WorkerPolicyV4,
    stage: ?*Stage,
) ![2]FreshInput {
    try std.testing.expectEqual(@as(usize, 2), bytes.len);
    var scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
    try scope.initInPlace(policy.worker_count);
    defer scope.deinit();
    if (stage) |value| value.* = .first_cold_open;
    const global_pair: ?GlobalReplayMetadataV1 = if (metadata_json) |data| try decodeGlobalReplayMetadata(allocator, data) else null;
    const first_coordinate = try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, if (global_pair) |metadata| metadata.leaves[0].segment_index else 0);
    var first = if (fixed_program) |program|
        try FreshInput.coldOpenWithProgramAdmission(allocator, bytes[0], first_coordinate, .{}, program)
    else
        try FreshInput.coldOpen(allocator, bytes[0], first_coordinate, .{});
    errdefer first.deinit();
    if (stage) |value| value.* = .second_cold_open;
    const second_coordinate = try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, if (global_pair) |metadata| metadata.leaves[1].segment_index else 1);
    var second = if (fixed_program) |program|
        try FreshInput.coldOpenWithProgramAdmission(allocator, bytes[1], second_coordinate, .{}, program)
    else
        try FreshInput.coldOpen(allocator, bytes[1], second_coordinate, .{});
    errdefer second.deinit();
    if (global_pair) |metadata| {
        try first.admitGlobalMetadata(&metadata.leaves[0]);
        try second.admitGlobalMetadata(&metadata.leaves[1]);
    }
    std.debug.print("ETHEREUM_NATIVE_VERIFICATION workers={d} captures=2 scope=joined\n", .{scope.workerCount()});
    return .{ first, second };
}

fn probeNativeColdOpen(
    allocator: std.mem.Allocator,
    bytes: []const []const u8,
    metadata_json: ?[]const u8,
    fixed_program: ?*const FixedProgram,
    policy: runtime_mod.WorkerPolicyV4,
) ![2][32]u8 {
    var phase = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var pair = try coldOpenNativePair(allocator, bytes, metadata_json, fixed_program, policy, null);
    defer pair[0].deinit();
    defer pair[1].deinit();
    // Both captures are alive at the measurement boundary, matching runWrapper.
    try finishAndPrintPhase(&phase, .cold_open, policy);
    return .{ pair[0].capability_identity_sha256, pair[1].capability_identity_sha256 };
}

fn compareNativeColdOpenAllocators(bytes: []const []const u8, metadata_json: ?[]const u8, fixed_program: ?*const FixedProgram, policy: runtime_mod.WorkerPolicyV4) !void {
    var baseline: ?[2][32]u8 = null;
    // ABBA reduces warm-up/order bias without introducing another proof route.
    for ([_]bool{ false, true, true, false }, 0..) |use_smp, index| {
        std.debug.print("ETHEREUM_NATIVE_ALLOCATOR_PROBE sample={d} allocator={s} captures_live=2\n", .{ index, if (use_smp) "tracked_smp" else "std_testing" });
        var tracked = runtime_mod.TrackedSmpAllocatorV4{};
        const identities = try probeNativeColdOpen(if (use_smp) tracked.allocator() else std.testing.allocator, bytes, metadata_json, fixed_program, policy);
        try tracked.requireEmpty();
        if (baseline) |expected| try std.testing.expectEqualDeep(expected, identities) else baseline = identities;
    }
    std.debug.print("ETHEREUM_NATIVE_ALLOCATOR_PROBE samples=4 exact_source_identities=true all_native_owners_destroyed=true\n", .{});
}

fn wrapperPairSlot(allocator: std.mem.Allocator) !u1 {
    const value = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_WRAPPER_PAIR_SLOT") catch |err| {
        if (err == error.EnvironmentVariableNotFound) return 0;
        return err;
    };
    defer allocator.free(value);
    if (std.mem.eql(u8, value, "0")) return 0;
    if (std.mem.eql(u8, value, "1")) return 1;
    return error.InvalidWrapperPairSlot;
}

fn completionOpeningSelected(allocator: std.mem.Allocator) !bool {
    const value = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_COMPLETION_OPENING_V1") catch |err| {
        if (err == error.EnvironmentVariableNotFound) return false;
        return err;
    };
    defer allocator.free(value);
    if (!std.mem.eql(u8, value, "1")) return error.InvalidCompletionOpeningAdmissionMode;
    return true;
}

/// A real replay obtains its ELF and exact leaf metadata authority from the
/// independently pinned retained materialization. The default fixture pin is
/// unchanged when this explicit ingress is absent.
fn realReplayProgramSha(allocator: std.mem.Allocator, manifest: ?NativeReplayManifestV1, metadata_json: ?[]const u8, opening: bool) !?[32]u8 {
    const path = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_REAL_MATERIALIZATION") catch |err| {
        if (err == error.EnvironmentVariableNotFound) return null;
        return err;
    };
    defer allocator.free(path);
    if (!opening or manifest == null or manifest.?.claim_admission != .fixed_program_narrow_v5)
        return error.InvalidRealProgramReplayAdmission;
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_REAL_MATERIALIZATION_SHA256");
    defer allocator.free(pin);
    if (pin.len != 64) return error.InvalidRealMaterializationPin;
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, pin);
    const metadata = try decodeGlobalReplayMetadata(allocator, metadata_json orelse return error.MissingGlobalReplayMetadata);
    const absolute = try std.fs.cwd().realpathAlloc(allocator, path);
    defer allocator.free(absolute);
    var retained = try @import("ethereum_incremental_capture_retained_authority_v4.zig").RetainedAuthorityV4.openWithCampaignGeometryV1(allocator, absolute, .authenticated_v1);
    defer retained.deinit();
    if (!std.meta.eql(expected, retained.materialization_identity.sha256)) return error.EthereumBundleMaterializationIdentityMismatch;
    for (&metadata.leaves) |*leaf| try retained.validateLeafMetadata(leaf);
    if (metadata.leaves[0].segment_index == std.math.maxInt(u32) or metadata.leaves[1].segment_index != metadata.leaves[0].segment_index + 1)
        return error.NonAdjacentRealReplayLeaves;
    if (!std.meta.eql(retained.elf_identity.sha256, manifest.?.program_sha256)) return error.NativeReplayProgramMismatch;
    std.debug.print("ETHEREUM_REAL_REPLAY materialization_pinned=true first_segment={d} leaf_count=2 whole_elf_pinned=true\n", .{metadata.leaves[0].segment_index});
    return retained.elf_identity.sha256;
}

fn replaySavedPair(comptime mode: WrapperMode) !void {
    const allocator = std.testing.allocator;
    if ((mode == .prove or mode == .root_prove) and try runtime_mod.stopAfterMaterialize(allocator))
        return error.ProofGateCannotStopAfterMaterialize;
    if (mode == .root_prove) {
        // Reject a missing durable destination before loading the real inputs.
        const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => return error.EthereumRootCorpusRequired,
            else => return err,
        };
        defer allocator.free(corpus);
        if (corpus.len == 0) return error.EthereumRootCorpusRequired;
        // This legacy constructor diagnostic is unsupported by the detached
        // root endpoint. Never silently ignore its request.
        if (std.process.hasEnvVarConstant("STWO_ETHEREUM_COMPOSITION_ADMISSION_REGRESSION"))
            return error.EthereumRootProductionCannotRunLegacyCaptureRegression;
    }
    const selected_directory = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_NATIVE_REPLAY_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    const directory = selected_directory orelse try replayDirectory(allocator, .base_bound_v3);
    defer allocator.free(directory);
    var manifest: ?NativeReplayManifestV1 = null;
    var global_metadata_json: ?[]u8 = null;
    defer if (global_metadata_json) |bytes| allocator.free(bytes);
    var digest_storage: [fixture.LEAF_COUNT][64]u8 = undefined;
    var digests: [fixture.LEAF_COUNT][]const u8 = .{
        "7984f63fe4e285cdfb6a59ca877435edadade565de3540c5c73dc019a85af559",
        "9fe54ac33fa51210fa82974f339de5b2ec8df35e4916a05b8ea6351eb0a82088",
    };
    if (selected_directory != null) {
        var dir = try std.fs.cwd().openDir(directory, .{});
        defer dir.close();
        const manifest_bytes = try dir.readFileAlloc(allocator, "native-inputs-v1.json", 128 * 1024);
        defer allocator.free(manifest_bytes);
        const parsed = try std.json.parseFromSlice(NativeReplayManifestV1, allocator, manifest_bytes, .{});
        defer parsed.deinit();
        if (parsed.value.version != 1) return error.UnsupportedNativeReplayManifest;
        manifest = parsed.value;
        for (&digest_storage, &digests, parsed.value.native_sha256) |*storage, *hex, digest| {
            storage.* = std.fmt.bytesToHex(digest, .lower);
            hex.* = storage;
        }
        const metadata_path = try std.fs.path.join(allocator, &.{ directory, "global-metadata-v1.json" });
        defer allocator.free(metadata_path);
        global_metadata_json = try readPinnedStage101(allocator, metadata_path, &std.fmt.bytesToHex(parsed.value.global_metadata_sha256, .lower));
        _ = try decodeGlobalReplayMetadata(allocator, global_metadata_json.?);
    }
    var bytes: [fixture.LEAF_COUNT][]u8 = undefined;
    var initialized: usize = 0;
    defer for (bytes[0..initialized]) |value| allocator.free(value);
    for (&bytes, digests) |*value, digest| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.bin", .{ directory, digest });
        defer allocator.free(path);
        value.* = try readPinnedStage101(allocator, path, digest);
        initialized += 1;
    }
    const policy = try runtime_mod.WorkerPolicyV4.fromEnvironment(allocator, STAGE101_FIXTURE_HOST_BYTE_BUDGET);
    var total_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var stage: Stage = .first_cold_open;
    errdefer |err| std.debug.print("ETHEREUM_ROLE0_SAVED_WRAPPER_STAGE={s} error={s}\n", .{ @tagName(stage), @errorName(err) });
    std.debug.print("ETHEREUM_ROLE0_SAVED_WRAPPER_REPLAY excludes_stage101_proving=true\n", .{});
    const program_path = try std.fs.path.join(allocator, &.{ directory, "program.elf" });
    defer allocator.free(program_path);
    const pair_slot = try wrapperPairSlot(allocator);
    const completion_mode = try completionOpeningSelected(allocator);
    const expected_elf = fixture.programElf();
    var elf_digest: [32]u8 = undefined;
    Sha256.hash(&expected_elf, &elf_digest, .{});
    if (try realReplayProgramSha(allocator, manifest, global_metadata_json, completion_mode)) |real_sha| elf_digest = real_sha;
    if (manifest) |admitted| if (!std.meta.eql(elf_digest, admitted.program_sha256)) return error.NativeReplayProgramMismatch;
    const program_elf = try readPinnedStage101(allocator, program_path, &std.fmt.bytesToHex(elf_digest, .lower));
    defer allocator.free(program_elf);
    // The selected profile is explicit in the independently pinned fixture
    // manifest. Never create a program authority from a proof descriptor.
    if (completion_mode and (manifest == null or manifest.?.claim_admission != .fixed_program_narrow_v5)) return error.InvalidCompletionOpeningAdmissionMode;
    const fixed_program: ?*FixedProgram = if (manifest != null and manifest.?.claim_admission == .fixed_program_narrow_v5)
        if (completion_mode) try FixedProgram.createWithCompletionFromElf(allocator, program_elf, elf_digest) else try FixedProgram.createFromElf(allocator, program_elf, elf_digest)
    else
        null;
    if (completion_mode) std.debug.print("ETHEREUM_COMPLETION_OPENING admitted_version=1 whole_elf_pinned=true\n", .{});
    defer if (fixed_program) |program| program.deinit();
    if (fixed_program != null and global_metadata_json == null) return error.MissingGlobalReplayMetadata;
    if (mode == .allocator_probe) {
        try compareNativeColdOpenAllocators(&bytes, global_metadata_json, fixed_program, policy);
        return;
    }
    if (mode == .candidate_replay) {
        const candidate_path = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_WRAPPER_CANDIDATE");
        defer allocator.free(candidate_path);
        const candidate_bytes = try @import("ethereum_wrapper_candidate_v1.zig").load(allocator, candidate_path);
        defer allocator.free(candidate_bytes);
        var tracked = runtime_mod.TrackedSmpAllocatorV4{};
        defer std.debug.assert(tracked.isEmpty());
        {
            // This branch never constructs a wrapper producer. Only pinned
            // base artifacts, ELF bytes and the retained candidate enter it.
            stage = .verifier_rebuild;
            var verifier_inputs = try rebuildVerifierInputs(allocator, tracked.allocator(), &bytes, program_elf, fixed_program, global_metadata_json, policy, pair_slot);
            defer verifier_inputs.deinit();
            stage = .role0_reopen;
            const cold = try Proof.coldOpenWithWorkers(tracked.allocator(), &verifier_inputs, candidate_bytes, policy.worker_count);
            try checkRecursivePublication(cold, policy, &stage);
        }
        try std.testing.expect(tracked.isEmpty());
        std.debug.print("ETHEREUM_ROLE0_WRAPPER_CANDIDATE source=disk fresh_verifier=true producer_constructed=false wrapper_verified=true\n", .{});
        try finishAndPrintPhase(&total_usage, .total, policy);
        return;
    }
    try runWrapper(mode, allocator, &bytes, program_elf, fixed_program, global_metadata_json, policy, pair_slot, &total_usage, &stage);
}

fn exerciseRetainedCampaignMembership(materialized: *Materialized) !void {
    const campaign = materialized.campaign_authority;
    const index = materialized.campaign_leaf_index;
    const input_value = &materialized.base.input;
    const witness = &materialized.role_aware_io;
    const schedule = &materialized.schedule;
    try campaign_mod.validatePreparedInputAt(Engine, campaign, index, input_value, witness, schedule);
    try std.testing.expectError(error.InvalidCampaignProviderGeometryInputV4, campaign_mod.validatePreparedInputAt(Engine, campaign, campaign.view().leaf_count, input_value, witness, schedule));
    const count = witness.active_tuple_count;
    witness.active_tuple_count += 1;
    const bad_count = campaign_mod.validatePreparedInputAt(Engine, campaign, index, input_value, witness, schedule);
    witness.active_tuple_count = count;
    try expectRejected(bad_count);
    const word = schedule.calls[0].input[0];
    schedule.calls[0].input[0] ^= 1;
    const bad_call = campaign_mod.validatePreparedInputAt(Engine, campaign, index, input_value, witness, schedule);
    schedule.calls[0].input[0] = word;
    try expectRejected(bad_call);
    var bad_campaign = campaign.view().*;
    bad_campaign.authority_identity_sha256[0] ^= 1;
    try std.testing.expectError(error.CampaignProviderGeometryMismatchV4, campaign_mod.validatePreparedInputAt(Engine, &bad_campaign, index, input_value, witness, schedule));
    try materialized.validate();
}

fn exerciseMaterializerFailureOwnership(
    allocator: std.mem.Allocator,
    fresh_input: *FreshInput,
    campaign: *const Campaign,
) !void {
    const identity = fresh_input.capability_identity_sha256;
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    var prepared = try Materialized.initOwned(measured.allocator(), fresh_input, campaign, 0);
    const final_allocation = measured.alloc_index - 1;
    fresh_input.* = prepared.deinitRetainingInput();

    // Fail the final allocation of the real constructor, after Base has taken
    // the fresh_input. Rollback must restore it for the caller's retry or cleanup.
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = final_allocation });
    if (Materialized.initOwned(failing.allocator(), fresh_input, campaign, 0)) |value| {
        var unexpected = value;
        fresh_input.* = unexpected.deinitRetainingInput();
        return error.ExpectedMaterializerAllocationFailure;
    } else |err| try std.testing.expect(err == error.OutOfMemory);
    try std.testing.expect(failing.has_induced_failure);
    try fresh_input.validate();
    try std.testing.expectEqualSlices(u8, &identity, &fresh_input.capability_identity_sha256);
    std.debug.print("ETHEREUM_ROLE0_MATERIALIZER_ROLLBACK fail_index={d} input_valid=true\n", .{final_allocation});
}
