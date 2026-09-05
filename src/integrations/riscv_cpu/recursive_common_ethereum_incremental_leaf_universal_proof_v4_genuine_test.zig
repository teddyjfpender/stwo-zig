//! Genuine, isolated role-0 q193 transaction.
//!
//! The campaign has two real Stage-101 leaves produced from one segmented
//! Ethereum execution.  The registry below admits the independently cold-
//! derived role-0 geometry only.  Its other entries are deliberately
//! unrouteable test sentinels and cannot mint production padding parity.

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
const Campaign = campaign_mod.OwnedCampaignProviderGeometryV4;
const Materialized =
    campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
const Proof = proof_mod.Types(Engine);
const Sha256 = std.crypto.hash.sha2.Sha256;
const STAGE101_FIXTURE_HOST_BYTE_BUDGET: usize = 8 * 1024 * 1024 * 1024;

const Stage = enum {
    stage101_build,
    first_cold_open,
    second_cold_open,
    campaign,
    materialize,
    role0_prove,
    role0_reopen,
    fixture_registry,
    recursive_artifact,
    neutral_child,
    mutations,
};

test "role0 genuine two-leaf q193 proof cold-opens into neutral real child" {
    const allocator = std.testing.allocator;
    const worker_policy = try runtime_mod.WorkerPolicyV4.fromEnvironment(
        allocator,
        STAGE101_FIXTURE_HOST_BYTE_BUDGET,
    );
    var total_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var stage: Stage = .stage101_build;
    errdefer |err| std.debug.print(
        "ETHEREUM_INCREMENTAL_ROLE0_GENUINE_STAGE={s} error={s}\n",
        .{ @tagName(stage), @errorName(err) },
    );

    var artifacts = try fixture.buildArtifactsWithExecution(
        Engine,
        allocator,
        .{ .cpu = try worker_policy.cpuRequest() },
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

    stage = .first_cold_open;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var first = try FreshInput.coldOpen(
        allocator,
        artifacts.bytes[0],
        try @import("recursive_node_artifact_v1.zig")
            .TaskCoordinateV1.init(0, 0),
        proof_artifact.Limits{},
    );
    var first_live = true;
    defer if (first_live) first.deinit();

    stage = .second_cold_open;
    var second = try FreshInput.coldOpen(
        allocator,
        artifacts.bytes[1],
        try @import("recursive_node_artifact_v1.zig")
            .TaskCoordinateV1.init(0, 1),
        proof_artifact.Limits{},
    );
    defer second.deinit();
    try finishAndPrintPhase(&phase_usage, .cold_open, worker_policy);

    stage = .campaign;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    const inventory = try fixtureInventory();
    const fresh_inputs = [_]*const FreshInput{ &first, &second };
    var campaign = try Campaign.mintFromBorrowedFreshInputs(
        Engine,
        allocator,
        inventory,
        &fresh_inputs,
    );
    defer campaign.deinit();
    try std.testing.expectEqual(@as(u32, fixture.LEAF_COUNT), campaign.leaf_count);
    try std.testing.expectEqual(@as(usize, fixture.LEAF_COUNT), campaign.active_tuple_counts.len);
    try std.testing.expect(campaign.active_tuple_counts[0] > 0);
    try std.testing.expectEqual(@as(u32, 0), campaign.active_tuple_counts[1]);
    try std.testing.expectEqual(@as(u32, 0), campaign.maximum_leaf_index);
    try finishAndPrintPhase(&phase_usage, .campaign, worker_policy);

    stage = .materialize;
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
    var materialization_metrics = materializer_mod.MaterializationMetricsV4{};
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var materialized = try Materialized.initOwnedMeasuredWithExecution(
        runtime_allocator,
        &first,
        &campaign,
        0,
        .{ .worker_count = worker_policy.worker_count },
        &materialization_metrics,
    );
    try finishAndPrintPhase(&phase_usage, .materialize, worker_policy);
    first_live = false;
    var materialized_live = true;
    defer if (materialized_live) materialized.deinit();
    printMaterializationMetrics(
        materialization_metrics,
        worker_policy.worker_count,
    );
    printAllocatorSnapshot("materialized-live", tracked_allocator.snapshot());
    if (try runtime_mod.stopAfterMaterialize(allocator)) {
        phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
        var cleanup_timer = try std.time.Timer.start();
        materialized.deinit();
        materialized_live = false;
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
        try finishAndPrintPhase(&total_usage, .total, worker_policy);
        return;
    }

    stage = .role0_prove;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var proved = try Proof.proveAndColdVerify(
        runtime_allocator,
        &materialized,
        .{ .worker_count = worker_policy.worker_count },
    );
    try proved.receipt.validate();
    try std.testing.expectEqual(
        @as(u32, @intCast(worker_policy.worker_count)),
        proved.receipt.worker_count,
    );
    const retained = try allocator.dupe(u8, proved.proof.artifact_bytes);
    defer allocator.free(retained);
    proved.deinit();
    try finishAndPrintPhase(&phase_usage, .role0_prove, worker_policy);

    stage = .role0_reopen;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    var cold = try Proof.coldOpen(runtime_allocator, &materialized, retained);
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    try cold.validateBorrowed();
    try std.testing.expectEqual(@as(u16, 36), cold.geometry_value.component_count);
    try std.testing.expectEqual(@as(u16, 36), cold.geometry_value.proof_shape.claimed_sum_count);
    try std.testing.expectEqual(
        @as(u16, 193),
        cold.geometry_value.proof_shape.query_count,
    );
    try finishAndPrintPhase(&phase_usage, .role0_reopen, worker_policy);

    stage = .fixture_registry;
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    const registry = try testOnlyRole0Registry(&cold.geometry_value);
    try registry.validate();
    try expectNoProductionParity(&registry, cold.geometry_value);

    stage = .recursive_artifact;
    var evidence = try Proof.EvidenceV4.initOwned(
        cold,
        registry,
        sha256("role0-genuine-two-leaf-campaign"),
    );
    cold_live = false;
    var evidence_live = true;
    defer if (evidence_live) evidence.deinit();
    try evidence.validateBorrowed();
    const encoded_node = try evidence.node_artifact.encodeCanonical();
    const decoded_node = try @import("recursive_node_artifact_v2.zig")
        .RecursiveNodeArtifactV2.decodeCanonical(&encoded_node);
    try std.testing.expectEqualDeep(evidence.node_artifact, decoded_node);

    stage = .neutral_child;
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

    stage = .mutations;
    const saved_query = evidence.cold.query_authority.query_words[0];
    evidence.cold.query_authority.query_words[0] = M31.fromCanonical(
        saved_query.toU32() +% 1,
    );
    try expectRejected(real.validateBorrowed());
    evidence.cold.query_authority.query_words[0] = saved_query;
    try real.validateBorrowed();

    var registry_mutation = registry;
    registry_mutation.identity_sha256[0] ^= 1;
    try expectRejected(tagged.projection(&registry_mutation));
    try finishAndPrintPhase(
        &phase_usage,
        .role0_postprocess,
        worker_policy,
    );
    std.debug.print(
        "ETHEREUM_INCREMENTAL_ROLE0_RUNTIME peak_allocator_bytes={d}\n",
        .{tracked_allocator.peakBytes()},
    );
    phase_usage = try runtime_mod.PhaseUsageMeasurementV4.begin();
    evidence.deinit();
    evidence_live = false;
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
    try finishAndPrintPhase(&total_usage, .total, worker_policy);
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
    std.debug.print(
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
