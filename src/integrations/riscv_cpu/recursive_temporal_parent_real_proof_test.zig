//! Real authenticated temporal `2 -> 1` parent proof.
//!
//! This gate deliberately begins with two distinct adjacent native SegmentV2
//! executions.  Each child crosses the native prove/serialize/preflight/
//! decode/verify-with-capture boundary, then receives its own independently
//! verified 39-row outer proof.  Only verifier-minted publications and
//! captures enter the temporal pair, row-18 recorder authority, and complete
//! rows-0--35 parent transaction below.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const ingress = @import("recursive_segment_v2_leaf_outer_proof_test.zig");
const outer_proof = @import("recursive_segment_v2_outer_proof_test.zig");
const recording_support = @import("recursive_v3_recording_test_support.zig");

const leaf_outer = integration.recursive_segment_v2_leaf_outer;
const outer_cohort = integration.recursive_segment_v2_outer_cohort;
const outer_engine = integration.recursive_segment_v2_outer_engine;
const child_authority =
    integration.recursive_segment_v2_temporal_child_authority;
const pair_authority = integration.recursive_temporal_pair_authority_v2;
const prefix_runtime = integration.recursive_temporal_parent_prefix_runtime;
const row18_source = integration.recursive_temporal_parent_row18_source_v3;
const temporal_cohort = integration.recursive_temporal_parent_cohort_v3;
const temporal_manifest = integration.recursive_temporal_parent_manifest_v3;
const binary_driver = integration.recursive_binary_outer;
const binary_cohort_mod = integration.recursive_binary_outer_cohort;

const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const binary_fixture = frontend.testing.binary_pair_outer_fixture;

const BinaryCohort = binary_cohort_mod.Cohort(
    binary_fixture.CHILD_DIMENSIONS,
    binary_fixture.STATEMENT_DIMENSIONS,
);
const ParentKernel = binary_driver.NativeEngineKernelForManifest(
    temporal_cohort.Cohort,
    temporal_manifest,
);

pub fn runGate(allocator: std.mem.Allocator) !void {
    return ingress.runTemporalPairGateWithHook(allocator, RealParentHook);
}

const RealParentHook = struct {
    pub fn run(
        allocator: std.mem.Allocator,
        left_prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
        right_prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        return proveTemporalParentWithConsumer(
            allocator,
            left_prepared,
            right_prepared,
            DefaultParentConsumer{},
        );
    }
};

const DefaultParentConsumer = struct {
    fn consume(
        _: DefaultParentConsumer,
        _: *const ParentKernel.VerifiedPublicationV1,
        _: *const ParentKernel.VerifiedArtifactV1,
        _: binary_driver.Receipt,
    ) !void {}
};

pub fn proveTemporalParentWithConsumer(
    allocator: std.mem.Allocator,
    left_prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    right_prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    consumer: anytype,
) !void {
    if (left_prepared == right_prepared or std.mem.eql(
        u8,
        &left_prepared.identity,
        &right_prepared.identity,
    )) return error.DuplicateTemporalLeaf;

    std.debug.print(
        "\nTEMPORAL_CHILD_GEOMETRY left={d}/{d}:{d}/{d}:{d}/{d} " ++
            "right={d}/{d}:{d}/{d}:{d}/{d}\n",
        .{
            left_prepared.authority_prepared.authority_hash_plan.component_count,
            left_prepared.capture.vm_air.component_descs.len,
            left_prepared.authority_prepared.authority_hash_plan.infra_count,
            left_prepared.capture.vm_air.infra_descs.len,
            left_prepared.capture.vm_air.detailed_claims.len,
            left_prepared.capture.vm_air.profile.claimed_sum_count,
            right_prepared.authority_prepared.authority_hash_plan.component_count,
            right_prepared.capture.vm_air.component_descs.len,
            right_prepared.authority_prepared.authority_hash_plan.infra_count,
            right_prepared.capture.vm_air.infra_descs.len,
            right_prepared.capture.vm_air.detailed_claims.len,
            right_prepared.capture.vm_air.profile.claimed_sum_count,
        },
    );

    var left = try outer_proof.provePreparedNativeLeaf(
        outer_cohort.Cohort,
        allocator,
        left_prepared,
        left_prepared,
        outer_engine.ExecutionOptions{ .worker_count = 1 },
    );
    defer left.capture.deinit(allocator);
    var right = try outer_proof.provePreparedNativeLeaf(
        outer_cohort.Cohort,
        allocator,
        right_prepared,
        right_prepared,
        outer_engine.ExecutionOptions{ .worker_count = 1 },
    );
    defer right.capture.deinit(allocator);
    try left.publication.validate();
    try right.publication.validate();
    if (std.meta.eql(
        left.publication.publication_id,
        right.publication.publication_id,
    )) return error.DuplicateTemporalLeaf;

    // The manifest and finalized constraint graph are profile authority,
    // not child-witness authority.  One fresh cohort supplies their stable
    // storage while both child artifacts remain separately re-admitted.
    var segment_cohort = outer_cohort.Cohort.init(
        allocator,
        left_prepared,
    ) catch |err| return stageFailure("segment_cohort", err);
    defer segment_cohort.deinit();
    var right_segment_cohort = outer_cohort.Cohort.init(
        allocator,
        right_prepared,
    ) catch |err| return stageFailure("right_segment_cohort", err);
    defer right_segment_cohort.deinit();
    std.debug.print(
        "\nTEMPORAL_CHILD_MANIFEST left_match={} right_match={} " ++
            "same_publication_manifest={}\n",
        .{
            std.mem.eql(
                u8,
                &segment_cohort.manifest().seal,
                &left.publication.manifest_sha_id,
            ),
            std.mem.eql(
                u8,
                &segment_cohort.manifest().seal,
                &right.publication.manifest_sha_id,
            ),
            std.mem.eql(
                u8,
                &left.publication.manifest_sha_id,
                &right.publication.manifest_sha_id,
            ),
        },
    );
    reportManifestDiff(
        segment_cohort.manifest(),
        right_segment_cohort.manifest(),
    );

    var left_child: child_authority.PreparedTemporalChildV1 = undefined;
    try child_authority.admitInto(&left_child, &left.publication);
    var right_child: child_authority.PreparedTemporalChildV1 = undefined;
    try child_authority.admitInto(&right_child, &right.publication);
    const root_pin = recursion.temporal_pair_node.RootVkPinV2{
        .expected_aggregator_vk_id = left.publication.recursive_parent_vk_id,
    };
    var pair: pair_authority.PreparedTemporalPairAuthorityV1 = undefined;
    try pair_authority.prepareInto(
        &pair,
        &left_child,
        &right_child,
        &root_pin,
    );
    try pair.validate();

    const artifacts = binary_driver.TemporalParentArtifactViewV1.init(
        .{
            .publication = &left.publication,
            .capture = &left.capture,
            .recursive_witness = &left.recursive_witness,
        },
        .{
            .publication = &right.publication,
            .capture = &right.capture,
            .recursive_witness = &right.recursive_witness,
        },
        .{
            segment_cohort.manifest(),
            right_segment_cohort.manifest(),
        },
        &pair,
    ) catch |err| return stageFailure("artifact_view", err);
    const runtime = prefix_runtime.RuntimeInputsV1{
        .artifacts = &artifacts,
        .prepared_leaves = .{ left_prepared, right_prepared },
    };
    _ = try runtime.validate();

    // Record the SegmentV2 verifier graph once.  Claims used to construct
    // these adapters come from the left verifier transaction; the graph
    // itself is witness-independent and row18 independently evaluates it
    // for both authenticated children below.
    const segment_relations = universal.UniversalRelations.fromDraws(
        &left.recursive_witness.relation_draws,
    );
    try segment_relations.validate();
    const segment_provider_relations =
        try shared_provider.SharedProviderRelations.init(
            &segment_relations,
        );
    const segment_generated =
        segment_cohort.rebuildGeneratedInteractions(
            &segment_relations,
            &segment_provider_relations,
        ) catch |err| return stageFailure("segment_interactions", err);
    var segment_components = segment_cohort.initComponents(
        &segment_generated,
        &segment_relations,
        &segment_provider_relations,
    ) catch |err| return stageFailure("segment_components", err);
    defer segment_components.deinit();

    var fixture = try binary_fixture.Fixture.init(allocator);
    defer fixture.deinit();
    const binary_inputs = BinaryCohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    var universal_cohort = try BinaryCohort.init(
        allocator,
        binary_inputs,
    );
    defer universal_cohort.deinit();
    var binary_channel = binary_driver.Engine.Channel{};
    const binary_relations = try universal.UniversalRelations.draw(
        allocator,
        &binary_channel,
    );
    const binary_provider_relations =
        try shared_provider.SharedProviderRelations.init(
            &binary_relations,
        );
    const binary_generated =
        try universal_cohort.rebuildGeneratedInteractions(
            &binary_relations,
            &binary_provider_relations,
        );
    var binary_components = try universal_cohort.initComponents(
        &binary_generated,
        &binary_relations,
        &binary_provider_relations,
    );
    defer binary_components.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const binary_capture = try recording_support.syntheticCapture(
        arena.allocator(),
        universal_cohort.manifest(),
        8_301,
    );
    const manifests = composition_v3.TrustedManifestsV3{
        .universal = universal_cohort.manifest(),
        .segment = segment_cohort.manifest(),
    };
    const air_program_ids = composition_v3.AirProgramIdsV3{
        .segment_leaf = left.publication.air_program_id,
        .binary_node = recording_support.nativeDigest(8_401),
        .empty_leaf = recording_support.nativeDigest(8_501),
    };
    const session = try composition_v3.HeterogeneousSessionV3.create(
        allocator,
        manifests,
        air_program_ids,
        &left.capture,
        &binary_capture,
    );
    var session_live = true;
    defer if (session_live) session.deinit();
    try session.recordPrograms(
        &segment_components,
        &binary_components,
        &binary_components,
    );
    const recording = try session.finish();
    session_live = false;
    defer recording.deinit();

    const row18 = row18_source.Row18AuthorityV3.init(
        allocator,
        runtime,
        recording,
        manifests,
        air_program_ids,
    ) catch |err| return stageFailure("row18_authority", err);
    defer row18.deinit();
    try row18.validateAgainst(runtime);

    {
        var parent_preflight = temporal_cohort.Cohort.init(
            allocator,
            .{ .runtime = runtime, .row18 = row18 },
        ) catch |err| return stageFailure("parent_cohort_init", err);
        defer parent_preflight.deinit();
        parent_preflight.validate() catch |err|
            return stageFailure("parent_cohort_validate", err);
    }

    var parent_capture: binary_driver.OuterProofCapture = undefined;
    var parent_publication: ParentKernel.VerifiedPublicationV1 = undefined;
    var parent_artifact: ParentKernel.VerifiedArtifactV1 = undefined;
    const receipt = ParentKernel.proveAndVerifyWithExecutionAndArtifact(
        allocator,
        .{ .runtime = runtime, .row18 = row18 },
        .{ .worker_count = 1 },
        &parent_capture,
        &parent_publication,
        &parent_artifact,
    ) catch |err| return stageFailure("parent_prove_verify", err);
    defer parent_capture.deinit(allocator);
    try parent_publication.validate();
    try parent_artifact.validateAgainst(&parent_publication);
    try parent_artifact.recursive_admission.validateAgainst(&parent_capture);
    try std.testing.expectEqual(
        parent_artifact.recursive_wire_bytes,
        try recursion.outer_parent_child_admission.runtimeCanonicalByteCount(
            parent_artifact.recursive_admission.seal,
            &parent_artifact.recursive_admission.receipt,
            &parent_capture,
        ),
    );
    try std.testing.expectEqual(
        parent_artifact.recursive_proof_id,
        try recursion.outer_parent_child_admission.proofIdRuntime(
            parent_artifact.recursive_admission.seal,
            &parent_artifact.recursive_admission.receipt,
            &parent_capture,
        ),
    );
    try std.testing.expect(temporal_cohort.COMPLETE_PARENT_PROOF_AVAILABLE);
    try std.testing.expect(temporal_cohort.TEMPORAL_PARENT_VERIFIED);
    try std.testing.expect(!temporal_cohort.PROTOCOL_SUBSTRATE_ONLY);
    try std.testing.expect(temporal_manifest.SUFFIX_SOURCE_AVAILABLE);
    try std.testing.expect(temporal_manifest.COMPLETE_PARENT_PROOF_AVAILABLE);
    try std.testing.expect(
        binary_driver.CURRENT_TEMPORAL_PARENT_CAPABILITIES.ready(),
    );
    try std.testing.expect(receipt.canonical_proof_bytes > 0);
    try std.testing.expect(receipt.prove_ns > 0);
    try std.testing.expect(receipt.verify_ns > 0);
    try std.testing.expectEqual(
        @as(u8, temporal_manifest.COMPONENT_COUNT),
        receipt.roster_count,
    );
    try std.testing.expect(parent_capture.commitments.len > 0);
    try std.testing.expect(parent_capture.queries.raw.len > 0);

    std.debug.print(
        "\nTEMPORAL_PARENT_REAL_PROOF bytes={d} prove_ms={d:.3} " ++
            "verify_ms={d:.3} rows={d} pair_poseidon={d}\n",
        .{
            receipt.canonical_proof_bytes,
            milliseconds(receipt.prove_ns),
            milliseconds(receipt.verify_ns),
            receipt.roster_count,
            receipt.pair_authentication_poseidon_permutations,
        },
    );
    const proof_sha256_hex = std.fmt.bytesToHex(
        receipt.canonical_proof_sha256,
        .lower,
    );
    const publication_sha256_hex = std.fmt.bytesToHex(
        parent_publication.publication_sha_id,
        .lower,
    );
    const cohort_authority_sha256_hex = std.fmt.bytesToHex(
        parent_publication.cohort_authority_sha_id,
        .lower,
    );
    const audit_sha256_hex = std.fmt.bytesToHex(
        parent_publication.audit_sha_id,
        .lower,
    );
    const closure_receipt_sha256_hex = std.fmt.bytesToHex(
        parent_publication.closure_receipt_sha_id,
        .lower,
    );
    std.debug.print(
        "TEMPORAL_PARENT_REAL_IDENTITIES proof_sha256={s} " ++
            "publication_sha256={s} cohort_authority_sha256={s} " ++
            "audit_sha256={s} closure_receipt_sha256={s}\n",
        .{
            &proof_sha256_hex,
            &publication_sha256_hex,
            &cohort_authority_sha256_hex,
            &audit_sha256_hex,
            &closure_receipt_sha256_hex,
        },
    );
    try consumer.consume(&parent_publication, &parent_artifact, receipt);
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn stageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nTEMPORAL_PARENT_STAGE_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
    return err;
}

fn reportManifestDiff(left: anytype, right: @TypeOf(left)) void {
    for (left.placements, right.placements, 0..) |lhs, rhs, row| {
        if (std.meta.eql(lhs, rhs)) continue;
        const left_log = if (lhs) |placement| placement.geometry.log_size else 0;
        const right_log = if (rhs) |placement| placement.geometry.log_size else 0;
        std.debug.print(
            "TEMPORAL_CHILD_MANIFEST_DIFF row={d} log={d}/{d}\n",
            .{ row, left_log, right_log },
        );
    }
    std.debug.print(
        "TEMPORAL_CHILD_MANIFEST_AUTH transcript={} statement={} " ++
            "public={} boundary={}\n",
        .{
            std.meta.eql(
                left.transcript_manifest_id,
                right.transcript_manifest_id,
            ),
            std.meta.eql(
                left.statement_manifest_id,
                right.statement_manifest_id,
            ),
            std.meta.eql(left.public_manifest_id, right.public_manifest_id),
            std.meta.eql(
                left.boundary_manifest_id,
                right.boundary_manifest_id,
            ),
        },
    );
}

test "real authenticated temporal SegmentV2 2-to-1 parent independently verifies" {
    try runGate(std.testing.allocator);
}
