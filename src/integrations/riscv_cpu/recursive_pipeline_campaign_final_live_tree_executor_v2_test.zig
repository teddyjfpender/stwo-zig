const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const worker_support = @import("recursive_pipeline_worker_support_v1.zig");
const executor_mod = @import(
    "recursive_pipeline_campaign_final_live_build_executor_v2.zig",
);
const committed_adapter_mod = @import(
    "recursive_pipeline_campaign_final_live_committed_stage_v2.zig",
);
const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");
const test_adapter_mod = @import(
    "recursive_pipeline_campaign_final_live_build_test_support_v2.zig",
);
const fold_binder_mod = @import(
    "recursive_pipeline_campaign_final_live_fold_child_binder_v2.zig",
);
const description_mod = @import(
    "recursive_pipeline_campaign_final_description_v2.zig",
);
const live_plan_mod = @import(
    "recursive_pipeline_campaign_final_live_build_plan_v2.zig",
);
const empty_source = @import(
    "recursive_common_canonical_empty_campaign_source_v2.zig",
);
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const bridge_fixture = @import(
    "recursive_pipeline_worker_campaign_final_session_bridge_v4_test.zig",
);
const fixture_mod = @import(
    "recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig",
);
const fixture_support = @import(
    "recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig",
);

const recursion = frontend.recursion;
const Lifecycle = bridge_fixture.Lifecycle;
const TestAdapter = test_adapter_mod.AdapterV2(Lifecycle.ReplayProviderV4);
const TestWorker = worker_mod.Worker(TestAdapter);
const FoldBinder = fold_binder_mod.BinderFor(TestWorker);
const FoldChild = FoldBinder.BorrowedChildV2;
const LiveBuildPlan = live_plan_mod.PlanFor(FoldChild, FoldChild);
const Executor = executor_mod.ExecutorFor(TestWorker, LiveBuildPlan);
const Describer = description_mod.DescriberFor(FoldChild, FoldChild);
const CommittedAdapter = committed_adapter_mod.AdapterFor(Executor);
const Driver = driver_mod.DriverFor(Lifecycle.ImmutableSessionV4, TestAdapter);

test "campaign live-tree executor remains fixture-only and capability opaque" {
    std.testing.refAllDecls(FoldBinder);
    std.testing.refAllDecls(Executor);
    try std.testing.expect(!fold_binder_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!fold_binder_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!test_adapter_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!test_adapter_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!test_adapter_mod.GENUINE_Q193_GATE_GREEN);
    try std.testing.expect(!@hasDecl(FoldChild, "encode"));
    try std.testing.expect(!@hasField(FoldChild, "payload"));
}

test "campaign live committed-stage adapter borrows exact cold publication" {
    std.testing.refAllDecls(CommittedAdapter);
    try std.testing.expect(!committed_adapter_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!committed_adapter_mod.ROUTER_ACTIVATION);
    try std.testing.expect(
        committed_adapter_mod.LIVE_LEASE_REQUIRED_AT_PROJECTION,
    );
    try std.testing.expect(!committed_adapter_mod.LEASE_CLOSE_OWNERSHIP);
    try std.testing.expect(!@hasDecl(CommittedAdapter, "encode"));
    try std.testing.expect(!@hasField(CommittedAdapter, "payload"));
}

test "campaign live-tree executes three real plus typed empty to one retained root" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();

    // Three is deliberately fixture-only. Every production-facing authority,
    // description, worker, and executor consumes the authenticated runtime
    // campaign shape rather than a compile-time leaf count.
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 3);
    defer fixture.deinit();
    try std.testing.expectEqual(@as(u32, 3), fixture.shape.real_leaf_count);
    try std.testing.expectEqual(@as(u32, 4), fixture.shape.padded_leaf_count);

    const final = try installImmutableStage102(
        allocator,
        &store,
        root,
        fixture,
    );
    defer final.deinit();
    const session = try final.immutableSession();
    const driver = try Driver.init(allocator, session);
    const runtime_plan = try driver_mod.RuntimePlanDescriptionV2.init(
        &fixture.final_remint,
        &fixture.policy,
    );
    var visitation = RuntimePlanVisitationV2{};
    try driver_mod.walkDescribedRuntimePlan(
        &runtime_plan,
        &fixture.final_remint,
        &fixture.policy,
        &visitation,
    );
    try visitation.expectThreeToFour();

    var worker = try TestWorker.init(allocator, root);
    defer worker.deinit();
    var retained_real: [3]fixture_support.RetainedColdOpenV4 = undefined;
    var retained_real_count: usize = 0;
    defer for (retained_real[0..retained_real_count]) |*value| value.deinit();
    for (fixture.rows, 0..) |*row, index| {
        retained_real[index] = try fixture_support.coldOpenAndRetainAtCount(
            TestWorker,
            &worker,
            allocator,
            row,
            row.stage_manifest_ref,
            index + 1,
        );
        retained_real_count += 1;
    }
    try expectLeaseCount(&worker, 3);

    const empty = try publishEmptySource(&store, fixture, 3);
    const empty_description = try description_mod.describeStage103(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        executionAuthorities(fixture.rows[0].execution),
        empty.source_ref,
        &empty.cold,
    );
    defer empty_description.deinit();

    var path_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer path_arena_state.deinit();
    const path_arena = path_arena_state.allocator();
    var executor = Executor.init(&worker);
    const empty_built = try executor.buildWithoutDependencies(
        allocator,
        allocator,
        empty_description,
        try buildPaths(path_arena, root, "empty-3"),
    );
    defer empty_built.deinit();
    try expectLeaseCount(&worker, 3);
    const empty_retained = try executor.coldOpenAndRetain(
        allocator,
        allocator,
        empty_built,
        1,
        "root",
    );
    defer empty_retained.deinit();
    try expectLeaseCount(&worker, 4);
    try expectSealedPublication(
        allocator,
        &worker.store,
        empty_description,
        empty_built.output_ref,
        empty_retained.stage_manifest_ref,
    );
    const empty_committed_adapter = try CommittedAdapter.init(
        allocator,
        empty_description,
        empty_built,
        empty_retained,
    );

    var leaf_dependency_refs: [3][1]artifact_store.BlobRefV1 = undefined;
    var leaf_receipts: [4]driver_mod.CommittedStageV2 = undefined;
    for (session.entries, 0..) |*entry, index| {
        leaf_dependency_refs[index] = .{
            entry.admission.dependency_stage_manifest_ref,
        };
        leaf_receipts[index] = .{
            .node = entry.admission.node,
            .semantic = entry.admission.semantic,
            .execution = entry.admission.execution,
            .ordered_inputs = entry.admission.ordered_inputs,
            .output_ref = entry.output_ref,
            .stage_manifest_ref = retained_real[index].stage_manifest_ref,
            .dependency_stage_manifest_refs = &leaf_dependency_refs[index],
            .lease_id = retained_real[index].lease_id,
        };
    }
    leaf_receipts[3] = try empty_committed_adapter.committed(allocator);
    try driver.validateLeafFrontier(allocator, &leaf_receipts);

    var real_receipts: [3]fold_binder_mod.RetainedLeaseReceiptV2 = undefined;
    for (&real_receipts, &retained_real, fixture.rows) |
        *receipt,
        retained,
        *row,
    | {
        receipt.* = .{
            .node = &row.node,
            .output_ref = row.output_ref,
            .stage_manifest_ref = retained.stage_manifest_ref,
            .lease_id = retained.lease_id,
        };
    }
    const empty_receipt = fold_binder_mod.RetainedLeaseReceiptV2{
        .node = &empty_description.node,
        .output_ref = empty_built.output_ref,
        .stage_manifest_ref = empty_retained.stage_manifest_ref,
        .lease_id = empty_retained.lease_id,
    };
    const fold_binder = FoldBinder.init(&worker);

    // Bind only after all four leaf leases are installed. A projection may
    // borrow map-resident typed state, so no later insertion may occur before
    // the corresponding build consumes the two views.
    const leaf0 = try fold_binder.bind(
        &real_receipts[0],
        &fixture.final_remint,
    );
    const leaf1 = try fold_binder.bind(
        &real_receipts[1],
        &fixture.final_remint,
    );
    try std.testing.expectEqual(.real, leaf0.nodeArtifact().node_kind);
    try std.testing.expectEqual(.real, leaf1.nodeArtifact().node_kind);
    const parent01_description = try Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        executionAuthorities(fixture.rows[0].execution),
        &leaf0,
        &leaf1,
    );
    defer parent01_description.deinit();
    const parent01_plan = try LiveBuildPlan.init(
        allocator,
        parent01_description,
        &leaf0,
        &leaf1,
    );
    const parent01_built = try executor.build(
        allocator,
        allocator,
        &parent01_plan,
        try buildPaths(path_arena, root, "fold-1-0"),
    );
    defer parent01_built.deinit();
    try expectLeaseCount(&worker, 2);
    try expectRejected(leaf0.validate());
    try expectRejected(leaf1.validate());
    const parent01_retained = try executor.coldOpenAndRetain(
        allocator,
        allocator,
        parent01_built,
        1,
        "root",
    );
    defer parent01_retained.deinit();
    try expectLeaseCount(&worker, 3);
    try expectSealedPublication(
        allocator,
        &worker.store,
        parent01_description,
        parent01_built.output_ref,
        parent01_retained.stage_manifest_ref,
    );
    const parent01_committed_adapter = try CommittedAdapter.init(
        allocator,
        parent01_description,
        parent01_built,
        parent01_retained,
    );

    // Rebind after the parent insertion; this pair is the remaining real leaf
    // and the independently built/cold-opened typed empty leaf.
    const leaf2 = try fold_binder.bind(
        &real_receipts[2],
        &fixture.final_remint,
    );
    const empty_leaf = try fold_binder.bind(
        &empty_receipt,
        &fixture.final_remint,
    );
    try std.testing.expectEqual(.real, leaf2.nodeArtifact().node_kind);
    try std.testing.expectEqual(.empty, empty_leaf.nodeArtifact().node_kind);
    const parent23_description = try Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        executionAuthorities(fixture.rows[0].execution),
        &leaf2,
        &empty_leaf,
    );
    defer parent23_description.deinit();
    const parent23_plan = try LiveBuildPlan.init(
        allocator,
        parent23_description,
        &leaf2,
        &empty_leaf,
    );
    const parent23_built = try executor.build(
        allocator,
        allocator,
        &parent23_plan,
        try buildPaths(path_arena, root, "fold-1-1"),
    );
    defer parent23_built.deinit();
    try expectLeaseCount(&worker, 1);
    try expectRejected(leaf2.validate());
    try expectRejected(empty_leaf.validate());
    const parent23_retained = try executor.coldOpenAndRetain(
        allocator,
        allocator,
        parent23_built,
        1,
        "root",
    );
    defer parent23_retained.deinit();
    try expectLeaseCount(&worker, 2);
    try expectSealedPublication(
        allocator,
        &worker.store,
        parent23_description,
        parent23_built.output_ref,
        parent23_retained.stage_manifest_ref,
    );
    const parent23_committed_adapter = try CommittedAdapter.init(
        allocator,
        parent23_description,
        parent23_built,
        parent23_retained,
    );
    const level1_receipts = [2]driver_mod.CommittedStageV2{
        try parent01_committed_adapter.committed(allocator),
        try parent23_committed_adapter.committed(allocator),
    };
    try driver.validateLevel(
        allocator,
        1,
        &leaf_receipts,
        &level1_receipts,
    );

    const parent01_receipt = fold_binder_mod.RetainedLeaseReceiptV2{
        .node = &parent01_description.node,
        .output_ref = parent01_built.output_ref,
        .stage_manifest_ref = parent01_retained.stage_manifest_ref,
        .lease_id = parent01_retained.lease_id,
    };
    const parent23_receipt = fold_binder_mod.RetainedLeaseReceiptV2{
        .node = &parent23_description.node,
        .output_ref = parent23_built.output_ref,
        .stage_manifest_ref = parent23_retained.stage_manifest_ref,
        .lease_id = parent23_retained.lease_id,
    };
    const parent01 = try fold_binder.bind(
        &parent01_receipt,
        &fixture.final_remint,
    );
    const parent23 = try fold_binder.bind(
        &parent23_receipt,
        &fixture.final_remint,
    );
    try std.testing.expectEqual(@as(u8, 1), parent01.nodeArtifact().coordinate.height);
    try std.testing.expectEqual(@as(u32, 0), parent01.nodeArtifact().coordinate.index);
    try std.testing.expectEqual(@as(u8, 1), parent23.nodeArtifact().coordinate.height);
    try std.testing.expectEqual(@as(u32, 1), parent23.nodeArtifact().coordinate.index);

    const root_description = try Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        executionAuthorities(fixture.rows[0].execution),
        &parent01,
        &parent23,
    );
    defer root_description.deinit();
    const root_plan = try LiveBuildPlan.init(
        allocator,
        root_description,
        &parent01,
        &parent23,
    );
    const root_built = try executor.build(
        allocator,
        allocator,
        &root_plan,
        try buildPaths(path_arena, root, "fold-2-0"),
    );
    defer root_built.deinit();
    try expectLeaseCount(&worker, 0);
    try expectRejected(parent01.validate());
    try expectRejected(parent23.validate());
    const root_retained = try executor.coldOpenAndRetain(
        allocator,
        allocator,
        root_built,
        1,
        "root",
    );
    defer root_retained.deinit();
    try expectLeaseCount(&worker, 1);
    try expectSealedPublication(
        allocator,
        &worker.store,
        root_description,
        root_built.output_ref,
        root_retained.stage_manifest_ref,
    );
    const root_committed_adapter = try CommittedAdapter.init(
        allocator,
        root_description,
        root_built,
        root_retained,
    );
    const root_receipts = [1]driver_mod.CommittedStageV2{
        try root_committed_adapter.committed(allocator),
    };
    try driver.validateLevel(
        allocator,
        2,
        &level1_receipts,
        &root_receipts,
    );
    const levels = [_][]const driver_mod.CommittedStageV2{
        &leaf_receipts,
        &level1_receipts,
        &root_receipts,
    };
    const accepted_root = try driver.validateComplete(allocator, &levels);
    try std.testing.expect(accepted_root == &root_receipts[0]);

    const root_receipt = fold_binder_mod.RetainedLeaseReceiptV2{
        .node = &root_description.node,
        .output_ref = root_built.output_ref,
        .stage_manifest_ref = root_retained.stage_manifest_ref,
        .lease_id = root_retained.lease_id,
    };
    const root_child = try fold_binder.bind(
        &root_receipt,
        &fixture.final_remint,
    );
    try root_child.validate();
    try std.testing.expectEqual(.root, root_child.nodeArtifact().stage_kind);
    try std.testing.expectEqual(.mixed, root_child.nodeArtifact().node_kind);
    try std.testing.expectEqual(fixture.shape.root_height, root_child.nodeArtifact().coordinate.height);
    try std.testing.expectEqual(@as(u32, 0), root_child.nodeArtifact().coordinate.index);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.stage_manifest,
        root_retained.stage_manifest_ref.kind,
    );
    try std.testing.expect(!artifact_store.BlobRefV1.eql(
        parent01_retained.stage_manifest_ref,
        parent23_retained.stage_manifest_ref,
    ));

    try executor.closeRetainedParent(allocator, root_retained);
    try expectLeaseCount(&worker, 0);
    try expectRejected(root_child.validate());
    try expectRejected(root_committed_adapter.validate(allocator));
}

const EmptyPublicationV2 = struct {
    source_ref: artifact_store.BlobRefV1,
    cold: empty_source.ColdInputV2,
};

const RuntimePlanVisitationV2 = struct {
    const FoldVisitV2 = struct {
        parent: driver_mod.Coordinate,
        left: driver_mod.Coordinate,
        right: driver_mod.Coordinate,
    };

    empty: [1]driver_mod.Coordinate = undefined,
    folds: [3]FoldVisitV2 = undefined,
    empty_count: usize = 0,
    fold_count: usize = 0,

    pub fn stage103(
        self: *RuntimePlanVisitationV2,
        coordinate: driver_mod.Coordinate,
    ) !void {
        if (self.empty_count >= self.empty.len)
            return error.CampaignFinalLiveTreeFixtureMismatchV2;
        self.empty[self.empty_count] = coordinate;
        self.empty_count += 1;
    }

    pub fn stage104(
        self: *RuntimePlanVisitationV2,
        parent: driver_mod.Coordinate,
        left: driver_mod.Coordinate,
        right: driver_mod.Coordinate,
    ) !void {
        if (self.fold_count >= self.folds.len)
            return error.CampaignFinalLiveTreeFixtureMismatchV2;
        self.folds[self.fold_count] = .{
            .parent = parent,
            .left = left,
            .right = right,
        };
        self.fold_count += 1;
    }

    fn expectThreeToFour(self: RuntimePlanVisitationV2) !void {
        try std.testing.expectEqual(@as(usize, 1), self.empty_count);
        try std.testing.expectEqual(@as(usize, 3), self.fold_count);
        try expectCoordinate(self.empty[0], 0, 3);
        try expectCoordinate(self.folds[0].parent, 1, 0);
        try expectCoordinate(self.folds[0].left, 0, 0);
        try expectCoordinate(self.folds[0].right, 0, 1);
        try expectCoordinate(self.folds[1].parent, 1, 1);
        try expectCoordinate(self.folds[1].left, 0, 2);
        try expectCoordinate(self.folds[1].right, 0, 3);
        try expectCoordinate(self.folds[2].parent, 2, 0);
        try expectCoordinate(self.folds[2].left, 1, 0);
        try expectCoordinate(self.folds[2].right, 1, 1);
    }
};

fn expectCoordinate(
    value: driver_mod.Coordinate,
    height: u8,
    index: u32,
) !void {
    try std.testing.expectEqual(height, value.height);
    try std.testing.expectEqual(index, value.index);
}

fn publishEmptySource(
    store: *artifact_store.Store,
    fixture: *fixture_mod.FixtureV4,
    index: u32,
) !EmptyPublicationV2 {
    const job = try campaignJob(fixture.shape.real_leaf_count);
    var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &leaf,
        job,
        index,
        poseidonDigest(0x301),
        poseidonDigest(0x311),
        poseidonDigest(0x321),
    );
    const source = try empty_source.SourceArtifactV2.seal(
        &fixture.shape,
        &leaf,
    );
    const bytes = try source.encodeCanonical(&fixture.shape);
    const source_ref = try store.putBytes(
        .source,
        empty_source.SCHEMA_VERSION,
        &bytes,
    );
    const expected_ref = try node_store.toSharedRef(
        try source.artifactRef(&fixture.shape),
    );
    if (!artifact_store.BlobRefV1.eql(source_ref, expected_ref))
        return error.CampaignFinalLiveTreeFixtureMismatchV2;
    return .{
        .source_ref = source_ref,
        .cold = try empty_source.ColdInputV2.open(&fixture.shape, &bytes),
    };
}

fn installImmutableStage102(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    root: []const u8,
    fixture: *fixture_mod.FixtureV4,
) !*Lifecycle.OwnedFinalSessionV4 {
    var building: ?*Lifecycle.OwnedBuildingV4 = try Lifecycle.begin(
        allocator,
        allocator,
        store,
        root,
        &fixture.authority,
        &fixture.policy,
    );
    defer if (building) |value| value.deinit();
    for (fixture.rows) |*row| {
        row.stage_manifest_ref = try fixture_support.coldOpenAndClose(
            Lifecycle.BuildWorkerV4,
            building.?.workerView(),
            allocator,
            row,
            null,
        );
    }
    var quiesced: ?*Lifecycle.OwnedQuiescedV4 = try building.?.quiesce();
    building = null;
    defer if (quiesced) |value| value.deinit();
    var sealed: ?*Lifecycle.OwnedSealedV4 = try quiesced.?.sealComplete(
        allocator,
    );
    quiesced = null;
    defer if (sealed) |value| value.deinit();
    const final = try sealed.?.installImmutable(allocator);
    sealed = null;
    return final;
}

fn buildPaths(
    allocator: std.mem.Allocator,
    root: []const u8,
    label: []const u8,
) !executor_mod.BuildPathsV2 {
    return .{
        .output_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.output",
            .{ root, label },
        ),
        .profile_receipt_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.profile.json",
            .{ root, label },
        ),
        .candidate_ref_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.candidate.json",
            .{ root, label },
        ),
    };
}

fn executionAuthorities(
    execution: artifact_store.ExecutionKeyV1,
) protocol.ExecutionAuthorities {
    const fields = execution.fields;
    return .{
        .producer_identity_sha256 = fields.producer_identity,
        .verifier_identity_sha256 = fields.verifier_identity,
        .source_identity_sha256 = fields.source_identity,
        .build_identity_sha256 = fields.build_identity,
        .executable_identity_sha256 = fields.executable_identity,
        .toolchain_identity_sha256 = fields.toolchain_identity,
        .backend_identity_sha256 = fields.backend_identity,
        .optimization_identity_sha256 = fields.optimization_identity,
        .worker_policy_identity_sha256 = fields.worker_policy_identity,
        .memory_policy_identity_sha256 = fields.memory_policy_identity,
        .retention_policy_identity_sha256 = fields.retention_policy_identity,
        .timeout_policy_identity_sha256 = fields.timeout_policy_identity,
    };
}

fn campaignJob(
    segment_count: u32,
) !recursion.span_statement.JobContext {
    return recursion.span_statement.JobContext.init(
        try recursion.span_statement.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            poseidonDigest(0x41),
            try recursion.span_statement.MachineState.init(
                0x1000,
                [_]u32{0} ** 32,
                poseidonDigest(0x11),
                poseidonDigest(0x21),
            ),
            try recursion.span_statement.MachineState.init(
                0x2000,
                [_]u32{0} ** 32,
                poseidonDigest(0x31),
                poseidonDigest(0x41),
            ),
            poseidonDigest(0x51),
            poseidonDigest(0x61),
            88_000,
        ),
        segment_count,
    );
}

fn poseidonDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn expectLeaseCount(worker: *TestWorker, expected: usize) !void {
    try std.testing.expectEqual(expected, worker.leases.count());
    try std.testing.expectEqual(expected, TestAdapter.liveLeaseCount());
}

fn expectSealedPublication(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    description: *const description_mod.OwnedStageDescriptionV2,
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
) !void {
    try worker_support.validateExistingStageManifest(
        allocator,
        store,
        stage_manifest_ref,
        description.node,
        description.ordered_inputs,
        description.semantic,
        description.execution,
        output_ref,
        description.dependency_stage_manifest_refs,
        "root",
    );
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedCampaignFinalLiveTreeRejectionV2;
}

comptime {
    if (test_adapter_mod.PRODUCTION_ACTIVATION or
        test_adapter_mod.ROUTER_ACTIVATION or
        test_adapter_mod.GENUINE_Q193_GATE_GREEN or
        fold_binder_mod.PRODUCTION_ACTIVATION or
        fold_binder_mod.ROUTER_ACTIVATION)
    {
        @compileError("campaign final live-tree fixture activated");
    }
    _ = campaign_artifact.SCHEMA_VERSION;
}
