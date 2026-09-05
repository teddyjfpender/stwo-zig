const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const subject =
    @import("recursive_pipeline_campaign_final_live_receipt_binder_v2.zig");
const receipt_owner_mod =
    @import("recursive_pipeline_campaign_final_live_role0_receipts_v2.zig");
const description_mod =
    @import("recursive_pipeline_campaign_final_description_v2.zig");
const live_build_plan_mod =
    @import("recursive_pipeline_campaign_final_live_build_plan_v2.zig");
const driver_fixture =
    @import("recursive_pipeline_campaign_final_driver_role0_frontier_v4_test.zig");
const frontier_mod =
    @import("recursive_pipeline_worker_campaign_role0_frontier_v4.zig");
const bridge_fixture =
    @import("recursive_pipeline_worker_campaign_final_session_bridge_v4_test.zig");
const fixture_mod =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig");
const fixture_support =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig");

const Lifecycle = bridge_fixture.Lifecycle;
const FinalWorker = bridge_fixture.FinalWorker;
const Bridge = bridge_fixture.Bridge;
const Frontier = frontier_mod.FrontierFor(Bridge);
const ReplayAdapter = fixture_support.AdapterV4(Lifecycle.ReplayProviderV4);
const ReplayWorker = worker_mod.Worker(ReplayAdapter);
const Binder = subject.BinderFor(
    ReplayWorker,
    driver_fixture.Driver,
    Frontier,
);
const ReceiptOwner = receipt_owner_mod.OwnerFor(Binder);
const LiveBuildPlan = live_build_plan_mod.PlanFor(
    Binder.BorrowedRole0ReceiptV2,
    Binder.BorrowedRole0ReceiptV2,
);

test "live receipt binder admits two sealed role0 worker leases" {
    try exerciseLiveBinder(2, true);
}

test "live receipt binder preserves a non-power-of-two three-row frontier" {
    try exerciseLiveBinder(3, false);
}

fn exerciseLiveBinder(count: usize, test_mutations: bool) !void {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, count);
    defer fixture.deinit();

    var building: ?*Lifecycle.OwnedBuildingV4 = try Lifecycle.begin(
        allocator,
        allocator,
        &store,
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
    defer final.deinit();

    const assembly = FinalWorker.ValidatedAssemblyV2{
        .role0_authority = &fixture.authority,
        .final_remint = &fixture.final_remint,
    };
    const bridge = try Bridge.init(final, &assembly, allocator);
    const expected = try allocator.alloc(
        frontier_mod.ExpectedPublicationV4,
        fixture.rows.len,
    );
    defer allocator.free(expected);
    for (expected, fixture.rows) |*publication, row| {
        publication.* = .{
            .output_ref = row.output_ref,
            .stage_manifest_ref = row.stage_manifest_ref.?,
        };
    }
    var frontier = try Frontier.OwnedFrontierV4.init(
        allocator,
        allocator,
        bridge,
        &fixture.policy,
        expected,
    );
    defer frontier.deinit();

    var worker = try ReplayWorker.init(allocator, root);
    defer worker.deinit();
    const retained = try allocator.alloc(
        fixture_support.RetainedColdOpenV4,
        count,
    );
    defer allocator.free(retained);
    var retained_count: usize = 0;
    defer for (retained[0..retained_count]) |*value| value.deinit();
    for (fixture.rows, 0..) |*row, index| {
        retained[index] = try fixture_support.coldOpenAndRetainAtCount(
            ReplayWorker,
            &worker,
            allocator,
            row,
            row.stage_manifest_ref,
            index + 1,
        );
        retained_count += 1;
    }

    const session = try final.immutableSession();
    const driver = try driver_fixture.Driver.init(allocator, session);
    const binder = Binder.init(&worker, &driver);
    var request_arena_state = std.heap.ArenaAllocator.init(allocator);
    var request_arena_live = true;
    defer if (request_arena_live) request_arena_state.deinit();
    const request_arena = request_arena_state.allocator();
    const publications = try request_arena.alloc(
        receipt_owner_mod.ColdPublicationV2,
        retained.len,
    );
    for (publications, retained, fixture.rows) |
        *publication,
        cold,
        row,
    | {
        try std.testing.expectEqualDeep(
            row.stage_manifest_ref.?,
            cold.stage_manifest_ref,
        );
        publication.* = .{
            .output_ref = row.output_ref,
            .stage_manifest_ref = cold.stage_manifest_ref,
            .lease_id = try request_arena.dupe(u8, cold.lease_id),
        };
    }
    if (test_mutations) {
        std.mem.swap(
            receipt_owner_mod.ColdPublicationV2,
            &publications[0],
            &publications[publications.len - 1],
        );
        try expectRejected(ReceiptOwner.init(
            allocator,
            allocator,
            binder,
            &frontier,
            publications,
        ));
        std.mem.swap(
            receipt_owner_mod.ColdPublicationV2,
            &publications[0],
            &publications[publications.len - 1],
        );
        const saved_second_lease = publications[1].lease_id;
        publications[1].lease_id = publications[0].lease_id;
        try expectRejected(ReceiptOwner.init(
            allocator,
            allocator,
            binder,
            &frontier,
            publications,
        ));
        publications[1].lease_id = saved_second_lease;
    }
    const receipt_owner = try ReceiptOwner.init(
        allocator,
        allocator,
        binder,
        &frontier,
        publications,
    );
    defer receipt_owner.deinit();
    request_arena_state.deinit();
    request_arena_live = false;
    try receipt_owner.validate(allocator);
    const receipts = receipt_owner.receipts;
    const bound = try receipt_owner.boundRole0Frontier(allocator);
    try std.testing.expectEqual(count, bound.len());
    for (0..bound.len()) |index| {
        const view = try bound.role0At(index);
        try view.validate();
        try std.testing.expect(view.node() == receipts[index].node);
        try std.testing.expectEqualDeep(
            receipts[index].output_ref,
            view.outputRef(),
        );
        try std.testing.expectEqualDeep(
            receipts[index].stage_manifest_ref,
            view.stageManifestRef(),
        );
        try std.testing.expectEqualStrings(
            receipts[index].lease_id,
            view.liveLeaseSelector(),
        );
        try std.testing.expect(
            view.nodeArtifact() ==
                frontier.orderedRows()[index].role0.lease.nodeArtifact(),
        );
    }

    const left = try bound.role0At(0);
    const right = try bound.role0At(1);
    const Describer = description_mod.DescriberFor(
        @TypeOf(left),
        @TypeOf(right),
    );
    const execution_authorities = executionAuthorities(
        receipts[0].execution.*,
    );
    const parent = try Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        execution_authorities,
        &left,
        &right,
    );
    defer parent.deinit();
    try parent.validate(allocator);
    const live_build_plan = try LiveBuildPlan.init(
        allocator,
        parent,
        &left,
        &right,
    );
    try live_build_plan.validate(allocator);
    try std.testing.expect(live_build_plan.stageDescription() == parent);
    try std.testing.expectEqual(@as(usize, 2), live_build_plan.dependencyLeaseIds().len);
    try std.testing.expectEqualStrings(
        left.liveLeaseSelector(),
        live_build_plan.dependencyLeaseIds()[0],
    );
    try std.testing.expectEqualStrings(
        right.liveLeaseSelector(),
        live_build_plan.dependencyLeaseIds()[1],
    );
    try std.testing.expectEqual(@as(u8, 1), parent.planned_semantic.coordinate.height);
    try std.testing.expectEqual(@as(u32, 0), parent.planned_semantic.coordinate.index);
    try std.testing.expectEqual(@as(u8, 2), parent.planned_semantic.child_count);
    try std.testing.expectEqualDeep(
        receipts[0].output_ref,
        parent.ordered_inputs[0].blob,
    );
    try std.testing.expectEqualDeep(
        receipts[1].output_ref,
        parent.ordered_inputs[1].blob,
    );
    try std.testing.expectEqualDeep(
        receipts[0].stage_manifest_ref,
        parent.dependency_stage_manifest_refs[0],
    );
    try std.testing.expectEqualDeep(
        receipts[1].stage_manifest_ref,
        parent.dependency_stage_manifest_refs[1],
    );
    const encoded = try parent.encodeCanonicalJsonAlloc(allocator);
    defer allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        left.liveLeaseSelector(),
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        right.liveLeaseSelector(),
    ) == null);
    if (!test_mutations) return;

    try expectRejected(Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        execution_authorities,
        &left,
        &left,
    ));
    try expectRejected(Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        execution_authorities,
        &right,
        &left,
    ));

    const saved_lease = receipts[0].lease_id;
    receipts[0].lease_id = receipts[1].lease_id;
    try expectRejected(binder.validateLiveReceipts(receipts));
    try expectRejected(live_build_plan.validate(allocator));
    receipts[0].lease_id = saved_lease;
    try live_build_plan.validate(allocator);

    const saved_output = receipts[0].output_ref;
    receipts[0].output_ref = receipts[1].output_ref;
    try expectRejected(binder.validateLiveReceipts(receipts));
    receipts[0].output_ref = saved_output;

    const saved_manifest = receipts[0].stage_manifest_ref;
    receipts[0].stage_manifest_ref = receipts[1].stage_manifest_ref;
    try expectRejected(binder.validateLiveReceipts(receipts));
    receipts[0].stage_manifest_ref = saved_manifest;
    try binder.validateLiveReceipts(receipts);

    try closeLease(&worker, allocator, receipts[0].lease_id);
    try expectRejected(binder.validateLiveReceipts(receipts));
    try expectRejected(bound.role0At(0));
    try expectRejected(live_build_plan.validate(allocator));
    try expectRejected(Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        execution_authorities,
        &left,
        &right,
    ));
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

fn closeLease(
    worker: *ReplayWorker,
    allocator: std.mem.Allocator,
    lease_id: []const u8,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var payload = protocol.jsonObject(arena);
    try protocol.put(&payload, "lease_id", protocol.string(lease_id));
    _ = try worker.handle(arena, .{
        .sequence = 0,
        .action = .close_lease,
        .payload = payload,
    });
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedCampaignLiveReceiptRejectionV2;
}
