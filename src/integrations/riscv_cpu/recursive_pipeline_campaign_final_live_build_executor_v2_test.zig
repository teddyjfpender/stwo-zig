const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const subject = @import(
    "recursive_pipeline_campaign_final_live_build_executor_v2.zig",
);
const test_adapter_mod = @import(
    "recursive_pipeline_campaign_final_live_build_test_support_v2.zig",
);
const binder_mod = @import(
    "recursive_pipeline_campaign_final_live_receipt_binder_v2.zig",
);
const receipt_owner_mod = @import(
    "recursive_pipeline_campaign_final_live_role0_receipts_v2.zig",
);
const description_mod = @import(
    "recursive_pipeline_campaign_final_description_v2.zig",
);
const live_plan_mod = @import(
    "recursive_pipeline_campaign_final_live_build_plan_v2.zig",
);
const driver_fixture = @import(
    "recursive_pipeline_campaign_final_driver_role0_frontier_v4_test.zig",
);
const frontier_mod = @import(
    "recursive_pipeline_worker_campaign_role0_frontier_v4.zig",
);
const bridge_fixture = @import(
    "recursive_pipeline_worker_campaign_final_session_bridge_v4_test.zig",
);
const fixture_mod = @import(
    "recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig",
);
const fixture_support = @import(
    "recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig",
);

const Lifecycle = bridge_fixture.Lifecycle;
const FinalWorker = bridge_fixture.FinalWorker;
const Bridge = bridge_fixture.Bridge;
const Frontier = frontier_mod.FrontierFor(Bridge);
const TestAdapter = test_adapter_mod.AdapterV2(Lifecycle.ReplayProviderV4);
const TestWorker = worker_mod.Worker(TestAdapter);
const Binder = binder_mod.BinderFor(
    TestWorker,
    driver_fixture.Driver,
    Frontier,
);
const ReceiptOwner = receipt_owner_mod.OwnerFor(Binder);
const LiveBuildPlan = live_plan_mod.PlanFor(
    Binder.BorrowedRole0ReceiptV2,
    Binder.BorrowedRole0ReceiptV2,
);
const Executor = subject.ExecutorFor(TestWorker, LiveBuildPlan);

test "Stage104 live-build executor contract stays unrouteable and opaque" {
    std.testing.refAllDecls(Executor);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!subject.SERIALIZABLE_LIVE_LEASE_SELECTOR);
    try std.testing.expect(subject.EXACT_ORDERED_LEASE_CONSUMPTION_REQUIRED);
    try std.testing.expect(!subject.PARENT_LEASE_PAYLOAD_EXPOSED);
    try std.testing.expect(!subject.LEASE_CLOSE_OWNERSHIP);
    try std.testing.expect(!@hasField(
        Executor.OwnedRetainedParentV2,
        "payload",
    ));
    try std.testing.expect(!@hasDecl(
        Executor.OwnedRetainedParentV2,
        "encode",
    ));
}

test "Stage104 worker failure retains both children and success cold-opens one parent" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 2);
    defer fixture.deinit();

    const final = try installImmutableStage102(
        allocator,
        &store,
        root,
        fixture,
    );
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

    var worker = try TestWorker.init(allocator, root);
    defer worker.deinit();
    var retained: [2]fixture_support.RetainedColdOpenV4 = undefined;
    var retained_count: usize = 0;
    defer for (retained[0..retained_count]) |*value| value.deinit();
    for (fixture.rows, 0..) |*row, index| {
        retained[index] = try fixture_support.coldOpenAndRetainAtCount(
            TestWorker,
            &worker,
            allocator,
            row,
            row.stage_manifest_ref,
            index + 1,
        );
        retained_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), TestAdapter.liveLeaseCount());

    const session = try final.immutableSession();
    const driver = try driver_fixture.Driver.init(allocator, session);
    const binder = Binder.init(&worker, &driver);
    var publications: [2]receipt_owner_mod.ColdPublicationV2 = undefined;
    for (&publications, &retained, fixture.rows) |*publication, cold, row| {
        publication.* = .{
            .output_ref = row.output_ref,
            .stage_manifest_ref = cold.stage_manifest_ref,
            .lease_id = cold.lease_id,
        };
    }
    const receipt_owner = try ReceiptOwner.init(
        allocator,
        allocator,
        binder,
        &frontier,
        &publications,
    );
    defer receipt_owner.deinit();
    const bound = try receipt_owner.boundRole0Frontier(allocator);
    const left = try bound.role0At(0);
    const right = try bound.role0At(1);
    const Describer = description_mod.DescriberFor(
        @TypeOf(left),
        @TypeOf(right),
    );
    const parent = try Describer.describeStage104(
        allocator,
        &fixture.final_remint,
        &fixture.policy,
        executionAuthorities(fixture.rows[0].execution),
        &left,
        &right,
    );
    defer parent.deinit();
    const plan = try LiveBuildPlan.init(allocator, parent, &left, &right);
    var executor = Executor.init(&worker);
    const output_path = try std.fs.path.join(
        allocator,
        &.{ root, "stage104.output" },
    );
    defer allocator.free(output_path);
    const profile_path = try std.fs.path.join(
        allocator,
        &.{ root, "stage104.profile.json" },
    );
    defer allocator.free(profile_path);
    const candidate_path = try std.fs.path.join(
        allocator,
        &.{ root, "stage104.candidate.json" },
    );
    defer allocator.free(candidate_path);
    const paths = subject.BuildPathsV2{
        .output_path = output_path,
        .profile_receipt_path = profile_path,
        .candidate_ref_path = candidate_path,
    };

    TestAdapter.armOneBuildFailure();
    try std.testing.expectError(
        error.CampaignFinalLiveBuildFixtureFailureV2,
        executor.build(allocator, allocator, &plan, paths),
    );
    try plan.validate(allocator);
    try binder.validateLiveReceipts(receipt_owner.receipts);
    try std.testing.expectEqual(@as(usize, 2), worker.leases.count());
    try std.testing.expectEqual(@as(usize, 2), TestAdapter.liveLeaseCount());
    try expectMissing(output_path);
    try expectMissing(profile_path);
    try expectMissing(candidate_path);

    const built = try executor.build(
        allocator,
        allocator,
        &plan,
        paths,
    );
    defer built.deinit();
    try built.validate(allocator);
    try std.testing.expectEqual(@as(usize, 0), worker.leases.count());
    try std.testing.expectEqual(@as(usize, 0), TestAdapter.liveLeaseCount());
    try expectRejected(plan.validate(allocator));
    try expectRejected(binder.validateLiveReceipts(receipt_owner.receipts));
    try expectRegular(output_path);
    try expectSealedJson(allocator, profile_path);
    try expectSealedJson(allocator, candidate_path);

    const parent_lease = try executor.coldOpenAndRetain(
        allocator,
        allocator,
        built,
        1,
        "root",
    );
    defer parent_lease.deinit();
    try parent_lease.validate();
    try std.testing.expectEqual(@as(usize, 1), worker.leases.count());
    try std.testing.expectEqual(@as(usize, 1), TestAdapter.liveLeaseCount());
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.stage_manifest,
        parent_lease.stage_manifest_ref.kind,
    );
    try std.testing.expectEqual(@as(u16, 1), parent_lease.stage_manifest_ref.schema_version);
    try executor.closeRetainedParent(allocator, parent_lease);
    try std.testing.expectEqual(@as(usize, 0), worker.leases.count());
    try std.testing.expectEqual(@as(usize, 0), TestAdapter.liveLeaseCount());
    try expectRejected(parent_lease.validate());
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

fn expectRegular(path: []const u8) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    try std.testing.expectEqual(std.fs.File.Kind.file, stat.kind);
}

fn expectMissing(path: []const u8) !void {
    var file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    file.close();
    return error.ExpectedMissingLiveBuildOutputV2;
}

fn expectSealedJson(
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(
        protocol.Json,
        allocator,
        bytes,
        .{ .parse_numbers = true },
    );
    defer parsed.deinit();
    const object = try protocol.objectValue(parsed.value);
    try protocol.validateSeal(allocator, object);
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedCampaignLiveBuildRejectionV2;
}
