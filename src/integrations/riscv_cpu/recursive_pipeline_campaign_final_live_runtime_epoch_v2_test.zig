const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import(
    "recursive_pipeline_campaign_final_live_runtime_epoch_v2.zig",
);
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");
const test_adapter_mod = @import(
    "recursive_pipeline_campaign_final_live_build_test_support_v2.zig",
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
const Provider = Lifecycle.ReplayProviderV4;
const TestAdapter = test_adapter_mod.AdapterV2(Provider);
const TestWorker = worker_mod.Worker(TestAdapter);
const TestDriver = driver_mod.DriverFor(
    Lifecycle.ImmutableSessionV4,
    TestAdapter,
);
const Epoch = subject.OwnerFor(
    TestWorker,
    TestDriver,
    Lifecycle,
    Provider,
);

test "campaign final runtime epoch requires exact installed session and store" {
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

    std.testing.refAllDecls(Epoch);
    try std.testing.expect(Epoch.available);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(subject.EXACT_INSTALLED_SESSION_POINTER_REQUIRED);
    try std.testing.expect(
        subject.WORKER_AND_LEASES_DESTROYED_BEFORE_LIFECYCLE,
    );

    const session = try final.immutableSession();
    try Provider.requireInstalledSession(session);
    var copied_session = session.*;
    try std.testing.expectError(
        error.CampaignWorkerSessionNotInstalledV4,
        Provider.requireInstalledSession(&copied_session),
    );
    try std.testing.expectError(
        error.CampaignFinalLiveRuntimeEpochMismatchV2,
        Epoch.init(
            allocator,
            allocator,
            "/fixture-store-root-must-not-match",
            final,
        ),
    );

    const epoch = try Epoch.init(allocator, allocator, root, final);
    defer epoch.deinit();
    try epoch.validate(allocator);
    try std.testing.expect(epoch.session == session);
    try std.testing.expect(epoch.driverView().session == session);
    const exact_session = epoch.session;
    epoch.session = &copied_session;
    try std.testing.expectError(
        error.CampaignFinalLiveRuntimeEpochMismatchV2,
        epoch.validate(allocator),
    );
    epoch.session = exact_session;
    try epoch.validate(allocator);
}

test "campaign final runtime epoch destroys retained leases before lifecycle" {
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

    var epoch: ?*Epoch = try Epoch.init(allocator, allocator, root, final);
    defer if (epoch) |value| value.deinit();
    try std.testing.expectEqual(@as(usize, 0), TestAdapter.liveLeaseCount());
    var retained = try fixture_support.coldOpenAndRetainAtCount(
        TestWorker,
        epoch.?.workerView(),
        allocator,
        &fixture.rows[0],
        fixture.rows[0].stage_manifest_ref,
        1,
    );
    defer retained.deinit();
    try std.testing.expectEqual(@as(usize, 1), TestAdapter.liveLeaseCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        epoch.?.workerView().leases.count(),
    );

    epoch.?.deinit();
    epoch = null;
    try std.testing.expectEqual(@as(usize, 0), TestAdapter.liveLeaseCount());
    try std.testing.expect(Provider.isInstalled());
    try final.validate(allocator);
    try Provider.requireInstalledSession(try final.immutableSession());
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
