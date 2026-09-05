const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import(
    "recursive_pipeline_campaign_final_assembly_bound_runtime_v2.zig",
);
const epoch_mod = @import(
    "recursive_pipeline_campaign_final_live_runtime_epoch_v2.zig",
);
const runtime_mod = @import(
    "recursive_pipeline_campaign_final_owned_live_runtime_v2.zig",
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
const Epoch = epoch_mod.OwnerFor(
    TestWorker,
    TestDriver,
    Lifecycle,
    Provider,
);
const Runtime = runtime_mod.OwnerFor(Epoch, Lifecycle);

const ActiveSources = struct {
    identity: [32]u8,
};

const Assembly = struct {
    base: *const bridge_fixture.FinalWorker.ValidatedAssemblyV2,
    role0_authority: *const fixture_mod.FixtureAuthorityV4,
    active_sources: *const ActiveSources,

    pub fn validate(self: *const Assembly) !void {
        try self.base.validate();
        const final_remint = self.base.finalRemint();
        const namespace = final_remint.shape.campaign_namespace_sha256;
        if (self.role0_authority != self.base.role0_authority or
            (try Provider.authorityForCampaign(namespace)) !=
                self.role0_authority or
            (try Provider.finalRemintForCampaign(namespace)) != final_remint)
        {
            return error.CampaignFinalAssemblyFixtureMismatchV2;
        }
    }

    pub fn finalRemint(
        self: *const Assembly,
    ) *const @import(
        "recursive_pipeline_campaign_final_remint_v2.zig",
    ).CampaignFinalRemintAuthorityV2 {
        return self.base.finalRemint();
    }
};

const Owner = subject.OwnerFor(Runtime, Assembly, ActiveSources);

test "campaign runtime guard exact-binds assembly and active sources" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 2);
    defer fixture.deinit();
    var lifecycle: ?*Lifecycle.OwnedFinalSessionV4 =
        try installImmutableStage102(allocator, &store, root, fixture);
    defer if (lifecycle) |value| value.deinit();
    var runtime: ?*Runtime = try Runtime.init(
        allocator,
        allocator,
        root,
        lifecycle.?,
    );
    lifecycle = null;
    defer if (runtime) |value| value.deinit();

    const base = bridge_fixture.FinalWorker.ValidatedAssemblyV2{
        .role0_authority = &fixture.authority,
        .final_remint = &fixture.final_remint,
    };
    const active_sources = ActiveSources{ .identity = digest(1) };
    var active_sources_copy = active_sources;
    var assembly = Assembly{
        .base = &base,
        .role0_authority = &fixture.authority,
        .active_sources = &active_sources,
    };
    try std.testing.expectError(
        error.CampaignFinalAssemblyBoundRuntimeMismatchV2,
        Owner.init(
            allocator,
            allocator,
            runtime.?,
            &assembly,
            &active_sources_copy,
        ),
    );
    try runtime.?.validate(allocator);

    var owner: ?*Owner = try Owner.init(
        allocator,
        allocator,
        runtime.?,
        &assembly,
        &active_sources,
    );
    runtime = null;
    defer if (owner) |value| value.deinit();
    std.testing.refAllDecls(Owner);
    try std.testing.expect(Owner.available);
    try owner.?.validate(allocator);

    var assembly_copy = assembly;
    owner.?.assembly = &assembly_copy;
    try std.testing.expectError(
        error.CampaignFinalAssemblyBoundRuntimeMismatchV2,
        owner.?.validate(allocator),
    );
    owner.?.assembly = &assembly;
    owner.?.active_sources = &active_sources_copy;
    try std.testing.expectError(
        error.CampaignFinalAssemblyBoundRuntimeMismatchV2,
        owner.?.validate(allocator),
    );
    owner.?.active_sources = &active_sources;

    var authority_copy = fixture.authority;
    assembly.role0_authority = &authority_copy;
    try expectRejected(owner.?.validate(allocator));
    assembly.role0_authority = &fixture.authority;
    try owner.?.validate(allocator);
}

test "campaign assembly guard tears down leases before installed authority" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 2);
    defer fixture.deinit();
    var lifecycle: ?*Lifecycle.OwnedFinalSessionV4 =
        try installImmutableStage102(allocator, &store, root, fixture);
    defer if (lifecycle) |value| value.deinit();
    const runtime = try Runtime.init(
        allocator,
        allocator,
        root,
        lifecycle.?,
    );
    lifecycle = null;
    const base = bridge_fixture.FinalWorker.ValidatedAssemblyV2{
        .role0_authority = &fixture.authority,
        .final_remint = &fixture.final_remint,
    };
    const active_sources = ActiveSources{ .identity = digest(2) };
    const assembly = Assembly{
        .base = &base,
        .role0_authority = &fixture.authority,
        .active_sources = &active_sources,
    };
    var owner: ?*Owner = try Owner.init(
        allocator,
        allocator,
        runtime,
        &assembly,
        &active_sources,
    );
    defer if (owner) |value| value.deinit();
    var retained = try fixture_support.coldOpenAndRetainAtCount(
        TestWorker,
        owner.?.runtimeView().epochView().workerView(),
        allocator,
        &fixture.rows[0],
        fixture.rows[0].stage_manifest_ref,
        1,
    );
    defer retained.deinit();
    try std.testing.expectEqual(@as(usize, 1), TestAdapter.liveLeaseCount());
    try std.testing.expect(Provider.isInstalled());
    owner.?.deinit();
    owner = null;
    try std.testing.expectEqual(@as(usize, 0), TestAdapter.liveLeaseCount());
    try std.testing.expect(!Provider.isInstalled());
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
    const lifecycle = try sealed.?.installImmutable(allocator);
    sealed = null;
    return lifecycle;
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @truncate(index));
    return result;
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedCampaignFinalAssemblyRejectionV2;
}
