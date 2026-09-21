const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

const subject =
    @import("recursive_pipeline_worker_campaign_stage102_final_lifecycle_v4.zig");
const fixture_mod =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig");
const fixture_support =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig");

const Assembly = fixture_support.FinalLifecycleAssemblyV4(
    fixture_mod.FixtureAuthorityV4,
);
const Supervisor = subject.SupervisorFor(Assembly);
const GateOnlyAssembly = fixture_support.GateOnlyFinalLifecycleAssemblyV4(
    fixture_mod.FixtureAuthorityV4,
);
const GateOnlySupervisor = subject.SupervisorFor(GateOnlyAssembly);

test "Stage102 final lifecycle quiesces live leases before immutable admission" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 2);
    defer fixture.deinit();

    var building: ?*Supervisor.OwnedBuildingV4 = try Supervisor.begin(
        allocator,
        allocator,
        &store,
        root,
        &fixture.authority,
        &fixture.policy,
    );
    defer if (building) |value| value.deinit();
    fixture.rows[0].stage_manifest_ref = try fixture_support.coldOpenAndClose(
        Supervisor.BuildWorkerV4,
        building.?.workerView(),
        allocator,
        &fixture.rows[0],
        null,
    );
    var retained = try fixture_support.coldOpenAndRetain(
        Supervisor.BuildWorkerV4,
        building.?.workerView(),
        allocator,
        &fixture.rows[1],
        null,
    );
    defer retained.deinit();
    fixture.rows[1].stage_manifest_ref = retained.stage_manifest_ref;
    try std.testing.expectEqual(
        @as(usize, 1),
        Supervisor.BuildAdapterV4.liveLeaseCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        try building.?.builderView().adoptedCount(),
    );

    var quiesced: ?*Supervisor.OwnedQuiescedV4 = try building.?.quiesce();
    building = null;
    defer if (quiesced) |value| value.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        Supervisor.BuildAdapterV4.liveLeaseCount(),
    );
    try std.testing.expect(!Supervisor.BuildProviderV4.isInstalled());

    var sealed: ?*Supervisor.OwnedSealedV4 = try quiesced.?.sealComplete(
        allocator,
    );
    quiesced = null;
    defer if (sealed) |value| value.deinit();
    var final: ?*Supervisor.OwnedFinalSessionV4 =
        try sealed.?.installImmutable(allocator);
    sealed = null;
    defer if (final) |value| value.deinit();
    try final.?.validate(allocator);
    try std.testing.expect(Supervisor.ReplayProviderV4.isInstalled());

    for (fixture.rows) |*row| {
        const view = try final.?.role0ForOutput(row.output_ref);
        try view.validate();
        try std.testing.expectEqualDeep(
            row.stage_manifest_ref.?,
            view.admission.stage_manifest_ref,
        );
        try std.testing.expect(view.final_remint == &fixture.final_remint);
        const duplicate = try final.?.role0ForOutput(row.output_ref);
        try std.testing.expect(duplicate.lease == view.lease);
    }
    try std.testing.expectEqual(
        fixture.rows.len,
        Supervisor.Role0OpenerV4.liveLeaseCount(),
    );
    try expectRejected(final.?.role0ForOutput(
        fixture.rows[0].ordered_inputs[0].blob,
    ));

    final.?.deinit();
    final = null;
    try std.testing.expectEqual(
        @as(usize, 0),
        Supervisor.Role0OpenerV4.liveLeaseCount(),
    );
    try std.testing.expect(!Supervisor.ReplayProviderV4.isInstalled());
}

test "Stage102 final lifecycle resumes an incomplete three-leaf seal atomically" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 3);
    defer fixture.deinit();

    var building: ?*Supervisor.OwnedBuildingV4 = try Supervisor.begin(
        allocator,
        allocator,
        &store,
        root,
        &fixture.authority,
        &fixture.policy,
    );
    defer if (building) |value| value.deinit();
    const last = fixture.rows.len - 1;
    fixture.rows[last].stage_manifest_ref = try fixture_support.coldOpenAndClose(
        Supervisor.BuildWorkerV4,
        building.?.workerView(),
        allocator,
        &fixture.rows[last],
        null,
    );
    var quiesced: ?*Supervisor.OwnedQuiescedV4 = try building.?.quiesce();
    building = null;
    defer if (quiesced) |value| value.deinit();
    try std.testing.expectError(
        error.CampaignStage102BuilderIncompleteV4,
        quiesced.?.sealComplete(allocator),
    );

    building = try quiesced.?.resumeBuilding(allocator);
    quiesced = null;
    var index: usize = 0;
    while (index < last) : (index += 1) {
        fixture.rows[index].stage_manifest_ref =
            try fixture_support.coldOpenAndClose(
                Supervisor.BuildWorkerV4,
                building.?.workerView(),
                allocator,
                &fixture.rows[index],
                null,
            );
    }
    try std.testing.expectEqual(
        fixture.rows.len,
        try building.?.builderView().adoptedCount(),
    );
    quiesced = try building.?.quiesce();
    building = null;
    var sealed: ?*Supervisor.OwnedSealedV4 = try quiesced.?.sealComplete(
        allocator,
    );
    quiesced = null;
    defer if (sealed) |value| value.deinit();
    var final: ?*Supervisor.OwnedFinalSessionV4 =
        try sealed.?.installImmutable(allocator);
    sealed = null;
    defer if (final) |value| value.deinit();
    try final.?.validate(allocator);
    for (fixture.rows) |row| {
        const view = try final.?.role0ForOutput(row.output_ref);
        try view.validate();
    }
}

test "Stage102 genuine gate bypasses only release checks across immutable install" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 2);
    defer fixture.deinit();

    try std.testing.expect(!GateOnlySupervisor.available);
    try std.testing.expectError(
        error.CampaignStage102FinalLifecycleUnavailableV4,
        GateOnlySupervisor.begin(
            allocator,
            allocator,
            &store,
            root,
            &fixture.authority,
            &fixture.policy,
        ),
    );
    var building: ?*GateOnlySupervisor.OwnedBuildingV4 =
        try GateOnlySupervisor.beginForGenuineGate(
            allocator,
            allocator,
            &store,
            root,
            &fixture.authority,
            &fixture.policy,
        );
    defer if (building) |value| value.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const empty_payload = protocol.jsonObject(arena);
    try std.testing.expectError(
        error.CampaignStage102FinalLifecycleMismatchV4,
        building.?.buildForGenuineGate(arena, .{
            .sequence = 0,
            .action = .cold_open,
            .payload = empty_payload,
        }),
    );
    try std.testing.expectError(
        error.CampaignStage102FinalLifecycleMismatchV4,
        building.?.adoptForGenuineGate(arena, .{
            .sequence = 1,
            .action = .build,
            .payload = empty_payload,
        }),
    );

    for (fixture.rows) |*row| {
        row.stage_manifest_ref =
            try fixture_support.coldOpenAndCloseForGenuineGate(
                GateOnlySupervisor.BuildWorkerV4,
                building.?.workerView(),
                allocator,
                row,
                null,
            );
    }
    try std.testing.expectEqual(
        fixture.rows.len,
        try building.?.builderView().adoptedCount(),
    );
    var quiesced: ?*GateOnlySupervisor.OwnedQuiescedV4 =
        try building.?.quiesceForGenuineGate();
    building = null;
    defer if (quiesced) |value| value.deinit();
    try std.testing.expect(!GateOnlySupervisor.BuildProviderV4.isInstalled());

    var sealed: ?*GateOnlySupervisor.OwnedSealedV4 =
        try quiesced.?.sealCompleteForGenuineGate(allocator);
    quiesced = null;
    defer if (sealed) |value| value.deinit();
    var final: ?*GateOnlySupervisor.OwnedFinalSessionV4 =
        try sealed.?.installImmutableForGenuineGate(allocator);
    sealed = null;
    defer if (final) |value| value.deinit();
    try final.?.validate(allocator);

    for (fixture.rows) |row| {
        try std.testing.expectError(
            error.CampaignStage102FinalLifecycleUnavailableV4,
            final.?.role0ForOutput(row.output_ref),
        );
        const view = try final.?.role0ForOutputForGenuineGate(row.output_ref);
        try view.validate();
        try std.testing.expect(view.session == try final.?.immutableSession());
        try std.testing.expectEqualDeep(
            row.stage_manifest_ref.?,
            view.admission.stage_manifest_ref,
        );
    }
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedFixtureRejectionV4;
}
