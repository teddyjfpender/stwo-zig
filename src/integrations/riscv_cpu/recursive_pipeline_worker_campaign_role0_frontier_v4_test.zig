const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject =
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
const Frontier = subject.FrontierFor(Bridge);

test "role0 final frontier binds a two-row CAS inventory and policy" {
    try exerciseFrontier(2);
}

test "role0 final frontier preserves non-power-of-two three-row order" {
    try exerciseFrontier(3);
}

fn exerciseFrontier(count: usize) !void {
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
        subject.ExpectedPublicationV4,
        fixture.rows.len,
    );
    defer allocator.free(expected);
    for (expected, fixture.rows) |*publication, row| {
        publication.* = .{
            .output_ref = row.output_ref,
            .stage_manifest_ref = row.stage_manifest_ref.?,
        };
    }

    std.mem.swap(
        subject.ExpectedPublicationV4,
        &expected[0],
        &expected[expected.len - 1],
    );
    try expectRejected(Frontier.OwnedFrontierV4.init(
        allocator,
        allocator,
        bridge,
        &fixture.policy,
        expected,
    ));
    std.mem.swap(
        subject.ExpectedPublicationV4,
        &expected[0],
        &expected[expected.len - 1],
    );

    const saved_second = expected[1];
    expected[1] = expected[0];
    try expectRejected(Frontier.OwnedFrontierV4.init(
        allocator,
        allocator,
        bridge,
        &fixture.policy,
        expected,
    ));
    expected[1] = saved_second;
    expected[0].stage_manifest_ref = expected[1].stage_manifest_ref;
    try expectRejected(Frontier.OwnedFrontierV4.init(
        allocator,
        allocator,
        bridge,
        &fixture.policy,
        expected,
    ));
    expected[0].stage_manifest_ref = fixture.rows[0].stage_manifest_ref.?;

    var policy_copy = fixture.policy;
    try expectRejected(Frontier.OwnedFrontierV4.init(
        allocator,
        allocator,
        bridge,
        &policy_copy,
        expected,
    ));

    var frontier = try Frontier.OwnedFrontierV4.init(
        allocator,
        allocator,
        bridge,
        &fixture.policy,
        expected,
    );
    defer frontier.deinit();
    try frontier.validate(allocator);
    try std.testing.expectEqual(fixture.rows.len, frontier.orderedRows().len);
    for (frontier.orderedRows(), 0..) |row, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), row.coordinate);
        try std.testing.expectEqualDeep(expected[index], row.publication);
        try std.testing.expect(row.role0.admission.execution !=
            &fixture.rows[index].execution);
    }
    frontier.rows[0].coordinate = 1;
    try expectRejected(frontier.validate(allocator));
    frontier.rows[0].coordinate = 0;
    try frontier.validate(allocator);
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedFixtureRejectionV4;
}
