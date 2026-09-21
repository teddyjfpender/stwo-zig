const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");
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
const BaseAdapter = fixture_support.AdapterV4(Lifecycle.ReplayProviderV4);

/// Driver-only fixture surface. It deliberately cannot build or activate a
/// route; validation delegates to the exact Stage-102 adapter codec and typed
/// lease surface already exercised by the sealed lifecycle.
pub const DriverAdapterV4 = struct {
    pub const available = false;
    pub const LeasePayload = BaseAdapter.LeasePayload;

    pub fn acceptsNodeAdapter(value: []const u8) bool {
        return BaseAdapter.acceptsNodeAdapter(value);
    }

    pub fn describe(
        stage_kind: artifact_store.StageKindV1,
        stage_schema_version: u16,
    ) !protocol.StageDescription {
        return BaseAdapter.describe(stage_kind, stage_schema_version);
    }

    pub fn buildOutputWithExecutionAndLeases(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.ExecutionKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
        _: []const *const LeasePayload,
    ) ![]u8 {
        return error.CampaignFinalDriverFixtureBuildUnavailableV4;
    }

    pub fn coldOpenLease(
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        bytes: []const u8,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        return BaseAdapter.coldOpenLease(
            allocator,
            store,
            bytes,
            node,
            semantic,
            ordered_inputs,
        );
    }

    pub fn deinitLeasePayload(
        value: *LeasePayload,
        allocator: std.mem.Allocator,
    ) void {
        BaseAdapter.deinitLeasePayload(value, allocator);
    }
};

pub const Driver = driver_mod.DriverFor(
    Lifecycle.ImmutableSessionV4,
    DriverAdapterV4,
);

test "campaign final driver consumes a sealed two-row role0 frontier" {
    try exerciseDriverFrontier(2, true);
}

test "campaign final driver preserves a non-power-of-two role0 frontier" {
    try exerciseDriverFrontier(3, false);
}

fn exerciseDriverFrontier(count: usize, test_mutations: bool) !void {
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

    const session = try final.immutableSession();
    const receipts = try allocator.alloc(
        driver_mod.CommittedStageV2,
        session.entries.len,
    );
    defer allocator.free(receipts);
    const dependency_refs = try allocator.alloc(
        [1]artifact_store.BlobRefV1,
        session.entries.len,
    );
    defer allocator.free(dependency_refs);
    for (receipts, dependency_refs, session.entries) |
        *receipt,
        *dependencies,
        *entry,
    | {
        dependencies.* = .{entry.admission.dependency_stage_manifest_ref};
        receipt.* = .{
            .node = entry.admission.node,
            .semantic = entry.admission.semantic,
            .execution = entry.admission.execution,
            .ordered_inputs = entry.admission.ordered_inputs,
            .output_ref = entry.output_ref,
            .stage_manifest_ref = entry.admission.stage_manifest_ref,
            .dependency_stage_manifest_refs = dependencies,
            .lease_id = entry.admission.node.node_id,
        };
    }

    const driver = try Driver.init(allocator, session);
    try driver.validateRole0Frontier(allocator, &frontier, receipts);
    if (!test_mutations) return;

    std.mem.swap(
        driver_mod.CommittedStageV2,
        &receipts[0],
        &receipts[receipts.len - 1],
    );
    try expectRejected(driver.validateRole0Frontier(
        allocator,
        &frontier,
        receipts,
    ));
    std.mem.swap(
        driver_mod.CommittedStageV2,
        &receipts[0],
        &receipts[receipts.len - 1],
    );

    const saved_manifest = receipts[0].stage_manifest_ref;
    receipts[0].stage_manifest_ref = receipts[1].stage_manifest_ref;
    try expectRejected(driver.validateRole0Frontier(
        allocator,
        &frontier,
        receipts,
    ));
    receipts[0].stage_manifest_ref = saved_manifest;

    const saved_node = receipts[0].node;
    var node_copy = saved_node.*;
    try std.testing.expect(saved_node != &node_copy);
    receipts[0].node = &node_copy;
    try expectRejected(driver.validateRole0Frontier(
        allocator,
        &frontier,
        receipts,
    ));
    receipts[0].node = saved_node;
    try driver.validateRole0Frontier(allocator, &frontier, receipts);
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedCampaignFinalDriverRejectionV4;
}
