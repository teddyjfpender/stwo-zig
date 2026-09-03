const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject =
    @import("recursive_pipeline_worker_campaign_final_session_bridge_v4.zig");
const lifecycle_mod =
    @import("recursive_pipeline_worker_campaign_stage102_final_lifecycle_v4.zig");
const fixture_mod =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig");
const fixture_support =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

const Assembly = fixture_support.FinalLifecycleAssemblyV4(
    fixture_mod.FixtureAuthorityV4,
);
pub const Lifecycle = lifecycle_mod.SupervisorFor(Assembly);
pub const FinalWorker = struct {
    pub const Role0BackendV4 = struct {
        pub const AuthorityV4 = fixture_mod.FixtureAuthorityV4;
    };
    pub const Role0InventoryOpenerV4 = Lifecycle.Role0OpenerV4;
    pub const ValidatedAssemblyV2 = struct {
        role0_authority: *const fixture_mod.FixtureAuthorityV4,
        final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,

        pub fn validate(self: *const @This()) !void {
            const namespace = self.final_remint.shape.campaign_namespace_sha256;
            try self.final_remint.validateAgainstCampaign(namespace);
            try self.role0_authority.validate(
                std.testing.allocator,
                namespace,
            );
        }

        pub fn finalRemint(
            self: *const @This(),
        ) *const final_mod.CampaignFinalRemintAuthorityV2 {
            return self.final_remint;
        }
    };
};
pub const Bridge = subject.BridgeFor(Lifecycle, FinalWorker);

test "final worker bridge exact-matches immutable Stage102 authority and role0 admission" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try fixture_mod.FixtureV4.init(allocator, &store, 2);
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
    var final: ?*Lifecycle.OwnedFinalSessionV4 =
        try sealed.?.installImmutable(allocator);
    sealed = null;
    defer if (final) |value| value.deinit();

    const assembly = FinalWorker.ValidatedAssemblyV2{
        .role0_authority = &fixture.authority,
        .final_remint = &fixture.final_remint,
    };
    const bridge = try Bridge.init(final.?, &assembly, allocator);
    try bridge.validate(allocator);
    for (fixture.rows) |row| {
        const view = try bridge.role0ForOutput(allocator, row.output_ref);
        try view.validate();
        try std.testing.expect(view.session == try final.?.immutableSession());
        try std.testing.expect(view.admission.semantic != &row.semantic);
        try std.testing.expect(view.admission.execution != &row.execution);
        try std.testing.expectEqualDeep(row.semantic, view.admission.semantic.*);
        try std.testing.expectEqualDeep(row.execution, view.admission.execution.*);
        try std.testing.expectEqualDeep(
            row.stage_manifest_ref.?,
            view.admission.stage_manifest_ref,
        );
    }

    var authority_copy = fixture.authority;
    const wrong_authority = FinalWorker.ValidatedAssemblyV2{
        .role0_authority = &authority_copy,
        .final_remint = &fixture.final_remint,
    };
    try expectRejected(Bridge.init(final.?, &wrong_authority, allocator));

    var final_copy = fixture.final_remint;
    const wrong_final = FinalWorker.ValidatedAssemblyV2{
        .role0_authority = &fixture.authority,
        .final_remint = &final_copy,
    };
    try expectRejected(Bridge.init(final.?, &wrong_final, allocator));
    try expectRejected(bridge.role0ForOutput(
        allocator,
        fixture.rows[0].ordered_inputs[0].blob,
    ));
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedFixtureRejectionV4;
}
