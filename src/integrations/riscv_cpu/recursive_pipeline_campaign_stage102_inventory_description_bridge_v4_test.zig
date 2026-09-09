const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const bridge_mod =
    @import("recursive_pipeline_campaign_stage102_inventory_description_bridge_v4.zig");
const description_mod =
    @import("recursive_pipeline_campaign_stage102_inventory_description_v4.zig");
const lifecycle_mod =
    @import("recursive_pipeline_worker_campaign_stage102_final_lifecycle_v4.zig");
const fixture_mod =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig");
const fixture_support =
    @import("recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

const Assembly = fixture_support.FinalLifecycleAssemblyV4(
    fixture_mod.FixtureAuthorityV4,
);
const Lifecycle = lifecycle_mod.SupervisorFor(Assembly);
const Bridge = bridge_mod.BridgeFor(Lifecycle);

test "final Stage102 lifecycle emits deterministic two and three row receipts" {
    try exerciseDeterministicReceipt(2);
    try exerciseDeterministicReceipt(3);
}

test "final Stage102 receipt output remains intact when live validation fails" {
    const allocator = std.testing.allocator;
    const fixture = try InstalledFixtureV4.init(allocator, 3);
    defer fixture.deinit();

    try fixture.temporary.dir.makeDir("receipt-failure");
    var output_dir = try fixture.temporary.dir.openDir(
        "receipt-failure",
        .{ .iterate = true },
    );
    defer output_dir.close();
    const retained = "caller-owned-prior-receipt\n";
    {
        const output = try output_dir.createFile(
            "stage102.json",
            .{ .exclusive = true },
        );
        defer output.close();
        try output.writeAll(retained);
    }

    const session = try fixture.final.immutableSession();
    const entry = @constCast(&session.entries[0]);
    entry.output_ref.sha256[0] ^= 1;
    defer entry.output_ref.sha256[0] ^= 1;
    try expectRejected(Bridge.writeCanonicalFileAtomic(
        allocator,
        fixture.final,
        output_dir,
        "stage102.json",
    ));

    const observed = try output_dir.readFileAlloc(
        allocator,
        "stage102.json",
        1024,
    );
    defer allocator.free(observed);
    try std.testing.expectEqualSlices(u8, retained, observed);
    var entries = output_dir.iterate();
    var entry_count: usize = 0;
    while (try entries.next()) |_| entry_count += 1;
    try std.testing.expectEqual(@as(usize, 1), entry_count);
}

test "final Stage102 receipt bridge stays unrouteable and owner stays opaque" {
    try std.testing.expect(!bridge_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!bridge_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!bridge_mod.SERIALIZABLE_FINAL_SESSION);
    try std.testing.expect(bridge_mod.CALLER_OWNS_OUTPUT_PATH);
    try std.testing.expect(bridge_mod.VALIDATE_BEFORE_OPEN);
    try std.testing.expect(bridge_mod.ATOMIC_REPLACE);
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        try std.testing.expect(!@hasDecl(Lifecycle.OwnedFinalSessionV4, name));
}

fn exerciseDeterministicReceipt(count: usize) !void {
    const allocator = std.testing.allocator;
    const fixture = try InstalledFixtureV4.init(allocator, count);
    defer fixture.deinit();

    // Exercise the lifecycle's independent CAS-backed cold opener first. The
    // durable receipt remains byte-identical before and after live leases are
    // minted because those capabilities have no serialized projection.
    const before = try Bridge.encodeCanonicalJsonAlloc(
        allocator,
        fixture.final,
    );
    defer allocator.free(before);
    for (fixture.fixture.rows) |row| {
        const opened = try fixture.final.role0ForOutput(row.output_ref);
        try opened.validate();
    }
    const after = try Bridge.encodeCanonicalJsonAlloc(
        allocator,
        fixture.final,
    );
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);

    var parsed = try std.json.parseFromSlice(
        protocol.Json,
        allocator,
        after,
        .{},
    );
    defer parsed.deinit();
    const root = try protocol.objectValue(parsed.value);
    try protocol.validateSeal(allocator, root);
    try std.testing.expectEqualStrings(
        description_mod.FORMAT,
        try protocol.stringField(root, "format"),
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(count)),
        try protocol.positiveField(u64, root, "real_leaf_count"),
    );
    const rows = root.get("rows") orelse return error.MissingFixtureRowsV4;
    if (rows != .array or rows.array.items.len != count)
        return error.InvalidFixtureRowsV4;
    inline for (.{
        "lease_id",
        "live_lease_selector",
        "admission",
        "proof_capture",
    }) |forbidden| try std.testing.expect(
        std.mem.indexOf(u8, after, forbidden) == null,
    );

    try fixture.temporary.dir.makeDir("receipt-success");
    var output_dir = try fixture.temporary.dir.openDir(
        "receipt-success",
        .{},
    );
    defer output_dir.close();
    try Bridge.writeCanonicalFileAtomic(
        allocator,
        fixture.final,
        output_dir,
        "stage102.json",
    );
    const persisted = try output_dir.readFileAlloc(
        allocator,
        "stage102.json",
        64 * 1024 * 1024,
    );
    defer allocator.free(persisted);
    try std.testing.expectEqualSlices(u8, after, persisted);
}

const InstalledFixtureV4 = struct {
    allocator: std.mem.Allocator,
    temporary: std.testing.TmpDir,
    root: []u8,
    store: artifact_store.Store,
    fixture: *fixture_mod.FixtureV4,
    final: *Lifecycle.OwnedFinalSessionV4,

    fn init(
        allocator: std.mem.Allocator,
        count: usize,
    ) !*InstalledFixtureV4 {
        const self = try allocator.create(InstalledFixtureV4);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.temporary = std.testing.tmpDir(.{});
        errdefer self.temporary.cleanup();
        self.root = try self.temporary.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(self.root);
        self.store = try artifact_store.Store.openOrCreate(
            allocator,
            self.root,
            false,
        );
        errdefer self.store.deinit();
        self.fixture = try fixture_mod.FixtureV4.init(
            allocator,
            &self.store,
            count,
        );
        errdefer self.fixture.deinit();

        var building: ?*Lifecycle.OwnedBuildingV4 = try Lifecycle.begin(
            allocator,
            allocator,
            &self.store,
            self.root,
            &self.fixture.authority,
            &self.fixture.policy,
        );
        defer if (building) |value| value.deinit();
        for (self.fixture.rows) |*row| {
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
        self.final = try sealed.?.installImmutable(allocator);
        sealed = null;
        errdefer self.final.deinit();
        try self.final.validate(allocator);
        return self;
    }

    fn deinit(self: *InstalledFixtureV4) void {
        const allocator = self.allocator;
        self.final.deinit();
        self.fixture.deinit();
        self.store.deinit();
        allocator.free(self.root);
        self.temporary.cleanup();
        self.* = undefined;
        allocator.destroy(self);
    }
};

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedFixtureRejectionV4;
}
