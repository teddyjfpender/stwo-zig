const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const air = @import("recursion/air/segment_public_outer_air_v2.zig");
const components = @import("recursion/segment_public_outer_components_v2.zig");
const public_source = @import("recursion/segment_public_outer_source_v2.zig");
const fixture_support = @import("recursion/segment_public_outer_test_support.zig");
const relation = @import("air/lang/relation.zig");
const manifest_mod = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("recursion/air/segment_outer_typed_catalog_v2.zig");
const universal_roster = @import("recursion/air/universal_roster.zig");
const universal = @import("recursion/air/universal_challenges.zig");
const range_bridge = @import("recursion/air/range_check_8_8_bridge.zig");
const boundary_authority = @import("recursion/segment_leaf_outer_authority_v2.zig");

test "V2 public relay AIR declarations instantiate" {
    std.testing.refAllDeclsRecursive(air.PublicationHeader);
    std.testing.refAllDeclsRecursive(air.NativePublicSums);
    std.testing.refAllDeclsRecursive(air.PublicationSeal);
    std.testing.refAllDeclsRecursive(air.StatementBoundary);
    std.testing.refAllDeclsRecursive(air.NativeChallenges);
    std.testing.refAllDeclsRecursive(air.ControlRelay);
    std.testing.refAllDeclsRecursive(components.Claims);
    std.testing.refAllDeclsRecursive(components.Components);
    std.testing.refAllDeclsRecursive(components.Source);
    std.testing.refAllDeclsRecursive(components.Workspace);
    try std.testing.expectEqual(@as(usize, 0), components.HOT_HEAP_ALLOCATIONS);
    try std.testing.expect(components.TREE_WRITES_FAIL_BEFORE_FIRST_WRITE);
}

test "V2 public relay AIR identities and catalog handoff are exact" {
    const Airs = .{
        air.PublicationHeader,
        air.NativePublicSums,
        air.PublicationSeal,
        air.StatementBoundary,
        air.NativeChallenges,
        air.ControlRelay,
    };
    try std.testing.expectEqual(@as(usize, 6), air.COMPONENT_OVERRIDE_TABLE_V2.len);
    inline for (Airs, 0..) |Air, index| {
        const identity = if (@hasDecl(Air, "semanticIdentity"))
            (try Air.semanticIdentity(std.testing.allocator)).bytes
        else
            try Air.computeSemanticDigest(std.testing.allocator);
        try std.testing.expectEqualSlices(u8, &Air.SEMANTIC_DIGEST, &identity);
        const item = air.COMPONENT_OVERRIDE_TABLE_V2[index];
        try std.testing.expectEqual(@as(u8, 12 + index), item.component_index);
        try std.testing.expectEqual(
            @as(u16, @intCast(Air.PREPROCESSED_COLUMN_COUNT)),
            item.preprocessed_columns,
        );
        try std.testing.expectEqual(
            @as(u16, @intCast(Air.PHYSICAL_MAIN_COLUMN_COUNT)),
            item.main_columns,
        );
        try std.testing.expectEqual(
            @as(u16, @intCast(Air.INTERACTION_COLUMN_COUNT)),
            item.interaction_columns,
        );
        try std.testing.expectEqual(
            @as(u16, @intCast(Air.RELATION_EVENT_COUNT)),
            item.relation_events,
        );
        try std.testing.expectEqualSlices(
            u8,
            &Air.SEMANTIC_DIGEST,
            &item.semantic_digest,
        );
    }
}

test "V2 public rows 12 through 17 fill all trees and bind exact claims" {
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = measured.allocator();
    var fixture = try fixture_support.Fixture.init(allocator);
    defer fixture.deinit();
    const prepared = try public_source.preflight(fixture.inputs());
    const manifest = try buildManifest(&fixture, &prepared);

    var owner = try components.Source.init(allocator, &prepared, &manifest);
    defer owner.deinit();
    try std.testing.expect(!owner.productionReady());
    var workspace = try components.Workspace.init(allocator, &prepared);
    defer workspace.deinit();
    try workspace.prepare(
        &owner,
        &prepared,
        &manifest,
        fixture.inputs(),
    );

    var tree0 = try OwnedTree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer tree0.deinit();
    var tree1 = try OwnedTree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer tree1.deinit();
    var tree2 = try OwnedTree.init(
        allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer tree2.deinit();
    tree0.fillSentinel();
    tree1.fillSentinel();
    tree2.fillSentinel();

    const relations = universal.UniversalRelations.dummy();
    const allocations_before = measured.alloc_index;
    try components.fillPreprocessedInto(
        &owner,
        &workspace,
        &prepared,
        &manifest,
        tree0.columns,
    );
    try components.fillMainInto(
        &owner,
        &workspace,
        &prepared,
        &manifest,
        tree1.columns,
    );
    const claims = try components.fillInteractionInto(
        &owner,
        &workspace,
        &prepared,
        &manifest,
        &relations,
        tree2.columns,
    );
    try std.testing.expectEqual(allocations_before, measured.alloc_index);
    try workspace.validateAgainst(&prepared);

    const concrete = try owner.initComponents(
        &prepared,
        &manifest,
        &relations,
        claims,
    );
    var gate = try manifest_mod.ProofGate.init(&manifest);
    gate.count = components.FIRST_ROW;
    try concrete.appendToGate(&manifest, &gate);
    try std.testing.expectEqual(
        @as(u8, components.FIRST_ROW + components.ROW_COUNT),
        gate.count,
    );
    var claim_vector = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bindInto(&claim_vector);
    const public_mask = ((@as(u64, 1) << components.ROW_COUNT) - 1) <<
        components.FIRST_ROW;
    try std.testing.expectEqual(public_mask, claim_vector.bound_mask);

    const audits = try components.auditInteractionDomains(
        allocator,
        &owner,
        &workspace,
        &prepared,
        &relations,
        claims,
        null,
    );
    for (audits, claims.asArray()) |audit, claim| {
        try std.testing.expect(audit.total.eql(claim));
        try std.testing.expect(audit.values[
            @intFromEnum(relation.Domain.range_check_8_8)
        ].isZero());
    }

    tree0.fillSentinel();
    const before = tree0.digest();
    try std.testing.expectError(
        error.DestinationColumnCountMismatch,
        components.fillPreprocessedInto(
            &owner,
            &workspace,
            &prepared,
            &manifest,
            tree0.columns[0 .. tree0.columns.len - 1],
        ),
    );
    try std.testing.expectEqual(before, tree0.digest());
}

fn buildManifest(
    fixture: *const fixture_support.Fixture,
    prepared: *const public_source.PreparedV2,
) !manifest_mod.Manifest {
    const boundary = try boundary_authority.OuterManifestV2.init(
        fixture.source_prepared.manifest,
    );
    var log_sizes = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    log_sizes[0] = 5;
    log_sizes[1] = 6;
    log_sizes[5] = 7;
    log_sizes[11] = boundary.components[0].trace_log_size;
    for (prepared.manifest.log_sizes, 0..) |log_size, index|
        log_sizes[components.FIRST_ROW + index] = log_size;
    log_sizes[@intFromEnum(universal_roster.Component.poseidon2)] = 11;
    log_sizes[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    const catalog = try catalog_mod.build(log_sizes, boundary.components);
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = prepared.manifest.identity,
        .boundary_manifest_id = boundary.identity,
        .boundary_authority_sha_id = boundary.authority_sha_id,
    });
}

const OwnedTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !OwnedTree {
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
            manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
            else => return error.InvalidTree,
        };
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        var allocated: usize = 0;
        errdefer for (columns[0..allocated]) |column| allocator.free(column);
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
                manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
                manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
                else => unreachable,
            };
            const local_count: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..local_count]) |*column| {
                column.* = try allocator.alloc(M31, size);
                allocated += 1;
            }
        }
        if (allocated != count) return error.InvalidTree;
        return .{ .allocator = allocator, .columns = columns };
    }

    fn deinit(self: *OwnedTree) void {
        for (self.columns) |column| self.allocator.free(column);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    fn fillSentinel(self: *OwnedTree) void {
        for (self.columns) |column|
            @memset(column, M31.fromCanonical(0x5a5a));
    }

    fn digest(self: *const OwnedTree) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for (self.columns) |column| for (column) |value| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, value.toU32(), .little);
            hash.update(&encoded);
        };
        return hash.finalResult();
    }
};

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
