//! Isolated compile/test root for the segment transcript outer-proof source.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;

const source = @import("recursion/segment_transcript_outer_source.zig");
const fixed_wire = @import("recursion/fixed_wire.zig");
const fixed_profile = @import("recursion/fixed_profile.zig");
const channel = @import("recursion/poseidon2_channel.zig");
const protocol = @import("recursion/protocol.zig");
const transcript = @import("recursion/transcript_program.zig");
const segment_witness = @import("recursion/segment_transcript_witness.zig");
const air = @import("recursion/air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const roster = air.universal_roster;
const schedule = air.verifier_schedule;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;

const dimensions = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 2,
    .sampled_value_count = 3,
    .queried_value_count = 12,
    .trace_path_count = 12,
    .fri_layer_count = 1,
    .query_count = 3,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};

test "segment transcript outer source instantiates its fixed profile" {
    const SourceType = source.Source(dimensions);
    _ = SourceType;
    _ = source.Parameters.segmentLeaf();
    try std.testing.expectError(
        error.SourceLogSizeMismatch,
        source.PowLogSizes.init(source.MIN_LOG_SIZE - 1, source.MIN_LOG_SIZE),
    );
}

const Wire = fixed_wire.FixedStarkProofWire(dimensions);
const Prepared = segment_witness.Prepared(dimensions);
const Source = source.Source(dimensions);

test "segment transcript outer source fills and binds universal rows 0 through 9" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var authority = try Source.init(
        std.testing.allocator,
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        try source.PowLogSizes.init(4, 4),
    );
    defer authority.deinit();
    var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
    authority.installLogSizes(&logs);
    logs[@intFromEnum(roster.Component.range_check_8_8)] = air.range_check_8_8_bridge.LOG_SIZE;
    const manifest = try universal_manifest.build(logs);
    inline for (0..3) |tree| {
        const cells = try ownedTreeCellCount(&manifest, tree);
        try std.testing.expectEqual(cells, try authority.stagingCellCount(tree));
        try std.testing.expectEqual(
            cells * @sizeOf(M31),
            try authority.stagingByteCount(tree),
        );
    }
    try std.testing.expectError(error.InvalidTreeIndex, authority.stagingCellCount(3));

    var preprocessed = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    try authority.fillPreprocessedInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        preprocessed.columns,
    );
    var staged_preprocessed = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer staged_preprocessed.deinit();
    setOwnedTree(&manifest, manifest_mod.PREPROCESSED_TREE_INDEX, staged_preprocessed.columns);
    try authority.fillPreprocessedInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        staged_preprocessed.columns,
    );
    try expectEqualTree(preprocessed.storage, staged_preprocessed.storage);

    var main = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    try authority.fillMainInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        main.columns,
    );
    var staged_main = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer staged_main.deinit();
    setOwnedTree(&manifest, manifest_mod.MAIN_TREE_INDEX, staged_main.columns);
    try authority.fillMainInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        staged_main.columns,
    );
    try expectEqualTree(main.storage, staged_main.storage);

    var interaction = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();
    const relations = universal.UniversalRelations.dummy();
    const claims = try authority.fillInteractionInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        &relations,
        interaction.columns,
    );
    const domain_audits = try authority.auditInteractionDomains(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &relations,
        claims,
        null,
    );
    for (domain_audits, claims.asArray()) |audit, claim|
        try std.testing.expect(audit.total.eql(claim));
    var staged_interaction = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer staged_interaction.deinit();
    setOwnedTree(&manifest, manifest_mod.INTERACTION_TREE_INDEX, staged_interaction.columns);
    const staged_claims = try authority.fillInteractionInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        &relations,
        staged_interaction.columns,
    );
    try std.testing.expect(std.meta.eql(claims, staged_claims));
    try expectEqualTree(interaction.storage, staged_interaction.storage);
    const components = try authority.initComponents(
        &manifest,
        &relations,
        claims,
    );
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try components.appendToGate(&manifest, &gate);
    try std.testing.expectEqual(@as(u8, source.ROW_COUNT), gate.count);

    const transcript_placement = try manifest.placement(.transcript_air);
    try std.testing.expect(!allZero(main.columns[transcript_placement.main_offset]));
    const control_placement = try manifest.placement(.control);
    try std.testing.expect(!allZero(
        preprocessed.columns[control_placement.preprocessed_offset],
    ));
}

test "segment transcript outer source rejects prepared mutation without destination writes" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var authority = try Source.init(
        std.testing.allocator,
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        try source.PowLogSizes.init(4, 4),
    );
    defer authority.deinit();
    var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
    authority.installLogSizes(&logs);
    logs[@intFromEnum(roster.Component.range_check_8_8)] = air.range_check_8_8_bridge.LOG_SIZE;
    const manifest = try universal_manifest.build(logs);
    var main = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    const sentinel = M31.fromCanonical(765_431);
    @memset(main.storage, sentinel);

    fixture.prepared.transcript_word.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        authority.fillMainInto(
            &fixture.vm_plan,
            &fixture.recursion_plan,
            &fixture.preprocessing,
            &fixture.prepared,
            &manifest,
            main.columns,
        ),
    );
    for (main.storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "segment transcript outer source rejects aliased destinations atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var authority = try Source.init(
        std.testing.allocator,
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        try source.PowLogSizes.init(4, 4),
    );
    defer authority.deinit();
    var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
    authority.installLogSizes(&logs);
    logs[@intFromEnum(roster.Component.range_check_8_8)] = air.range_check_8_8_bridge.LOG_SIZE;
    const manifest = try universal_manifest.build(logs);
    var main = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    const placement = try manifest.placement(.transcript_air);
    const saved = main.columns[placement.main_offset + 1];
    main.columns[placement.main_offset + 1] = main.columns[placement.main_offset];
    defer main.columns[placement.main_offset + 1] = saved;
    try std.testing.expectError(
        error.DestinationAlias,
        authority.fillMainInto(
            &fixture.vm_plan,
            &fixture.recursion_plan,
            &fixture.preprocessing,
            &fixture.prepared,
            &manifest,
            main.columns,
        ),
    );
    try std.testing.expect(allZero(main.storage));
}

test "segment transcript outer source releases every allocation failure" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{&fixture},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator, fixture: *Fixture) !void {
    var authority = try Source.init(
        allocator,
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        try source.PowLogSizes.init(4, 4),
    );
    defer authority.deinit();
    var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
    authority.installLogSizes(&logs);
    logs[@intFromEnum(roster.Component.range_check_8_8)] = air.range_check_8_8_bridge.LOG_SIZE;
    const manifest = try universal_manifest.build(logs);
    var preprocessed = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    authority.fillPreprocessedInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        preprocessed.columns,
    ) catch |err| {
        try std.testing.expect(allZero(preprocessed.storage));
        return err;
    };
    var main = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    authority.fillMainInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        main.columns,
    ) catch |err| {
        try std.testing.expect(allZero(main.storage));
        return err;
    };
    var interaction = try Tree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();
    const relations = universal.UniversalRelations.dummy();
    _ = authority.fillInteractionInto(
        &fixture.vm_plan,
        &fixture.recursion_plan,
        &fixture.preprocessing,
        &fixture.prepared,
        &manifest,
        &relations,
        interaction.columns,
    ) catch |err| {
        try std.testing.expect(allZero(interaction.storage));
        return err;
    };
}

const Fixture = struct {
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    preprocessing: segment_witness.Preprocessing,
    prepared: Prepared,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var vm_plan = try testPlan(allocator, .vm);
        errdefer vm_plan.deinit();
        var recursion_plan = try testPlan(allocator, .recursion);
        errdefer recursion_plan.deinit();
        var preprocessing = try segment_witness.Preprocessing.init(
            allocator,
            &vm_plan,
            &recursion_plan,
        );
        errdefer preprocessing.deinit();
        const statement = testStatement();
        const public_claim = testPublicClaim();
        const wire = testWire();
        const prepared = try Prepared.init(
            allocator,
            &preprocessing,
            &vm_plan,
            &recursion_plan,
            &statement,
            public_claim,
            &wire,
        );
        return .{
            .vm_plan = vm_plan,
            .recursion_plan = recursion_plan,
            .preprocessing = preprocessing,
            .prepared = prepared,
        };
    }

    fn deinit(self: *Fixture) void {
        self.prepared.deinit();
        self.preprocessing.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }
};

const Tree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !Tree {
        const count = treeColumnCount(manifest, tree);
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        var total: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const column_count = geometryColumnCount(placement.geometry, tree);
            total += column_count * (@as(usize, 1) << @intCast(placement.geometry.log_size));
        }
        const storage = try allocator.alloc(M31, total);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset = treeOffset(placement, tree);
            const column_count = geometryColumnCount(placement.geometry, tree);
            const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..column_count]) |*column| {
                column.* = storage[cursor..][0..row_count];
                cursor += row_count;
            }
        }
        std.debug.assert(cursor == storage.len);
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
    }

    fn deinit(self: *Tree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

fn testPlan(allocator: std.mem.Allocator, schema: schedule.Schema) !schedule.Plan {
    const fri = try fixed_profile.FriSchedule.init(4, protocol.PCS_CONFIG.fri_config);
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            schema,
            3,
            if (schema == .vm) 1 else 0,
            2,
            3,
        ),
        .{
            .protocol_id = protocol.protocolId(),
            .shape_id = channel.hashBytes("segment-outer-source-test-shape", 0x4f53),
            .interaction_pow_bits = 0,
            .pcs_pow_bits = 0,
            .query_count = dimensions.query_count,
            .table_count = 4,
            .claimed_sum_count = dimensions.claimed_sum_count,
            .sampled_value_count = dimensions.sampled_value_count,
            .tree_heights = .{ 5, 5, 5, 5 },
            .fri = fri,
        },
    );
}

fn testStatement() transcript.StatementWords {
    var words: transcript.StatementWords = undefined;
    for (&words, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast((19 * index + 5) % 65_521));
    return words;
}

fn testPublicClaim() transcript.PublicClaim {
    var digest: [transcript.RATE]M31 = undefined;
    for (&digest, 0..) |*word, index|
        word.* = M31.fromCanonical(@intCast(151 + index));
    return .{ .vm = digest };
}

fn testWire() Wire {
    var wire = std.mem.zeroes(Wire);
    for (&wire.commitments, 0..) |*digest, digest_index| {
        for (digest, 0..) |*value, index|
            value.* = @intCast(1 + 17 * digest_index + index);
    }
    for (&wire.claimed_sums, 0..) |*value, index| {
        for (value, 0..) |*limb, limb_index|
            limb.* = @intCast(200 + 4 * index + limb_index);
    }
    for (&wire.sampled_values, 0..) |*value, index| {
        for (value, 0..) |*limb, limb_index|
            limb.* = @intCast(300 + 4 * index + limb_index);
    }
    for (&wire.fri_layers[0].commitment, 0..) |*value, index|
        value.* = @intCast(400 + index);
    for (&wire.last_layer_coefficients[0], 0..) |*value, index|
        value.* = @intCast(500 + index);
    return wire;
}

fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn geometryColumnCount(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

fn allZero(values: []const M31) bool {
    for (values) |value| if (!value.isZero()) return false;
    return true;
}

fn expectEqualTree(actual: []const M31, expected: []const M31) !void {
    try std.testing.expectEqual(actual.len, expected.len);
    for (actual, expected) |actual_value, expected_value|
        try std.testing.expect(actual_value.eql(expected_value));
}

fn ownedTreeCellCount(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
) !usize {
    var result: usize = 0;
    inline for (0..source.ROW_COUNT) |index| {
        const row: roster.Component = @enumFromInt(source.FIRST_ROW + index);
        const placement = try manifest.placement(row);
        result += geometryColumnCount(placement.geometry, tree) *
            (@as(usize, 1) << @intCast(placement.geometry.log_size));
    }
    return result;
}

fn setOwnedTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) void {
    inline for (0..source.ROW_COUNT) |index| {
        const row: roster.Component = @enumFromInt(source.FIRST_ROW + index);
        const placement = manifest.placement(row) catch unreachable;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (destination[offset..][0..count]) |column| @memset(column, M31.one());
    }
}
