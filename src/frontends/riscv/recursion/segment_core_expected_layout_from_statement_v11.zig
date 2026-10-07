//! Deterministic pre-leaf authority for ordered direct-core Tree0--3 logs.
//!
//! The native incremental verifier already reconstructs commitment-tree logs
//! from the admitted RISC-V statement, pinned physical lookup manifest and
//! optional V3 bridge geometry. This module reproduces that order before child
//! capture for both SegmentV2 and incremental V3 leaves.
//! Only composition Tree3 remains an explicit verifier-selected parameter.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const statement_mod = @import("../air/statement.zig");
const preprocessed = @import("../prover/preprocessed.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const bridge_mod = @import("../prover/incremental_bridge_external_v3.zig");
const row23 = @import("segment_core_trace_row23_fixed_v11.zig");
const template = @import("air/segment_leaf_wrapper_template_v10.zig");
const protocol = @import("protocol.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TREE_COUNT: usize = 4;

pub const OwnedLayout = struct {
    allocator: std.mem.Allocator,
    trees: [TREE_COUNT][]u32,
    views: [TREE_COUNT][]const u32,
    statement_identity: [32]u8,
    bridge_identity: [32]u8,

    /// `statement` and `bridge` must be selected/authenticated by verifier
    /// policy before this method is called. No proof capture is accepted.
    pub fn build(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        bridge: *const bridge_mod.GeometryV3,
        selected_tree3_logs: []const u32,
    ) !OwnedLayout {
        return buildWithBridge(allocator, statement, bridge, selected_tree3_logs);
    }

    /// SegmentV2 has no external memory bridge. Its tree logs must still be
    /// derived from the verifier-selected statement before reading the leaf.
    pub fn buildSegmentV2(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        selected_tree3_logs: []const u32,
    ) !OwnedLayout {
        return buildWithBridge(allocator, statement, null, selected_tree3_logs);
    }

    fn buildWithBridge(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        bridge: ?*const bridge_mod.GeometryV3,
        selected_tree3_logs: []const u32,
    ) !OwnedLayout {
        if (statement.n_components > statement_mod.MAX_COMPONENTS or
            statement.n_infra > statement_mod.MAX_INFRA_COMPONENTS or
            selected_tree3_logs.len == 0)
            return error.InvalidExpectedLayoutSourceV11;
        var manifest = lookup.Manifest.native();
        const authenticated = try lookup.AuthenticatedStatement.init(statement, &manifest);
        const base_interaction = try authenticated.totalInteractionColumns(statement, &manifest);
        if (bridge) |selected| try selected.validate(statement, std.math.cast(u32, base_interaction) orelse return error.InvalidExpectedLayoutSourceV11);
        const bridge_log = if (bridge) |selected| selected.log_size else 0;

        const tree0_base = try preprocessed.logSizes(allocator, statement.*);
        defer allocator.free(tree0_base);
        const tree0 = try appendUniform(allocator, tree0_base, if (bridge != null) bridge_mod.PREPROCESSED_COLUMNS else 0, bridge_log);
        errdefer allocator.free(tree0);
        try extendForCommitment(tree0);

        const tree1_base = try allocator.alloc(u32, statement.nMainColumns());
        defer allocator.free(tree1_base);
        var offset: usize = 0;
        for (statement.component_descs[0..statement.n_components]) |descriptor| {
            @memset(tree1_base[offset..][0..descriptor.n_columns], descriptor.log_size);
            offset += descriptor.n_columns;
        }
        for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
            @memset(tree1_base[offset..][0..descriptor.n_columns], descriptor.log_size);
            offset += descriptor.n_columns;
        }
        if (offset != tree1_base.len) return error.InvalidExpectedLayoutSourceV11;
        const tree1 = try appendUniform(allocator, tree1_base, if (bridge != null) bridge_mod.MAIN_COLUMNS else 0, bridge_log);
        errdefer allocator.free(tree1);
        try extendForCommitment(tree1);

        const tree2_base = try allocator.alloc(u32, base_interaction);
        defer allocator.free(tree2_base);
        offset = 0;
        for (statement.component_descs[0..statement.n_components]) |descriptor| {
            const count = manifest.entryForFamily(descriptor.family).interaction_column_count;
            @memset(tree2_base[offset..][0..count], descriptor.log_size);
            offset += count;
        }
        for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
            const count = statement_mod.nInteractionColsForInfra(descriptor.kind);
            @memset(tree2_base[offset..][0..count], descriptor.log_size);
            offset += count;
        }
        if (offset != tree2_base.len) return error.InvalidExpectedLayoutSourceV11;
        const tree2 = try appendUniform(allocator, tree2_base, if (bridge != null) bridge_mod.INTERACTION_COLUMNS else 0, bridge_log);
        errdefer allocator.free(tree2);
        try extendForCommitment(tree2);
        const tree3 = try allocator.dupe(u32, selected_tree3_logs);
        errdefer allocator.free(tree3);
        for (tree3) |log_size| if (log_size == 0) return error.InvalidExpectedLayoutSourceV11;

        const trees = [TREE_COUNT][]u32{ tree0, tree1, tree2, tree3 };
        return .{
            .allocator = allocator,
            .trees = trees,
            .views = .{ tree0, tree1, tree2, tree3 },
            .statement_identity = authenticated.statement_identity,
            .bridge_identity = if (bridge) |selected| selected.identity_sha256 else [_]u8{0} ** 32,
        };
    }

    pub fn deinit(self: *OwnedLayout) void {
        for (self.trees) |tree| self.allocator.free(tree);
        self.* = undefined;
    }

    pub fn expected(self: *const OwnedLayout) row23.ExpectedLayout {
        // Direct leaf uses one verified source profile in its segment and
        // recursive verifier lanes. A future heterogeneous source needs two
        // independently derived layouts, not child-selected differences.
        return .{ .vm_trees = &self.views, .recursion_trees = &self.views };
    }

    pub fn validateAgainstTemplate(self: *const OwnedLayout, key: *const template.TemplateManifestV10) !void {
        try key.validate();
        try self.expected().validateAgainst(key);
    }
};

fn appendUniform(allocator: std.mem.Allocator, base: []const u32, count: usize, log_size: u32) ![]u32 {
    const result = try allocator.alloc(u32, try std.math.add(usize, base.len, count));
    @memcpy(result[0..base.len], base);
    @memset(result[base.len..], log_size);
    return result;
}

fn extendForCommitment(logs: []u32) !void {
    // CommitmentSchemeVerifier.commit stores the FRI-extended column logs in
    // ProofCapture. Row 23 consumes that PCS convention, not raw AIR logs.
    for (logs) |*log_size|
        log_size.* = try std.math.add(u32, log_size.*, protocol.FRI_LOG_BLOWUP_FACTOR);
}

fn expectExtended(raw: []const u32, extended: []const u32) !void {
    try std.testing.expectEqual(raw.len, extended.len);
    for (raw, extended) |before, after|
        try std.testing.expectEqual(try std.math.add(u32, before, protocol.FRI_LOG_BLOWUP_FACTOR), after);
}

test "V11 statement layout matches native verifier Tree0--2 log construction" {
    const allocator = std.testing.allocator;
    const native_append = @import("../prover/guest_precompile/external_profile_tree.zig");
    const fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    var statement = std.mem.zeroes(statement_mod.RiscVStatement);
    statement.initializeDescriptorStorage();
    statement.n_components = fixture.components.len;
    @memcpy(statement.component_descs[0..fixture.components.len], &fixture.components);
    statement.n_infra = fixture.infra.len;
    @memcpy(statement.infra_descs[0..fixture.infra.len], &fixture.infra);
    var manifest = lookup.Manifest.native();
    for (statement.component_descs[0..statement.n_components]) |*descriptor|
        descriptor.n_columns = manifest.entryForFamily(descriptor.family).main_column_count;
    const authenticated = try lookup.AuthenticatedStatement.init(&statement, &manifest);
    const base_interaction = try authenticated.totalInteractionColumns(&statement, &manifest);
    const bridge = try bridge_mod.GeometryV3.canonical(&statement, 16, @intCast(base_interaction));
    const tree3 = [_]u32{5} ** 8;
    var owned = try OwnedLayout.build(allocator, &statement, &bridge, &tree3);
    defer owned.deinit();

    const native0_base = try preprocessed.logSizes(allocator, statement);
    defer allocator.free(native0_base);
    const empty0 = [_][]const M31{&.{}} ** bridge_mod.PREPROCESSED_COLUMNS;
    const native0 = try native_append.appendLogSizes(allocator, native0_base, &.{.{ .log_size = bridge.log_size, .columns = &empty0 }});
    defer allocator.free(native0);
    try expectExtended(native0, owned.trees[0]);

    const native1_base = try allocator.alloc(u32, statement.nMainColumns());
    defer allocator.free(native1_base);
    var offset: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        @memset(native1_base[offset..][0..descriptor.n_columns], descriptor.log_size);
        offset += descriptor.n_columns;
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        @memset(native1_base[offset..][0..descriptor.n_columns], descriptor.log_size);
        offset += descriptor.n_columns;
    }
    const empty1 = [_][]const M31{&.{}} ** bridge_mod.MAIN_COLUMNS;
    const native1 = try native_append.appendLogSizes(allocator, native1_base, &.{.{ .log_size = bridge.log_size, .columns = &empty1 }});
    defer allocator.free(native1);
    try expectExtended(native1, owned.trees[1]);

    // `canonicalInteractionClaim` is the native Tree2 owner; its log sizes
    // depend only on the statement and pinned manifest, while values depend
    // on the claim. A zero claim gives the same authoritative log order.
    var claim: statement_mod.RiscVInteractionClaim = undefined;
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    const canonical = try authenticated.canonicalInteractionClaim(&statement, &manifest, &claim);
    const empty2 = [_][]const M31{&.{}} ** bridge_mod.INTERACTION_COLUMNS;
    const native2 = try native_append.appendLogSizes(allocator, canonical.view().log_sizes, &.{.{ .log_size = bridge.log_size, .columns = &empty2 }});
    defer allocator.free(native2);
    try expectExtended(native2, owned.trees[2]);
    try std.testing.expectEqualSlices(u32, &tree3, owned.trees[3]);
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
}
