//! Physical 50-row direct roster with the versioned row36 Statement AIR.
//! Row5 NPV2 geometry is still pending; this key cannot admit a proof.

const std = @import("std");
const core = @import("stwo_core");
const legacy = @import("segment_leaf_wrapper_roster_direct_v5.zig");
const statement = @import("segment_leaf_statement_source_direct_v6.zig");
const typed = @import("universal_typed_component.zig");
const v2 = @import("segment_outer_adapter_manifest_v2.zig");
const v4 = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const link = @import("../ethereum_leaf_link_program_v3.zig");
const child = @import("../ethereum_leaf_child_field_program_v1.zig");
const statement_v1 = @import("../../air/statement.zig");
const relation = @import("../../air/lang/relation.zig");
const global_statement = @import("../segment_leaf_wrapper_global_statement_boundary_v6.zig");

pub const FORMAT_VERSION: u16 = 6;
pub const COMPONENT_COUNT = legacy.COMPONENT_COUNT;
pub const DOMAIN = "stwo-zig/riscv-direct-leaf-wrapper-roster/v6\x00";
pub const TRANSCRIPT_DOMAIN: u32 = 0x5256_3657; // RV6W
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW5_NPV2_GEOMETRY_PENDING = true;
pub const Geometry = legacy.Geometry;
pub const Placement = legacy.Placement;

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    legacy_plan: legacy.Plan,
    placements: [COMPONENT_COUNT]?Placement,
    seal: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        program: *const link.ProgramV3,
        shape: v4.Shape,
        local_source: *const child.ProgramV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !Plan {
        const base = try legacy.Plan.build(allocator, base_manifest, program, shape, local_source, component_descs, infra_descs);
        return fromLegacy(&base);
    }

    pub fn fromLegacy(base: *const legacy.Plan) !Plan {
        try base.validate();
        var placements = base.placements;
        var row36 = placements[36] orelse return error.InvalidDirectV6WrapperRoster;
        row36.geometry = statementGeometry(row36.geometry.log_size);
        placements[36] = row36;
        var result = Plan{ .legacy_plan = base.*, .placements = placements, .seal = undefined };
        result.seal = result.computeSeal();
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Plan) !void {
        try self.legacy_plan.validate();
        if (self.format_version != FORMAT_VERSION or !std.meta.eql(self.seal, self.computeSeal()))
            return error.InvalidDirectV6WrapperRoster;
        for (self.placements, self.legacy_plan.placements, 0..) |new, old, index| {
            var expected = old orelse return error.InvalidDirectV6WrapperRoster;
            if (index == 36) expected.geometry = statementGeometry(expected.geometry.log_size);
            if (!std.meta.eql(new, @as(?Placement, expected))) return error.InvalidDirectV6WrapperRoster;
        }
        const old = self.legacy_plan.placements[36].?.geometry;
        const new = self.placements[36].?.geometry;
        if (new.preprocessed_columns != old.preprocessed_columns or
            new.main_columns != old.main_columns or
            new.interaction_columns != old.interaction_columns or
            new.direct_constraints != old.direct_constraints or
            new.interaction_batches != old.interaction_batches)
            return error.InvalidDirectV6WrapperRoster;
    }

    pub fn validateAgainst(
        self: *const Plan,
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        program: *const link.ProgramV3,
        shape: v4.Shape,
        local_source: *const child.ProgramV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !void {
        try self.validate();
        const expected = try build(allocator, base_manifest, program, shape, local_source, component_descs, infra_descs);
        if (!std.meta.eql(self.*, expected)) return error.InvalidDirectV6WrapperRoster;
    }

    pub fn mixGeometryPrefix(self: *const Plan, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, COMPONENT_COUNT, self.legacy_plan.total_preprocessed_columns, self.legacy_plan.total_main_columns, self.legacy_plan.total_interaction_columns, self.legacy_plan.total_constraints });
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, index|
            word.* = std.mem.readInt(u32, self.seal[index * 4 ..][0..4], .little);
        channel.mixU32s(&words);
        channel.mixU32s(&digestWords(relation.registryOrderDigest()));
    }

    /// The expected global span is verifier public input. It must enter the
    /// channel after main commitment and before universal relation draws.
    pub fn mixBeforeRelationDraw(self: *const Plan, channel: anytype, expected: global_statement.ExpectedPublic) !void {
        try self.mixGeometryPrefix(channel);
        expected.mixBeforeRelations(channel);
    }

    pub fn requireCompleteWrapperProof(_: *const Plan) error{V6WrapperProofUnavailable}!void {
        return error.V6WrapperProofUnavailable;
    }

    fn computeSeal(self: *const Plan) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hash.update(&self.legacy_plan.seal);
        hash.update(&statement.SEMANTIC_DIGEST);
        hash.update(&self.legacy_plan.local_schedule_id);
        return hash.finalResult();
    }
};

fn statementGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = 36,
        .log_size = log_size,
        .preprocessed_columns = statement.PREPROCESSED_COLUMN_COUNT,
        .main_columns = statement.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = statement.INTERACTION_COLUMN_COUNT,
        .direct_constraints = statement.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = statement.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(statement)),
        .profiled_constraint_degree = statement.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = statement.SEMANTIC_DIGEST,
    };
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return result;
}

test "V6 roster changes row36 identity and fails closed on resealed mutation" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const catalog = @import("segment_outer_typed_catalog_v2.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try link.ProgramV3.init(allocator);
    defer program.deinit();
    var local_source = try child.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer local_source.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    var plan = try Plan.build(allocator, &manifest, &program, shape, &local_source, &child_fixture.components, &child_fixture.infra);
    try plan.validateAgainst(allocator, &manifest, &program, shape, &local_source, &child_fixture.components, &child_fixture.infra);
    try std.testing.expectEqualDeep(statement.SEMANTIC_DIGEST, plan.placements[36].?.geometry.semantic_digest);
    try std.testing.expect(!std.meta.eql(plan.seal, plan.legacy_plan.seal));
    var first = @import("../poseidon2_channel.zig").Channel{};
    var expected = global_statement.ExpectedPublic{ .words = @splat(core.fields.m31.M31.zero()) };
    try plan.mixBeforeRelationDraw(&first, expected);
    expected.words[17] = core.fields.m31.M31.one();
    var changed = @import("../poseidon2_channel.zig").Channel{};
    try plan.mixBeforeRelationDraw(&changed, expected);
    try std.testing.expect(!std.meta.eql(first.drawU32s(), changed.drawU32s()));
    plan.placements[36].?.geometry.semantic_digest[0] ^= 1;
    plan.seal = plan.computeSeal();
    try std.testing.expectError(error.InvalidDirectV6WrapperRoster, plan.validate());
}
