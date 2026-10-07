//! Physical 50-row direct roster with versioned row5 and row36 AIR.
//! No proof is admitted until the complete V6 cohort is qualified.

const std = @import("std");
const core = @import("stwo_core");
const legacy = @import("segment_leaf_wrapper_roster_direct_v5.zig");
const statement = @import("segment_leaf_statement_source_direct_v6.zig");
const payload = @import("transcript_payload_direct_v6.zig");
const public_logup = @import("vm_public_logup_control_v6.zig");
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
pub const ROW5_NPV2_GEOMETRY_PENDING = false;
pub const Geometry = legacy.Geometry;
pub const Placement = legacy.Placement;

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    legacy_plan: legacy.Plan,
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
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
        const result = try buildRawFromLegacy(base);
        try result.validate();
        return result;
    }

    fn buildRawFromLegacy(base: *const legacy.Plan) !Plan {
        var placements: [COMPONENT_COUNT]?Placement = @splat(null);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (base.placements, 0..) |old, index| {
            const prior = old orelse return error.InvalidDirectV6WrapperRoster;
            var geometry = prior.geometry;
            if (index == 5) geometry = payloadGeometry(geometry.log_size);
            if (index == 17) geometry = publicLogupGeometry(geometry.log_size);
            if (index == 36) geometry = statementGeometry(geometry.log_size);
            try geometry.validateForComponentCount(COMPONENT_COUNT);
            placements[index] = .{
                .geometry = geometry,
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
                .constraint_offset = constraints,
                .claimed_sum_index = @intCast(index),
            };
            pp = try std.math.add(u32, pp, geometry.preprocessed_columns);
            main = try std.math.add(u32, main, geometry.main_columns);
            interaction = try std.math.add(u32, interaction, geometry.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, geometry.direct_constraints) + geometry.interaction_batches);
        }
        var result = Plan{
            .legacy_plan = base.*,
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        return result;
    }

    pub fn validate(self: *const Plan) !void {
        try self.legacy_plan.validate();
        if (self.format_version != FORMAT_VERSION)
            return error.InvalidDirectV6WrapperRoster;
        const expected = try buildRawFromLegacy(&self.legacy_plan);
        if (!std.meta.eql(self.*, expected))
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
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, COMPONENT_COUNT, self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints });
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
        hash.update(&payload.SEMANTIC_DIGEST);
        hash.update(&public_logup.SEMANTIC_DIGEST);
        hash.update(&statement.SEMANTIC_DIGEST);
        hash.update(&self.legacy_plan.local_schedule_id);
        for (self.placements) |maybe_item| {
            const item = maybe_item orelse return @splat(0);
            const g = item.geometry;
            hashInt(&hash, u32, g.log_size);
            inline for (.{ g.preprocessed_columns, g.main_columns, g.interaction_columns, g.direct_constraints, g.interaction_batches }) |n|
                hashInt(&hash, u16, n);
            hash.update(&g.semantic_digest);
            inline for (.{ item.preprocessed_offset, item.main_offset, item.interaction_offset, item.constraint_offset }) |n|
                hashInt(&hash, u32, n);
        }
        inline for (.{ self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints }) |n|
            hashInt(&hash, u32, n);
        return hash.finalResult();
    }
};

fn payloadGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = 5,
        .log_size = log_size,
        .preprocessed_columns = payload.PREPROCESSED_COLUMN_COUNT,
        .main_columns = payload.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = payload.INTERACTION_COLUMN_COUNT,
        .direct_constraints = payload.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = payload.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(payload)),
        .profiled_constraint_degree = payload.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = payload.SEMANTIC_DIGEST,
    };
}

fn publicLogupGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = 17,
        .log_size = log_size,
        .preprocessed_columns = public_logup.PREPROCESSED_COLUMN_COUNT,
        .main_columns = public_logup.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = public_logup.INTERACTION_COLUMN_COUNT,
        .direct_constraints = public_logup.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = public_logup.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(public_logup)),
        .profiled_constraint_degree = public_logup.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = public_logup.SEMANTIC_DIGEST,
    };
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

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
    try std.testing.expectEqualDeep(payload.SEMANTIC_DIGEST, plan.placements[5].?.geometry.semantic_digest);
    try std.testing.expectEqualDeep(public_logup.SEMANTIC_DIGEST, plan.placements[17].?.geometry.semantic_digest);
    try std.testing.expectEqualDeep(statement.SEMANTIC_DIGEST, plan.placements[36].?.geometry.semantic_digest);
    try std.testing.expectEqual(plan.legacy_plan.total_preprocessed_columns + 1, plan.total_preprocessed_columns);
    try std.testing.expectEqual(plan.legacy_plan.total_interaction_columns + 4, plan.total_interaction_columns);
    try std.testing.expectEqual(plan.legacy_plan.placements[6].?.preprocessed_offset + 1, plan.placements[6].?.preprocessed_offset);
    try std.testing.expectEqual(plan.legacy_plan.placements[6].?.interaction_offset + 4, plan.placements[6].?.interaction_offset);
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
    plan.placements[36].?.geometry.semantic_digest[0] ^= 1;
    plan.placements[5].?.geometry.semantic_digest[0] ^= 1;
    plan.seal = plan.computeSeal();
    try std.testing.expectError(error.InvalidDirectV6WrapperRoster, plan.validate());
}
