//! Versioned 50-row geometry for the native u16-to-ProgramV2 bridge.
//! The V6 plan is diagnostic input only; this overlay rekeys row 5 and row 42
//! and recalculates every placement before a future proof transaction.
const std = @import("std");
const core = @import("stwo_core");
const v6 = @import("segment_leaf_wrapper_roster_direct_v6.zig");
const payload = @import("transcript_payload_direct_v7.zig");
const program = @import("transcript_program_v2_field_bridge_v6.zig");
const typed = @import("universal_typed_component.zig");
const global_statement = @import("../segment_leaf_wrapper_global_statement_boundary_v6.zig");

pub const FORMAT_VERSION: u16 = 7;
pub const COMPONENT_COUNT = v6.COMPONENT_COUNT;
pub const DOMAIN = "stwo-zig/riscv-direct-leaf-wrapper-roster/v7\x00";
pub const TRANSCRIPT_DOMAIN: u32 = 0x5256_3757; // RV7W
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Geometry = v6.Geometry;
pub const Placement = v6.Placement;

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    v6_plan: v6.Plan,
    placements: [COMPONENT_COUNT]Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn fromV6(base: *const v6.Plan) !Plan {
        try base.validate();
        const result = try buildRaw(base);
        try result.validate();
        return result;
    }

    fn buildRaw(base: *const v6.Plan) !Plan {
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (&placements, base.placements, 0..) |*target, maybe_prior, index| {
            const prior = maybe_prior orelse return error.InvalidDirectV7WrapperRoster;
            var geometry = prior.geometry;
            if (index == 5) geometry = airGeometry(5, geometry.log_size, payload);
            if (index == 42) geometry = airGeometry(42, geometry.log_size, program);
            try geometry.validateForComponentCount(COMPONENT_COUNT);
            target.* = .{
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
            .v6_plan = base.*,
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
        try self.v6_plan.validate();
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.*, try buildRaw(&self.v6_plan)))
            return error.InvalidDirectV7WrapperRoster;
    }

    pub fn mixBeforeRelationDraw(self: *const Plan, channel: anytype, expected: global_statement.ExpectedPublic) !void {
        try self.validate();
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, COMPONENT_COUNT, self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints });
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, index|
            word.* = std.mem.readInt(u32, self.seal[index * 4 ..][0..4], .little);
        channel.mixU32s(&words);
        expected.mixBeforeRelations(channel);
    }

    pub fn requireCompleteWrapperProof(_: *const Plan) error{V7WrapperProofUnavailable}!void {
        return error.V7WrapperProofUnavailable;
    }

    fn computeSeal(self: *const Plan) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hash.update(&self.v6_plan.seal);
        hash.update(&payload.SEMANTIC_DIGEST);
        hash.update(&program.SEMANTIC_DIGEST);
        for (self.placements) |item| {
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

fn airGeometry(comptime row: u8, log_size: u32, comptime air: type) Geometry {
    return .{
        .roster_row = row,
        .log_size = log_size,
        .preprocessed_columns = air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(air)),
        .profiled_constraint_degree = air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = air.SEMANTIC_DIGEST,
    };
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V7 roster pins wire-half AIR geometry and remains proof-inactive" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const catalog = @import("segment_outer_typed_catalog_v2.zig");
    const base_manifest = @import("segment_outer_adapter_manifest_v2.zig");
    const link = @import("../ethereum_leaf_link_program_v3.zig");
    const child = @import("../ethereum_leaf_child_field_program_v1.zig");
    const shape = @import("segment_leaf_wrapper_roster_direct_v4.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const manifest = try base_manifest.assemble(&source_catalog, fixture.authorityIds());
    var link_program = try link.ProgramV3.init(allocator);
    defer link_program.deinit();
    var local_source = try child.ProgramV1.initWithNativeProgramBridge(allocator, &child_fixture.components, &child_fixture.infra);
    defer local_source.deinit();
    const base = try v6.Plan.build(allocator, &manifest, &link_program, shape.Shape{ .program_words = 100, .base_poseidon_calls = 1193 }, &local_source, &child_fixture.components, &child_fixture.infra);
    var plan = try Plan.fromV6(&base);
    try std.testing.expectEqualDeep(payload.SEMANTIC_DIGEST, plan.placements[5].geometry.semantic_digest);
    try std.testing.expectEqualDeep(program.SEMANTIC_DIGEST, plan.placements[42].geometry.semantic_digest);
    try std.testing.expect(!std.meta.eql(plan.seal, base.seal));
    try std.testing.expectError(error.V7WrapperProofUnavailable, plan.requireCompleteWrapperProof());
    plan.placements[42].geometry.semantic_digest[0] ^= 1;
    plan.seal = plan.computeSeal();
    try std.testing.expectError(error.InvalidDirectV7WrapperRoster, plan.validate());
}
