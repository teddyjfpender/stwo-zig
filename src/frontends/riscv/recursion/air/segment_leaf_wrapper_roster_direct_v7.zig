//! Versioned 50-row geometry for the native u16-to-ProgramV2 bridge.
//! All placements come from the verifier-rebuilt V7 template, never a leaf's
//! V2 manifest. Proof publication remains disabled pending all fixed writers.
const std = @import("std");
const template_mod = @import("segment_leaf_wrapper_template_v7.zig");
const v6 = @import("segment_leaf_wrapper_template_v6.zig");
const payload = @import("transcript_payload_direct_v7.zig");
const program = @import("transcript_program_v2_field_bridge_v6.zig");
const global_statement = @import("../segment_leaf_wrapper_global_statement_boundary_v6.zig");

pub const FORMAT_VERSION: u16 = 7;
pub const COMPONENT_COUNT = template_mod.COMPONENT_COUNT;
pub const DOMAIN = "stwo-zig/riscv-direct-leaf-wrapper-roster/v7\x00";
pub const TRANSCRIPT_DOMAIN: u32 = 0x5256_3757; // RV7W
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Geometry = template_mod.Geometry;
pub const Placement = template_mod.Placement;

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    template: template_mod.TemplateManifestV7,
    placements: [COMPONENT_COUNT]Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn fromTemplate(template: *const template_mod.TemplateManifestV7) !Plan {
        try template.validate();
        const result = buildRaw(template);
        try result.validate();
        return result;
    }

    fn buildRaw(template: *const template_mod.TemplateManifestV7) Plan {
        var result = Plan{
            .template = template.*,
            .placements = template.placements,
            .total_preprocessed_columns = template.total_preprocessed_columns,
            .total_main_columns = template.total_main_columns,
            .total_interaction_columns = template.total_interaction_columns,
            .total_constraints = template.total_constraints,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        return result;
    }

    pub fn validate(self: *const Plan) !void {
        try self.template.validate();
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.*, buildRaw(&self.template)) or
            !std.meta.eql(self.placements[5].geometry.semantic_digest, payload.SEMANTIC_DIGEST) or
            !std.meta.eql(self.placements[42].geometry.semantic_digest, program.SEMANTIC_DIGEST))
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
        hash.update(&self.template.seal);
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

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V7 roster pins wire-half AIR geometry and remains proof-inactive" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const catalog = @import("segment_outer_typed_catalog_v2.zig");
    const shape = @import("segment_leaf_wrapper_roster_direct_v4.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("../segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const instructions = try @import("../transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const geometry = shape.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const template = try template_mod.TemplateManifestV7.build(
        allocator,
        &source_catalog,
        geometry,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
    );
    var plan = try Plan.fromTemplate(&template);
    try std.testing.expectEqualDeep(payload.SEMANTIC_DIGEST, plan.placements[5].geometry.semantic_digest);
    try std.testing.expectEqualDeep(program.SEMANTIC_DIGEST, plan.placements[42].geometry.semantic_digest);
    try std.testing.expect(plan.placements[5].geometry.log_size > template.v6_template.placements[5].geometry.log_size);
    try std.testing.expect(!std.meta.eql(plan.seal, template.seal));
    try std.testing.expectError(error.V7WrapperProofUnavailable, plan.requireCompleteWrapperProof());
    plan.placements[42].geometry.semantic_digest[0] ^= 1;
    plan.seal = plan.computeSeal();
    try std.testing.expectError(error.InvalidDirectV7WrapperRoster, plan.validate());
}
