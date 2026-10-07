//! Candidate 50-row V8 roster for the fixed-key Statement replacement.
//!
//! The detached verifier rebuilds the V8 template from admitted shape,
//! then derives the Statement wire-count parameter separately from its
//! authenticated SegmentV2 public input. This plan does not authorize a
//! recursive proof, a root, or publication.
const std = @import("std");
const template_mod = @import("segment_leaf_wrapper_template_v8.zig");
const statement_air = @import("segment_leaf_statement_source_direct_v8.zig");
const global_statement = @import("../segment_leaf_wrapper_global_statement_boundary_v6.zig");

pub const FORMAT_VERSION: u16 = 8;
pub const COMPONENT_COUNT = template_mod.COMPONENT_COUNT;
pub const DOMAIN = "stwo-zig/riscv-direct-leaf-wrapper-roster/v8\x00";
pub const TRANSCRIPT_DOMAIN: u32 = 0x5256_3857; // RV8W
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Placement = template_mod.Placement;

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    template: template_mod.TemplateManifestV8,
    placements: [COMPONENT_COUNT]Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn fromTemplate(template: *const template_mod.TemplateManifestV8) !Plan {
        try template.validate();
        const plan = buildRaw(template);
        try plan.validate();
        return plan;
    }

    pub fn validate(self: *const Plan) !void {
        try self.template.validate();
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.*, buildRaw(&self.template)) or
            !std.meta.eql(self.placements[36].geometry.semantic_digest, statement_air.SEMANTIC_DIGEST) or
            self.placements[36].geometry.log_size != statement_air.LOG_SIZE)
            return error.InvalidDirectV8WrapperRoster;
    }

    /// This cannot be used as a production transcript until complete fixed
    /// preprocessing and a detached proof/verifier are independently admitted.
    pub fn mixBeforeRelationDraw(self: *const Plan, channel: anytype, expected: global_statement.ExpectedPublic) !void {
        try self.validate();
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, COMPONENT_COUNT, self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints });
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, index|
            word.* = std.mem.readInt(u32, self.seal[index * 4 ..][0..4], .little);
        channel.mixU32s(&words);
        expected.mixBeforeRelations(channel);
    }

    pub fn requireCompleteWrapperProof(_: *const Plan) error{V8WrapperProofUnavailable}!void {
        return error.V8WrapperProofUnavailable;
    }

    fn buildRaw(template: *const template_mod.TemplateManifestV8) Plan {
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

    fn computeSeal(self: *const Plan) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.template.seal);
        hash.update(&statement_air.SEMANTIC_DIGEST);
        hash.update(&self.template.row36_fixed_ordinal_id);
        hash.update(&self.template.public_parameter.contract_digest);
        for (self.placements) |placement| {
            const g = placement.geometry;
            hashInt(&hash, u8, g.roster_row);
            hashInt(&hash, u32, g.log_size);
            inline for (.{ g.preprocessed_columns, g.main_columns, g.interaction_columns, g.direct_constraints, g.interaction_batches }) |n|
                hashInt(&hash, u16, n);
            hashInt(&hash, u8, g.protocol_constraint_degree);
            hashInt(&hash, u8, g.profiled_constraint_degree);
            hash.update(&g.semantic_digest);
            inline for (.{ placement.preprocessed_offset, placement.main_offset, placement.interaction_offset, placement.constraint_offset }) |n|
                hashInt(&hash, u32, n);
            hashInt(&hash, u8, placement.claimed_sum_index);
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

test "V8 candidate roster binds row36 fixed key and public contract" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const v6 = @import("segment_leaf_wrapper_template_v6.zig");
    const catalog = @import("segment_outer_typed_catalog_v2.zig");
    const shape_mod = @import("segment_leaf_wrapper_roster_direct_v4.zig");
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
    const shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const template = try template_mod.TemplateManifestV8.build(
        allocator,
        &source_catalog,
        shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
    );
    var plan = try Plan.fromTemplate(&template);
    try std.testing.expectEqualDeep(template.row36_fixed_ordinal_id, plan.template.row36_fixed_ordinal_id);
    try std.testing.expectEqualDeep(template.public_parameter, plan.template.public_parameter);
    try std.testing.expectEqualDeep(statement_air.SEMANTIC_DIGEST, plan.placements[36].geometry.semantic_digest);
    try std.testing.expect(!std.meta.eql(plan.seal, template.seal));
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
    try std.testing.expectError(error.V8WrapperProofUnavailable, plan.requireCompleteWrapperProof());
    plan.placements[36].geometry.main_columns += 1;
    plan.seal = plan.computeSeal();
    try std.testing.expectError(error.InvalidDirectV8WrapperRoster, plan.validate());
}
