//! Candidate V7 fixed key for the native-half direct leaf wrapper.
//!
//! The verifier rebuilds row 5 and row 42 from admitted shape. Their complete
//! fixed columns (including zero padding) and physical AIR geometry enter a
//! new seal. A complete 50-row preprocessing writer does not yet exist, so
//! this candidate cannot be used as a proof key or authorize publication.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const v6 = @import("segment_leaf_wrapper_template_v6.zig");
const catalog = @import("segment_outer_typed_catalog_v2.zig");
const shape_mod = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const typed = @import("universal_typed_component.zig");
const statement = @import("../../air/statement.zig");
const native = @import("verifier_schedule.zig");
const query_mapping = @import("query_mapping_witness.zig");
const link_program = @import("../ethereum_leaf_link_program_v3.zig");
const row5_template = @import("../segment_leaf_template_payload_fixed_v7.zig");
const row5_air = @import("transcript_payload_direct_v7.zig");
const row42_template = @import("../transcript_program_v2_template_words_v6.zig");
const row42_air = @import("transcript_program_v2_field_bridge_v6.zig");
const security = @import("../segment_v3_production_security_policy.zig");

pub const FORMAT_VERSION: u16 = 7;
pub const DOMAIN = "stwo-zig/riscv-leaf-template-manifest/v7\x00";
pub const FIXED_COLUMNS_DOMAIN = "stwo-zig/riscv-v7-complete-fixed-columns/v1\x00";
pub const COMPONENT_COUNT = v6.COMPONENT_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_TEMPLATE_PREPROCESSING_AVAILABLE = false;
pub const Placement = v6.Placement;
pub const Geometry = v6.Geometry;

/// A provisional shape key, not a final preprocessing commitment. The V6
/// field is retained to prove that no request-specific V2 manifest enters.
pub const TemplateManifestV7 = struct {
    v6_template: v6.TemplateManifestV6,
    placements: [COMPONENT_COUNT]Placement,
    row5_active_rows: u32,
    row5_preprocessed_id: [32]u8,
    row42_preprocessed_id: [32]u8,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        base_catalog: *const catalog.Catalog,
        shape: shape_mod.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const native.Plan,
        core_profile: *const v6.CoreProfileV6,
        core_query_mapping: *const query_mapping.Reference,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
    ) !TemplateManifestV7 {
        const prior = try v6.TemplateManifestV6.build(
            allocator,
            base_catalog,
            shape,
            component_descs,
            infra_descs,
            native_plan,
            core_profile,
            core_query_mapping,
            native_wire_word_count,
            native_lookup_enabled,
        );
        var link = try link_program.ProgramV3.init(allocator);
        defer link.deinit();
        var row5 = try row5_template.Template.initFromShape(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
            &link,
        );
        defer row5.deinit();
        var words = try row42_template.Template.initFromShape(
            allocator,
            native_plan,
            security.REQUIRED_PCS_CONFIG,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
        );
        defer words.deinit();
        const fixed42 = try row42_air.FixedSchedule.initFromTemplate(words.words);
        if (words.words.len != shape.program_words) return error.V7TemplateProgramShapeMismatch;
        const result = try fromSchedules(&prior, &row5, fixed42);
        try result.validate();
        return result;
    }

    fn fromSchedules(prior: *const v6.TemplateManifestV6, row5: *const row5_template.Template, fixed42: row42_air.FixedSchedule) !TemplateManifestV7 {
        try prior.validate();
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        if (row5.rows.len > std.math.maxInt(u32)) return error.InvalidV7TemplateRow5Geometry;
        const row5_capacity = try std.math.ceilPowerOfTwo(usize, @max(row5.rows.len, 16));
        const row5_log_size: u32 = @intCast(std.math.log2_int(usize, row5_capacity));
        for (&placements, prior.placements, 0..) |*target, old, index| {
            var geometry = old.geometry;
            if (index == 5) geometry = airGeometry(5, @max(geometry.log_size, row5_log_size), row5_air);
            if (index == 42) geometry = airGeometry(42, geometry.log_size, row42_air);
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
        if (fixed42.log_size != placements[42].geometry.log_size) return error.V7TemplateRow42GeometryMismatch;
        var result = TemplateManifestV7{
            .v6_template = prior.*,
            .placements = placements,
            .row5_active_rows = @intCast(row5.rows.len),
            .row5_preprocessed_id = try row5FixedColumnsId(row5, placements[5].geometry.log_size),
            .row42_preprocessed_id = try row42FixedColumnsId(fixed42),
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        return result;
    }

    pub fn validate(self: *const TemplateManifestV7) !void {
        try self.v6_template.validate();
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        if (self.row5_active_rows == 0) return error.InvalidV7TemplateManifest;
        const row5_capacity = try std.math.ceilPowerOfTwo(usize, @max(self.row5_active_rows, 16));
        const row5_log_size: u32 = @intCast(std.math.log2_int(usize, row5_capacity));
        for (self.placements, self.v6_template.placements, 0..) |placement, old, index| {
            const expected = if (index == 5)
                airGeometry(5, @max(old.geometry.log_size, row5_log_size), row5_air)
            else if (index == 42)
                airGeometry(42, old.geometry.log_size, row42_air)
            else
                old.geometry;
            if (!std.meta.eql(placement.geometry, expected) or
                placement.preprocessed_offset != pp or placement.main_offset != main or
                placement.interaction_offset != interaction or placement.constraint_offset != constraints or
                placement.claimed_sum_index != index)
                return error.InvalidV7TemplateManifest;
            pp = try std.math.add(u32, pp, expected.preprocessed_columns);
            main = try std.math.add(u32, main, expected.main_columns);
            interaction = try std.math.add(u32, interaction, expected.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, expected.direct_constraints) + expected.interaction_batches);
        }
        if (pp != self.total_preprocessed_columns or main != self.total_main_columns or
            interaction != self.total_interaction_columns or constraints != self.total_constraints or
            !std.mem.eql(u8, &self.seal, &self.computeSeal()))
            return error.InvalidV7TemplateManifest;
    }

    /// Validation is against newly compiled verifier inputs, not a seal
    /// supplied by the child or by a previously admitted leaf.
    pub fn validateAgainst(
        self: *const TemplateManifestV7,
        allocator: std.mem.Allocator,
        base_catalog: *const catalog.Catalog,
        shape: shape_mod.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const native.Plan,
        core_profile: *const v6.CoreProfileV6,
        core_query_mapping: *const query_mapping.Reference,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
    ) !void {
        try self.validate();
        const rebuilt = try buildUnchecked(
            allocator,
            base_catalog,
            shape,
            component_descs,
            infra_descs,
            native_plan,
            core_profile,
            core_query_mapping,
            native_wire_word_count,
            native_lookup_enabled,
        );
        if (!std.meta.eql(self.*, rebuilt)) return error.V7TemplateAdmissionMismatch;
    }

    fn buildUnchecked(
        allocator: std.mem.Allocator,
        base_catalog: *const catalog.Catalog,
        shape: shape_mod.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const native.Plan,
        core_profile: *const v6.CoreProfileV6,
        core_query_mapping: *const query_mapping.Reference,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
    ) !TemplateManifestV7 {
        const prior = try v6.TemplateManifestV6.build(
            allocator,
            base_catalog,
            shape,
            component_descs,
            infra_descs,
            native_plan,
            core_profile,
            core_query_mapping,
            native_wire_word_count,
            native_lookup_enabled,
        );
        var link = try link_program.ProgramV3.init(allocator);
        defer link.deinit();
        var row5 = try row5_template.Template.initFromShape(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
            &link,
        );
        defer row5.deinit();
        var words = try row42_template.Template.initFromShape(
            allocator,
            native_plan,
            security.REQUIRED_PCS_CONFIG,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
        );
        defer words.deinit();
        if (words.words.len != shape.program_words) return error.V7TemplateProgramShapeMismatch;
        return fromSchedules(&prior, &row5, try row42_air.FixedSchedule.initFromTemplate(words.words));
    }

    pub fn requireCompletePreprocessing(_: *const TemplateManifestV7) error{V7TemplatePreprocessingUnavailable}!void {
        return error.V7TemplatePreprocessingUnavailable;
    }

    fn computeSeal(self: *const TemplateManifestV7) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.v6_template.seal);
        hashInt(&hash, u32, self.row5_active_rows);
        hash.update(&self.row5_preprocessed_id);
        hash.update(&self.row42_preprocessed_id);
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

/// Hash all fixed columns, column-major in logical row order. The AIR writer
/// deterministically permutes logical rows into committed order; the digest
/// includes zero padding up to the exact committed trace capacity.
pub fn row5FixedColumnsId(template: *const row5_template.Template, log_size: u32) ![32]u8 {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidV7TemplateRow5Geometry;
    const capacity = @as(usize, 1) << @intCast(log_size);
    if (template.rows.len > capacity) return error.InvalidV7TemplateRow5Geometry;
    var hash = fixedColumnsHasher(5, log_size, row5_air.PREPROCESSED_COLUMN_COUNT, row5_air.SEMANTIC_DIGEST);
    for (0..row5_air.PREPROCESSED_COLUMN_COUNT) |column| for (0..capacity) |row| {
        const value = if (row < template.rows.len)
            template.rows[row][row5_air.PHYSICAL_MAIN_COLUMN_COUNT + column]
        else
            M31.zero();
        hashInt(&hash, u32, value.toU32());
    };
    return hash.finalResult();
}

pub fn row42FixedColumnsId(fixed: row42_air.FixedSchedule) ![32]u8 {
    var hash = fixedColumnsHasher(42, fixed.log_size, row42_air.PREPROCESSED_COLUMN_COUNT, row42_air.SEMANTIC_DIGEST);
    for (0..row42_air.PREPROCESSED_COLUMN_COUNT) |column| for (0..fixed.rowCapacity()) |row| {
        const values = try fixed.preprocessedRow(row);
        hashInt(&hash, u32, values[column].toU32());
    };
    return hash.finalResult();
}

fn fixedColumnsHasher(row: u8, log_size: u32, column_count: usize, semantic_digest: [32]u8) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(FIXED_COLUMNS_DOMAIN);
    hashInt(&hash, u8, row);
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u16, @intCast(column_count));
    hash.update(&semantic_digest);
    return hash;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V7 candidate key binds complete fixed columns and ignores distinct leaf values" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const v2 = @import("segment_outer_adapter_manifest_v2.zig");
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
    const key = try TemplateManifestV7.build(
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
    try key.validateAgainst(
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
    try std.testing.expectEqualDeep(row5_air.SEMANTIC_DIGEST, key.placements[5].geometry.semantic_digest);
    try std.testing.expect(key.placements[5].geometry.log_size > key.v6_template.placements[5].geometry.log_size);
    try std.testing.expectEqualDeep(row42_air.SEMANTIC_DIGEST, key.placements[42].geometry.semantic_digest);
    try std.testing.expect(!std.meta.eql(key.row42_preprocessed_id, key.v6_template.shape.row42_preprocessed_id));

    // These are two different V2 leaf authorities under the identical public
    // shape. Neither may alter a verifier-owned template key.
    const first_leaf = try v2.assemble(&source_catalog, fixture.authorityIds());
    var changed_ids = fixture.authorityIds();
    changed_ids.transcript_manifest_id[0] += 1;
    changed_ids.statement_manifest_id[0] += 1;
    const second_leaf = try v2.assemble(&source_catalog, changed_ids);
    try std.testing.expect(!std.meta.eql(first_leaf.seal, second_leaf.seal));
    const same_shape_key = try TemplateManifestV7.build(
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
    try std.testing.expectEqualDeep(key.seal, same_shape_key.seal);
    try std.testing.expectEqualDeep(key.row5_preprocessed_id, same_shape_key.row5_preprocessed_id);
    try std.testing.expectEqualDeep(key.row42_preprocessed_id, same_shape_key.row42_preprocessed_id);

    const changed_shape = shape_mod.Shape{ .program_words = shape.program_words, .base_poseidon_calls = shape.base_poseidon_calls + 1 };
    const changed_key = try TemplateManifestV7.build(
        allocator,
        &source_catalog,
        changed_shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
    );
    try std.testing.expect(!std.meta.eql(key.seal, changed_key.seal));
    try std.testing.expectError(error.V7TemplateAdmissionMismatch, key.validateAgainst(
        allocator,
        &source_catalog,
        changed_shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
    ));
    const wider_instructions = try @import("../transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        129,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const wider_shape = shape_mod.Shape{ .program_words = wider_instructions.canonical_program_word_count, .base_poseidon_calls = shape.base_poseidon_calls };
    const wider_key = try TemplateManifestV7.build(
        allocator,
        &source_catalog,
        wider_shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        129,
        false,
    );
    try std.testing.expect(!std.meta.eql(key.seal, wider_key.seal));
    try std.testing.expect(!std.meta.eql(key.row5_preprocessed_id, wider_key.row5_preprocessed_id));
    try std.testing.expect(!std.meta.eql(key.row42_preprocessed_id, wider_key.row42_preprocessed_id));
    var tampered = key;
    tampered.row5_preprocessed_id[0] ^= 1;
    try std.testing.expectError(error.InvalidV7TemplateManifest, tampered.validate());
    try std.testing.expectError(error.V7TemplatePreprocessingUnavailable, key.requireCompletePreprocessing());
}
