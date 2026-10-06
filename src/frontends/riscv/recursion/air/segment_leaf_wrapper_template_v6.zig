//! Candidate fixed-key geometry for the 50-row direct leaf wrapper.
//!
//! This deliberately starts from the typed 39-row catalog, not the V2
//! manifest: the latter seals request-specific source identities. A complete
//! immutable preprocessing writer does not exist yet, so this module cannot
//! admit a root, key, proof, or publication.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const catalog_mod = @import("segment_outer_typed_catalog_v2.zig");
const geometry_mod = @import("universal_manifest_contract.zig");
const v4 = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const v5 = @import("segment_leaf_wrapper_roster_direct_v5.zig");
const link_manifest = @import("segment_leaf_wrapper_link_manifest_v3.zig");
const link_program = @import("../ethereum_leaf_link_program_v3.zig");
const child_program = @import("../ethereum_leaf_child_field_program_v1.zig");
const local = @import("../segment_leaf_wrapper_local_identity_v5.zig");
const statement = @import("../../air/statement.zig");
const hash_witness = @import("vm_public_claim_hash_witness.zig");
const frame_air = @import("transcript_word_direct_v4.zig");
const statement_air = @import("segment_leaf_statement_source_direct_v5.zig");
const program_air = @import("transcript_program_v2_field_bridge_v5.zig");
const typed = @import("universal_typed_component.zig");
const native_schedule = @import("verifier_schedule.zig");
const instruction_template = @import("../transcript_instruction_template_v6.zig");
const word_template = @import("../transcript_program_v2_template_words_v6.zig");
const frame_template = @import("../transcript_word_template_v6.zig");
const wrapper_profile = @import("../segment_leaf_wrapper_protocol_direct_v4.zig");

pub const FORMAT_VERSION: u16 = 6;
pub const COMPONENT_COUNT: usize = 50;
pub const DOMAIN = "stwo-zig/riscv-leaf-template-manifest/v6\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_TEMPLATE_PREPROCESSING_AVAILABLE = false;
pub const Geometry = geometry_mod.Geometry;
pub const Placement = geometry_mod.Placement;

/// Only dimensions, component mix, immutable program schedules and AIR IDs.
/// No native proof ID, wire ID, statement digest, Tree0 root, V2 manifest seal,
/// source receipt, or public value has a slot in this type.
pub const TemplateShapeV6 = struct {
    base_catalog_id: [32]u8,
    program_words: u32,
    base_poseidon_calls: u32,
    component_descriptors: u16,
    infra_descriptors: u16,
    link_schedule_id: [32]u8,
    local_schedule_id: [32]u8,
    native_plan_id: [8]u32,
    native_wire_word_count: u32,
    native_lookup_enabled: bool,
    native_instruction_schedule_id: [32]u8,
    /// Independently rebuilt complete row-42 fixed columns, including padding.
    row42_preprocessed_id: [32]u8,
    row4_preprocessed_id: [32]u8,
    /// Full shape-compiled row42 fixed columns; unlike the currently active
    /// V5 schedule this pins every proof-independent ProgramV2 word.
    row42_shape_preprocessed_id: [32]u8,
};

pub const TemplateManifestV6 = struct {
    shape: TemplateShapeV6,
    placements: [COMPONENT_COUNT]Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    poseidon_calls: v5.PoseidonCalls,
    seal: [32]u8,

    /// All inputs here are verifier admission parameters, never child proof
    /// fields. The API reconstructs the fixed link and local schedules itself.
    pub fn build(
        allocator: std.mem.Allocator,
        base_catalog: *const catalog_mod.Catalog,
        shape: v4.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const native_schedule.Plan,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
    ) !TemplateManifestV6 {
        try base_catalog.validate();
        if (shape.program_words == 0 or shape.base_poseidon_calls == 0 or
            shape.program_words > std.math.maxInt(u32) or
            shape.base_poseidon_calls > std.math.maxInt(u32) or
            component_descs.len > std.math.maxInt(u16) or
            infra_descs.len > std.math.maxInt(u16))
            return error.InvalidTemplateShapeV6;

        var link = try link_program.ProgramV3.init(allocator);
        defer link.deinit();
        var child = try child_program.ProgramV1.init(allocator, component_descs, infra_descs);
        defer child.deinit();
        const linked = try link_manifest.Manifest.build(allocator, &link);
        const child_layout = try local.Layout.init(&child);
        const local_schedule_id = try local.directScheduleId(&child);
        const native_instructions = try instruction_template.InstructionTemplateV6.build(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
        );
        if (shape.program_words != native_instructions.canonical_program_word_count)
            return error.NativeProgramWordCountMismatchV6;
        var row4_template = try frame_template.Template.buildFromAdmittedShape(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            native_lookup_enabled,
        );
        defer row4_template.deinit();
        const row4_capacity = try std.math.ceilPowerOfTwo(usize, @max(row4_template.rows.len, 16));
        const row4_log_size: u32 = @intCast(std.math.log2_int(usize, row4_capacity));

        const program_calls = try std.math.divCeil(usize, shape.program_words + 1, hash_witness.RATE);
        const base_calls = v4.PoseidonCalls{
            .base = shape.base_poseidon_calls,
            .metadata = link_program.METADATA_HASH_ROW_COUNT,
            .link = link_program.LINK_HASH_ROW_COUNT,
            .program = program_calls,
            .total = try checkedSum(&.{ shape.base_poseidon_calls, link_program.METADATA_HASH_ROW_COUNT, link_program.LINK_HASH_ROW_COUNT, program_calls }),
        };
        const calls = try v5.PoseidonCalls.init(base_calls, child.authority_hash.rows.len, child.receipt_hash.rows.len);
        const provider_log = try hash_witness.traceLogSize(calls.total);
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (&placements, 0..) |*placement, row| {
            var g: Geometry = if (row < 39)
                base_catalog.entries[row].geometry
            else if (row < 42)
                linked.placements[row].?.geometry
            else switch (row) {
                42 => manualGeometry(42, try hash_witness.traceLogSize(shape.program_words), program_air),
                43 => v4.FieldHashAdapter.manifestGeometry(.program_hash, try hash_witness.traceLogSize(program_calls)),
                44 => v4.Tree0Adapter.manifestGeometry(.tree0_field, 4),
                45 => v4.FieldHashAdapter.manifestGeometry(.metadata_hash, link.metadata_hash.log_size),
                46 => v4.FieldHashAdapter.manifestGeometry(.link_hash, link.link_hash.log_size),
                47 => v5.RouterAdapter.manifestGeometry(.local_router, child_layout.placements[0].log_size),
                48 => v5.HashAdapter.manifestGeometry(.local_authority_hash, child_layout.placements[1].log_size),
                49 => v5.HashAdapter.manifestGeometry(.local_receipt_hash, child_layout.placements[2].log_size),
                else => unreachable,
            };
            if (row == 4) g = manualGeometry(4, @max(g.log_size, row4_log_size), frame_air);
            if (row == 34) g.log_size = provider_log;
            if (row == 36) g = manualGeometry(36, g.log_size, statement_air);
            try g.validateForComponentCount(COMPONENT_COUNT);
            if (g.roster_row != row) return error.InvalidTemplateGeometryV6;
            placement.* = .{
                .geometry = g,
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
                .constraint_offset = constraints,
                .claimed_sum_index = @intCast(row),
            };
            pp = try std.math.add(u32, pp, g.preprocessed_columns);
            main = try std.math.add(u32, main, g.main_columns);
            interaction = try std.math.add(u32, interaction, g.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, g.direct_constraints) + g.interaction_batches);
        }
        var result = TemplateManifestV6{
            .shape = .{
                .base_catalog_id = base_catalog.identity,
                .program_words = @intCast(shape.program_words),
                .base_poseidon_calls = @intCast(shape.base_poseidon_calls),
                .component_descriptors = @intCast(component_descs.len),
                .infra_descriptors = @intCast(infra_descs.len),
                .link_schedule_id = link.schedule_id,
                .local_schedule_id = local_schedule_id,
                .native_plan_id = native_instructions.native_plan_id,
                .native_wire_word_count = native_instructions.wire_word_count,
                .native_lookup_enabled = native_instructions.lookup_enabled,
                .native_instruction_schedule_id = native_instructions.schedule_id,
                .row42_preprocessed_id = try row42PreprocessedShaId(shape.program_words),
                .row4_preprocessed_id = try row4_template.preprocessedId(placements[4].geometry.log_size),
                .row42_shape_preprocessed_id = try row42ShapePreprocessedShaId(
                    allocator,
                    native_plan,
                    native_wire_word_count,
                    component_descs,
                    infra_descs,
                    native_lookup_enabled,
                ),
            },
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .poseidon_calls = calls,
            .seal = undefined,
        };
        result.seal = templateSeal(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const TemplateManifestV6) !void {
        try self.poseidon_calls.validate();
        if (self.shape.program_words == 0 or self.shape.base_poseidon_calls == 0 or
            !std.mem.eql(u8, &self.shape.row42_preprocessed_id, &(try row42PreprocessedShaId(self.shape.program_words))) or
            !std.mem.eql(u8, &self.seal, &templateSeal(self)))
            return error.InvalidTemplateManifestV6;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.placements, 0..) |placement, row| {
            const g = placement.geometry;
            try g.validateForComponentCount(COMPONENT_COUNT);
            if (g.roster_row != row or placement.claimed_sum_index != row or
                placement.preprocessed_offset != pp or placement.main_offset != main or
                placement.interaction_offset != interaction or placement.constraint_offset != constraints)
                return error.InvalidTemplateManifestV6;
            pp = try std.math.add(u32, pp, g.preprocessed_columns);
            main = try std.math.add(u32, main, g.main_columns);
            interaction = try std.math.add(u32, interaction, g.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, g.direct_constraints) + g.interaction_batches);
        }
        if (pp != self.total_preprocessed_columns or main != self.total_main_columns or
            interaction != self.total_interaction_columns or constraints != self.total_constraints)
            return error.InvalidTemplateManifestV6;
    }

    /// Rebuild against the independently selected verifier template. This
    /// compares every geometry and schedule field, not just a cached seal.
    pub fn validateAgainst(
        self: *const TemplateManifestV6,
        allocator: std.mem.Allocator,
        base_catalog: *const catalog_mod.Catalog,
        shape: v4.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const native_schedule.Plan,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
    ) !void {
        try self.validate();
        const rebuilt = try build(allocator, base_catalog, shape, component_descs, infra_descs, native_plan, native_wire_word_count, native_lookup_enabled);
        if (!std.meta.eql(self.*, rebuilt)) return error.TemplateAdmissionMismatchV6;
    }

    pub fn requireCompletePreprocessing(_: *const TemplateManifestV6) error{TemplatePreprocessingUnavailable}!void {
        return error.TemplatePreprocessingUnavailable;
    }
};

fn manualGeometry(row: u8, log_size: u32, comptime Air: type) Geometry {
    return .{
        .roster_row = row,
        .log_size = log_size,
        .preprocessed_columns = Air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = Air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = Air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = Air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = Air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(Air)),
        .profiled_constraint_degree = Air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = Air.SEMANTIC_DIGEST,
    };
}

/// Actual fixed-column bytes for V5 row 42, rebuilt without a native proof,
/// ProgramV2 instance, V2 manifest, or child-carried expected word. This is
/// one completed subtable, not a 50-row preprocessing root.
pub fn row42PreprocessedShaId(word_count: usize) ![32]u8 {
    const schedule = try program_air.FixedSchedule.init(word_count);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv-v6-row42-fixed-columns/v1\x00");
    hashInt(&hash, u32, schedule.word_count);
    hashInt(&hash, u8, schedule.log_size);
    for (0..schedule.rowCapacity()) |row| {
        const values = try schedule.preprocessedRow(row);
        for (values) |value| hashInt(&hash, u32, value.toU32());
    }
    return hash.finalResult();
}

pub fn row42ShapePreprocessedShaId(
    allocator: std.mem.Allocator,
    native_plan: *const native_schedule.Plan,
    native_wire_word_count: u32,
    component_descs: []const statement.FamilyComponentDesc,
    infra_descs: []const statement.InfraComponentDesc,
    native_lookup_enabled: bool,
) ![32]u8 {
    var template = try word_template.Template.initFromShape(
        allocator,
        native_plan,
        wrapper_profile.PCS_CONFIG,
        native_wire_word_count,
        component_descs,
        infra_descs,
        native_lookup_enabled,
    );
    defer template.deinit();
    const geometry = try program_air.FixedSchedule.init(template.words.len);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv-v6-row42-shape-columns/v1\x00");
    hashInt(&hash, u32, geometry.word_count);
    hashInt(&hash, u8, geometry.log_size);
    for (0..geometry.rowCapacity()) |row| {
        const values = if (row < template.words.len)
            try template.preprocessedRow(row)
        else
            [_]M31{M31.zero()} ** program_air.PREPROCESSED_COLUMN_COUNT;
        for (values) |value| hashInt(&hash, u32, value.toU32());
    }
    return hash.finalResult();
}

fn templateSeal(value: *const TemplateManifestV6) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&value.shape.base_catalog_id);
    inline for (.{ value.shape.program_words, value.shape.base_poseidon_calls }) |n| hashInt(&hash, u32, n);
    inline for (.{ value.shape.component_descriptors, value.shape.infra_descriptors }) |n| hashInt(&hash, u16, n);
    hash.update(&value.shape.link_schedule_id);
    hash.update(&value.shape.local_schedule_id);
    for (value.shape.native_plan_id) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.shape.native_wire_word_count);
    hashInt(&hash, u8, @intFromBool(value.shape.native_lookup_enabled));
    hash.update(&value.shape.native_instruction_schedule_id);
    hash.update(&value.shape.row42_preprocessed_id);
    hash.update(&value.shape.row4_preprocessed_id);
    hash.update(&value.shape.row42_shape_preprocessed_id);
    for (value.placements) |placement| {
        const g = placement.geometry;
        hashInt(&hash, u8, g.roster_row);
        hashInt(&hash, u32, g.log_size);
        inline for (.{ g.preprocessed_columns, g.main_columns, g.interaction_columns, g.direct_constraints, g.interaction_batches }) |n| hashInt(&hash, u16, n);
        hashInt(&hash, u8, g.protocol_constraint_degree);
        hashInt(&hash, u8, g.profiled_constraint_degree);
        hash.update(&g.semantic_digest);
        inline for (.{ placement.preprocessed_offset, placement.main_offset, placement.interaction_offset, placement.constraint_offset }) |n| hashInt(&hash, u32, n);
        hashInt(&hash, u8, placement.claimed_sum_index);
    }
    inline for (.{ value.total_preprocessed_columns, value.total_main_columns, value.total_interaction_columns, value.total_constraints }) |n| hashInt(&hash, u32, n);
    for (value.poseidon_calls.ordered()) |range| {
        hashInt(&hash, u64, @intCast(range.start));
        hashInt(&hash, u64, @intCast(range.count));
    }
    hashInt(&hash, u64, @intCast(value.poseidon_calls.total));
    return hash.finalResult();
}

fn checkedSum(values: []const usize) !usize {
    var result: usize = 0;
    for (values) |value| result = try std.math.add(usize, result, value);
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "V6 template geometry is rebuilt without either leaf V2 manifest seal" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const v2 = @import("segment_outer_adapter_manifest_v2.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const base_catalog = try catalog_mod.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("../segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const native = try instruction_template.InstructionTemplateV6.build(allocator, &plans.vm, 128, &child_fixture.components, &child_fixture.infra, false);
    var lookup_components = child_fixture.components;
    const lookup_manifest = @import("../../air/lang/lookup_physical_manifest_v2.zig").Manifest.native();
    for (&lookup_components) |*descriptor| descriptor.n_columns = lookup_manifest.entryForFamily(descriptor.family).main_column_count;
    const without_lookup = try instruction_template.InstructionTemplateV6.build(allocator, &plans.vm, 128, &lookup_components, &child_fixture.infra, false);
    const with_lookup = try instruction_template.InstructionTemplateV6.build(allocator, &plans.vm, 128, &lookup_components, &child_fixture.infra, true);
    try std.testing.expect(!std.meta.eql(without_lookup.schedule_id, with_lookup.schedule_id));
    try std.testing.expect(with_lookup.canonical_program_word_count > without_lookup.canonical_program_word_count);
    const shape = v4.Shape{ .program_words = native.canonical_program_word_count, .base_poseidon_calls = 1193 };
    const template = try TemplateManifestV6.build(allocator, &base_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false);
    try template.validateAgainst(allocator, &base_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false);
    var tampered_row4 = template;
    tampered_row4.shape.row4_preprocessed_id[0] ^= 1;
    try std.testing.expectError(error.InvalidTemplateManifestV6, tampered_row4.validate());

    const first = try v2.assemble(&base_catalog, fixture.authorityIds());
    var changed_ids = fixture.authorityIds();
    changed_ids.transcript_manifest_id[0] += 1;
    changed_ids.statement_manifest_id[0] += 1;
    const second = try v2.assemble(&base_catalog, changed_ids);
    try std.testing.expect(!std.meta.eql(first.seal, second.seal));

    var link = try link_program.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try child_program.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const first_v5 = try v5.Plan.build(allocator, &first, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    const second_v5 = try v5.Plan.build(allocator, &second, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    try std.testing.expect(!std.meta.eql(first_v5.seal, second_v5.seal));
    for (template.placements, 0..) |placement, row| {
        if (row == 4) {
            try std.testing.expect(placement.geometry.log_size >= first_v5.placements[row].?.geometry.log_size);
            continue;
        }
        try std.testing.expect(std.meta.eql(placement, first_v5.placements[row].?));
        try std.testing.expect(std.meta.eql(placement, second_v5.placements[row].?));
    }
    try std.testing.expectError(error.TemplatePreprocessingUnavailable, template.requireCompletePreprocessing());

    const changed_shape = v4.Shape{ .program_words = shape.program_words, .base_poseidon_calls = 1194 };
    const other_template = try TemplateManifestV6.build(allocator, &base_catalog, changed_shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false);
    try std.testing.expect(!std.meta.eql(template.seal, other_template.seal));
    try std.testing.expectError(error.TemplateAdmissionMismatchV6, template.validateAgainst(allocator, &base_catalog, changed_shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false));
    try std.testing.expectError(error.NativeProgramWordCountMismatchV6, TemplateManifestV6.build(allocator, &base_catalog, .{ .program_words = shape.program_words + 1, .base_poseidon_calls = 1193 }, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, false));
    try std.testing.expectError(error.InvalidMainGeometry, TemplateManifestV6.build(allocator, &base_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, 128, true));
    var corrupted = template;
    corrupted.placements[42].geometry.log_size += 1;
    try std.testing.expectError(error.InvalidTemplateManifestV6, corrupted.validate());
}
