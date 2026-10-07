//! Candidate V10 direct-leaf key with exact fixed rows 27 and 29.
//!
//! V9 owns the verifier-selected transcript shape, VM/recursion plans and
//! row-28 fixed key. This version independently rebuilds the FRI-Merkle
//! anchor and canonical FRI arithmetic graph from that authority, sealing
//! every padded fixed cell and the corrected physical placements. It cannot
//! authorize a proof until the other direct-wrapper rows and detached verifier
//! are independently qualified.
const std = @import("std");
const v9 = @import("segment_leaf_wrapper_template_v9.zig");
const v6 = @import("segment_leaf_wrapper_template_v6.zig");
const catalog = @import("segment_outer_typed_catalog_v2.zig");
const shape_mod = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const statement = @import("../../air/statement.zig");
const schedule = @import("verifier_schedule.zig");
const query_mapping = @import("query_mapping_witness.zig");
const row27 = @import("../segment_core_fri_row27_fixed_v9.zig");
const row29 = @import("../segment_core_fri_row29_fixed_v9.zig");

pub const FORMAT_VERSION: u16 = 10;
pub const DOMAIN = "stwo-zig/riscv-leaf-template-manifest/v10\x00";
pub const COMPONENT_COUNT = v9.COMPONENT_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_TEMPLATE_PREPROCESSING_AVAILABLE = false;
pub const Placement = v9.Placement;

pub const TemplateManifestV10 = struct {
    v9_template: v9.TemplateManifestV9,
    row27_preprocessed_id: [32]u8,
    row29_graph_identity: [32]u8,
    row29_preprocessed_id: [32]u8,
    placements: [COMPONENT_COUNT]Placement,
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
        native_plan: *const schedule.Plan,
        core_profile: *const v6.CoreProfileV6,
        core_query_mapping: *const query_mapping.Reference,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
        admitted_shape: schedule.ScheduleShape,
    ) !TemplateManifestV10 {
        const prior = try v9.TemplateManifestV9.build(
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
            admitted_shape,
        );
        return fromVerifierTemplate(allocator, &prior);
    }

    pub fn fromVerifierTemplate(allocator: std.mem.Allocator, prior: *const v9.TemplateManifestV9) !TemplateManifestV10 {
        try prior.validate();
        var anchor = try row27.Writer.initFromVerifierTemplate(allocator, prior);
        defer anchor.deinit();
        var input = try row29.Writer.initFromVerifierTemplate(allocator, prior);
        defer input.deinit();
        const anchor_desc = try anchor.descriptor(prior);
        const input_desc = try input.descriptor(prior);
        try validateDescriptors(prior, anchor_desc, input_desc);
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (&placements, prior.placements, 0..) |*target, old, index| {
            const geometry = switch (index) {
                row27.ROW => anchor_desc.geometry,
                row29.ROW => input_desc.geometry,
                else => old.geometry,
            };
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
        var result = TemplateManifestV10{
            .v9_template = prior.*,
            .row27_preprocessed_id = anchor_desc.fixed_columns_id,
            .row29_graph_identity = input_desc.graph_identity,
            .row29_preprocessed_id = input_desc.fixed_columns_id,
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

    pub fn validate(self: *const TemplateManifestV10) !void {
        return self.validateWithAllocator(std.heap.page_allocator);
    }

    fn validateWithAllocator(self: *const TemplateManifestV10, allocator: std.mem.Allocator) !void {
        try self.v9_template.validate();
        var anchor = try row27.Writer.initFromVerifierTemplate(allocator, &self.v9_template);
        defer anchor.deinit();
        var input = try row29.Writer.initFromVerifierTemplate(allocator, &self.v9_template);
        defer input.deinit();
        const anchor_desc = try anchor.descriptor(&self.v9_template);
        const input_desc = try input.descriptor(&self.v9_template);
        try validateDescriptors(&self.v9_template, anchor_desc, input_desc);
        if (!std.meta.eql(self.row27_preprocessed_id, anchor_desc.fixed_columns_id) or
            !std.meta.eql(self.row29_graph_identity, input_desc.graph_identity) or
            !std.meta.eql(self.row29_preprocessed_id, input_desc.fixed_columns_id))
            return error.InvalidV10TemplateManifest;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.placements, self.v9_template.placements, 0..) |placement, old, index| {
            const geometry = switch (index) {
                row27.ROW => anchor_desc.geometry,
                row29.ROW => input_desc.geometry,
                else => old.geometry,
            };
            if (!std.meta.eql(placement.geometry, geometry) or
                placement.preprocessed_offset != pp or
                placement.main_offset != main or
                placement.interaction_offset != interaction or
                placement.constraint_offset != constraints or
                placement.claimed_sum_index != index)
                return error.InvalidV10TemplateManifest;
            pp = try std.math.add(u32, pp, geometry.preprocessed_columns);
            main = try std.math.add(u32, main, geometry.main_columns);
            interaction = try std.math.add(u32, interaction, geometry.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, geometry.direct_constraints) + geometry.interaction_batches);
        }
        if (pp != self.total_preprocessed_columns or
            main != self.total_main_columns or
            interaction != self.total_interaction_columns or
            constraints != self.total_constraints or
            !std.meta.eql(self.seal, self.computeSeal()))
            return error.InvalidV10TemplateManifest;
    }

    pub fn validateAgainst(
        self: *const TemplateManifestV10,
        allocator: std.mem.Allocator,
        base_catalog: *const catalog.Catalog,
        shape: shape_mod.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const schedule.Plan,
        core_profile: *const v6.CoreProfileV6,
        core_query_mapping: *const query_mapping.Reference,
        native_wire_word_count: u32,
        native_lookup_enabled: bool,
        admitted_shape: schedule.ScheduleShape,
    ) !void {
        try self.v9_template.validateAgainst(
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
            admitted_shape,
        );
        // V9 admission authenticates the external parameters. The local
        // validation below independently rebuilds both fixed descriptors,
        // corrected placements and the V10 seal, so rebuilding an identical
        // V10 key here would repeat the full fixed-column work.
        try self.validateWithAllocator(allocator);
    }

    pub fn admitRow27Writer(self: *const TemplateManifestV10, allocator: std.mem.Allocator, writer: *const row27.Writer) !void {
        try self.validateWithAllocator(allocator);
        const descriptor = try writer.descriptor(&self.v9_template);
        if (!std.meta.eql(descriptor.v9_template_seal, self.v9_template.seal) or
            !std.meta.eql(descriptor.vm_plan_digest, self.v9_template.v8_template.v7_template.v6_template.shape.native_plan_id) or
            !std.meta.eql(descriptor.recursion_plan_digest, self.v9_template.recursion_plan_digest) or
            !std.meta.eql(descriptor.geometry, self.placements[row27.ROW].geometry) or
            !std.meta.eql(descriptor.fixed_columns_id, self.row27_preprocessed_id))
            return error.V10Row27WriterAdmissionMismatch;
    }

    pub fn admitRow29Writer(self: *const TemplateManifestV10, allocator: std.mem.Allocator, writer: *const row29.Writer) !void {
        try self.validateWithAllocator(allocator);
        const descriptor = try writer.descriptor(&self.v9_template);
        if (!std.meta.eql(descriptor.v9_template_seal, self.v9_template.seal) or
            !std.meta.eql(descriptor.graph_identity, self.row29_graph_identity) or
            !std.meta.eql(descriptor.geometry, self.placements[row29.ROW].geometry) or
            !std.meta.eql(descriptor.fixed_columns_id, self.row29_preprocessed_id))
            return error.V10Row29WriterAdmissionMismatch;
    }

    pub fn requireCompletePreprocessing(_: *const TemplateManifestV10) error{V10TemplatePreprocessingUnavailable}!void {
        return error.V10TemplatePreprocessingUnavailable;
    }

    fn computeSeal(self: *const TemplateManifestV10) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.v9_template.seal);
        hash.update(&self.row27_preprocessed_id);
        hash.update(&self.row29_graph_identity);
        hash.update(&self.row29_preprocessed_id);
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

fn validateDescriptors(prior: *const v9.TemplateManifestV9, anchor: row27.FixedDescriptor, input: row29.FixedDescriptor) !void {
    if (!std.meta.eql(anchor.v9_template_seal, prior.seal) or
        !std.meta.eql(input.v9_template_seal, prior.seal) or
        !std.meta.eql(anchor.vm_plan_digest, prior.v8_template.v7_template.v6_template.shape.native_plan_id) or
        !std.meta.eql(anchor.recursion_plan_digest, prior.recursion_plan_digest) or
        anchor.geometry.roster_row != row27.ROW or
        input.geometry.roster_row != row29.ROW)
        return error.V10FixedDescriptorAuthorityMismatch;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V10 candidate seals rows27 and29 for two distinct admitted shapes" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const segment_profile = @import("../segment_profile.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const first_shape = try segment_profile.transcriptShape();
    const second_shape = try @import("../transcript_shape.zig").derive(
        segment_profile.circuitProfile(),
        segment_profile.TREE_HEIGHTS,
        .{
            .sampled_value_count = segment_profile.SAMPLED_VALUE_COUNT + 1,
            .queried_values_per_query = segment_profile.TABLE_COUNT + 1,
            .claimed_sum_count = segment_profile.CLAIMED_SUM_COUNT,
            .interaction_pow_bits = @import("../protocol.zig").INTERACTION_POW_BITS,
            .pcs_pow_bits = @import("../protocol.zig").PCS_POW_BITS,
        },
    );
    var prior_seal: ?[32]u8 = null;
    for ([_]schedule.ScheduleShape{ first_shape, second_shape }, 0..) |selected_shape, shape_index| {
        var vm = try schedule.Plan.initShape(allocator, try schedule.vmProgramSpec(16, 16), selected_shape);
        defer vm.deinit();
        const instructions = try @import("../transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
            allocator,
            &vm,
            128,
            &child_fixture.components,
            &child_fixture.infra,
            false,
        );
        const wrapper_shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
        const key = try TemplateManifestV10.build(
            allocator,
            &source_catalog,
            wrapper_shape,
            &child_fixture.components,
            &child_fixture.infra,
            &vm,
            &profile,
            &mapping,
            128,
            false,
            selected_shape,
        );
        try key.validateAgainst(
            allocator,
            &source_catalog,
            wrapper_shape,
            &child_fixture.components,
            &child_fixture.infra,
            &vm,
            &profile,
            &mapping,
            128,
            false,
            selected_shape,
        );
        if (shape_index == 0) try std.testing.expectError(error.V9ScheduleShapeMismatch, key.validateAgainst(
            allocator,
            &source_catalog,
            wrapper_shape,
            &child_fixture.components,
            &child_fixture.infra,
            &vm,
            &profile,
            &mapping,
            128,
            false,
            second_shape,
        ));
        if (prior_seal) |prior| try std.testing.expect(!std.meta.eql(prior, key.seal));
        prior_seal = key.seal;
        try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
        try std.testing.expectError(error.V10TemplatePreprocessingUnavailable, key.requireCompletePreprocessing());
        if (shape_index != 0) continue;
        var anchor = try row27.Writer.initFromVerifierTemplate(allocator, &key.v9_template);
        defer anchor.deinit();
        var input = try row29.Writer.initFromVerifierTemplate(allocator, &key.v9_template);
        defer input.deinit();
        try key.admitRow27Writer(allocator, &anchor);
        try key.admitRow29Writer(allocator, &input);
        try std.testing.expectEqualDeep((try anchor.descriptor(&key.v9_template)).geometry, key.placements[row27.ROW].geometry);
        try std.testing.expectEqualDeep((try input.descriptor(&key.v9_template)).geometry, key.placements[row29.ROW].geometry);

        var changed_anchor = key;
        changed_anchor.row27_preprocessed_id[0] ^= 1;
        changed_anchor.seal = changed_anchor.computeSeal();
        try std.testing.expectError(error.InvalidV10TemplateManifest, changed_anchor.validate());
        var changed_input = key;
        changed_input.row29_preprocessed_id[0] ^= 1;
        changed_input.seal = changed_input.computeSeal();
        try std.testing.expectError(error.InvalidV10TemplateManifest, changed_input.validate());
        var changed_graph = key;
        changed_graph.row29_graph_identity[0] ^= 1;
        changed_graph.seal = changed_graph.computeSeal();
        try std.testing.expectError(error.InvalidV10TemplateManifest, changed_graph.validate());
        var changed_geometry = key;
        changed_geometry.placements[row27.ROW].geometry.semantic_digest[0] ^= 1;
        changed_geometry.seal = changed_geometry.computeSeal();
        try std.testing.expectError(error.InvalidV10TemplateManifest, changed_geometry.validate());
        var changed_offset = key;
        changed_offset.placements[row29.ROW].preprocessed_offset += 1;
        changed_offset.seal = changed_offset.computeSeal();
        try std.testing.expectError(error.InvalidV10TemplateManifest, changed_offset.validate());
    }
}
