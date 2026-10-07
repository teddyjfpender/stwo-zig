//! Candidate V9 direct-leaf fixed key with admitted recursion FRI-control plan.
//!
//! The verifier selects one transcript `ScheduleShape`, recompiles both the
//! VM and recursion plans from it, and checks the VM plan against the V8 key.
//! The actual recursion plan digest and every committed row-28 fixed cell are
//! then sealed in a new key. No child proof or captured row chooses either
//! plan. Complete 50-row preprocessing and proof activation remain absent.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const v8 = @import("segment_leaf_wrapper_template_v8.zig");
const v6 = @import("segment_leaf_wrapper_template_v6.zig");
const catalog = @import("segment_outer_typed_catalog_v2.zig");
const shape_mod = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const statement = @import("../../air/statement.zig");
const schedule = @import("verifier_schedule.zig");
const query_mapping = @import("query_mapping_witness.zig");
const row28 = @import("../segment_core_fri_row28_fixed_v8.zig");
const row28_air = @import("fri_verifier_control.zig");

pub const FORMAT_VERSION: u16 = 9;
pub const DOMAIN = "stwo-zig/riscv-leaf-template-manifest/v9\x00";
pub const ROW28_FIXED_DOMAIN = "stwo-zig/riscv-v9-row28-complete-fixed-columns/v1\x00";
pub const COMPONENT_COUNT = v8.COMPONENT_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_TEMPLATE_PREPROCESSING_AVAILABLE = false;
pub const Placement = v8.Placement;

pub const TemplateManifestV9 = struct {
    v8_template: v8.TemplateManifestV8,
    schedule_shape: schedule.ScheduleShape,
    vm_program_spec: schedule.ProgramSpec,
    recursion_plan_digest: [8]u32,
    row28_preprocessed_id: [32]u8,
    placements: [COMPONENT_COUNT]Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    /// The caller chooses `admitted_shape` from verifier policy, before
    /// reading a child proof. Both programs are recompiled from that shape.
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
    ) !TemplateManifestV9 {
        const prior = try v8.TemplateManifestV8.build(
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
        return fromVerifierTemplate(allocator, &prior, native_plan, admitted_shape);
    }

    pub fn fromVerifierTemplate(
        allocator: std.mem.Allocator,
        prior: *const v8.TemplateManifestV8,
        native_plan: *const schedule.Plan,
        admitted_shape: schedule.ScheduleShape,
    ) !TemplateManifestV9 {
        try prior.validate();
        try native_plan.validate();
        try admitted_shape.validate();
        try requireShapeMatchesProfile(admitted_shape, &prior.v7_template.v6_template.shape.core_profile);
        if (native_plan.schema != .vm or
            !std.meta.eql(native_plan.authority_digest, prior.v7_template.v6_template.shape.native_plan_id))
            return error.V9NativePlanAdmissionMismatch;
        var rebuilt_vm = try schedule.Plan.initShape(allocator, native_plan.spec, admitted_shape);
        defer rebuilt_vm.deinit();
        if (!std.meta.eql(rebuilt_vm.authority_digest, native_plan.authority_digest))
            return error.V9ScheduleShapeMismatch;
        var recursion = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, admitted_shape);
        defer recursion.deinit();
        var fixed = try row28.Writer.init(
            allocator,
            &prior.v7_template.v6_template.shape.core_profile,
            &rebuilt_vm,
            &recursion,
        );
        defer fixed.deinit();
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (&placements, prior.placements, 0..) |*target, old, index| {
            const geometry = if (index == row28.ROW) fixed.geometry() else old.geometry;
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
        var result = TemplateManifestV9{
            .v8_template = prior.*,
            .schedule_shape = admitted_shape,
            .vm_program_spec = native_plan.spec,
            .recursion_plan_digest = recursion.authority_digest,
            .row28_preprocessed_id = try row28FixedColumnsId(allocator, &fixed),
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        try result.validateWithAllocator(allocator);
        return result;
    }

    pub fn validate(self: *const TemplateManifestV9) !void {
        return self.validateWithAllocator(std.heap.page_allocator);
    }

    fn validateWithAllocator(self: *const TemplateManifestV9, allocator: std.mem.Allocator) !void {
        try self.v8_template.validate();
        try self.schedule_shape.validate();
        try requireShapeMatchesProfile(self.schedule_shape, &self.v8_template.v7_template.v6_template.shape.core_profile);
        if (self.vm_program_spec.schema != .vm) return error.InvalidV9TemplateManifest;
        var vm = try schedule.Plan.initShape(allocator, self.vm_program_spec, self.schedule_shape);
        defer vm.deinit();
        if (!std.meta.eql(vm.authority_digest, self.v8_template.v7_template.v6_template.shape.native_plan_id))
            return error.InvalidV9TemplateManifest;
        var recursion = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, self.schedule_shape);
        defer recursion.deinit();
        if (!std.meta.eql(self.recursion_plan_digest, recursion.authority_digest))
            return error.InvalidV9TemplateManifest;
        var fixed = try row28.Writer.init(
            allocator,
            &self.v8_template.v7_template.v6_template.shape.core_profile,
            &vm,
            &recursion,
        );
        defer fixed.deinit();
        if (!std.meta.eql(self.row28_preprocessed_id, try row28FixedColumnsId(allocator, &fixed)))
            return error.InvalidV9TemplateManifest;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.placements, self.v8_template.placements, 0..) |placement, old, index| {
            const geometry = if (index == row28.ROW) fixed.geometry() else old.geometry;
            if (!std.meta.eql(placement.geometry, geometry) or
                placement.preprocessed_offset != pp or
                placement.main_offset != main or
                placement.interaction_offset != interaction or
                placement.constraint_offset != constraints or
                placement.claimed_sum_index != index)
                return error.InvalidV9TemplateManifest;
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
            return error.InvalidV9TemplateManifest;
    }

    pub fn validateAgainst(
        self: *const TemplateManifestV9,
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
        try self.validateWithAllocator(allocator);
        try self.v8_template.validateAgainst(
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
        const rebuilt = try fromVerifierTemplate(allocator, &self.v8_template, native_plan, admitted_shape);
        if (!std.meta.eql(self.*, rebuilt)) return error.V9TemplateAdmissionMismatch;
    }

    pub fn requireCompletePreprocessing(_: *const TemplateManifestV9) error{V9TemplatePreprocessingUnavailable}!void {
        return error.V9TemplatePreprocessingUnavailable;
    }

    /// Admit a physical row-28 writer against this candidate key. The writer
    /// may borrow plans, but their current full schedule authorities and all
    /// fixed cells must match the verifier-rebuilt V9 template exactly.
    pub fn admitRow28Writer(self: *const TemplateManifestV9, allocator: std.mem.Allocator, writer: *const row28.Writer) !void {
        try self.validateWithAllocator(allocator);
        try writer.reference.validateAuthority();
        if (!std.meta.eql(writer.profile, self.v8_template.v7_template.v6_template.shape.core_profile) or
            !std.meta.eql(writer.reference.vm.plan.authority_digest, self.v8_template.v7_template.v6_template.shape.native_plan_id) or
            !std.meta.eql(writer.reference.recursion.plan.authority_digest, self.recursion_plan_digest) or
            !std.meta.eql(writer.geometry(), self.placements[row28.ROW].geometry) or
            !std.meta.eql(try row28FixedColumnsId(allocator, writer), self.row28_preprocessed_id))
            return error.V9Row28WriterAdmissionMismatch;
    }

    fn computeSeal(self: *const TemplateManifestV9) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.v8_template.seal);
        for (self.schedule_shape.protocol_id) |word| hashInt(&hash, u32, word);
        for (self.schedule_shape.shape_id) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u16, @intFromEnum(self.vm_program_spec.schema));
        inline for (.{ self.vm_program_spec.relation_challenge_count, self.vm_program_spec.public_logup_term_count, self.vm_program_spec.air_instruction_count, self.vm_program_spec.relation_closure_count }) |count|
            hashInt(&hash, u32, count);
        for (self.recursion_plan_digest) |word| hashInt(&hash, u32, word);
        hash.update(&self.row28_preprocessed_id);
        for (self.placements) |placement| {
            const g = placement.geometry;
            hashInt(&hash, u8, g.roster_row);
            hashInt(&hash, u32, g.log_size);
            inline for (.{ g.preprocessed_columns, g.main_columns, g.interaction_columns, g.direct_constraints, g.interaction_batches }) |count|
                hashInt(&hash, u16, count);
            hashInt(&hash, u8, g.protocol_constraint_degree);
            hashInt(&hash, u8, g.profiled_constraint_degree);
            hash.update(&g.semantic_digest);
            inline for (.{ placement.preprocessed_offset, placement.main_offset, placement.interaction_offset, placement.constraint_offset }) |offset|
                hashInt(&hash, u32, offset);
            hashInt(&hash, u8, placement.claimed_sum_index);
        }
        inline for (.{ self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints }) |total|
            hashInt(&hash, u32, total);
        return hash.finalResult();
    }
};

fn row28FixedColumnsId(allocator: std.mem.Allocator, fixed: *const row28.Writer) ![32]u8 {
    const geometry = fixed.geometry();
    const capacity = @as(usize, 1) << @intCast(geometry.log_size);
    const columns = try allocator.alloc([]M31, geometry.preprocessed_columns);
    defer allocator.free(columns);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
    }
    defer for (columns) |column| allocator.free(column);
    try fixed.writePhysical(geometry, columns);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROW28_FIXED_DOMAIN);
    hashInt(&hash, u8, row28.ROW);
    hashInt(&hash, u32, geometry.log_size);
    hashInt(&hash, u16, geometry.preprocessed_columns);
    hash.update(&row28_air.SEMANTIC_DIGEST);
    for (columns) |column| for (column) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn requireShapeMatchesProfile(shape: schedule.ScheduleShape, profile: *const v6.CoreProfileV6) !void {
    _ = try profile.reference();
    if (profile.vm.query_count != shape.query_count or
        profile.recursion.query_count != shape.query_count or
        profile.vm.tree_count != shape.tree_heights.len or
        profile.recursion.tree_count != shape.tree_heights.len or
        profile.vm.fri_count != shape.fri.count or
        profile.recursion.fri_count != shape.fri.count or
        profile.vm.lifting_log_size != shape.fri.active()[0].evaluation_log or
        profile.recursion.lifting_log_size != shape.fri.active()[0].evaluation_log)
        return error.V9ProfileShapeMismatch;
    for (shape.tree_heights, 0..) |height, index| {
        if (profile.vm.tree_heights[index] != height or profile.recursion.tree_heights[index] != height)
            return error.V9ProfileShapeMismatch;
    }
    for (shape.fri.active(), 0..) |round, index| {
        if (profile.vm.fri_fold_widths[index] != round.fold_width or
            profile.recursion.fri_fold_widths[index] != round.fold_width)
            return error.V9ProfileShapeMismatch;
    }
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V9 candidate binds actual recursion plan digest for two admitted shapes" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const segment_profile = @import("../segment_profile.zig");
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
    var prior_recursion: ?[8]u32 = null;
    for ([_]schedule.ScheduleShape{ first_shape, second_shape }) |selected_shape| {
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
        const key = try TemplateManifestV9.build(
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
        try std.testing.expectEqualDeep(row28_air.SEMANTIC_DIGEST, key.placements[row28.ROW].geometry.semantic_digest);
        var recursion = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, selected_shape);
        defer recursion.deinit();
        var physical = try row28.Writer.init(allocator, &profile, &vm, &recursion);
        defer physical.deinit();
        try key.admitRow28Writer(allocator, &physical);
        physical.preprocessing.rows[0].tag += 1;
        try std.testing.expectError(error.AuthorityMismatch, key.admitRow28Writer(allocator, &physical));
        physical.preprocessing.rows[0].tag -= 1;
        try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
        try std.testing.expectError(error.V9TemplatePreprocessingUnavailable, key.requireCompletePreprocessing());
        if (prior_seal) |prior| {
            try std.testing.expect(!std.meta.eql(prior, key.seal));
            try std.testing.expect(!std.meta.eql(prior_recursion.?, key.recursion_plan_digest));
        }
        prior_seal = key.seal;
        prior_recursion = key.recursion_plan_digest;

        var changed_plan = key;
        changed_plan.recursion_plan_digest[0] +%= 1;
        changed_plan.seal = changed_plan.computeSeal();
        try std.testing.expectError(error.InvalidV9TemplateManifest, changed_plan.validate());
        var changed_fixed = key;
        changed_fixed.row28_preprocessed_id[0] ^= 1;
        changed_fixed.seal = changed_fixed.computeSeal();
        try std.testing.expectError(error.InvalidV9TemplateManifest, changed_fixed.validate());
        var changed_shape = selected_shape;
        changed_shape.table_count += 1;
        try std.testing.expectError(error.V9ScheduleShapeMismatch, TemplateManifestV9.fromVerifierTemplate(allocator, &key.v8_template, &vm, changed_shape));
        changed_shape = selected_shape;
        changed_shape.tree_heights[0] -= 1;
        try std.testing.expectError(error.V9ProfileShapeMismatch, TemplateManifestV9.fromVerifierTemplate(allocator, &key.v8_template, &vm, changed_shape));
    }
}
