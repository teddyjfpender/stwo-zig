//! Candidate V11 direct-leaf key for exact trace-Merkle and PCS-DEEP rows.
//!
//! A verifier-selected ordered column/sample/mask profile, supplied before
//! any child capture, reconstructs rows 23 and 24. This key seals their full
//! padded Tree0 columns and the PCS arithmetic graph on top of V10. It is not
//! a complete 50-row preprocessing key and cannot activate a proof.
const std = @import("std");
const v10 = @import("segment_leaf_wrapper_template_v10.zig");
const row23 = @import("../segment_core_trace_row23_fixed_v11.zig");
const row24 = @import("../segment_core_pcs_row24_fixed_v11.zig");
const pcs_circuit = @import("pcs_deep_circuit.zig");

pub const FORMAT_VERSION: u16 = 11;
pub const DOMAIN = "stwo-zig/riscv-leaf-template-manifest/v11\x00";
pub const COMPONENT_COUNT = v10.COMPONENT_COUNT;
pub const Placement = v10.Placement;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_TEMPLATE_PREPROCESSING_AVAILABLE = false;

pub const TemplateManifestV11 = struct {
    v10_template: v10.TemplateManifestV10,
    ordered_layout_id: [32]u8,
    pcs_profile_identity: [32]u8,
    pcs_circuit_identity: [32]u8,
    row23_preprocessed_id: [32]u8,
    row24_preprocessed_id: [32]u8,
    placements: [COMPONENT_COUNT]Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn buildFromVerifierProfile(
        allocator: std.mem.Allocator,
        prior: *const v10.TemplateManifestV10,
        expected: row24.ExpectedProfile,
    ) !TemplateManifestV11 {
        try prior.validate();
        try expected.validateAgainst(prior);
        const layout = row23.ExpectedLayout{
            .vm_trees = expected.ordered_tree_logs,
            .recursion_trees = expected.ordered_tree_logs,
        };
        var trace = try row23.Writer.initFromExpectedLayout(allocator, prior, layout);
        defer trace.deinit();
        var pcs = try row24.Writer.initFromExpectedProfile(allocator, prior, expected);
        defer pcs.deinit();
        const trace_desc = try trace.descriptor(prior);
        const pcs_desc = try pcs.descriptor(prior);
        try validateDescriptors(prior, trace_desc, pcs_desc);
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (&placements, prior.placements, 0..) |*target, old, index| {
            const geometry = switch (index) {
                row23.ROW => trace_desc.geometry,
                row24.ROW => pcs_desc.geometry,
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
        var result = TemplateManifestV11{
            .v10_template = prior.*,
            .ordered_layout_id = trace_desc.ordered_layout_id,
            .pcs_profile_identity = pcs_desc.profile_identity,
            .pcs_circuit_identity = pcs_desc.circuit_identity,
            .row23_preprocessed_id = trace_desc.fixed_columns_id,
            .row24_preprocessed_id = pcs_desc.fixed_columns_id,
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

    /// Admission requires the original verifier-selected profile again;
    /// digest-only or captured-child inputs cannot instantiate the key.
    pub fn validateAgainstAuthority(
        self: *const TemplateManifestV11,
        allocator: std.mem.Allocator,
        prior: *const v10.TemplateManifestV10,
        expected: row24.ExpectedProfile,
    ) !void {
        if (!std.meta.eql(self.v10_template, prior.*) or
            !std.meta.eql(self.seal, self.computeSeal()))
            return error.InvalidV11TemplateManifest;
        const rebuilt = try buildFromVerifierProfile(allocator, prior, expected);
        if (!std.meta.eql(self.*, rebuilt)) return error.InvalidV11TemplateManifest;
    }

    pub fn admitRow23Writer(
        self: *const TemplateManifestV11,
        allocator: std.mem.Allocator,
        expected: row24.ExpectedProfile,
        writer: *const row23.Writer,
    ) !void {
        try self.validateAgainstAuthority(allocator, &self.v10_template, expected);
        const descriptor = try writer.descriptor(&self.v10_template);
        if (!std.meta.eql(descriptor.v10_template_seal, self.v10_template.seal) or
            !std.meta.eql(descriptor.ordered_layout_id, self.ordered_layout_id) or
            !std.meta.eql(descriptor.geometry, self.placements[row23.ROW].geometry) or
            !std.meta.eql(descriptor.fixed_columns_id, self.row23_preprocessed_id))
            return error.V11Row23WriterAdmissionMismatch;
    }

    /// Cold admission for the complete V11 pair. Both fixed tables are
    /// reconstructed once, then both externally held writers are checked
    /// against the same authenticated key and layout.
    pub fn admitBothWriters(
        self: *const TemplateManifestV11,
        allocator: std.mem.Allocator,
        expected: row24.ExpectedProfile,
        trace_writer: *const row23.Writer,
        pcs_writer: *const row24.Writer,
    ) !void {
        try self.validateAgainstAuthority(allocator, &self.v10_template, expected);
        const trace_desc = try trace_writer.descriptor(&self.v10_template);
        const pcs_desc = try pcs_writer.descriptor(&self.v10_template);
        try validateDescriptors(&self.v10_template, trace_desc, pcs_desc);
        if (!std.meta.eql(trace_desc.ordered_layout_id, self.ordered_layout_id) or
            !std.meta.eql(trace_desc.geometry, self.placements[row23.ROW].geometry) or
            !std.meta.eql(trace_desc.fixed_columns_id, self.row23_preprocessed_id))
            return error.V11Row23WriterAdmissionMismatch;
        if (!std.meta.eql(pcs_desc.profile_identity, self.pcs_profile_identity) or
            !std.meta.eql(pcs_desc.circuit_identity, self.pcs_circuit_identity) or
            !std.meta.eql(pcs_desc.geometry, self.placements[row24.ROW].geometry) or
            !std.meta.eql(pcs_desc.fixed_columns_id, self.row24_preprocessed_id))
            return error.V11Row24WriterAdmissionMismatch;
    }

    pub fn admitRow24Writer(
        self: *const TemplateManifestV11,
        allocator: std.mem.Allocator,
        expected: row24.ExpectedProfile,
        writer: *const row24.Writer,
    ) !void {
        try self.validateAgainstAuthority(allocator, &self.v10_template, expected);
        const descriptor = try writer.descriptor(&self.v10_template);
        if (!std.meta.eql(descriptor.v10_template_seal, self.v10_template.seal) or
            !std.meta.eql(descriptor.ordered_layout_id, self.ordered_layout_id) or
            !std.meta.eql(descriptor.profile_identity, self.pcs_profile_identity) or
            !std.meta.eql(descriptor.circuit_identity, self.pcs_circuit_identity) or
            !std.meta.eql(descriptor.geometry, self.placements[row24.ROW].geometry) or
            !std.meta.eql(descriptor.fixed_columns_id, self.row24_preprocessed_id))
            return error.V11Row24WriterAdmissionMismatch;
    }

    pub fn requireCompletePreprocessing(_: *const TemplateManifestV11) error{V11TemplatePreprocessingUnavailable}!void {
        return error.V11TemplatePreprocessingUnavailable;
    }

    fn computeSeal(self: *const TemplateManifestV11) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.v10_template.seal);
        hash.update(&self.ordered_layout_id);
        hash.update(&self.pcs_profile_identity);
        hash.update(&self.pcs_circuit_identity);
        hash.update(&self.row23_preprocessed_id);
        hash.update(&self.row24_preprocessed_id);
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

fn validateDescriptors(prior: *const v10.TemplateManifestV10, trace: row23.FixedDescriptor, pcs: row24.FixedDescriptor) !void {
    if (!std.meta.eql(trace.v10_template_seal, prior.seal) or
        !std.meta.eql(pcs.v10_template_seal, prior.seal) or
        !std.meta.eql(trace.ordered_layout_id, pcs.ordered_layout_id) or
        !std.meta.eql(trace.vm_plan_digest, prior.v9_template.v8_template.v7_template.v6_template.shape.native_plan_id) or
        !std.meta.eql(trace.recursion_plan_digest, prior.v9_template.recursion_plan_digest) or
        trace.geometry.roster_row != row23.ROW or
        pcs.geometry.roster_row != row24.ROW)
        return error.V11FixedDescriptorAuthorityMismatch;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V11 candidate admits exact rows23 and24 and rejects resealed drift" {
    const allocator = std.testing.allocator;
    const prior = try testPrior(allocator);
    const logs0 = [_]u32{21} ** 38;
    const logs1 = [_]u32{21} ** 625;
    const logs2 = [_]u32{21} ** 200;
    const logs3 = [_]u32{21} ** 8;
    const trees = [_][]const u32{ &logs0, &logs1, &logs2, &logs3 };
    var layouts = [_]pcs_circuit.SamplePointLayout{.current} ** 871;
    for (layouts[38 + 625 .. 38 + 625 + 200]) |*layout| layout.* = .current_previous;
    const expected = row24.ExpectedProfile{ .ordered_tree_logs = &trees, .sample_layouts = &layouts };
    const key = try TemplateManifestV11.buildFromVerifierProfile(allocator, &prior, expected);
    try key.validateAgainstAuthority(allocator, &prior, expected);
    try std.testing.expectEqualDeep(prior.seal, key.v10_template.seal);
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
    try std.testing.expectError(error.V11TemplatePreprocessingUnavailable, key.requireCompletePreprocessing());
    const selected_layout = row23.ExpectedLayout{ .vm_trees = &trees, .recursion_trees = &trees };
    var trace = try row23.Writer.initFromExpectedLayout(allocator, &prior, selected_layout);
    defer trace.deinit();
    var pcs = try row24.Writer.initFromExpectedProfile(allocator, &prior, expected);
    defer pcs.deinit();
    try key.admitBothWriters(allocator, expected, &trace, &pcs);
    try std.testing.expectEqualDeep(trace.geometry(), key.placements[row23.ROW].geometry);
    try std.testing.expectEqualDeep(pcs.geometry(), key.placements[row24.ROW].geometry);

    var resealed = key;
    resealed.pcs_circuit_identity[0] ^= 1;
    resealed.seal = resealed.computeSeal();
    try std.testing.expectError(error.InvalidV11TemplateManifest, resealed.validateAgainstAuthority(allocator, &prior, expected));
    var wrong_layouts = layouts;
    std.mem.swap(pcs_circuit.SamplePointLayout, &wrong_layouts[0], &wrong_layouts[38 + 625]);
    const wrong_expected = row24.ExpectedProfile{ .ordered_tree_logs = &trees, .sample_layouts = &wrong_layouts };
    try std.testing.expectError(error.InvalidV11TemplateManifest, key.validateAgainstAuthority(allocator, &prior, wrong_expected));
}

fn testPrior(allocator: std.mem.Allocator) !v10.TemplateManifestV10 {
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const v6 = @import("segment_leaf_wrapper_template_v6.zig");
    const catalog = @import("segment_outer_typed_catalog_v2.zig");
    const shape_mod = @import("segment_leaf_wrapper_roster_direct_v4.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("../segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const instructions = try @import("../transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const wrapper_shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    return v10.TemplateManifestV10.build(
        allocator,
        &source_catalog,
        wrapper_shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
        try @import("../segment_profile.zig").transcriptShape(),
    );
}
