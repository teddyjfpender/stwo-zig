//! Candidate V8 direct-leaf template with one fixed row-36 Statement key.
//!
//! The V7 template is independently rebuilt from verifier-selected shape;
//! this version replaces only its row-36 geometry. The one fixed ordinal
//! column is independent of the authenticated SegmentV2 wire count. That
//! count is a public AIR parameter derived afresh by the detached verifier,
//! never part of the preprocessing key or supplied by a witness column.
//!
//! This is a candidate placement contract, not a proof or an admitted root.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const v7 = @import("segment_leaf_wrapper_template_v7.zig");
const v6 = @import("segment_leaf_wrapper_template_v6.zig");
const catalog = @import("segment_outer_typed_catalog_v2.zig");
const shape_mod = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const statement = @import("../../air/statement.zig");
const native = @import("verifier_schedule.zig");
const query_mapping = @import("query_mapping_witness.zig");
const typed = @import("universal_typed_component.zig");
const air = @import("segment_leaf_statement_source_direct_v8.zig");
const physical = @import("../segment_leaf_wrapper_row36_direct_v8.zig");
const boundary = @import("../segment_leaf_statement_contract_v2.zig");
const PublicDataV2 = @import("../../air/public_data_v2.zig").PublicDataV2;

pub const FORMAT_VERSION: u16 = 8;
pub const DOMAIN = "stwo-zig/riscv-leaf-template-manifest/v8\x00";
pub const PARAMETER_DOMAIN = "stwo-zig/riscv-v8-statement-public-parameter/v1\x00";
pub const COMPONENT_COUNT = v7.COMPONENT_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_TEMPLATE_PREPROCESSING_AVAILABLE = false;
pub const Geometry = v7.Geometry;
pub const Placement = v7.Placement;

/// The count's name, AIR slot, admissible range, and authenticated source are
/// pinned separately from its per-leaf value. A change in this contract
/// necessarily changes the V8 key, even if the fixed ordinal column does not.
pub const PublicParameterContract = struct {
    parameter_count: u8 = air.PARAMETER_COUNT,
    input_slot: u16 = air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT,
    min_wire_words: u32 = air.MIN_WIRE_WORDS,
    max_wire_words: u32 = air.MAX_WIRE_WORDS,
    contract_digest: [32]u8,

    pub fn canonical() PublicParameterContract {
        return .{ .contract_digest = parameterDigest() };
    }

    pub fn validate(self: *const PublicParameterContract) !void {
        if (!std.meta.eql(self.*, canonical())) return error.InvalidV8StatementParameterContract;
    }

    pub fn admit(
        self: *const PublicParameterContract,
        expected: *const PublicDataV2,
        admitted_manifest: *const boundary.ManifestV2,
    ) ![air.PARAMETER_COUNT]M31 {
        try self.validate();
        return (try air.VerifierWireCount.derive(expected, admitted_manifest)).parameters();
    }
};

pub const TemplateManifestV8 = struct {
    v7_template: v7.TemplateManifestV7,
    placements: [COMPONENT_COUNT]Placement,
    row36_fixed_ordinal_id: [32]u8,
    public_parameter: PublicParameterContract,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    /// Build V7 from verifier-owned inputs first. No SegmentV2 wire count or
    /// child-carried manifest enters this candidate preprocessing key.
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
    ) !TemplateManifestV8 {
        const prior = try v7.TemplateManifestV7.build(
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
        return fromVerifierTemplate(allocator, &prior);
    }

    /// Call only with a V7 template freshly compiled from verifier-owned
    /// inputs. `validateAgainst` repeats that compilation for admission.
    pub fn fromVerifierTemplate(allocator: std.mem.Allocator, prior: *const v7.TemplateManifestV7) !TemplateManifestV8 {
        try prior.validate();
        const fixed = try physical.FixedKey.compile(allocator);
        try fixed.validate();
        var placements: [COMPONENT_COUNT]Placement = undefined;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (&placements, prior.placements, 0..) |*target, old, index| {
            const geometry = if (index == 36) row36Geometry() else old.geometry;
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
        var result = TemplateManifestV8{
            .v7_template = prior.*,
            .placements = placements,
            .row36_fixed_ordinal_id = fixed.column_digest,
            .public_parameter = PublicParameterContract.canonical(),
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        try result.validate();
        return result;
    }

    pub fn validate(self: *const TemplateManifestV8) !void {
        try self.v7_template.validate();
        try self.public_parameter.validate();
        const fixed = try physical.FixedKey.compile(std.heap.page_allocator);
        try fixed.validate();
        if (!std.meta.eql(self.row36_fixed_ordinal_id, fixed.column_digest))
            return error.InvalidV8TemplateManifest;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.placements, self.v7_template.placements, 0..) |placement, old, index| {
            const geometry = if (index == 36) row36Geometry() else old.geometry;
            if (!std.meta.eql(placement.geometry, geometry) or
                placement.preprocessed_offset != pp or
                placement.main_offset != main or
                placement.interaction_offset != interaction or
                placement.constraint_offset != constraints or
                placement.claimed_sum_index != index)
                return error.InvalidV8TemplateManifest;
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
            return error.InvalidV8TemplateManifest;
    }

    pub fn validateAgainst(
        self: *const TemplateManifestV8,
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
        try self.v7_template.validateAgainst(
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
        const rebuilt = try fromVerifierTemplate(allocator, &self.v7_template);
        if (!std.meta.eql(self.*, rebuilt)) return error.V8TemplateAdmissionMismatch;
    }

    pub fn admitWireParameter(
        self: *const TemplateManifestV8,
        expected: *const PublicDataV2,
        admitted_manifest: *const boundary.ManifestV2,
    ) ![air.PARAMETER_COUNT]M31 {
        try self.validate();
        return self.public_parameter.admit(expected, admitted_manifest);
    }

    pub fn requireCompletePreprocessing(_: *const TemplateManifestV8) error{V8TemplatePreprocessingUnavailable}!void {
        return error.V8TemplatePreprocessingUnavailable;
    }

    fn computeSeal(self: *const TemplateManifestV8) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.v7_template.seal);
        hash.update(&self.row36_fixed_ordinal_id);
        hash.update(&self.public_parameter.contract_digest);
        hashInt(&hash, u8, self.public_parameter.parameter_count);
        hashInt(&hash, u16, self.public_parameter.input_slot);
        hashInt(&hash, u32, self.public_parameter.min_wire_words);
        hashInt(&hash, u32, self.public_parameter.max_wire_words);
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

fn row36Geometry() Geometry {
    return .{
        .roster_row = 36,
        .log_size = air.LOG_SIZE,
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

fn parameterDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PARAMETER_DOMAIN);
    hash.update(&air.SEMANTIC_DIGEST);
    hash.update("authenticated SegmentV2/PublicDataV2 + exact ManifestV2\x00");
    for (air.PARAMETER_NAMES) |name| {
        hashInt(&hash, u32, @intCast(name.len));
        hash.update(name);
    }
    hashInt(&hash, u8, air.PARAMETER_COUNT);
    hashInt(&hash, u16, air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT);
    hashInt(&hash, u32, air.MIN_WIRE_WORDS);
    hashInt(&hash, u32, air.MAX_WIRE_WORDS);
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V8 candidate roster replaces only row36 and admits one fixed key for 664 and 668" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
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
    const key = try TemplateManifestV8.build(
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
    try std.testing.expectEqualDeep(air.SEMANTIC_DIGEST, key.placements[36].geometry.semantic_digest);
    try std.testing.expectEqual(@as(u32, air.LOG_SIZE), key.placements[36].geometry.log_size);
    try std.testing.expectEqualDeep((try physical.FixedKey.compile(allocator)).column_digest, key.row36_fixed_ordinal_id);
    for (key.placements, key.v7_template.placements, 0..) |current, prior, index|
        if (index != 36) try std.testing.expectEqualDeep(prior.geometry, current.geometry);

    // These counts have different active Statement rows but the same padded
    // geometry. Neither is allowed to enter the verifier's fixed-key seal.
    var prior_fixed_ordinal: ?M31 = null;
    for ([_]u32{ 664, 668 }) |wire_count| {
        try std.testing.expect(wire_count >= key.public_parameter.min_wire_words);
        try std.testing.expect(wire_count <= key.public_parameter.max_wire_words);
        const row = try air.logicalRow(664, wire_count, M31.one(), 0);
        const ordinal = row[air.PHYSICAL_MAIN_COLUMN_COUNT];
        if (prior_fixed_ordinal) |prior| try std.testing.expectEqual(prior, ordinal);
        prior_fixed_ordinal = ordinal;
        try std.testing.expectEqual(@as(u32, @intFromBool(wire_count == 668)), row[1].toU32());
        try std.testing.expectEqual(wire_count, row[air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT].toU32());
        const rebuilt = try TemplateManifestV8.build(
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
        try std.testing.expectEqualDeep(key.seal, rebuilt.seal);
        try std.testing.expectEqualDeep(key.row36_fixed_ordinal_id, rebuilt.row36_fixed_ordinal_id);
    }
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
    try std.testing.expectError(error.V8TemplatePreprocessingUnavailable, key.requireCompletePreprocessing());

    var wrong_air = key;
    wrong_air.placements[36].geometry.semantic_digest[0] ^= 1;
    wrong_air.seal = wrong_air.computeSeal();
    try std.testing.expectError(error.InvalidV8TemplateManifest, wrong_air.validate());
    var wrong_fixed = key;
    wrong_fixed.row36_fixed_ordinal_id[0] ^= 1;
    wrong_fixed.seal = wrong_fixed.computeSeal();
    try std.testing.expectError(error.InvalidV8TemplateManifest, wrong_fixed.validate());
    var wrong_parameter = key;
    wrong_parameter.public_parameter.input_slot += 1;
    wrong_parameter.seal = wrong_parameter.computeSeal();
    try std.testing.expectError(error.InvalidV8StatementParameterContract, wrong_parameter.validate());
    const changed_shape = shape_mod.Shape{ .program_words = shape.program_words, .base_poseidon_calls = shape.base_poseidon_calls + 1 };
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
}

test "V8 candidate verifier rejects wrong Statement source and parameter" {
    const allocator = std.testing.allocator;
    const fixture_mod = @import("../../air/public_data_v2_test_support.zig");
    const fixture = try fixture_mod.Fixture.init();
    const words = try fixture_mod.encode(allocator, &fixture.leftSource());
    defer allocator.free(words);
    const expected = try PublicDataV2.authenticate(words);
    const manifest = try boundary.ManifestV2.init(words.len);
    const contract = PublicParameterContract.canonical();
    try std.testing.expectEqual(@as(u32, @intCast(words.len)), (try contract.admit(&expected, &manifest))[0].toU32());
    const wrong_manifest = try boundary.ManifestV2.init(words.len + 4);
    try std.testing.expectError(error.DirectStatementV8ManifestMismatch, contract.admit(&expected, &wrong_manifest));
    const saved = words[0];
    defer words[0] = saved;
    words[0] = saved.add(M31.one());
    if (contract.admit(&expected, &manifest)) |_| return error.TestExpectedError else |_| {}
}
