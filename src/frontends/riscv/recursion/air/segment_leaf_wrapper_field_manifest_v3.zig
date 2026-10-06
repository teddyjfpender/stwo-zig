//! Four typed field-source/hash rows following the V3 link extension.
//! Native ProgramV2 and verified-outer provider words are host-admitted before
//! this manifest is built. The rows can enter a future STARK cohort; this
//! partial manifest cannot mint a V3 root or close Poseidon/verifier tuples.
const std = @import("std");
const base = @import("universal_manifest_contract.zig");
const typed = @import("universal_typed_component.zig");
const binding = @import("universal_relation_binding.zig");
const link = @import("segment_leaf_wrapper_link_manifest_v3.zig");
const word_air = @import("transcript_program_v2_field_source_v1.zig");
const hash_air = @import("vm_public_claim_hash.zig");
const hash_relation = @import("vm_public_claim_hash_relation.zig");
const field = @import("../segment_leaf_wrapper_field_witness_v3.zig");
const closure = @import("../segment_leaf_wrapper_field_lookup_v3.zig");
const program_authority = @import("../transcript_program_v2_field_authority_v1.zig");
const provider_authority = @import("../segment_outer_shared_provider_field_authority_v1.zig");
const hash_witness = @import("../segment_leaf_wrapper_field_hash_witness_v3.zig");
const leaf_source = @import("ethereum_leaf_link_source_v1.zig");
const channel = @import("../poseidon2_channel.zig");
const M31 = @import("stwo_core").fields.m31.M31;

pub const FORMAT_VERSION: u16 = 3;
pub const PRIOR_COMPONENT_COUNT: usize = link.COMPONENT_COUNT;
pub const FIELD_COMPONENT_COUNT: usize = 4;
pub const COMPONENT_COUNT: usize = PRIOR_COMPONENT_COUNT + FIELD_COMPONENT_COUNT;
pub const TREE_COUNT: usize = 3;
pub const PREPROCESSED_TREE_INDEX: usize = 0;
pub const MAIN_TREE_INDEX: usize = 1;
pub const INTERACTION_TREE_INDEX: usize = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPLETE_WRAPPER_PROOF_AVAILABLE = false;
pub const DOMAIN = "stwo-zig/riscv-v3-field-extension-manifest/v1\x00";

comptime {
    if (PRIOR_COMPONENT_COUNT != 42)
        @compileError("V3 field rows require the pinned 39+3 link roster");
}

pub const ComponentKey = enum(u8) {
    program_words = 42,
    program_hash = 43,
    provider_words = 44,
    provider_hash = 45,
};
pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = @import("universal_adapter_manifest.zig").AdapterBinding;
pub const WordAdapter = typed.ComponentForManifest(word_air, binding.Binding(word_air), @This());
pub const HashAdapter = typed.ComponentForManifest(hash_air, hash_relation, @This());

/// Public parameter and digest authority for one field hash caller. The
/// digest is a field result, not a SHA transport seal.
pub const FieldInputV3 = struct {
    word_count: u32,
    domain: u32,
    scope: u32,
    digest_kind: u32,
    step_base: u32,
    digest: channel.Digest,

    pub fn parameters(self: FieldInputV3) [hash_air.PARAMETER_COUNT]M31 {
        return .{
            M31.one(),
            M31.fromCanonical(self.domain),
            M31.fromCanonical(self.scope),
            M31.fromCanonical(hash_witness.VERIFIER_ID),
            M31.fromCanonical(self.digest_kind),
        };
    }
};

pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    roster_rows: [FIELD_COMPONENT_COUNT]u8 = .{ 42, 43, 44, 45 },
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    program_input: FieldInputV3,
    provider_input: FieldInputV3,
    seal: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        native: *const field.NativeV1,
        provider: *const field.ProviderV1,
    ) !Manifest {
        try validateFieldPairs(allocator, native, provider);
        var word_definition = try word_air.build(allocator);
        defer word_definition.deinit();
        _ = try word_air.authenticate(&word_definition);
        var hash_definition = try hash_air.build(allocator);
        defer hash_definition.deinit();
        _ = try hash_relation.authenticate(&hash_definition);
        const geometry = geometries(
            native.program_words.log_size,
            native.program_hash.log_size,
            provider.words.log_size,
            provider.hash.log_size,
        );
        var placements: [COMPONENT_COUNT]?Placement = @splat(null);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (geometry, 0..) |item, index| {
            try item.validateForComponentCount(COMPONENT_COUNT);
            placements[PRIOR_COMPONENT_COUNT + index] = .{
                .geometry = item,
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
                .constraint_offset = constraints,
                .claimed_sum_index = @intCast(PRIOR_COMPONENT_COUNT + index),
            };
            pp = try std.math.add(u32, pp, item.preprocessed_columns);
            main = try std.math.add(u32, main, item.main_columns);
            interaction = try std.math.add(u32, interaction, item.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, item.direct_constraints) + item.interaction_batches);
        }
        var result = Manifest{
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .program_input = fieldInput(&native.program_hash),
            .provider_input = fieldInput(&provider.hash),
            .seal = undefined,
        };
        result.seal = digest(&result);
        try result.validateAgainst(allocator, native, provider);
        return result;
    }

    pub fn validate(self: *const Manifest) !void {
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.roster_rows, .{ 42, 43, 44, 45 }))
            return error.InvalidV3FieldManifest;
        for (self.placements[0..PRIOR_COMPONENT_COUNT]) |item|
            if (item != null) return error.InvalidV3FieldManifest;
        const geometry = geometries(
            (self.placements[keyIndex(.program_words)] orelse return error.InvalidV3FieldManifest).geometry.log_size,
            (self.placements[keyIndex(.program_hash)] orelse return error.InvalidV3FieldManifest).geometry.log_size,
            (self.placements[keyIndex(.provider_words)] orelse return error.InvalidV3FieldManifest).geometry.log_size,
            (self.placements[keyIndex(.provider_hash)] orelse return error.InvalidV3FieldManifest).geometry.log_size,
        );
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (geometry, 0..) |expected, index| {
            const row = PRIOR_COMPONENT_COUNT + index;
            const item = self.placements[row].?;
            try expected.validateForComponentCount(COMPONENT_COUNT);
            if (!std.meta.eql(item.geometry, expected) or
                item.preprocessed_offset != pp or item.main_offset != main or
                item.interaction_offset != interaction or
                item.constraint_offset != constraints or
                item.claimed_sum_index != row)
                return error.InvalidV3FieldManifest;
            pp = try std.math.add(u32, pp, expected.preprocessed_columns);
            main = try std.math.add(u32, main, expected.main_columns);
            interaction = try std.math.add(u32, interaction, expected.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, expected.direct_constraints) + expected.interaction_batches);
        }
        inline for (.{ self.program_input.digest, self.provider_input.digest }) |digest_words|
            for (digest_words) |word|
                if (word >= @import("stwo_core").fields.m31.Modulus)
                    return error.InvalidV3FieldManifest;
        if (self.total_preprocessed_columns != pp or
            self.total_main_columns != main or
            self.total_interaction_columns != interaction or
            self.total_constraints != constraints or
            self.program_input.word_count == 0 or
            self.provider_input.word_count == 0 or
            self.program_input.word_count >= @import("stwo_core").fields.m31.Modulus or
            self.provider_input.word_count >= @import("stwo_core").fields.m31.Modulus or
            self.program_input.domain != program_authority.PROGRAM_DOMAIN or
            self.program_input.scope != field.PROGRAM_SCOPE or
            self.program_input.digest_kind != leaf_source.PROGRAM_AUTHORITY_KIND or
            self.program_input.step_base != hash_witness.PROGRAM_STEP_BASE or
            self.provider_input.domain != provider_authority.DOMAIN or
            self.provider_input.scope != field.PROVIDER_SCOPE or
            self.provider_input.digest_kind != hash_witness.PROVIDER_FIELD_DIGEST_KIND or
            self.provider_input.step_base != hash_witness.PROVIDER_STEP_BASE or
            !std.mem.eql(u8, &self.seal, &digest(self)))
            return error.InvalidV3FieldManifest;
    }

    pub fn validateAgainst(
        self: *const Manifest,
        allocator: std.mem.Allocator,
        native: *const field.NativeV1,
        provider: *const field.ProviderV1,
    ) !void {
        try validateFieldPairs(allocator, native, provider);
        try self.validate();
        if (!std.meta.eql(self.program_input, fieldInput(&native.program_hash)) or
            !std.meta.eql(self.provider_input, fieldInput(&provider.hash)))
            return error.InvalidV3FieldManifest;
        const log_sizes = [_]u32{
            native.program_words.log_size,
            native.program_hash.log_size,
            provider.words.log_size,
            provider.hash.log_size,
        };
        for (self.roster_rows, log_sizes) |row, log_size|
            if (self.placements[row].?.geometry.log_size != log_size)
                return error.InvalidV3FieldManifest;
    }

    pub fn placement(self: *const Manifest, key: ComponentKey) !Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse error.InvalidV3FieldManifest;
    }

    pub fn hashParameters(self: *const Manifest, key: ComponentKey) ![hash_air.PARAMETER_COUNT]M31 {
        try self.validate();
        return switch (key) {
            .program_hash => self.program_input.parameters(),
            .provider_hash => self.provider_input.parameters(),
            else => error.InvalidV3FieldManifest,
        };
    }

    pub fn requireCompleteWrapperProof(_: *const Manifest) error{V3WrapperProofUnavailable}!void {
        return error.V3WrapperProofUnavailable;
    }
};
fn fieldInput(hash: *const hash_witness.HashV1) FieldInputV3 {
    return .{
        .word_count = @intCast(hash.word_count),
        .domain = hash.domain,
        .scope = hash.scope,
        .digest_kind = hash.digest_kind,
        .step_base = hash.step_base,
        .digest = hash.digest,
    };
}

fn validateFieldPairs(allocator: std.mem.Allocator, native: *const field.NativeV1, provider: *const field.ProviderV1) !void {
    try native.program_words.validateAgainst(native.program.words, field.PROGRAM_SCOPE);
    try native.program_hash.validateAgainst(native.program.words, program_authority.PROGRAM_DOMAIN, field.PROGRAM_SCOPE, leaf_source.PROGRAM_AUTHORITY_KIND, hash_witness.PROGRAM_STEP_BASE, native.program.digest);
    _ = try closure.verifyExact(allocator, &native.program_words, &native.program_hash);
    try provider.words.validateAgainst(provider.authority.words, field.PROVIDER_SCOPE);
    try provider.hash.validateAgainst(provider.authority.words, provider_authority.DOMAIN, field.PROVIDER_SCOPE, hash_witness.PROVIDER_FIELD_DIGEST_KIND, hash_witness.PROVIDER_STEP_BASE, provider.authority.digest);
    _ = try closure.verifyExact(allocator, &provider.words, &provider.hash);
}

fn geometries(program_words: u32, program_hash: u32, provider_words: u32, provider_hash: u32) [FIELD_COMPONENT_COUNT]Geometry {
    return .{
        WordAdapter.manifestGeometry(.program_words, program_words),
        HashAdapter.manifestGeometry(.program_hash, program_hash),
        WordAdapter.manifestGeometry(.provider_words, provider_words),
        HashAdapter.manifestGeometry(.provider_hash, provider_hash),
    };
}

fn digest(value: *const Manifest) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.roster_rows);
    for (value.placements[PRIOR_COMPONENT_COUNT..]) |maybe| {
        const item = maybe orelse return @splat(0);
        const geometry = item.geometry;
        hashInt(&hash, u8, geometry.roster_row);
        hashInt(&hash, u32, geometry.log_size);
        inline for (.{ geometry.preprocessed_columns, geometry.main_columns, geometry.interaction_columns, geometry.direct_constraints, geometry.interaction_batches }) |n|
            hashInt(&hash, u16, n);
        hashInt(&hash, u8, geometry.protocol_constraint_degree);
        hashInt(&hash, u8, geometry.profiled_constraint_degree);
        hash.update(&geometry.semantic_digest);
        inline for (.{ item.preprocessed_offset, item.main_offset, item.interaction_offset, item.constraint_offset }) |n|
            hashInt(&hash, u32, n);
        hashInt(&hash, u8, item.claimed_sum_index);
    }
    inline for (.{ value.total_preprocessed_columns, value.total_main_columns, value.total_interaction_columns, value.total_constraints }) |n|
        hashInt(&hash, u32, n);
    inline for (.{ value.program_input, value.provider_input }) |input| {
        inline for (.{ input.word_count, input.domain, input.scope, input.digest_kind, input.step_base }) |n|
            hashInt(&hash, u32, n);
        for (input.digest) |word| hashInt(&hash, u32, word);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
