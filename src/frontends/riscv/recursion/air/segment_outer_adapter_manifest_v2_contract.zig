//! Internal segment outer adapter manifest v2 authority shard; use segment_outer_adapter_manifest_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const core_components = stwo_core.air.components;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const prover_component = @import("stwo_prover_engine").air.component_prover;

pub const digest = @import("../../air/lang/digest.zig");
pub const relation = @import("../../air/lang/relation.zig");
pub const base = @import("universal_adapter_manifest.zig");
pub const universal_manifest = @import("universal_manifest.zig");
pub const universal_roster = @import("universal_roster.zig");
pub const typed_catalog_v2 = @import("segment_outer_typed_catalog_v2.zig");
pub const transcript_v2 = @import("../segment_transcript_outer_source_v2.zig");
pub const statement_v2 = @import("../segment_statement_outer_source_v2.zig");
pub const public_v2 = @import("../segment_public_outer_source_v2.zig");
pub const boundary_v2 = @import("../segment_leaf_outer_authority_v2.zig");
pub const provider_authority_v2 =
    @import("../segment_publication_input_provider_authority_v2.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const TRANSCRIPT_FORMAT_VERSION: u32 = 3;
pub const TRANSCRIPT_DOMAIN: u32 = 0x5255_4d32; // "RUM2"
pub const DOMAIN =
    "stwo-zig/typed-air/recursion-segment-v2-adapter-manifest/v2\x00";
pub const CLAIM_DOMAIN =
    "stwo-zig/typed-air/recursion-segment-v2-claims/v2\x00";
pub const PROGRAM_GEOMETRY_DOMAIN =
    "stwo-zig/typed-air/recursion-segment-v2-program-geometry/v1\x00";

pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;

pub const UNIVERSAL_COMPONENT_COUNT: usize = universal_roster.COMPONENT_COUNT;
pub const SOURCE_COMPONENT_COUNT: usize = 2;
pub const PROVIDER_COMPONENT_COUNT: usize = 1;
pub const COMPONENT_COUNT: usize =
    UNIVERSAL_COMPONENT_COUNT + SOURCE_COMPONENT_COUNT +
    PROVIDER_COMPONENT_COUNT;
pub const STATEMENT_SOURCE_INDEX: u8 = UNIVERSAL_COMPONENT_COUNT;
pub const PUBLIC_LOGUP_SOURCE_INDEX: u8 = UNIVERSAL_COMPONENT_COUNT + 1;
pub const VERIFIER_INPUT_PROVIDER_INDEX: u8 = UNIVERSAL_COMPONENT_COUNT + 2;

pub const Error = base.Error || universal_manifest.Error ||
    typed_catalog_v2.Error || error{
    IncompleteRoster,
    SourceManifestMismatch,
};

/// V2 keeps all prior numeric indices unchanged and append-admits one committed
/// provider. The explicit enum prevents a caller-selected integer from
/// entering component admission.
pub const ComponentKey = enum(u8) {
    control = 0,
    transcript_air = 1,
    transcript_binding = 2,
    transcript_state = 3,
    transcript_word = 4,
    transcript_payload = 5,
    pow_check = 6,
    pow_frame = 7,
    relation_challenge = 8,
    verifier_randomness = 9,
    statement_input = 10,
    statement_semantics_input = 11,
    vm_public_claim_input = 12,
    vm_public_claim_hash = 13,
    vm_public_io_hash = 14,
    vm_public_claim_semantics_input = 15,
    vm_public_logup_input = 16,
    vm_public_logup_control = 17,
    vm_air_composition_input = 18,
    vm_air_composition_control = 19,
    query_bits = 20,
    query_mapping = 21,
    merkle_root = 22,
    trace_merkle = 23,
    pcs_deep_input = 24,
    fri_merkle_leaf = 25,
    fri_merkle_node = 26,
    fri_merkle_anchor = 27,
    fri_verifier_control = 28,
    fri_verifier_input = 29,
    qm31_mul = 30,
    qm31_inv = 31,
    linear_ops = 32,
    merkle_path = 33,
    poseidon2 = 34,
    range_check_8_8 = 35,
    statement_source_v2 = STATEMENT_SOURCE_INDEX,
    public_logup_source_v2 = PUBLIC_LOGUP_SOURCE_INDEX,
    segment_publication_input_provider_v2 = VERIFIER_INPUT_PROVIDER_INDEX,
};

pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}

pub fn fromUniversal(key: universal_roster.Component) ComponentKey {
    return @enumFromInt(@intFromEnum(key));
}

pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = base.AdapterBinding;
pub const TypedCatalogV2 = typed_catalog_v2.Catalog;
pub const V2_AUTHORITY_CHANGED_MASK =
    typed_catalog_v2.V2_AUTHORITY_CHANGED_MASK;
pub const V1_AUTHORITY_UNCHANGED_MASK =
    typed_catalog_v2.V1_AUTHORITY_UNCHANGED_MASK;
pub const APPENDED_SOURCE_MASK = typed_catalog_v2.APPENDED_SOURCE_MASK;
pub const APPENDED_PROVIDER_MASK = typed_catalog_v2.APPENDED_PROVIDER_MASK;

/// All six authorities are mandatory even for focused component tests. This
/// prevents a test-only builder from accidentally becoming a production path
/// that leaves statement/public source custody unbound.
pub const AuthorityIds = struct {
    transcript_manifest_id: transcript_v2.Digest,
    statement_manifest_id: statement_v2.Digest,
    public_manifest_id: public_v2.Digest,
    boundary_manifest_id: boundary_v2.NativeDigest,
    boundary_authority_sha_id: boundary_v2.Sha256Digest,
    provider_authority_sha_id: boundary_v2.Sha256Digest =
        [_]u8{0} ** 32,

    pub fn validate(self: AuthorityIds) Error!void {
        try requireNativeDigest(self.transcript_manifest_id);
        try requireNativeDigest(self.statement_manifest_id);
        try requireNativeDigest(self.public_manifest_id);
        try requireNativeDigest(self.boundary_manifest_id);
        if (allZero(self.boundary_authority_sha_id) or
            allZero(self.provider_authority_sha_id) or
            !std.mem.eql(
                u8,
                &self.provider_authority_sha_id,
                &provider_authority_v2.sourceAuthorityShaId(),
            ))
            return error.ManifestSealMismatch;
    }
};

pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    roster_count: u8,
    roster_rows: [COMPONENT_COUNT]u8,
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    catalog_identity: digest.Digest,
    transcript_manifest_id: transcript_v2.Digest,
    statement_manifest_id: statement_v2.Digest,
    public_manifest_id: public_v2.Digest,
    boundary_manifest_id: boundary_v2.NativeDigest,
    boundary_authority_sha_id: boundary_v2.Sha256Digest,
    provider_authority_sha_id: boundary_v2.Sha256Digest,
    seal: digest.Digest,

    pub fn validate(self: *const Manifest) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.roster_count != COMPONENT_COUNT)
        {
            return error.IncompleteRoster;
        }
        try self.authorityIds().validate();

        var preprocessed: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        var geometries: [COMPONENT_COUNT]Geometry = undefined;
        for (self.roster_rows, 0..) |row, ordinal| {
            if (row != ordinal)
                return error.RosterOrderMismatch;
            const item = self.placements[row] orelse
                return error.ManifestSealMismatch;
            try item.geometry.validateForComponentCount(COMPONENT_COUNT);
            if (item.geometry.roster_row != row or
                item.preprocessed_offset != preprocessed or
                item.main_offset != main or
                item.interaction_offset != interaction or
                item.constraint_offset != constraints or
                item.claimed_sum_index != row)
            {
                return error.ManifestSealMismatch;
            }
            geometries[row] = item.geometry;
            preprocessed = try checkedAdd(
                preprocessed,
                item.geometry.preprocessed_columns,
            );
            main = try checkedAdd(main, item.geometry.main_columns);
            interaction = try checkedAdd(
                interaction,
                item.geometry.interaction_columns,
            );
            constraints = try checkedAdd(
                constraints,
                @as(u32, item.geometry.direct_constraints) +
                    item.geometry.interaction_batches,
            );
        }
        try typed_catalog_v2.validateGeometries(
            geometries,
            self.catalog_identity,
        );
        if (self.total_preprocessed_columns != preprocessed or
            self.total_main_columns != main or
            self.total_interaction_columns != interaction or
            self.total_constraints != constraints or
            !std.mem.eql(u8, &self.seal, &manifestDigest(self)))
        {
            return error.ManifestSealMismatch;
        }
    }

    pub fn validateAgainstSources(
        self: *const Manifest,
        transcript: *const transcript_v2.ManifestV2,
        statement: *const statement_v2.ManifestV2,
        public: *const public_v2.ManifestV2,
        boundary: *const boundary_v2.OuterManifestV2,
    ) Error!void {
        try self.validate();
        transcript.validate() catch return error.SourceManifestMismatch;
        statement.validate() catch return error.SourceManifestMismatch;
        public.validate() catch return error.SourceManifestMismatch;
        boundary.validate() catch return error.SourceManifestMismatch;
        if (!std.meta.eql(self.transcript_manifest_id, transcript.identity) or
            !std.meta.eql(self.statement_manifest_id, statement.identity) or
            !std.meta.eql(self.public_manifest_id, public.identity) or
            !std.meta.eql(self.boundary_manifest_id, boundary.identity) or
            !std.mem.eql(
                u8,
                &self.boundary_authority_sha_id,
                &boundary.authority_sha_id,
            ))
        {
            return error.SourceManifestMismatch;
        }
        for (transcript.log_sizes, 0..) |log_size, row| {
            const placement_value = self.placements[row] orelse
                return error.SourceManifestMismatch;
            if (placement_value.geometry.log_size != log_size)
                return error.SourceManifestMismatch;
        }
        if (self.placements[10].?.geometry.log_size !=
            typed_catalog_v2.INACTIVE_STATEMENT_LOG_SIZE or
            self.placements[11].?.geometry.log_size != statement.trace_log_size)
        {
            return error.SourceManifestMismatch;
        }
        for (public.log_sizes, 0..) |log_size, index| {
            if (self.placements[12 + index].?.geometry.log_size != log_size)
                return error.SourceManifestMismatch;
        }
        try validateBoundaryGeometry(
            self.placements[STATEMENT_SOURCE_INDEX].?.geometry,
            boundary.components[0],
        );
        try validateBoundaryGeometry(
            self.placements[PUBLIC_LOGUP_SOURCE_INDEX].?.geometry,
            boundary.components[1],
        );
        if (!std.mem.eql(
            u8,
            &self.provider_authority_sha_id,
            &provider_authority_v2.sourceAuthorityShaId(),
        ) or self.placements[VERIFIER_INPUT_PROVIDER_INDEX].?.geometry
            .roster_row != VERIFIER_INPUT_PROVIDER_INDEX)
        {
            return error.SourceManifestMismatch;
        }
    }

    pub fn placement(self: *const Manifest, key: ComponentKey) Error!Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse
            error.ComponentNotAdmitted;
    }

    pub fn mixStatementPrefix(
        self: *const Manifest,
        channel: anytype,
    ) Error!void {
        try self.validate();
        channel.mixU32s(&.{
            TRANSCRIPT_DOMAIN,
            TRANSCRIPT_FORMAT_VERSION,
            self.roster_count,
            self.total_preprocessed_columns,
            self.total_main_columns,
            self.total_interaction_columns,
            self.total_constraints,
        });
        channel.mixU32s(&digestWords(self.seal));
        channel.mixU32s(&digestWords(self.catalog_identity));
        channel.mixU32s(&self.transcript_manifest_id);
        channel.mixU32s(&self.statement_manifest_id);
        channel.mixU32s(&self.public_manifest_id);
        channel.mixU32s(&self.boundary_manifest_id);
        channel.mixU32s(&digestWords(self.boundary_authority_sha_id));
        channel.mixU32s(&digestWords(self.provider_authority_sha_id));
        channel.mixU32s(&digestWords(relation.registryOrderDigest()));
    }

    pub fn authorityIds(self: *const Manifest) AuthorityIds {
        return .{
            .transcript_manifest_id = self.transcript_manifest_id,
            .statement_manifest_id = self.statement_manifest_id,
            .public_manifest_id = self.public_manifest_id,
            .boundary_manifest_id = self.boundary_manifest_id,
            .boundary_authority_sha_id = self.boundary_authority_sha_id,
            .provider_authority_sha_id = self.provider_authority_sha_id,
        };
    }
};

pub const Assembler = struct {
    manifest: Manifest,

    pub fn init(catalog_identity: digest.Digest, ids: AuthorityIds) Assembler {
        return .{ .manifest = emptyManifest(catalog_identity, ids) };
    }

    pub fn append(self: *Assembler, geometry: Geometry) Error!Placement {
        try geometry.validateForComponentCount(COMPONENT_COUNT);
        if (self.manifest.roster_count == COMPONENT_COUNT)
            return error.ManifestFull;
        if (self.manifest.roster_count != 0) {
            const prior = self.manifest.roster_rows[
                self.manifest.roster_count - 1
            ];
            if (geometry.roster_row <= prior)
                return error.RosterOrderMismatch;
        }
        if (self.manifest.placements[geometry.roster_row] != null)
            return error.RosterOrderMismatch;

        const placement_value = Placement{
            .geometry = geometry,
            .preprocessed_offset = self.manifest.total_preprocessed_columns,
            .main_offset = self.manifest.total_main_columns,
            .interaction_offset = self.manifest.total_interaction_columns,
            .constraint_offset = self.manifest.total_constraints,
            .claimed_sum_index = geometry.roster_row,
        };
        const next_preprocessed = try checkedAdd(
            self.manifest.total_preprocessed_columns,
            geometry.preprocessed_columns,
        );
        const next_main = try checkedAdd(
            self.manifest.total_main_columns,
            geometry.main_columns,
        );
        const next_interaction = try checkedAdd(
            self.manifest.total_interaction_columns,
            geometry.interaction_columns,
        );
        const next_constraints = try checkedAdd(
            self.manifest.total_constraints,
            @as(u32, geometry.direct_constraints) +
                geometry.interaction_batches,
        );

        const ordinal = self.manifest.roster_count;
        self.manifest.roster_rows[ordinal] = geometry.roster_row;
        self.manifest.placements[geometry.roster_row] = placement_value;
        self.manifest.roster_count += 1;
        self.manifest.total_preprocessed_columns = next_preprocessed;
        self.manifest.total_main_columns = next_main;
        self.manifest.total_interaction_columns = next_interaction;
        self.manifest.total_constraints = next_constraints;
        return placement_value;
    }

    pub fn seal(self: *Assembler) Error!Manifest {
        self.manifest.seal = manifestDigest(&self.manifest);
        try self.manifest.validate();
        return self.manifest;
    }
};

pub fn validateBoundaryGeometry(
    geometry: Geometry,
    source: boundary_v2.ComponentGeometryV2,
) Error!void {
    if (geometry.log_size != source.trace_log_size or
        geometry.preprocessed_columns != source.preprocessed_columns or
        geometry.main_columns != source.main_columns or
        geometry.interaction_columns != source.interaction_columns or
        geometry.direct_constraints != source.direct_constraints or
        geometry.interaction_batches != source.interaction_batches or
        geometry.protocol_constraint_degree != source.protocol_constraint_degree or
        !std.mem.eql(u8, &geometry.semantic_digest, &source.semantic_digest))
    {
        return error.SourceManifestMismatch;
    }
}

pub fn emptyManifest(
    catalog_identity: digest.Digest,
    ids: AuthorityIds,
) Manifest {
    return .{
        .roster_count = 0,
        .roster_rows = [_]u8{0} ** COMPONENT_COUNT,
        .placements = [_]?Placement{null} ** COMPONENT_COUNT,
        .total_preprocessed_columns = 0,
        .total_main_columns = 0,
        .total_interaction_columns = 0,
        .total_constraints = 0,
        .catalog_identity = catalog_identity,
        .transcript_manifest_id = ids.transcript_manifest_id,
        .statement_manifest_id = ids.statement_manifest_id,
        .public_manifest_id = ids.public_manifest_id,
        .boundary_manifest_id = ids.boundary_manifest_id,
        .boundary_authority_sha_id = ids.boundary_authority_sha_id,
        .provider_authority_sha_id = ids.provider_authority_sha_id,
        .seal = [_]u8{0} ** 32,
    };
}

pub fn manifestDigest(manifest: *const Manifest) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, manifest.format_version);
    hashInt(&hash, u8, manifest.roster_count);
    hashInt(&hash, u32, manifest.total_preprocessed_columns);
    hashInt(&hash, u32, manifest.total_main_columns);
    hashInt(&hash, u32, manifest.total_interaction_columns);
    hashInt(&hash, u32, manifest.total_constraints);
    hash.update(&manifest.catalog_identity);
    for (manifest.transcript_manifest_id) |word| hashInt(&hash, u32, word);
    for (manifest.statement_manifest_id) |word| hashInt(&hash, u32, word);
    for (manifest.public_manifest_id) |word| hashInt(&hash, u32, word);
    for (manifest.boundary_manifest_id) |word| hashInt(&hash, u32, word);
    hash.update(&manifest.boundary_authority_sha_id);
    hash.update(&manifest.provider_authority_sha_id);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const item = manifest.placements[row].?;
        hashInt(&hash, u8, row);
        hashGeometry(&hash, item.geometry);
        hashInt(&hash, u32, item.preprocessed_offset);
        hashInt(&hash, u32, item.main_offset);
        hashInt(&hash, u32, item.interaction_offset);
        hashInt(&hash, u32, item.constraint_offset);
        hashInt(&hash, u8, item.claimed_sum_index);
    }
    return hash.finalResult();
}

pub fn hashGeometry(hash: anytype, geometry: Geometry) void {
    hashInt(hash, u8, geometry.roster_row);
    hashInt(hash, u32, geometry.log_size);
    hashInt(hash, u16, geometry.preprocessed_columns);
    hashInt(hash, u16, geometry.main_columns);
    hashInt(hash, u16, geometry.interaction_columns);
    hashInt(hash, u16, geometry.direct_constraints);
    hashInt(hash, u16, geometry.interaction_batches);
    hashInt(hash, u8, geometry.protocol_constraint_degree);
    hashInt(hash, u8, geometry.profiled_constraint_degree);
    hash.update(&geometry.semantic_digest);
}

pub fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn digestWords(value: digest.Digest) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        const start = index * @sizeOf(u32);
        word.* = std.mem.readInt(
            u32,
            value[start..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

pub fn checkedAdd(left: u32, right: anytype) Error!u32 {
    return std.math.add(u32, left, @intCast(right)) catch
        error.ArithmeticOverflow;
}

pub fn componentBit(row: u8) u64 {
    return @as(u64, 1) << @intCast(row);
}

pub fn requireNativeDigest(value: [8]u32) Error!void {
    var nonzero = false;
    for (value) |word| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.ManifestSealMismatch;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero)
        return error.ManifestSealMismatch;
}

pub fn allZero(value: [32]u8) bool {
    for (value) |byte| if (byte != 0) return false;
    return true;
}
