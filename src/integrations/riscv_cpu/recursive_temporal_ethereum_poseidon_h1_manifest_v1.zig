//! Exact compact outer-STARK manifest for one full-Ethereum h1 parent.
//!
//! The four AIR kinds admitted by the verifier-minted ingress occupy twelve
//! physical placements.  Source, projection, and child-field router each
//! concatenate the two children.  The existing hash AIR has component-local
//! verifier parameters, so the four domain-separated hashes of each child are
//! eight distinct placements.  One native Poseidon2 provider closes all eight
//! request streams.  No row aliases the frozen 36-row universal roster.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover_component = @import("stwo_prover_engine").air.component_prover;

const recursion = frontend.recursion;
const base = recursion.air.universal_adapter_manifest;
const shared_provider = recursion.air.universal_shared_provider;
const typed_component = recursion.air.universal_typed_component;
const universal = recursion.air.universal_challenges;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const projection_air = recursion.air.ethereum_leaf_link_projection_v1;
const router_air = recursion.air.ethereum_leaf_child_field_router_v1;
const hash_air = recursion.air.vm_public_claim_hash;

const core_components = stwo_core.air.components;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const TRANSCRIPT_FORMAT_VERSION: u32 = 1;
pub const TRANSCRIPT_DOMAIN: u32 = 0x4548_314d; // "EH1M"
pub const DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-manifest/v1\x00";
pub const CLAIM_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-claims/v1\x00";
pub const CONTRACT_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-manifest-contract/v1\x00";

pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const COMPONENT_COUNT: usize = 12;
pub const HASH_PLACEMENT_COUNT: usize = 8;
pub const PRODUCTION_ACTIVATION = false;

pub const ComponentKey = enum(u8) {
    link_source = 0,
    link_projection = 1,
    child_field_router = 2,
    left_metadata_hash = 3,
    left_link_hash = 4,
    left_authority_hash = 5,
    left_receipt_hash = 6,
    right_metadata_hash = 7,
    right_link_hash = 8,
    right_authority_hash = 9,
    right_receipt_hash = 10,
    poseidon2 = 11,
};

pub const COMPONENT_KEYS = [COMPONENT_COUNT]ComponentKey{
    .link_source,
    .link_projection,
    .child_field_router,
    .left_metadata_hash,
    .left_link_hash,
    .left_authority_hash,
    .left_receipt_hash,
    .right_metadata_hash,
    .right_link_hash,
    .right_authority_hash,
    .right_receipt_hash,
    .poseidon2,
};

pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = base.AdapterBinding;
pub const LogSizes = [COMPONENT_COUNT]u32;

pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}

pub const Error = base.Error || error{
    InvalidEthereumPoseidonH1Manifest,
    InvalidIngressAuthority,
    InvalidProviderGeometry,
};

pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    roster_count: u8 = COMPONENT_COUNT,
    production_activation: bool = PRODUCTION_ACTIVATION,
    padding: [2]u8 = .{ 0, 0 },
    roster_rows: [COMPONENT_COUNT]u8,
    placements: [COMPONENT_COUNT]?Placement,
    log_sizes: LogSizes,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    ingress_authority_sha256: [32]u8,
    seal: [32]u8,

    pub fn validate(self: *const Manifest) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.roster_count != COMPONENT_COUNT or
            self.production_activation or
            !std.mem.allEqual(u8, &self.padding, 0) or
            std.mem.allEqual(u8, &self.ingress_authority_sha256, 0))
        {
            return error.InvalidEthereumPoseidonH1Manifest;
        }

        var preprocessed: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        inline for (COMPONENT_KEYS, 0..) |key, ordinal| {
            const row = keyIndex(key);
            if (self.roster_rows[ordinal] != row)
                return error.RosterOrderMismatch;
            const placement_value = self.placements[row] orelse
                return error.ManifestSealMismatch;
            try placement_value.geometry.validateForComponentCount(
                COMPONENT_COUNT,
            );
            const expected = try expectedGeometry(key, self.log_sizes[row]);
            if (!std.meta.eql(placement_value.geometry, expected) or
                placement_value.preprocessed_offset != preprocessed or
                placement_value.main_offset != main or
                placement_value.interaction_offset != interaction or
                placement_value.constraint_offset != constraints or
                placement_value.claimed_sum_index != row)
            {
                return error.ManifestSealMismatch;
            }
            preprocessed = try checkedAdd(
                preprocessed,
                placement_value.geometry.preprocessed_columns,
            );
            main = try checkedAdd(main, placement_value.geometry.main_columns);
            interaction = try checkedAdd(
                interaction,
                placement_value.geometry.interaction_columns,
            );
            constraints = try checkedAdd(
                constraints,
                @as(u32, placement_value.geometry.direct_constraints) +
                    placement_value.geometry.interaction_batches,
            );
        }
        if (preprocessed != self.total_preprocessed_columns or
            main != self.total_main_columns or
            interaction != self.total_interaction_columns or
            constraints != self.total_constraints or
            !std.mem.eql(u8, &self.seal, &manifestDigest(self)))
        {
            return error.ManifestSealMismatch;
        }
    }

    pub fn placement(
        self: *const Manifest,
        key: ComponentKey,
    ) Error!Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse
            error.ComponentNotAdmitted;
    }

    pub fn mixStatementPrefix(
        self: *const Manifest,
        transcript: anytype,
    ) Error!void {
        try self.validate();
        transcript.mixU32s(&.{
            TRANSCRIPT_DOMAIN,
            TRANSCRIPT_FORMAT_VERSION,
            self.roster_count,
            self.total_preprocessed_columns,
            self.total_main_columns,
            self.total_interaction_columns,
            self.total_constraints,
        });
        transcript.mixU32s(&digestWords(self.seal));
        transcript.mixU32s(&digestWords(self.ingress_authority_sha256));
        transcript.mixU32s(&digestWords(universal.registryOrderDigest()));
    }
};

pub const ClaimVector = struct {
    manifest_seal: [32]u8,
    admitted_mask: u64,
    bound_mask: u64,
    values: [COMPONENT_COUNT]QM31,
    seal: [32]u8,

    pub fn init(manifest: *const Manifest) Error!ClaimVector {
        try manifest.validate();
        return .{
            .manifest_seal = manifest.seal,
            .admitted_mask = completeMask(),
            .bound_mask = 0,
            .values = [_]QM31{QM31.zero()} ** COMPONENT_COUNT,
            .seal = [_]u8{0} ** 32,
        };
    }

    pub fn bind(
        self: *ClaimVector,
        key: ComponentKey,
        value: QM31,
    ) Error!void {
        const row = keyIndex(key);
        const bit = componentBit(row);
        if (self.admitted_mask & bit == 0) return error.ClaimNotAdmitted;
        if (self.bound_mask & bit != 0) return error.ClaimAlreadyBound;
        self.values[row] = value;
        self.bound_mask |= bit;
    }

    pub fn sealClaims(
        self: *ClaimVector,
        manifest: *const Manifest,
    ) Error!void {
        try validateClaimGeometry(self, manifest);
        if (self.bound_mask != self.admitted_mask) return error.ClaimMissing;
        self.seal = claimDigest(self, manifest);
    }

    pub fn validate(
        self: *const ClaimVector,
        manifest: *const Manifest,
    ) Error!void {
        try validateClaimGeometry(self, manifest);
        if (self.bound_mask != self.admitted_mask) return error.ClaimMissing;
        if (!std.mem.eql(u8, &self.seal, &claimDigest(self, manifest)))
            return error.ClaimSealMismatch;
    }

    pub fn mixInteractionClaims(
        self: *const ClaimVector,
        manifest: *const Manifest,
        transcript: anytype,
    ) Error!void {
        try self.validate(manifest);
        transcript.mixU32s(&.{manifest.roster_count});
        for (manifest.roster_rows) |row| {
            const placement_value = manifest.placements[row].?;
            transcript.mixU32s(&.{
                row,
                placement_value.geometry.log_size,
                placement_value.geometry.interaction_columns,
            });
            transcript.mixFelts(&.{self.values[row]});
        }
        transcript.mixU32s(&digestWords(self.seal));
    }
};

pub const ProofGate = struct {
    manifest_seal: [32]u8,
    roster_rows: [COMPONENT_COUNT]u8,
    verifier_components: [COMPONENT_COUNT]core_components.Component,
    prover_components: [COMPONENT_COUNT]prover_component.ComponentProver,
    claims: ClaimVector,
    count: u8,
    sealed: bool,

    pub fn init(manifest: *const Manifest) Error!ProofGate {
        try manifest.validate();
        return .{
            .manifest_seal = manifest.seal,
            .roster_rows = [_]u8{0} ** COMPONENT_COUNT,
            .verifier_components = undefined,
            .prover_components = undefined,
            .claims = try ClaimVector.init(manifest),
            .count = 0,
            .sealed = false,
        };
    }

    pub fn append(
        self: *ProofGate,
        manifest: *const Manifest,
        binding: AdapterBinding,
    ) Error!void {
        if (self.sealed) return error.AdapterCountMismatch;
        try manifest.validate();
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(u8, &binding.manifest_seal, &manifest.seal) or
            self.count >= COMPONENT_COUNT)
        {
            return error.ManifestSealMismatch;
        }
        const expected_row = manifest.roster_rows[self.count];
        const expected = manifest.placements[expected_row].?;
        if (binding.placement.geometry.roster_row != expected_row)
            return error.AdapterOrderMismatch;
        if (!binding.placement.eql(expected) or
            binding.verifier.nConstraints() !=
                @as(usize, expected.geometry.direct_constraints) +
                    expected.geometry.interaction_batches or
            binding.prover.nConstraints() != binding.verifier.nConstraints())
        {
            return error.AdapterGeometryMismatch;
        }
        try self.claims.bind(@enumFromInt(expected_row), binding.claimed_sum);
        self.roster_rows[self.count] = expected_row;
        self.verifier_components[self.count] = binding.verifier;
        self.prover_components[self.count] = binding.prover;
        self.count += 1;
    }

    pub fn sealGate(self: *ProofGate, manifest: *const Manifest) Error!void {
        if (self.count != COMPONENT_COUNT) return error.AdapterCountMismatch;
        try self.claims.sealClaims(manifest);
        self.sealed = true;
    }

    pub fn validate(self: *const ProofGate, manifest: *const Manifest) Error!void {
        try manifest.validate();
        if (!self.sealed or self.count != COMPONENT_COUNT or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.AdapterCountMismatch;
        }
        try self.claims.validate(manifest);
        for (self.roster_rows, manifest.roster_rows) |actual, expected|
            if (actual != expected) return error.AdapterOrderMismatch;
    }

    pub fn verifierSlice(
        self: *const ProofGate,
    ) Error![]const core_components.Component {
        if (!self.sealed) return error.AdapterCountMismatch;
        return &self.verifier_components;
    }

    pub fn proverSlice(
        self: *const ProofGate,
    ) Error![]const prover_component.ComponentProver {
        if (!self.sealed) return error.AdapterCountMismatch;
        return &self.prover_components;
    }
};

pub fn build(
    log_sizes: LogSizes,
    ingress_authority_sha256: [32]u8,
) Error!Manifest {
    if (std.mem.allEqual(u8, &ingress_authority_sha256, 0))
        return error.InvalidIngressAuthority;
    var result = Manifest{
        .roster_rows = undefined,
        .placements = [_]?Placement{null} ** COMPONENT_COUNT,
        .log_sizes = log_sizes,
        .total_preprocessed_columns = 0,
        .total_main_columns = 0,
        .total_interaction_columns = 0,
        .total_constraints = 0,
        .ingress_authority_sha256 = ingress_authority_sha256,
        .seal = [_]u8{0} ** 32,
    };
    for (&result.roster_rows, 0..) |*row, ordinal| row.* = @intCast(ordinal);
    inline for (COMPONENT_KEYS) |key| {
        const row = keyIndex(key);
        const geometry = try expectedGeometry(key, log_sizes[row]);
        result.placements[row] = .{
            .geometry = geometry,
            .preprocessed_offset = result.total_preprocessed_columns,
            .main_offset = result.total_main_columns,
            .interaction_offset = result.total_interaction_columns,
            .constraint_offset = result.total_constraints,
            .claimed_sum_index = row,
        };
        result.total_preprocessed_columns = try checkedAdd(
            result.total_preprocessed_columns,
            geometry.preprocessed_columns,
        );
        result.total_main_columns = try checkedAdd(
            result.total_main_columns,
            geometry.main_columns,
        );
        result.total_interaction_columns = try checkedAdd(
            result.total_interaction_columns,
            geometry.interaction_columns,
        );
        result.total_constraints = try checkedAdd(
            result.total_constraints,
            @as(u32, geometry.direct_constraints) + geometry.interaction_batches,
        );
    }
    result.seal = manifestDigest(&result);
    try result.validate();
    return result;
}

pub fn expectedGeometry(
    comptime key: ComponentKey,
    log_size: u32,
) Error!Geometry {
    return switch (key) {
        .link_source => typed_component.manifestGeometryForAir(
            source_air,
            @This(),
            key,
            log_size,
        ),
        .link_projection => typed_component.manifestGeometryForAir(
            projection_air,
            @This(),
            key,
            log_size,
        ),
        .child_field_router => typed_component.manifestGeometryForAir(
            router_air,
            @This(),
            key,
            log_size,
        ),
        .left_metadata_hash,
        .left_link_hash,
        .left_authority_hash,
        .left_receipt_hash,
        .right_metadata_hash,
        .right_link_hash,
        .right_authority_hash,
        .right_receipt_hash,
        => typed_component.manifestGeometryForAir(
            hash_air,
            @This(),
            key,
            log_size,
        ),
        .poseidon2 => providerGeometry(log_size),
    };
}

pub fn providerGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = keyIndex(.poseidon2),
        .log_size = log_size,
        .preprocessed_columns = shared_provider.POSEIDON_PREPROCESSED_COLUMN_COUNT,
        .main_columns = shared_provider.POSEIDON_MAIN_COLUMN_COUNT,
        .interaction_columns = shared_provider.POSEIDON_INTERACTION_COLUMN_COUNT,
        .direct_constraints = shared_provider.POSEIDON_DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = shared_provider.POSEIDON_INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = shared_provider.POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = shared_provider.POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
        .semantic_digest = shared_provider.POSEIDON_SOURCE_AUTHORITY_DIGEST,
    };
}

/// Stable authority for the H1 outer AIR roster. Runtime trace logs and the
/// ingress-specific manifest seal remain proof-bound; excluding them here
/// avoids a circular profile -> custody -> manifest -> profile identity.
pub fn contractIdentity() Error![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTRACT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, TRANSCRIPT_FORMAT_VERSION);
    hashInt(&hash, u32, TRANSCRIPT_DOMAIN);
    hashInt(&hash, u8, TREE_COUNT);
    hashInt(&hash, u8, PREPROCESSED_TREE_INDEX);
    hashInt(&hash, u8, MAIN_TREE_INDEX);
    hashInt(&hash, u8, INTERACTION_TREE_INDEX);
    hashInt(&hash, u8, COMPONENT_COUNT);
    hash.update(&universal.registryOrderDigest());
    inline for (COMPONENT_KEYS) |key| {
        const geometry = try expectedGeometry(key, 4);
        hashInt(&hash, u8, keyIndex(key));
        hashInt(&hash, u16, geometry.preprocessed_columns);
        hashInt(&hash, u16, geometry.main_columns);
        hashInt(&hash, u16, geometry.interaction_columns);
        hashInt(&hash, u16, geometry.direct_constraints);
        hashInt(&hash, u16, geometry.interaction_batches);
        hashInt(&hash, u8, geometry.protocol_constraint_degree);
        hashInt(&hash, u8, geometry.profiled_constraint_degree);
        hash.update(&geometry.semantic_digest);
    }
    return hash.finalResult();
}

fn validateClaimGeometry(
    claims: *const ClaimVector,
    manifest: *const Manifest,
) Error!void {
    try manifest.validate();
    if (!std.mem.eql(u8, &claims.manifest_seal, &manifest.seal))
        return error.ManifestSealMismatch;
    if (claims.admitted_mask != completeMask() or
        claims.bound_mask & ~completeMask() != 0)
    {
        return error.ClaimNotAdmitted;
    }
}

fn manifestDigest(manifest: *const Manifest) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, manifest.format_version);
    hashInt(&hash, u16, manifest.schema_version);
    hashInt(&hash, u8, manifest.roster_count);
    hashInt(&hash, u8, @intFromBool(manifest.production_activation));
    hash.update(&manifest.padding);
    inline for (.{
        manifest.total_preprocessed_columns,
        manifest.total_main_columns,
        manifest.total_interaction_columns,
        manifest.total_constraints,
    }) |value| hashInt(&hash, u32, value);
    hash.update(&manifest.ingress_authority_sha256);
    hash.update(&universal.registryOrderDigest());
    for (manifest.roster_rows) |row| {
        const placement_value = manifest.placements[row].?;
        hashInt(&hash, u8, row);
        hashGeometry(&hash, placement_value.geometry);
        hashInt(&hash, u32, placement_value.preprocessed_offset);
        hashInt(&hash, u32, placement_value.main_offset);
        hashInt(&hash, u32, placement_value.interaction_offset);
        hashInt(&hash, u32, placement_value.constraint_offset);
        hashInt(&hash, u8, placement_value.claimed_sum_index);
    }
    return hash.finalResult();
}

fn claimDigest(claims: *const ClaimVector, manifest: *const Manifest) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLAIM_DOMAIN);
    hash.update(&manifest.seal);
    hashInt(&hash, u64, claims.admitted_mask);
    hashInt(&hash, u64, claims.bound_mask);
    for (manifest.roster_rows) |row| {
        hashInt(&hash, u8, row);
        hashQm31(&hash, claims.values[row]);
    }
    return hash.finalResult();
}

fn hashGeometry(hash: anytype, geometry: Geometry) void {
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

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn digestWords(value: [32]u8) [8]u32 {
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

fn checkedAdd(left: u32, right: anytype) Error!u32 {
    return std.math.add(u32, left, @intCast(right)) catch
        error.ArithmeticOverflow;
}

fn componentBit(row: u8) u64 {
    return @as(u64, 1) << @intCast(row);
}

fn completeMask() u64 {
    return (@as(u64, 1) << COMPONENT_COUNT) - 1;
}

comptime {
    if (COMPONENT_COUNT > 64 or HASH_PLACEMENT_COUNT != 8 or
        @typeInfo(ComponentKey).@"enum".fields.len != COMPONENT_COUNT or
        TREE_COUNT != 3 or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 manifest contract drifted");
    }
    for (COMPONENT_KEYS, 0..) |key, ordinal| {
        if (keyIndex(key) != @as(u8, @intCast(ordinal)))
            @compileError("Ethereum Poseidon h1 component order drifted");
    }
}

test "Ethereum Poseidon h1 manifest binds twelve physical placements" {
    const logs = LogSizes{
        11, 11, 12,
        7,  3,  8,
        4,  7,  3,
        8,  4,  9,
    };
    const authority = [_]u8{7} ** 32;
    const manifest = try build(logs, authority);
    try std.testing.expectEqual(@as(u8, COMPONENT_COUNT), manifest.roster_count);
    try std.testing.expectEqual(
        keyIndex(.poseidon2),
        (try manifest.placement(.poseidon2)).geometry.roster_row,
    );
    var mutation = manifest;
    mutation.placements[keyIndex(.left_link_hash)].?.geometry.log_size += 1;
    try std.testing.expectError(error.ManifestSealMismatch, mutation.validate());
}
