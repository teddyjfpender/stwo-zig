//! Versioned 36-row manifest and proof gate for an adjacent-span temporal parent.
//!
//! Frozen universal V1 cannot admit this proof: row 8 is the disjoint packed
//! relation-challenge V2 AIR. This contract retains every numeric roster index,
//! binds rows 0--17 to the exact temporal prefix custody, and derives rows
//! 18--35 only from their typed AIR/native-provider authorities. It owns no
//! equations and accepts no caller-authored geometry.
//!
//! The authenticated suffix source and complete parent proof are now available.
//! A non-zero suffix authority identity binds the rows-18--35 owner without
//! admitting caller-authored geometry into the manifest transcript.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover_component = @import("stwo_prover_engine").air.component_prover;

const core_components = stwo_core.air.components;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const base = recursion.air.universal_adapter_manifest;
const catalog = recursion.air.universal_catalog;
const roster = recursion.air.universal_roster;
const shared_provider = recursion.air.universal_shared_provider;
const typed_component = recursion.air.universal_typed_component;
const universal = recursion.air.universal_challenges;
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");

const Digest = @TypeOf(universal.registryOrderDigest());

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const TRANSCRIPT_FORMAT_VERSION: u32 = 3;
pub const TRANSCRIPT_DOMAIN: u32 = 0x5450_4d33; // "TPM3"
pub const DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-manifest/v3\x00";
pub const CLAIM_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-claims/v3\x00";

pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const PREFIX_ROW_COUNT: usize = temporal_nonfri.PREFIX_ROW_COUNT;
pub const SUFFIX_FIRST_ROW: usize = PREFIX_ROW_COUNT;
pub const SUFFIX_ROW_COUNT: usize = COMPONENT_COUNT - PREFIX_ROW_COUNT;
pub const SUFFIX_LAST_ROW: usize = COMPONENT_COUNT - 1;

pub const MANIFEST_CONTRACT_AVAILABLE = true;
pub const CLAIM_GATE_CONTRACT_AVAILABLE = true;
pub const SUFFIX_SOURCE_AVAILABLE = true;
pub const COMPLETE_PARENT_PROOF_AVAILABLE = true;
pub const PRODUCTION_CAPABILITY = false;

pub const ComponentKey = roster.Component;
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = base.AdapterBinding;
pub const SuffixLogSizes = [SUFFIX_ROW_COUNT]u32;

pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}

pub const Error = base.Error || error{
    ArithmeticOverflow,
    FrozenRow8SemanticMismatch,
    IncompleteRoster,
    InvalidSuffixAuthority,
    InvalidSuffixGeometry,
    InvalidSuffixRow,
    PrefixLayoutMismatch,
};

const PoseidonAdapter = shared_provider.Poseidon2AdapterForManifest(@This());
const RangeAdapter = shared_provider.RangeCheck8x8AdapterForManifest(@This());

/// Complete proof geometry. `prefix_layout` is retained by value so validation
/// replays its full pointer-free custody seal rather than trusting only a hash.
pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    roster_count: u8 = COMPONENT_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },
    roster_rows: [COMPONENT_COUNT]u8,
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    prefix_layout: temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    suffix_log_sizes: SuffixLogSizes,
    suffix_source_authority_sha_id: [32]u8,
    seal: Digest,

    pub fn validate(self: *const Manifest) Error!void {
        self.prefix_layout.validate() catch return error.PrefixLayoutMismatch;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.roster_count != COMPONENT_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            allZero(self.suffix_source_authority_sha_id))
        {
            return error.IncompleteRoster;
        }

        var preprocessed: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.roster_rows, 0..) |row, ordinal| {
            if (row != ordinal) return error.RosterOrderMismatch;
            const placement_value = self.placements[row] orelse
                return error.ManifestSealMismatch;
            try placement_value.geometry.validateForComponentCount(COMPONENT_COUNT);
            if (placement_value.geometry.roster_row != row or
                placement_value.preprocessed_offset != preprocessed or
                placement_value.main_offset != main or
                placement_value.interaction_offset != interaction or
                placement_value.constraint_offset != constraints or
                placement_value.claimed_sum_index != row)
            {
                return error.ManifestSealMismatch;
            }

            if (row < PREFIX_ROW_COUNT) {
                if (!placement_value.eql(self.prefix_layout.placements[row]))
                    return error.PrefixLayoutMismatch;
            } else {
                const suffix_index = row - SUFFIX_FIRST_ROW;
                const expected = try expectedSuffixGeometry(
                    @intCast(row),
                    self.suffix_log_sizes[suffix_index],
                );
                if (!std.meta.eql(placement_value.geometry, expected))
                    return error.InvalidSuffixGeometry;
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
            preprocessed < self.prefix_layout.total_preprocessed_columns or
            main < self.prefix_layout.total_main_columns or
            interaction < self.prefix_layout.total_interaction_columns or
            constraints < self.prefix_layout.total_constraints or
            !std.mem.eql(u8, &self.seal, &manifestDigest(self)))
        {
            return error.ManifestSealMismatch;
        }
    }

    pub fn validateAgainstPrefix(
        self: *const Manifest,
        prefix: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    ) Error!void {
        try self.validate();
        prefix.validate() catch return error.PrefixLayoutMismatch;
        if (!std.meta.eql(self.prefix_layout, prefix.*))
            return error.PrefixLayoutMismatch;
    }

    pub fn placement(
        self: *const Manifest,
        key: ComponentKey,
    ) Error!Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse
            error.ComponentNotAdmitted;
    }

    /// Binds the temporal manifest before relation challenges are drawn. Both
    /// source identities are mixed separately from the aggregate manifest seal
    /// to keep transcript reviews and mutation diagnostics local.
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
        channel.mixU32s(&digestWords(self.prefix_layout.layout_sha_id));
        channel.mixU32s(&digestWords(self.suffix_source_authority_sha_id));
        channel.mixU32s(&digestWords(universal.registryOrderDigest()));
    }
};

/// Allocation-free fixed-capacity claim vector. Claims can be bound only once
/// and are mixed in the same order as the committed 36-row manifest.
pub const ClaimVector = struct {
    manifest_seal: Digest,
    admitted_mask: u64,
    bound_mask: u64,
    values: [COMPONENT_COUNT]QM31,
    seal: Digest,

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
        if ((self.admitted_mask & bit) == 0) return error.ClaimNotAdmitted;
        if ((self.bound_mask & bit) != 0) return error.ClaimAlreadyBound;
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
        channel: anytype,
    ) Error!void {
        try self.validate(manifest);
        channel.mixU32s(&.{manifest.roster_count});
        for (manifest.roster_rows) |row| {
            const placement_value = manifest.placements[row].?;
            channel.mixU32s(&.{
                row,
                placement_value.geometry.log_size,
                placement_value.geometry.interaction_columns,
            });
            channel.mixFelts(&.{self.values[row]});
        }
        channel.mixU32s(&digestWords(self.seal));
    }
};

/// Ordered handoff to the native PCS/FRI engine. Component objects remain
/// caller-owned at stable addresses; this gate performs no allocation and adds
/// no virtual dispatch before the underlying proof engine begins.
pub const ProofGate = struct {
    manifest_seal: Digest,
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
            !std.mem.eql(u8, &binding.manifest_seal, &manifest.seal))
        {
            return error.ManifestSealMismatch;
        }
        if (self.count >= manifest.roster_count)
            return error.AdapterCountMismatch;
        const expected_row = manifest.roster_rows[self.count];
        if (binding.placement.geometry.roster_row != expected_row)
            return error.AdapterOrderMismatch;
        const expected = manifest.placements[expected_row].?;
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

    pub fn sealGate(
        self: *ProofGate,
        manifest: *const Manifest,
    ) Error!void {
        if (self.count != manifest.roster_count)
            return error.AdapterCountMismatch;
        try self.claims.sealClaims(manifest);
        self.sealed = true;
    }

    pub fn validate(
        self: *const ProofGate,
        manifest: *const Manifest,
    ) Error!void {
        try manifest.validate();
        if (!self.sealed or self.count != manifest.roster_count or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.AdapterCountMismatch;
        }
        try self.claims.validate(manifest);
        for (self.roster_rows[0..self.count], manifest.roster_rows) |
            actual,
            expected,
        | if (actual != expected) return error.AdapterOrderMismatch;
    }

    pub fn verifierSlice(
        self: *const ProofGate,
    ) Error![]const core_components.Component {
        if (!self.sealed) return error.AdapterCountMismatch;
        return self.verifier_components[0..self.count];
    }

    pub fn proverSlice(
        self: *const ProofGate,
    ) Error![]const prover_component.ComponentProver {
        if (!self.sealed) return error.AdapterCountMismatch;
        return self.prover_components[0..self.count];
    }
};

/// Seals one complete manifest. The caller supplies only per-row trace lengths
/// and the authenticated suffix source identity; all equation geometry is
/// derived here from the typed catalog and native providers.
pub fn build(
    prefix: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    suffix_log_sizes: SuffixLogSizes,
    suffix_source_authority_sha_id: [32]u8,
) Error!Manifest {
    prefix.validate() catch return error.PrefixLayoutMismatch;
    if (allZero(suffix_source_authority_sha_id))
        return error.InvalidSuffixAuthority;

    var result = Manifest{
        .roster_rows = undefined,
        .placements = [_]?Placement{null} ** COMPONENT_COUNT,
        .total_preprocessed_columns = 0,
        .total_main_columns = 0,
        .total_interaction_columns = 0,
        .total_constraints = 0,
        .prefix_layout = prefix.*,
        .suffix_log_sizes = suffix_log_sizes,
        .suffix_source_authority_sha_id = suffix_source_authority_sha_id,
        .seal = [_]u8{0} ** 32,
    };

    for (&result.roster_rows, 0..) |*destination, row|
        destination.* = @intCast(row);
    for (prefix.placements, 0..) |placement_value, row| {
        result.placements[row] = placement_value;
        result.total_preprocessed_columns = try checkedAdd(
            result.total_preprocessed_columns,
            placement_value.geometry.preprocessed_columns,
        );
        result.total_main_columns = try checkedAdd(
            result.total_main_columns,
            placement_value.geometry.main_columns,
        );
        result.total_interaction_columns = try checkedAdd(
            result.total_interaction_columns,
            placement_value.geometry.interaction_columns,
        );
        result.total_constraints = try checkedAdd(
            result.total_constraints,
            @as(u32, placement_value.geometry.direct_constraints) +
                placement_value.geometry.interaction_batches,
        );
    }
    if (result.total_preprocessed_columns != prefix.total_preprocessed_columns or
        result.total_main_columns != prefix.total_main_columns or
        result.total_interaction_columns != prefix.total_interaction_columns or
        result.total_constraints != prefix.total_constraints)
    {
        return error.PrefixLayoutMismatch;
    }

    for (suffix_log_sizes, 0..) |log_size, suffix_index| {
        const row: u8 = @intCast(SUFFIX_FIRST_ROW + suffix_index);
        const geometry = try expectedSuffixGeometry(row, log_size);
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

/// Public for source-side geometry receipts and focused mutation tests. Rows
/// outside 18--35 are rejected, and row 35 has one fixed provider domain size.
pub fn expectedSuffixGeometry(row: u8, log_size: u32) Error!Geometry {
    if (row < SUFFIX_FIRST_ROW or row > SUFFIX_LAST_ROW)
        return error.InvalidSuffixRow;
    inline for (catalog.LOGICAL_ROWS) |entry| {
        if (@intFromEnum(entry.row) == row) {
            return typed_component.manifestGeometryForAir(
                entry.Air,
                @This(),
                entry.row,
                log_size,
            );
        }
    }
    if (row == @intFromEnum(ComponentKey.poseidon2)) {
        if (log_size == 0 or
            log_size >= shared_provider.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT)
        {
            return error.InvalidSuffixGeometry;
        }
        return PoseidonAdapter.manifestGeometry(log_size);
    }
    if (row == @intFromEnum(ComponentKey.range_check_8_8)) {
        const geometry = RangeAdapter.manifestGeometry();
        if (log_size != geometry.log_size)
            return error.InvalidSuffixGeometry;
        return geometry;
    }
    return error.InvalidSuffixRow;
}

fn validateClaimGeometry(
    claims: *const ClaimVector,
    manifest: *const Manifest,
) Error!void {
    try manifest.validate();
    const expected_mask = completeMask();
    if (!std.mem.eql(u8, &claims.manifest_seal, &manifest.seal))
        return error.ManifestSealMismatch;
    if (claims.admitted_mask != expected_mask or
        claims.bound_mask & ~expected_mask != 0)
    {
        return error.ClaimNotAdmitted;
    }
}

fn manifestDigest(manifest: *const Manifest) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, manifest.format_version);
    hashInt(&hash, u16, manifest.schema_version);
    hashInt(&hash, u8, manifest.roster_count);
    hash.update(&manifest.padding);
    hashInt(&hash, u32, manifest.total_preprocessed_columns);
    hashInt(&hash, u32, manifest.total_main_columns);
    hashInt(&hash, u32, manifest.total_interaction_columns);
    hashInt(&hash, u32, manifest.total_constraints);
    hash.update(&manifest.prefix_layout.layout_sha_id);
    hash.update(&manifest.suffix_source_authority_sha_id);
    for (manifest.suffix_log_sizes) |log_size|
        hashInt(&hash, u32, log_size);
    hash.update(&universal.registryOrderDigest());
    for (manifest.roster_rows) |row| {
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

fn claimDigest(
    claims: *const ClaimVector,
    manifest: *const Manifest,
) Digest {
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
    for (value.toM31Array()) |limb|
        hashInt(hash, u32, limb.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn digestWords(value: Digest) [8]u32 {
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

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (COMPONENT_COUNT != 36 or PREFIX_ROW_COUNT != 18 or
        SUFFIX_FIRST_ROW != 18 or SUFFIX_ROW_COUNT != 18 or
        SUFFIX_LAST_ROW != 35 or COMPONENT_COUNT > 64 or TREE_COUNT != 3 or
        @typeInfo(ComponentKey).@"enum".fields.len != COMPONENT_COUNT or
        !MANIFEST_CONTRACT_AVAILABLE or !CLAIM_GATE_CONTRACT_AVAILABLE or
        !SUFFIX_SOURCE_AVAILABLE or !COMPLETE_PARENT_PROOF_AVAILABLE or
        PRODUCTION_CAPABILITY)
    {
        @compileError("temporal parent manifest capability/geometry drifted");
    }
}

test "temporal parent manifest suffix geometry is typed and range fixed" {
    std.testing.refAllDeclsRecursive(Manifest);
    std.testing.refAllDeclsRecursive(ProofGate);
    try std.testing.expectError(
        error.InvalidSuffixRow,
        expectedSuffixGeometry(17, 11),
    );
    const row18 = try expectedSuffixGeometry(18, 11);
    try std.testing.expectEqual(@as(u8, 18), row18.roster_row);
    const range = try expectedSuffixGeometry(
        @intFromEnum(ComponentKey.range_check_8_8),
        RangeAdapter.manifestGeometry().log_size,
    );
    try std.testing.expect(std.meta.eql(
        range,
        RangeAdapter.manifestGeometry(),
    ));
    try std.testing.expectError(
        error.InvalidSuffixGeometry,
        expectedSuffixGeometry(
            @intFromEnum(ComponentKey.range_check_8_8),
            range.log_size + 1,
        ),
    );
}
