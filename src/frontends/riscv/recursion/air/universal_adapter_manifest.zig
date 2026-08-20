//! Allocation-free roster manifest and outer-proof admission seam.
//!
//! Typed AIR admission is intentionally weaker than proof admission.  This
//! module closes the intervening protocol geometry without knowing component
//! equations: admitted components are appended in the pinned 36-row Stark-V
//! order, receive deterministic preprocessing/main/interaction offsets, and
//! bind their claimed sums at the original roster index.  A sealed proof gate
//! then exposes the exact prover and independent-verifier component slices
//! consumed by the generic PCS/FRI engine.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_components = stwo_core.air.components;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const roster = @import("universal_roster.zig");

/// Component key consumed by the generic typed-component adapter. Versioned
/// outer manifests expose the same tiny contract with their own key enum;
/// keeping the conversion here preserves every frozen-V1 call site and byte.
pub const ComponentKey = roster.Component;

pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}

pub const FORMAT_VERSION: u16 = 1;
pub const TRANSCRIPT_FORMAT_VERSION: u32 = 1;
pub const TRANSCRIPT_DOMAIN: u32 = 0x5255_4d31; // "RUM1"
pub const DOMAIN = "stwo-zig/typed-air/recursion-universal-adapter-manifest/v1\x00";
pub const CLAIM_DOMAIN = "stwo-zig/typed-air/recursion-universal-claims/v1\x00";
pub const TREE_COUNT: usize = 3;
pub const PREPROCESSED_TREE_INDEX: usize = 0;
pub const MAIN_TREE_INDEX: usize = 1;
pub const INTERACTION_TREE_INDEX: usize = 2;

pub const Error = error{
    AdapterCountMismatch,
    AdapterGeometryMismatch,
    AdapterOrderMismatch,
    ArithmeticOverflow,
    ClaimAlreadyBound,
    ClaimMissing,
    ClaimNotAdmitted,
    ClaimSealMismatch,
    ComponentNotAdmitted,
    InvalidComponentGeometry,
    InvalidLogSize,
    InvalidRosterRow,
    ManifestFull,
    ManifestSealMismatch,
    RosterOrderMismatch,
    UntypedRosterRow,
};

/// Equation-free geometry supplied by one typed component adapter.
pub const Geometry = struct {
    roster_row: u8,
    log_size: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    /// Degree admitted by the concrete adapter after compiler lowering. This
    /// determines the quotient domain and therefore proof geometry; source
    /// reference metadata may be lower when lowering retains derived tuple
    /// expressions instead of materializing them as columns.
    protocol_constraint_degree: u8,
    /// Conservative degree measured by the local static profiler. It is
    /// recorded independently because verifier-owned preprocessing may make
    /// the local bound higher, while generated budget padding may make it
    /// lower, than the protocol declaration.
    profiled_constraint_degree: u8,
    semantic_digest: digest.Digest,

    pub fn validate(self: Geometry) Error!void {
        try self.validateForComponentCount(roster.COMPONENT_COUNT);
        const status = roster.DESCRIPTORS[self.roster_row].status;
        if (status != .typed_logical and
            status != .authenticated_shared_provider)
        {
            return error.UntypedRosterRow;
        }
    }

    /// Geometry-only validation shared by versioned manifest contracts. The
    /// caller still owns protocol-specific component admission (name/order and
    /// semantic digest); this method deliberately validates no V1 descriptor.
    pub fn validateForComponentCount(
        self: Geometry,
        component_count: usize,
    ) Error!void {
        if (component_count == 0 or component_count > 64 or
            self.roster_row >= component_count)
        {
            return error.InvalidRosterRow;
        }
        if (self.log_size == 0 or self.log_size >= 31)
            return error.InvalidLogSize;
        if ((self.direct_constraints == 0 and self.interaction_batches == 0) or
            self.interaction_batches == 0 or
            self.protocol_constraint_degree < 2)
        {
            return error.InvalidComponentGeometry;
        }
        const expected_interaction = std.math.mul(
            u16,
            self.interaction_batches,
            4,
        ) catch return error.InvalidComponentGeometry;
        if (self.interaction_columns != expected_interaction)
            return error.InvalidComponentGeometry;
    }
};

/// Canonical offsets assigned by the ordered manifest builder.
pub const Placement = struct {
    geometry: Geometry,
    preprocessed_offset: u32,
    main_offset: u32,
    interaction_offset: u32,
    constraint_offset: u32,
    claimed_sum_index: u8,

    pub fn eql(self: Placement, other: Placement) bool {
        return std.meta.eql(self, other);
    }
};

pub const Manifest = struct {
    format_version: u16,
    roster_count: u8,
    roster_rows: [roster.COMPONENT_COUNT]u8,
    placements: [roster.COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: digest.Digest,

    pub fn validate(self: *const Manifest) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.roster_count > roster.COMPONENT_COUNT)
        {
            return error.ManifestSealMismatch;
        }

        var preprocessed: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        var prior: ?u8 = null;
        var seen = [_]bool{false} ** roster.COMPONENT_COUNT;
        for (self.roster_rows[0..self.roster_count]) |row| {
            if (row >= roster.COMPONENT_COUNT or seen[row])
                return error.RosterOrderMismatch;
            if (prior) |value| if (row <= value)
                return error.RosterOrderMismatch;
            prior = row;
            seen[row] = true;
            const item = self.placements[row] orelse
                return error.ManifestSealMismatch;
            try item.geometry.validate();
            if (item.geometry.roster_row != row or
                item.preprocessed_offset != preprocessed or
                item.main_offset != main or
                item.interaction_offset != interaction or
                item.constraint_offset != constraints or
                item.claimed_sum_index != row)
            {
                return error.ManifestSealMismatch;
            }
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
        for (self.placements, 0..) |item, row| {
            if ((item != null) != seen[row])
                return error.ManifestSealMismatch;
        }
        if (self.total_preprocessed_columns != preprocessed or
            self.total_main_columns != main or
            self.total_interaction_columns != interaction or
            self.total_constraints != constraints or
            !std.mem.eql(u8, &self.seal, &manifestDigest(self)))
        {
            return error.ManifestSealMismatch;
        }
    }

    pub fn placement(
        self: *const Manifest,
        row: ComponentKey,
    ) Error!Placement {
        try self.validate();
        return self.placements[keyIndex(row)] orelse
            error.ComponentNotAdmitted;
    }

    /// Binds the manifest and relation registry before challenge draws.
    pub fn mixStatementPrefix(self: *const Manifest, channel: anytype) Error!void {
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
        channel.mixU32s(&digestWords(relation.registryOrderDigest()));
    }
};

/// Fixed-capacity, allocation-free manifest construction.  Rows may be a
/// strict subset while development is in flight, but their relative order and
/// all offsets are already the final roster order for that admitted set.
pub const Builder = struct {
    manifest: Manifest = emptyManifest(),

    pub fn append(self: *Builder, geometry: Geometry) Error!Placement {
        try geometry.validate();
        if (self.manifest.roster_count == roster.COMPONENT_COUNT)
            return error.ManifestFull;
        if (self.manifest.roster_count != 0) {
            const prior = self.manifest.roster_rows[self.manifest.roster_count - 1];
            if (geometry.roster_row <= prior) return error.RosterOrderMismatch;
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
            @as(u32, geometry.direct_constraints) + geometry.interaction_batches,
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

    pub fn seal(self: *Builder) Error!Manifest {
        self.manifest.seal = manifestDigest(&self.manifest);
        try self.manifest.validate();
        return self.manifest;
    }
};

pub const ClaimVector = struct {
    manifest_seal: digest.Digest,
    admitted_mask: u64,
    bound_mask: u64,
    values: [roster.COMPONENT_COUNT]QM31,
    seal: digest.Digest,

    pub fn init(manifest: *const Manifest) Error!ClaimVector {
        try manifest.validate();
        var mask: u64 = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row|
            mask |= rosterBit(row);
        return .{
            .manifest_seal = manifest.seal,
            .admitted_mask = mask,
            .bound_mask = 0,
            .values = [_]QM31{QM31.zero()} ** roster.COMPONENT_COUNT,
            .seal = [_]u8{0} ** 32,
        };
    }

    pub fn bind(
        self: *ClaimVector,
        row: ComponentKey,
        value: QM31,
    ) Error!void {
        const index = keyIndex(row);
        const bit = rosterBit(index);
        if ((self.admitted_mask & bit) == 0) return error.ClaimNotAdmitted;
        if ((self.bound_mask & bit) != 0) return error.ClaimAlreadyBound;
        self.values[index] = value;
        self.bound_mask |= bit;
    }

    pub fn sealClaims(self: *ClaimVector, manifest: *const Manifest) Error!void {
        try validateClaimGeometry(self, manifest);
        if (self.bound_mask != self.admitted_mask) return error.ClaimMissing;
        self.seal = claimDigest(self, manifest);
    }

    pub fn validate(self: *const ClaimVector, manifest: *const Manifest) Error!void {
        try validateClaimGeometry(self, manifest);
        if (self.bound_mask != self.admitted_mask) return error.ClaimMissing;
        if (!std.mem.eql(u8, &self.seal, &claimDigest(self, manifest)))
            return error.ClaimSealMismatch;
    }

    /// Claimed sums are absorbed in canonical roster order, before the
    /// interaction commitment, exactly where the generic outer prover expects
    /// the component claim vector.
    pub fn mixInteractionClaims(
        self: *const ClaimVector,
        manifest: *const Manifest,
        channel: anytype,
    ) Error!void {
        try self.validate(manifest);
        channel.mixU32s(&.{manifest.roster_count});
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
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

/// Type-erased binding returned by one concrete typed adapter.  The component
/// object remains caller-owned and must stay at a stable address through the
/// prove/verify call, matching the underlying STWO component contract.
pub const AdapterBinding = struct {
    manifest_seal: digest.Digest,
    placement: Placement,
    claimed_sum: QM31,
    verifier: core_components.Component,
    prover: prover_component.ComponentProver,
};

/// Final ordered handoff to generic PCS/FRI proving and independent
/// verification.  No allocation or virtual dispatch occurs while assembling
/// the gate; virtual dispatch begins only inside the existing proof engine.
pub const ProofGate = struct {
    manifest_seal: digest.Digest,
    roster_rows: [roster.COMPONENT_COUNT]u8,
    verifier_components: [roster.COMPONENT_COUNT]core_components.Component,
    prover_components: [roster.COMPONENT_COUNT]prover_component.ComponentProver,
    claims: ClaimVector,
    count: u8,
    sealed: bool,

    pub fn init(manifest: *const Manifest) Error!ProofGate {
        try manifest.validate();
        return .{
            .manifest_seal = manifest.seal,
            .roster_rows = [_]u8{0} ** roster.COMPONENT_COUNT,
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

    pub fn sealGate(self: *ProofGate, manifest: *const Manifest) Error!void {
        if (self.count != manifest.roster_count)
            return error.AdapterCountMismatch;
        try self.claims.sealClaims(manifest);
        self.sealed = true;
    }

    pub fn validate(self: *const ProofGate, manifest: *const Manifest) Error!void {
        try manifest.validate();
        if (!self.sealed or self.count != manifest.roster_count or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.AdapterCountMismatch;
        }
        for (self.roster_rows[0..self.count], manifest.roster_rows[0..manifest.roster_count]) |
            got,
            expected,
        | if (got != expected) return error.AdapterOrderMismatch;
        try self.claims.validate(manifest);
    }

    pub fn verifierSlice(self: *const ProofGate) Error![]const core_components.Component {
        if (!self.sealed) return error.AdapterCountMismatch;
        return self.verifier_components[0..self.count];
    }

    pub fn proverSlice(self: *const ProofGate) Error![]const prover_component.ComponentProver {
        if (!self.sealed) return error.AdapterCountMismatch;
        return self.prover_components[0..self.count];
    }
};

fn emptyManifest() Manifest {
    return .{
        .format_version = FORMAT_VERSION,
        .roster_count = 0,
        .roster_rows = [_]u8{0} ** roster.COMPONENT_COUNT,
        .placements = [_]?Placement{null} ** roster.COMPONENT_COUNT,
        .total_preprocessed_columns = 0,
        .total_main_columns = 0,
        .total_interaction_columns = 0,
        .total_constraints = 0,
        .seal = [_]u8{0} ** 32,
    };
}

fn manifestDigest(manifest: *const Manifest) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, manifest.format_version);
    hashInt(&hash, u16, roster.COMPONENT_COUNT);
    hash.update(&relation.registryOrderDigest());
    hashInt(&hash, u8, manifest.roster_count);
    for (roster.DESCRIPTORS, 0..) |descriptor, row| {
        hashInt(&hash, u8, row);
        hashInt(&hash, u16, descriptor.name.len);
        hash.update(descriptor.name);
        const placement_value = manifest.placements[row];
        hashInt(&hash, u8, @intFromBool(placement_value != null));
        if (placement_value) |placement| {
            const geometry = placement.geometry;
            hashInt(&hash, u32, geometry.log_size);
            hashInt(&hash, u16, geometry.preprocessed_columns);
            hashInt(&hash, u16, geometry.main_columns);
            hashInt(&hash, u16, geometry.interaction_columns);
            hashInt(&hash, u16, geometry.direct_constraints);
            hashInt(&hash, u16, geometry.interaction_batches);
            hashInt(&hash, u8, geometry.protocol_constraint_degree);
            hashInt(&hash, u8, geometry.profiled_constraint_degree);
            hash.update(&geometry.semantic_digest);
            hashInt(&hash, u32, placement.preprocessed_offset);
            hashInt(&hash, u32, placement.main_offset);
            hashInt(&hash, u32, placement.interaction_offset);
            hashInt(&hash, u32, placement.constraint_offset);
            hashInt(&hash, u8, placement.claimed_sum_index);
        }
    }
    hashInt(&hash, u32, manifest.total_preprocessed_columns);
    hashInt(&hash, u32, manifest.total_main_columns);
    hashInt(&hash, u32, manifest.total_interaction_columns);
    hashInt(&hash, u32, manifest.total_constraints);
    return hash.finalResult();
}

fn claimDigest(claims: *const ClaimVector, manifest: *const Manifest) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLAIM_DOMAIN);
    hash.update(&manifest.seal);
    hashInt(&hash, u64, claims.admitted_mask);
    hashInt(&hash, u64, claims.bound_mask);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        hashInt(&hash, u8, row);
        for (claims.values[row].toM31Array()) |coordinate|
            hashInt(&hash, u32, coordinate.toU32());
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
    var expected_mask: u64 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row|
        expected_mask |= rosterBit(row);
    if (claims.admitted_mask != expected_mask or
        (claims.bound_mask & ~expected_mask) != 0)
    {
        return error.ClaimSealMismatch;
    }
}

fn rosterBit(row: u8) u64 {
    std.debug.assert(row < 64);
    return @as(u64, 1) << @intCast(row);
}

fn checkedAdd(lhs: u32, rhs: anytype) Error!u32 {
    return std.math.add(u32, lhs, @intCast(rhs)) catch
        error.ArithmeticOverflow;
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        word.* = std.mem.readInt(
            u32,
            value[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (roster.COMPONENT_COUNT > @bitSizeOf(u64))
        @compileError("universal adapter claim bitmap is too narrow");
    if (TREE_COUNT != 3 or PREPROCESSED_TREE_INDEX != 0 or
        MAIN_TREE_INDEX != 1 or INTERACTION_TREE_INDEX != 2)
    {
        @compileError("universal adapter tree order drifted");
    }
    _ = M31;
}
