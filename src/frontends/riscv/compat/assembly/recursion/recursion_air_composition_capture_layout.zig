//! Proof-kind-aware sampled-value geometry for the V3 composition recorder.
//!
//! SegmentV2 and universal binary proofs have different physical manifests and
//! therefore different flattened OODS sample layouts.  A shared circuit cannot
//! infer either layout from a caller-provided count.  This module derives and
//! seals both layouts from successful verifier captures plus their trusted
//! manifests, then exposes one max-sized sampled-value ABI.  The selected
//! proof kind occupies its canonical prefix; every inactive tail slot is zero.

const std = @import("std");
const stwo_core = @import("stwo_core");

const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const qm31 = stwo_core.fields.qm31;
const verifier_types = stwo_core.verifier_types;

const graph_mod = @import("stwo_riscv_rv32").recursion.air.composition_circuit;
const segment_manifest_mod = @import("stwo_riscv_recursion").air.segment_outer_adapter_manifest;
const universal_manifest_mod = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
const universal_roster = @import("stwo_riscv_air_lang").framework.universal_roster;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
// Fixed Initial38 composition ABI. The typed product manifest is admitted above.
pub const INITIAL_WRAPPER_COMPONENT_COUNT: usize = universal_roster.COMPONENT_COUNT + 2;
pub const ETHEREUM_WRAPPER_COMPOSITION_VERSION: u16 = 1;
pub const ETHEREUM_WRAPPER_COMPOSITION_LOG_SPLIT: u32 = 2;

/// Fixed Ethereum wrapper facts, derived without a proof or query positions.
/// The capture constructor below uses the same column/sample/split rules.
pub const EthereumWrapperGeometryV1 = struct {
    tree_column_counts: [TREE_COUNT]u32,
    tree_heights: [TREE_COUNT]u32,
    sampled_value_count: u32,
    composition_log_size: u32,
    composition_log_split: u32,
    composition_chunk_log_degree: u32,
};

pub fn ethereumWrapperFixedGeometry(manifest: anytype, fri_log_blowup: u32) Error!EthereumWrapperGeometryV1 {
    return ethereumWrapperFixedGeometryForCount(universal_roster.COMPONENT_COUNT, manifest, fri_log_blowup);
}

pub fn ethereumInitialWrapperFixedGeometryV1(manifest: anytype, fri_log_blowup: u32) Error!EthereumWrapperGeometryV1 {
    return ethereumWrapperFixedGeometryForCount(INITIAL_WRAPPER_COMPONENT_COUNT, manifest, fri_log_blowup);
}

fn ethereumWrapperFixedGeometryForCount(comptime component_count: usize, manifest: anytype, fri_log_blowup: u32) Error!EthereumWrapperGeometryV1 {
    try manifest.validate();
    if (manifest.roster_count != component_count or fri_log_blowup >= stwo_core.circle.M31_CIRCLE_LOG_ORDER)
        return error.InvalidCompositionGeometry;
    const split = ETHEREUM_WRAPPER_COMPOSITION_LOG_SPLIT;
    const columns = try expectedTreeColumnCounts(manifest, split);
    const composition_log = try deriveNormalizedCompositionLogSize(manifest, split);
    const chunk_log = composition_log - split;
    var heights: [TREE_COUNT]u32 = @splat(0);
    var samples: usize = 0;
    for (columns, 0..) |count, tree| for (0..count) |column| {
        samples = std.math.add(usize, samples, try expectedSampleCount(manifest, POSEIDON_ROSTER_ROW, tree, column)) catch return error.ArithmeticOverflow;
    };
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const height = std.math.add(u32, geometry.log_size, fri_log_blowup) catch return error.ArithmeticOverflow;
        if (height >= stwo_core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidTraceLogGeometry;
        for ([_]u16{ geometry.preprocessed_columns, geometry.main_columns, geometry.interaction_columns }, 0..) |count, tree|
            if (count != 0) {
                heights[tree] = @max(heights[tree], height);
            };
    }
    heights[COMPOSITION_TREE_INDEX] = std.math.add(u32, chunk_log, fri_log_blowup) catch return error.ArithmeticOverflow;
    if (heights[COMPOSITION_TREE_INDEX] >= stwo_core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidTraceLogGeometry;
    var counts: [TREE_COUNT]u32 = undefined;
    for (columns, &counts) |count, *out| out.* = std.math.cast(u32, count) orelse return error.CircuitTooLarge;
    return .{ .tree_column_counts = counts, .tree_heights = heights, .sampled_value_count = std.math.cast(u32, samples) orelse return error.CircuitTooLarge, .composition_log_size = composition_log, .composition_log_split = split, .composition_chunk_log_degree = chunk_log };
}
pub const LAYOUT_DOMAIN =
    "stwo-zig/typed-air/recursion-composition-capture-layout/v3\x00";
pub const INPUT_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-composition-sample-input/v3\x00";
pub const CANONICAL_EMPTY_LAYOUT_DOMAIN =
    "stwo-zig/typed-air/recursion-canonical-empty-layout/v3.1\x00";

pub const ProofKind = graph_mod.ProofKind;
pub const TREE_COUNT: usize = universal_manifest_mod.TREE_COUNT + 1;
pub const PREPROCESSED_TREE_INDEX: usize =
    universal_manifest_mod.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX: usize = universal_manifest_mod.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX: usize =
    universal_manifest_mod.INTERACTION_TREE_INDEX;
pub const COMPOSITION_TREE_INDEX: usize = universal_manifest_mod.TREE_COUNT;
pub const POSEIDON_ROSTER_ROW: usize =
    @intFromEnum(universal_roster.Component.poseidon2);
pub const HEAP_ALLOCATIONS_PER_SAMPLE_WRITE: usize = 0;
pub const EMPTY_SAMPLE_COUNT: u32 = 0;
pub const CANONICAL_EMPTY_LAYOUT_SCHEMA_VERSION: u16 = 1;

pub const Error = std.mem.Allocator.Error || segment_manifest_mod.Error ||
    universal_manifest_mod.Error || error{
    AliasedInput,
    ArithmeticOverflow,
    CaptureLayoutIdentityMismatch,
    CircuitTooLarge,
    InvalidCaptureShape,
    InvalidEthereumInitialManifest,
    InvalidCanonicalEmptyLayout,
    InvalidCompositionGeometry,
    InvalidProofKind,
    InvalidSampleGeometry,
    InvalidSampleInputAuthority,
    InvalidSampleInputCount,
    InvalidTraceLogGeometry,
    ManifestAuthorityMismatch,
    NonCanonicalField,
};

pub const ManifestFamily = enum(u8) {
    universal_v1 = 1,
    segment_v2 = 2,
    temporal_parent_v3 = 3,
    ethereum_poseidon_h1_v1 = 4,
    canonical_empty_field_v2 = 5,
    common_fold_field_v2 = 6,
    ethereum_incremental_leaf_wrapper_v4 = 7,
    detached_segment_parent_v1 = 8,
};

/// Owned, verifier-derived offset table.  `offsets[tree][column]` indexes the
/// canonical flattened capture; the sentinel at `column + 1` makes every
/// lookup bounds-checkable without scanning prior columns.
pub const CaptureLayoutV3 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    proof_kind: ProofKind,
    manifest_family: ManifestFamily,
    manifest_seal: [32]u8,
    catalog_identity: [32]u8,
    component_count: u8,
    sampled_value_count: u32,
    tree_column_counts: [TREE_COUNT]u32,
    offsets: [TREE_COUNT][]usize,
    composition_log_size: u32,
    composition_log_split: u32,
    quotient_max_log_degree_bound: u32,
    fri_log_blowup: u32,
    identity: [32]u8,

    pub fn initSegment(
        allocator: std.mem.Allocator,
        manifest: *const segment_manifest_mod.Manifest,
        capture: anytype,
    ) Error!CaptureLayoutV3 {
        try manifest.validate();
        var result = try initForManifest(
            allocator,
            .segment_leaf,
            .segment_v2,
            POSEIDON_ROSTER_ROW,
            manifest,
            manifest.catalog_identity,
            capture,
            null,
        );
        result.manifest_seal =
            segment_manifest_mod.programGeometryShaId(manifest);
        result.identity = layoutIdentity(&result);
        try result.validateSelfConsistency();
        return result;
    }

    pub fn initBinary(
        allocator: std.mem.Allocator,
        manifest: *const universal_manifest_mod.Manifest,
        capture: anytype,
    ) Error!CaptureLayoutV3 {
        try manifest.validate();
        return initForManifest(
            allocator,
            .binary_node,
            .universal_v1,
            POSEIDON_ROSTER_ROW,
            manifest,
            [_]u8{0} ** 32,
            capture,
            null,
        );
    }

    /// Manifest-parametric binary layout for a versioned recursive program
    /// which retains the universal 36-row ABI but has its own authenticated
    /// placement semantics. The family tag is part of the layout identity;
    /// callers cannot relabel this value as frozen universal V1.
    pub fn initAuthenticatedBinary(
        allocator: std.mem.Allocator,
        comptime family: ManifestFamily,
        manifest: anytype,
        capture: anytype,
    ) !CaptureLayoutV3 {
        return initAuthenticatedBinaryWithProviderRow(
            allocator,
            family,
            POSEIDON_ROSTER_ROW,
            manifest,
            capture,
        );
    }

    /// Authenticated binary family whose native Poseidon provider occupies a
    /// nonlegacy physical row. The row is comptime protocol authority because
    /// it changes the per-column OODS sample geometry.
    pub fn initAuthenticatedBinaryWithProviderRow(
        allocator: std.mem.Allocator,
        comptime family: ManifestFamily,
        comptime poseidon_roster_row: usize,
        manifest: anytype,
        capture: anytype,
    ) !CaptureLayoutV3 {
        if (family == .universal_v1 or family == .segment_v2)
            return error.InvalidProofKind;
        try manifest.validate();
        if (poseidon_roster_row >= manifest.placements.len or
            manifest.placements[poseidon_roster_row] == null or
            std.mem.indexOfScalar(u8, manifest.roster_rows[0..manifest.roster_count], @as(u8, @intCast(poseidon_roster_row))) == null)
        {
            return error.ManifestAuthorityMismatch;
        }
        return initForManifest(
            allocator,
            .binary_node,
            family,
            poseidon_roster_row,
            manifest,
            [_]u8{0} ** 32,
            capture,
            null,
        );
    }

    /// Explicit wrapper-v1 policy, selected by the caller's authenticated
    /// Ethereum wrapper contract, never inferred from untrusted proof shape.
    /// Native leaf and all existing capture constructors retain split one.
    pub fn initEthereumWrapperV1(
        allocator: std.mem.Allocator,
        manifest: anytype,
        capture: anytype,
    ) Error!CaptureLayoutV3 {
        return initEthereumWrapperForCount(universal_roster.COMPONENT_COUNT, allocator, manifest, capture);
    }

    pub fn initEthereumInitialWrapperV1(allocator: std.mem.Allocator, manifest: anytype, capture: anytype) Error!CaptureLayoutV3 {
        return initEthereumWrapperForCount(INITIAL_WRAPPER_COMPONENT_COUNT, allocator, manifest, capture);
    }

    fn initEthereumWrapperForCount(comptime component_count: usize, allocator: std.mem.Allocator, manifest: anytype, capture: anytype) Error!CaptureLayoutV3 {
        try manifest.validate();
        if (manifest.roster_count != component_count or
            manifest.roster_rows[POSEIDON_ROSTER_ROW] != POSEIDON_ROSTER_ROW)
            return error.ManifestAuthorityMismatch;
        return initForManifest(
            allocator,
            .binary_node,
            .ethereum_incremental_leaf_wrapper_v4,
            POSEIDON_ROSTER_ROW,
            manifest,
            [_]u8{0} ** 32,
            capture,
            ETHEREUM_WRAPPER_COMPOSITION_LOG_SPLIT,
        );
    }

    pub fn validateAgainstEthereumWrapperV1(
        self: *const CaptureLayoutV3,
        manifest: anytype,
    ) Error!void {
        return self.validateAgainstEthereumWrapperForCount(universal_roster.COMPONENT_COUNT, manifest);
    }

    pub fn validateAgainstEthereumInitialWrapperV1(self: *const CaptureLayoutV3, manifest: anytype) Error!void {
        return self.validateAgainstEthereumWrapperForCount(INITIAL_WRAPPER_COMPONENT_COUNT, manifest);
    }

    fn validateAgainstEthereumWrapperForCount(self: *const CaptureLayoutV3, comptime component_count: usize, manifest: anytype) Error!void {
        if (manifest.roster_count != component_count) return error.ManifestAuthorityMismatch;
        try self.validateAgainstAuthenticatedBinary(.ethereum_incremental_leaf_wrapper_v4, manifest);
        if (self.composition_log_split != ETHEREUM_WRAPPER_COMPOSITION_LOG_SPLIT or
            self.composition_log_size != try deriveNormalizedCompositionLogSize(manifest, ETHEREUM_WRAPPER_COMPOSITION_LOG_SPLIT))
            return error.InvalidCompositionGeometry;
    }

    pub fn deinit(self: *CaptureLayoutV3) void {
        for (self.offsets) |tree| self.allocator.free(tree);
        self.* = undefined;
    }

    pub fn validateAgainstSegment(
        self: *const CaptureLayoutV3,
        manifest: *const segment_manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        try self.validateSelfConsistency();
        const program_geometry_id =
            segment_manifest_mod.programGeometryShaId(manifest);
        if (self.proof_kind != .segment_leaf or
            self.manifest_family != .segment_v2 or
            self.component_count != segment_manifest_mod.COMPONENT_COUNT or
            !std.mem.eql(
                u8,
                &self.manifest_seal,
                &program_geometry_id,
            ) or
            !std.mem.eql(u8, &self.catalog_identity, &manifest.catalog_identity))
        {
            return error.ManifestAuthorityMismatch;
        }
    }

    pub fn validateAgainstBinary(
        self: *const CaptureLayoutV3,
        manifest: *const universal_manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        try self.validateSelfConsistency();
        if (self.proof_kind != .binary_node or
            self.manifest_family != .universal_v1 or
            self.component_count != universal_roster.COMPONENT_COUNT or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !allZero(&self.catalog_identity))
        {
            return error.ManifestAuthorityMismatch;
        }
    }

    pub fn validateAgainstAuthenticatedBinary(
        self: *const CaptureLayoutV3,
        comptime family: ManifestFamily,
        manifest: anytype,
    ) !void {
        if (family == .universal_v1 or family == .segment_v2)
            return error.InvalidProofKind;
        try manifest.validate();
        try self.validateSelfConsistency();
        if (self.proof_kind != .binary_node or
            self.manifest_family != family or
            self.component_count != manifest.roster_count or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !allZero(&self.catalog_identity))
        {
            return error.ManifestAuthorityMismatch;
        }
    }

    /// Structural self-check only; manifest agreement is established by the
    /// two `validateAgainst*` entry points above.
    pub fn validateSelfConsistency(self: *const CaptureLayoutV3) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.sampled_value_count == 0 or
            self.sampled_value_count >= m31.Modulus or
            self.composition_log_size <= self.composition_log_split or
            self.quotient_max_log_degree_bound !=
                self.composition_log_size - self.composition_log_split)
        {
            return error.CaptureLayoutIdentityMismatch;
        }
        var final_offset: ?usize = null;
        for (self.offsets, self.tree_column_counts) |tree, column_count| {
            if (tree.len != @as(usize, column_count) + 1 or tree.len == 0)
                return error.CaptureLayoutIdentityMismatch;
            for (tree[1..], tree[0 .. tree.len - 1]) |next, prior|
                if (next <= prior) return error.CaptureLayoutIdentityMismatch;
            if (final_offset) |prior_tree_end| {
                if (tree[0] != prior_tree_end)
                    return error.CaptureLayoutIdentityMismatch;
            } else if (tree[0] != 0) {
                return error.CaptureLayoutIdentityMismatch;
            }
            final_offset = tree[tree.len - 1];
        }
        if (final_offset.? != self.sampled_value_count or
            !std.mem.eql(u8, &self.identity, &layoutIdentity(self)))
        {
            return error.CaptureLayoutIdentityMismatch;
        }
    }

    pub fn at(
        self: *const CaptureLayoutV3,
        values: anytype,
        tree: usize,
        column: usize,
        sample: usize,
    ) Error!@TypeOf(values[0]) {
        if (tree >= TREE_COUNT or column + 1 >= self.offsets[tree].len)
            return error.InvalidSampleGeometry;
        const start = self.offsets[tree][column];
        const end = self.offsets[tree][column + 1];
        if (sample >= end - start or start + sample >= values.len)
            return error.InvalidSampleGeometry;
        return values[start + sample];
    }
};

/// Owned layout for the proofless canonical-empty program.
///
/// Empty has no verifier capture, but its inactive 36-row shell must still be
/// replayed with the exact universal column/quotient geometry.  Copying that
/// geometry into a distinct type prevents an empty recorder from accepting a
/// binary layout by accident.  `source_sample_count == 0` is the proof ABI;
/// `internal_sample_count` is the zero-constrained graph workspace used while
/// replaying the shell.
pub const CanonicalEmptyCaptureLayoutV3 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = CANONICAL_EMPTY_LAYOUT_SCHEMA_VERSION,
    manifest_seal: [32]u8,
    binary_geometry_identity: [32]u8,
    source_sample_count: u32 = 0,
    internal_sample_count: u32,
    geometry: CaptureLayoutV3,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const universal_manifest_mod.Manifest,
        binary: *const CaptureLayoutV3,
    ) Error!CanonicalEmptyCaptureLayoutV3 {
        try binary.validateAgainstBinary(manifest);
        var geometry = binary.*;
        geometry.allocator = allocator;
        geometry.offsets = undefined;
        var copied: usize = 0;
        errdefer for (geometry.offsets[0..copied]) |tree| allocator.free(tree);
        for (binary.offsets, 0..) |tree, index| {
            geometry.offsets[index] = try allocator.dupe(usize, tree);
            copied += 1;
        }
        var result = CanonicalEmptyCaptureLayoutV3{
            .allocator = allocator,
            .manifest_seal = manifest.seal,
            .binary_geometry_identity = binary.identity,
            .internal_sample_count = binary.sampled_value_count,
            .geometry = geometry,
            .identity = undefined,
        };
        result.identity = canonicalEmptyLayoutIdentity(&result);
        try result.validateAgainst(manifest, binary);
        return result;
    }

    pub fn deinit(self: *CanonicalEmptyCaptureLayoutV3) void {
        self.geometry.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const CanonicalEmptyCaptureLayoutV3,
        manifest: *const universal_manifest_mod.Manifest,
        binary: *const CaptureLayoutV3,
    ) Error!void {
        try manifest.validate();
        try binary.validateAgainstBinary(manifest);
        try self.geometry.validateAgainstBinary(manifest);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != CANONICAL_EMPTY_LAYOUT_SCHEMA_VERSION or
            self.source_sample_count != 0 or
            self.internal_sample_count == 0 or
            self.internal_sample_count != self.geometry.sampled_value_count or
            self.internal_sample_count != binary.sampled_value_count or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(
                u8,
                &self.binary_geometry_identity,
                &binary.identity,
            ) or
            !std.mem.eql(u8, &self.geometry.identity, &binary.identity) or
            !std.mem.eql(u8, &self.identity, &canonicalEmptyLayoutIdentity(self)))
        {
            return error.InvalidCanonicalEmptyLayout;
        }
    }
};

/// Pointer-free authority for the one shared sampled-value input vector.
/// Segment and binary captures retain separate layout identities; sharing the
/// max-sized storage does not conflate their column meanings.
pub const SampleInputAuthorityV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    segment_sample_count: u32,
    binary_sample_count: u32,
    empty_sample_count: u32 = EMPTY_SAMPLE_COUNT,
    max_sample_count: u32,
    segment_layout_identity: [32]u8,
    binary_layout_identity: [32]u8,
    identity: [32]u8,

    pub fn seal(
        segment: *const CaptureLayoutV3,
        binary: *const CaptureLayoutV3,
    ) Error!SampleInputAuthorityV3 {
        try segment.validateSelfConsistency();
        try binary.validateSelfConsistency();
        if (segment.proof_kind != .segment_leaf or
            binary.proof_kind != .binary_node)
        {
            return error.InvalidProofKind;
        }
        var result = SampleInputAuthorityV3{
            .segment_sample_count = segment.sampled_value_count,
            .binary_sample_count = binary.sampled_value_count,
            .max_sample_count = @max(
                segment.sampled_value_count,
                binary.sampled_value_count,
            ),
            .segment_layout_identity = segment.identity,
            .binary_layout_identity = binary.identity,
            .identity = undefined,
        };
        result.identity = sampleInputAuthorityIdentity(result);
        try result.validateAgainstLayouts(segment, binary);
        return result;
    }

    pub fn validateAgainstLayouts(
        self: SampleInputAuthorityV3,
        segment: *const CaptureLayoutV3,
        binary: *const CaptureLayoutV3,
    ) Error!void {
        try segment.validateSelfConsistency();
        try binary.validateSelfConsistency();
        try self.validateSelfConsistency();
        if (segment.proof_kind != .segment_leaf or
            binary.proof_kind != .binary_node or
            self.segment_sample_count != segment.sampled_value_count or
            self.binary_sample_count != binary.sampled_value_count or
            !std.mem.eql(
                u8,
                &self.segment_layout_identity,
                &segment.identity,
            ) or !std.mem.eql(
            u8,
            &self.binary_layout_identity,
            &binary.identity,
        )) return error.InvalidSampleInputAuthority;
    }

    /// Encoding consistency only. Trusted callers additionally validate both
    /// retained layouts against their manifests.
    pub fn validateSelfConsistency(self: SampleInputAuthorityV3) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.segment_sample_count == 0 or self.binary_sample_count == 0 or
            self.empty_sample_count != EMPTY_SAMPLE_COUNT or
            self.max_sample_count != @max(
                self.segment_sample_count,
                self.binary_sample_count,
            ) or self.max_sample_count >= m31.Modulus or
            allZero(&self.segment_layout_identity) or
            allZero(&self.binary_layout_identity) or
            !std.mem.eql(
                u8,
                &self.identity,
                &sampleInputAuthorityIdentity(self),
            ))
        {
            return error.InvalidSampleInputAuthority;
        }
    }

    pub fn sourceCount(self: SampleInputAuthorityV3, kind: ProofKind) u32 {
        return switch (kind) {
            .segment_leaf => self.segment_sample_count,
            .binary_node => self.binary_sample_count,
            .empty_leaf => self.empty_sample_count,
        };
    }

    /// Preflights count, canonicity, and overlap before zeroing the inactive
    /// tail. No rejected source can partially mutate the destination.
    pub fn writePaddedSamples(
        self: SampleInputAuthorityV3,
        kind: ProofKind,
        source: []const QM31,
        destination: []QM31,
    ) Error!void {
        try self.validateSelfConsistency();
        if (source.len != self.sourceCount(kind) or
            destination.len != self.max_sample_count)
        {
            return error.InvalidSampleInputCount;
        }
        for (source) |value| try requireCanonical(value);
        if (overlap(
            std.mem.sliceAsBytes(source),
            std.mem.sliceAsBytes(destination),
        )) return error.AliasedInput;

        @memset(destination, QM31.zero());
        if (source.len != 0) @memcpy(destination[0..source.len], source);
    }
};

fn initForManifest(
    allocator: std.mem.Allocator,
    kind: ProofKind,
    family: ManifestFamily,
    poseidon_roster_row: usize,
    manifest: anytype,
    catalog_identity: [32]u8,
    capture: anytype,
    normalized_split: ?u32,
) Error!CaptureLayoutV3 {
    if (capture.sampled_points.len != TREE_COUNT or
        capture.column_log_sizes.len != TREE_COUNT)
    {
        return error.InvalidCaptureShape;
    }
    const composition_columns = capture.sampled_points[COMPOSITION_TREE_INDEX].len;
    if (composition_columns == 0 or
        composition_columns % qm31.SECURE_EXTENSION_DEGREE != 0)
    {
        return error.InvalidCompositionGeometry;
    }
    const chunk_count = composition_columns / qm31.SECURE_EXTENSION_DEGREE;
    if (!std.math.isPowerOfTwo(chunk_count))
        return error.InvalidCompositionGeometry;
    const split: u32 = @intCast(std.math.log2_int(usize, chunk_count));
    const expected_composition_columns = verifier_types.compositionColumnCount(
        split,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidCompositionGeometry;
    if (split != (normalized_split orelse verifier_types.COMPOSITION_LOG_SPLIT) or
        composition_columns != expected_composition_columns)
    {
        return error.InvalidCompositionGeometry;
    }

    const composition_log_size = if (normalized_split) |admitted_split|
        try deriveNormalizedCompositionLogSize(manifest, admitted_split)
    else
        try deriveCompositionLogSize(manifest);
    if (composition_log_size <= split)
        return error.InvalidCompositionGeometry;
    const quotient_bound = composition_log_size - split;
    const expected_columns = try expectedTreeColumnCounts(manifest, split);
    for (capture.sampled_points, capture.column_log_sizes, expected_columns) |
        points,
        logs,
        expected,
    | if (points.len != expected or logs.len != expected)
        return error.InvalidSampleGeometry;

    const fri_log_blowup = try deriveFriLogBlowup(
        manifest,
        capture.column_log_sizes,
    );
    try validateColumnLogs(
        manifest,
        capture.column_log_sizes,
        quotient_bound,
        fri_log_blowup,
    );

    var offsets: [TREE_COUNT][]usize = undefined;
    var initialized: usize = 0;
    errdefer for (offsets[0..initialized]) |tree| allocator.free(tree);
    var tree_column_counts: [TREE_COUNT]u32 = undefined;
    var value_cursor: usize = 0;
    for (capture.sampled_points, &offsets, &tree_column_counts, 0..) |
        tree,
        *tree_offsets,
        *column_count,
        tree_index,
    | {
        column_count.* = std.math.cast(u32, tree.len) orelse
            return error.CircuitTooLarge;
        tree_offsets.* = try allocator.alloc(usize, tree.len + 1);
        initialized += 1;
        for (tree, 0..) |column, column_index| {
            const expected_samples = try expectedSampleCount(
                manifest,
                poseidon_roster_row,
                tree_index,
                column_index,
            );
            if (column.len != expected_samples)
                return error.InvalidSampleGeometry;
            tree_offsets.*[column_index] = value_cursor;
            value_cursor = std.math.add(
                usize,
                value_cursor,
                column.len,
            ) catch return error.ArithmeticOverflow;
        }
        tree_offsets.*[tree.len] = value_cursor;
    }
    if (value_cursor != capture.sampled_values.len)
        return error.InvalidSampleGeometry;
    const sampled_value_count = std.math.cast(u32, value_cursor) orelse
        return error.CircuitTooLarge;
    var result = CaptureLayoutV3{
        .allocator = allocator,
        .proof_kind = kind,
        .manifest_family = family,
        .manifest_seal = manifest.seal,
        .catalog_identity = catalog_identity,
        .component_count = manifest.roster_count,
        .sampled_value_count = sampled_value_count,
        .tree_column_counts = tree_column_counts,
        .offsets = offsets,
        .composition_log_size = composition_log_size,
        .composition_log_split = split,
        .quotient_max_log_degree_bound = quotient_bound,
        .fri_log_blowup = fri_log_blowup,
        .identity = undefined,
    };
    result.identity = layoutIdentity(&result);
    try result.validateSelfConsistency();
    return result;
}

const CaptureGeometry = @import("recursion_capture_geometry.zig");
const deriveNormalizedCompositionLogSize = CaptureGeometry.deriveNormalizedCompositionLogSize;
const deriveCompositionLogSize = CaptureGeometry.deriveCompositionLogSize;
const expectedTreeColumnCounts = CaptureGeometry.expectedTreeColumnCounts;
const expectedSampleCount = CaptureGeometry.expectedSampleCount;
const deriveFriLogBlowup = CaptureGeometry.deriveFriLogBlowup;
const validateColumnLogs = CaptureGeometry.validateColumnLogs;

const CaptureIdentity = @import("recursion_capture_identity.zig");
const layoutIdentity = CaptureIdentity.layoutIdentity;
const canonicalEmptyLayoutIdentity = CaptureIdentity.canonicalEmptyLayoutIdentity;
const sampleInputAuthorityIdentity = CaptureIdentity.sampleInputAuthorityIdentity;
const requireCanonical = CaptureIdentity.requireCanonical;
const overlap = CaptureIdentity.overlap;
const allZero = CaptureIdentity.allZero;

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or TREE_COUNT != 4 or
        PREPROCESSED_TREE_INDEX != 0 or MAIN_TREE_INDEX != 1 or
        INTERACTION_TREE_INDEX != 2 or COMPOSITION_TREE_INDEX != 3 or
        POSEIDON_ROSTER_ROW != 34 or
        EMPTY_SAMPLE_COUNT != 0 or HEAP_ALLOCATIONS_PER_SAMPLE_WRITE != 0)
    {
        @compileError("V3 composition capture-layout geometry drifted");
    }
}
