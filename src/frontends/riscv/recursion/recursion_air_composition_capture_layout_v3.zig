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
const Sha256 = std.crypto.hash.sha2.Sha256;

const graph_mod = @import("air/composition_circuit.zig");
const segment_manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const universal_manifest_mod = @import("air/universal_adapter_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
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
            manifest,
            manifest.catalog_identity,
            capture,
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
            manifest,
            [_]u8{0} ** 32,
            capture,
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
        if (family == .universal_v1 or family == .segment_v2)
            return error.InvalidProofKind;
        try manifest.validate();
        return initForManifest(
            allocator,
            .binary_node,
            family,
            manifest,
            [_]u8{0} ** 32,
            capture,
        );
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
    manifest: anytype,
    catalog_identity: [32]u8,
    capture: anytype,
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
    if (split != verifier_types.COMPOSITION_LOG_SPLIT or
        composition_columns != expected_composition_columns)
    {
        return error.InvalidCompositionGeometry;
    }

    const composition_log_size = try deriveCompositionLogSize(manifest);
    if (composition_log_size <= split)
        return error.InvalidCompositionGeometry;
    const quotient_bound = composition_log_size - split;
    const expected_columns = [TREE_COUNT]usize{
        @intCast(manifest.total_preprocessed_columns),
        @intCast(manifest.total_main_columns),
        @intCast(manifest.total_interaction_columns),
        expected_composition_columns,
    };
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

fn deriveCompositionLogSize(manifest: anytype) Error!u32 {
    var composition_log_size: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const degree_minus_one: u32 = geometry.protocol_constraint_degree - 1;
        const quotient_blowup: u32 = @max(
            1,
            std.math.log2_int_ceil(u32, degree_minus_one),
        );
        composition_log_size = @max(
            composition_log_size,
            std.math.add(u32, geometry.log_size, quotient_blowup) catch
                return error.ArithmeticOverflow,
        );
    }
    return composition_log_size;
}

fn expectedSampleCount(
    manifest: anytype,
    tree: usize,
    column: usize,
) Error!usize {
    if (tree != universal_manifest_mod.INTERACTION_TREE_INDEX) return 1;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = @intCast(placement.interaction_offset);
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (row == POSEIDON_ROSTER_ROW) return 2;
            const final_start = end - qm31.SECURE_EXTENSION_DEGREE;
            return if (column >= final_start) 2 else 1;
        }
    }
    return error.InvalidSampleGeometry;
}

fn deriveFriLogBlowup(manifest: anytype, logs: anytype) Error!u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        const candidates = [_]struct { tree: usize, start: u32, count: u16 }{
            .{ .tree = universal_manifest_mod.PREPROCESSED_TREE_INDEX, .start = placement.preprocessed_offset, .count = geometry.preprocessed_columns },
            .{ .tree = universal_manifest_mod.MAIN_TREE_INDEX, .start = placement.main_offset, .count = geometry.main_columns },
            .{ .tree = universal_manifest_mod.INTERACTION_TREE_INDEX, .start = placement.interaction_offset, .count = geometry.interaction_columns },
        };
        for (candidates) |candidate| {
            if (candidate.count == 0) continue;
            const observed = logs[candidate.tree][candidate.start];
            if (observed < geometry.log_size)
                return error.InvalidTraceLogGeometry;
            return observed - geometry.log_size;
        }
    }
    return error.InvalidTraceLogGeometry;
}

fn validateColumnLogs(
    manifest: anytype,
    logs: anytype,
    composition_chunk_log_size: u32,
    fri_log_blowup: u32,
) Error!void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        const expected = std.math.add(
            u32,
            geometry.log_size,
            fri_log_blowup,
        ) catch return error.ArithmeticOverflow;
        const ranges = [_]struct { tree: usize, start: u32, count: u16 }{
            .{ .tree = universal_manifest_mod.PREPROCESSED_TREE_INDEX, .start = placement.preprocessed_offset, .count = geometry.preprocessed_columns },
            .{ .tree = universal_manifest_mod.MAIN_TREE_INDEX, .start = placement.main_offset, .count = geometry.main_columns },
            .{ .tree = universal_manifest_mod.INTERACTION_TREE_INDEX, .start = placement.interaction_offset, .count = geometry.interaction_columns },
        };
        for (ranges) |range| for (logs[range.tree][range.start..][0..range.count]) |
            actual,
        | if (actual != expected) return error.InvalidTraceLogGeometry;
    }
    const expected_composition = std.math.add(
        u32,
        composition_chunk_log_size,
        fri_log_blowup,
    ) catch return error.ArithmeticOverflow;
    for (logs[COMPOSITION_TREE_INDEX]) |actual|
        if (actual != expected_composition)
            return error.InvalidTraceLogGeometry;
}

fn layoutIdentity(layout: *const CaptureLayoutV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LAYOUT_DOMAIN);
    hashInt(&hash, u16, layout.format_version);
    hashInt(&hash, u16, layout.schema_version);
    hashInt(&hash, u8, proofKindCode(layout.proof_kind));
    hashInt(&hash, u8, @intFromEnum(layout.manifest_family));
    hash.update(&layout.manifest_seal);
    hash.update(&layout.catalog_identity);
    hashInt(&hash, u8, layout.component_count);
    hashInt(&hash, u32, layout.sampled_value_count);
    for (layout.tree_column_counts) |count| hashInt(&hash, u32, count);
    for (layout.offsets) |tree| {
        hashInt(&hash, u32, @intCast(tree.len));
        for (tree) |offset| hashInt(&hash, u64, @intCast(offset));
    }
    hashInt(&hash, u32, layout.composition_log_size);
    hashInt(&hash, u32, layout.composition_log_split);
    hashInt(&hash, u32, layout.quotient_max_log_degree_bound);
    hashInt(&hash, u32, layout.fri_log_blowup);
    return hash.finalResult();
}

fn canonicalEmptyLayoutIdentity(
    layout: *const CanonicalEmptyCaptureLayoutV3,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CANONICAL_EMPTY_LAYOUT_DOMAIN);
    hashInt(&hash, u16, layout.format_version);
    hashInt(&hash, u16, layout.schema_version);
    hash.update(&layout.manifest_seal);
    hash.update(&layout.binary_geometry_identity);
    hashInt(&hash, u32, layout.source_sample_count);
    hashInt(&hash, u32, layout.internal_sample_count);
    hash.update(&layout.geometry.identity);
    return hash.finalResult();
}

fn sampleInputAuthorityIdentity(value: SampleInputAuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(INPUT_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.segment_sample_count);
    hashInt(&hash, u32, value.binary_sample_count);
    hashInt(&hash, u32, value.empty_sample_count);
    hashInt(&hash, u32, value.max_sample_count);
    hash.update(&value.segment_layout_identity);
    hash.update(&value.binary_layout_identity);
    return hash.finalResult();
}

fn proofKindCode(kind: ProofKind) u8 {
    return switch (kind) {
        .segment_leaf => 0,
        .binary_node => 1,
        .empty_leaf => 2,
    };
}

fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn allZero(value: []const u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

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
