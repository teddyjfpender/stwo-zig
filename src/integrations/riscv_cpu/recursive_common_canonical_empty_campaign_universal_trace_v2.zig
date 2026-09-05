//! Exact universal-tree materializer for the campaign-native empty wrapper.
//!
//! All 34 logical components are verifier-selected inactive.  The range
//! provider retains its canonical fixed preprocessing with zero multiplicity.
//! The Poseidon2 provider commits exactly the 113 atomic-I/O calls derived
//! from NodePublicV2.  No host hash stands in for a provider row.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_canonical_empty_campaign_field_public_v2.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air = frontend.recursion.air;
const provider = air.universal_shared_provider;
const range_bridge = air.range_check_8_8_bridge;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = field_public.Error || manifest_mod.Error ||
    provider.Error || error{
    CanonicalEmptyProviderClaimMismatch,
    CanonicalEmptyProviderTraceMismatch,
    CanonicalEmptyTreeAlias,
    CanonicalEmptyTreeNotFresh,
    CanonicalEmptyTreeShapeMismatch,
    StepClockCycle,
    ZeroDenominator,
};

pub const ProviderClaimsV2 = struct {
    poseidon2: QM31,
    poseidon2_io: QM31,

    pub fn total(self: ProviderClaimsV2) QM31 {
        return self.poseidon2.add(self.poseidon2_io);
    }

    pub fn validate(self: ProviderClaimsV2) Error!void {
        if (!self.poseidon2.isZero())
            return error.CanonicalEmptyProviderClaimMismatch;
    }
};

pub fn fillPreprocessed(
    manifest: *const manifest_mod.Manifest,
    destination: [][]M31,
) Error!void {
    _ = try manifest_mod.logSizesFromManifest(manifest);
    try preflightFreshTree(
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    errdefer clearTree(destination);

    const poseidon = try manifest.placement(.poseidon2);
    destination[poseidon.preprocessed_offset][
        committedRow(
            0,
            poseidon.geometry.log_size,
        )
    ] = M31.one();

    const range = try manifest.placement(.range_check_8_8);
    destination[range.preprocessed_offset][range_bridge.committedRow(0)] =
        M31.one();
    const low = destination[range.preprocessed_offset + 1];
    const high = destination[range.preprocessed_offset + 2];
    for (0..range_bridge.TABLE_SIZE) |logical_row| {
        const row = range_bridge.committedRow(logical_row);
        low[row] = M31.fromCanonical(@intCast(logical_row & 0xff));
        high[row] = M31.fromCanonical(@intCast(logical_row >> 8));
    }
}

pub fn fillMain(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    schedule: *const field_public.PoseidonScheduleV2,
    cold: *const source_mod.ColdInputV2,
    destination: [][]M31,
) Error!void {
    _ = try manifest_mod.logSizesFromManifest(manifest);
    try schedule.validateAgainst(cold);
    try preflightFreshTree(
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    errdefer clearTree(destination);

    const placement = try manifest.placement(.poseidon2);
    if (placement.geometry.log_size < manifest_mod.POSEIDON_LOG_SIZE)
        return error.CanonicalEmptyProviderTraceMismatch;
    var columns: [poseidon_air.N_MAIN_COLUMNS][]M31 = undefined;
    for (
        &columns,
        destination[placement.main_offset..][0..columns.len],
    ) |*target, source| target.* = source;
    try poseidon_air.generateMainInto(
        allocator,
        &columns,
        schedule.callsSlice(),
        placement.geometry.log_size,
    );
}

pub fn fillInteraction(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    schedule: *const field_public.PoseidonScheduleV2,
    cold: *const source_mod.ColdInputV2,
    relations: *const provider.SharedProviderRelations,
    destination: [][]M31,
) Error!ProviderClaimsV2 {
    _ = try manifest_mod.logSizesFromManifest(manifest);
    try relations.validate();
    try schedule.validateAgainst(cold);
    try preflightFreshTree(
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        destination,
    );
    errdefer clearTree(destination);

    const placement = try manifest.placement(.poseidon2);
    var generated = try poseidon_air.generateInteraction(
        allocator,
        schedule.callsSlice(),
        placement.geometry.log_size,
        &relations.native,
    );
    defer generated.deinit(allocator);
    for (
        destination[placement.interaction_offset..][0..poseidon_air.N_INTERACTION_COLUMNS],
        &generated.columns,
    ) |target, source| @memcpy(target, source);
    const result = ProviderClaimsV2{
        .poseidon2 = generated.claims.sums[0],
        .poseidon2_io = generated.claims.sums[1],
    };
    try result.validate();
    return result;
}

/// Allocation-backed verifier replay of the exact native provider claims.
/// This accepts no producer-supplied claim or output vector.
pub fn rebuildClaims(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    schedule: *const field_public.PoseidonScheduleV2,
    cold: *const source_mod.ColdInputV2,
    relations: *const provider.SharedProviderRelations,
) Error!ProviderClaimsV2 {
    _ = try manifest_mod.logSizesFromManifest(manifest);
    try relations.validate();
    try schedule.validateAgainst(cold);
    const placement = try manifest.placement(.poseidon2);
    var generated = try poseidon_air.generateInteraction(
        allocator,
        schedule.callsSlice(),
        placement.geometry.log_size,
        &relations.native,
    );
    defer generated.deinit(allocator);
    const result = ProviderClaimsV2{
        .poseidon2 = generated.claims.sums[0],
        .poseidon2_io = generated.claims.sums[1],
    };
    try result.validate();
    return result;
}

pub fn publicRequestBoundary(claims: ProviderClaimsV2) Error!QM31 {
    try claims.validate();
    return claims.poseidon2_io.neg();
}

fn preflightFreshTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: [][]M31,
) Error!void {
    try manifest_mod.validateExact(manifest);
    const expected_count: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => return error.CanonicalEmptyTreeShapeMismatch,
    };
    if (destination.len != expected_count)
        return error.CanonicalEmptyTreeShapeMismatch;
    for (destination, 0..) |column, column_index| {
        const expected_log = try columnLogSize(manifest, tree, column_index);
        const expected_len = @as(usize, 1) << @intCast(expected_log);
        if (column.len != expected_len)
            return error.CanonicalEmptyTreeShapeMismatch;
        for (column) |value| if (!value.isZero())
            return error.CanonicalEmptyTreeNotFresh;
        for (destination[column_index + 1 ..]) |other|
            if (slicesOverlap(column, other))
                return error.CanonicalEmptyTreeAlias;
    }
}

fn columnLogSize(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    column_index: usize,
) Error!u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
            manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
            manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
            else => return error.CanonicalEmptyTreeShapeMismatch,
        };
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
            manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
            else => return error.CanonicalEmptyTreeShapeMismatch,
        };
        if (column_index >= offset and column_index - offset < count)
            return placement.geometry.log_size;
    }
    return error.CanonicalEmptyTreeShapeMismatch;
}

fn clearTree(destination: [][]M31) void {
    for (destination) |column| @memset(column, M31.zero());
}

fn slicesOverlap(left: []const M31, right: []const M31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len * @sizeOf(M31);
    const right_end = right_start + right.len * @sizeOf(M31);
    return left_start < right_end and right_start < left_end;
}

fn committedRow(logical_row: usize, log_size: u32) usize {
    return stwo_core.utils.bitReverseIndex(
        stwo_core.utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        field_public.POSEIDON_CALL_COUNT != 173 or
        manifest_mod.POSEIDON_LOG_SIZE != 8 or PRODUCTION_ACTIVATION)
    {
        @compileError("campaign canonical-empty universal trace V2 drifted");
    }
}
