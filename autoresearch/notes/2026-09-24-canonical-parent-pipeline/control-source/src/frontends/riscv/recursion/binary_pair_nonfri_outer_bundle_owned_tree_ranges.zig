//! Internal binary pair nonfri outer bundle authority shard; use binary_pair_nonfri_outer_bundle.zig publicly.

const dependency_0 = @import("binary_pair_nonfri_outer_bundle_contract.zig");

const BUNDLE_ID_DOMAIN = dependency_0.BUNDLE_ID_DOMAIN;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const PREFIX_ROW_COUNT = dependency_0.PREFIX_ROW_COUNT;
const SHARED_PROVIDER_ROW = dependency_0.SHARED_PROVIDER_ROW;
const hashDigestWords = dependency_0.hashDigestWords;
const hashInt = dependency_0.hashInt;
const hashStatementWords = dependency_0.hashStatementWords;
const installedLogSizes = dependency_0.installedLogSizes;
const manifest_mod = dependency_0.manifest_mod;
const providerSnapshotId = dependency_0.providerSnapshotId;
const providerSourceAuthorityId = dependency_0.providerSourceAuthorityId;
const roster = dependency_0.roster;
const shared_provider = dependency_0.shared_provider;
const std = dependency_0.std;

pub fn bundleIdentity(bundle: anytype) [32]u8 {
    const input = bundle.inputs;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BUNDLE_ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&input.transcript_source.authority_seal);
    hashDigestWords(&hash, input.transcript_prepared.authenticated_root.pair.node_id);
    hashDigestWords(&hash, input.statement_parent.source_id);
    hashDigestWords(&hash, input.statement_prepared.source_id);
    hash.update(&input.public_authority.authority_seal);
    hash.update(&input.inactive_source.authority_seal);
    hash.update(&input.inactive_prepared.authority_seal);
    hash.update(&providerSourceAuthorityId(input));
    hash.update(&providerSnapshotId(input));
    hashDigestWords(&hash, input.transcript_prepared.authority.context.contextId() catch
        [_]u32{0} ** 8);
    const logs = installedLogSizes(bundle);
    for (logs[0..PREFIX_ROW_COUNT]) |value| hashInt(&hash, u32, value);
    hashInt(&hash, u32, logs[SHARED_PROVIDER_ROW]);
    hashStatementWords(&hash, &input.transcript_prepared.left_words);
    hashStatementWords(&hash, &input.transcript_prepared.right_words);
    hashStatementWords(&hash, &input.transcript_prepared.parent_words);
    return hash.finalResult();
}

pub fn preflightFreshOwnedTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    // Authenticate the complete roster and seal once. `Manifest.placement`
    // repeats this O(36) validation, so all remaining accesses use the sealed
    // table through `placementAfterValidation`.
    try manifest.validate();
    if (destination.len != try totalColumns(manifest, tree))
        return error.InvalidTraceShape;

    const owned = try ownedTreeRanges(manifest, tree);

    inline for (0..PREFIX_ROW_COUNT) |row|
        try preflightOwnedRow(manifest, tree, @enumFromInt(row), destination);
    try preflightOwnedRow(manifest, tree, .range_check_8_8, destination);

    // Ownership is two constant-time interval checks. In particular, no
    // authenticated placement lookup is permitted in either alias loop.
    for (destination, 0..) |owned_column, owned_index| {
        if (!owned.contains(owned_index)) continue;
        for (destination, 0..) |other, other_index| {
            if (owned_index == other_index) continue;
            if (owned.contains(other_index) and
                other_index < owned_index)
            {
                continue;
            }
            if (try slicesOverlap(owned_column, other))
                return error.DestinationAlias;
        }
    }
}

pub fn preflightOwnedRow(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    row: roster.Component,
    destination: []const []M31,
) !void {
    const placement = try placementAfterValidation(manifest, row);
    const offset = try treeOffset(placement, tree);
    const count = try treeColumnCount(placement, tree);
    const end = std.math.add(usize, offset, count) catch
        return error.ArithmeticOverflow;
    if (end > destination.len) return error.InvalidTraceShape;
    const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (destination[offset..end]) |column| {
        if (column.len != row_count) return error.InvalidTraceShape;
        for (column) |value| if (!value.isZero())
            return error.DestinationNotZero;
    }
}

pub fn clearOwnedTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) void {
    inline for (0..PREFIX_ROW_COUNT) |row|
        clearOwnedRow(manifest, tree, @enumFromInt(row), destination);
    clearOwnedRow(manifest, tree, .range_check_8_8, destination);
}

pub fn clearOwnedRow(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    row: roster.Component,
    destination: []const []M31,
) void {
    const placement = placementAfterValidation(manifest, row) catch unreachable;
    const offset = treeOffset(placement, tree) catch unreachable;
    const count = treeColumnCount(placement, tree) catch unreachable;
    for (destination[offset .. offset + count]) |column|
        @memset(column, M31.zero());
}

pub const ColumnRange = struct {
    start: usize,
    end: usize,

    fn contains(self: ColumnRange, column: usize) bool {
        return column >= self.start and column < self.end;
    }
};

pub const OwnedTreeRanges = struct {
    prefix: ColumnRange,
    shared_provider: ColumnRange,

    fn contains(self: OwnedTreeRanges, column: usize) bool {
        return self.prefix.contains(column) or
            self.shared_provider.contains(column);
    }
};

/// Roster ordering makes rows 0--17 one contiguous range in every tree; row
/// 35 is the second and final owned range. Preparing both once turns every
/// alias-loop ownership test into constant-time integer comparisons.
pub fn ownedTreeRanges(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
) !OwnedTreeRanges {
    const first = try placementAfterValidation(manifest, .control);
    const last = try placementAfterValidation(
        manifest,
        .vm_public_logup_control,
    );
    const provider = try placementAfterValidation(manifest, .range_check_8_8);

    const prefix_start = try treeOffset(first, tree);
    const prefix_end = std.math.add(
        usize,
        try treeOffset(last, tree),
        try treeColumnCount(last, tree),
    ) catch return error.ArithmeticOverflow;
    const provider_start = try treeOffset(provider, tree);
    const provider_end = std.math.add(
        usize,
        provider_start,
        try treeColumnCount(provider, tree),
    ) catch return error.ArithmeticOverflow;
    return .{
        .prefix = .{ .start = prefix_start, .end = prefix_end },
        .shared_provider = .{
            .start = provider_start,
            .end = provider_end,
        },
    };
}

/// Reads one placement only after the caller has authenticated the complete
/// manifest. Keeping this private prevents an unchecked table read from
/// becoming a second public admission path.
pub fn placementAfterValidation(
    manifest: *const manifest_mod.Manifest,
    row: roster.Component,
) !manifest_mod.Placement {
    return manifest.placements[@intFromEnum(row)] orelse
        error.ComponentNotAdmitted;
}

pub fn totalColumns(manifest: *const manifest_mod.Manifest, tree: usize) !usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => error.InvalidTreeIndex,
    };
}

pub fn treeOffset(placement: manifest_mod.Placement, tree: usize) !usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => error.InvalidTreeIndex,
    };
}

pub fn treeColumnCount(placement: manifest_mod.Placement, tree: usize) !usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
        else => error.InvalidTreeIndex,
    };
}

pub fn slicesOverlap(left: []const M31, right: []const M31) !bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_bytes = std.math.mul(usize, left.len, @sizeOf(M31)) catch
        return error.ArithmeticOverflow;
    const right_bytes = std.math.mul(usize, right.len, @sizeOf(M31)) catch
        return error.ArithmeticOverflow;
    const left_end = std.math.add(usize, left_start, left_bytes) catch
        return error.ArithmeticOverflow;
    const right_end = std.math.add(usize, right_start, right_bytes) catch
        return error.ArithmeticOverflow;
    return left_start < right_end and right_start < left_end;
}
