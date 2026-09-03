//! Exact Tree0/Tree1 materialization for the authenticated Ethereum h1 cohort.
//!
//! The three routing AIRs and eight parameter-distinct hash instances are
//! written from the verifier-minted logical witness. The final placement is
//! the reviewed native Poseidon2 provider: Tree0 contains its canonical first
//! row selector and Tree1 contains the exact 445-column permutation witness.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const materializer_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_materializer_v1.zig");
const cohort_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_cohort_v1.zig");
const leaf_witness_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_leaf_witness_v1.zig");

const recursion = frontend.recursion;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const projection_air = recursion.air.ethereum_leaf_link_projection_v1;
const router_air = recursion.air.ethereum_leaf_child_field_router_v1;
const hash_air = recursion.air.vm_public_claim_hash;
const framework = recursion.air.framework_interaction;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const M31 = stwo_core.fields.m31.M31;

pub const TreeV1 = struct {
    allocator: std.mem.Allocator,
    manifest_seal: [32]u8,
    tree_index: u8,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree_index: usize,
    ) !TreeV1 {
        try manifest.validate();
        const column_count = try treeColumnCount(manifest, tree_index);
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        var cell_count: usize = 0;
        for (manifest.roster_rows) |row| {
            const placement = manifest.placements[row] orelse
                return error.ManifestSealMismatch;
            const rows = try traceSize(placement.geometry.log_size);
            cell_count = try checkedAdd(
                cell_count,
                try checkedMul(
                    rows,
                    treeGeometryColumns(placement.geometry, tree_index),
                ),
            );
        }
        const storage = try allocator.alloc(M31, cell_count);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (manifest.roster_rows) |row| {
            const placement = manifest.placements[row].?;
            const rows = try traceSize(placement.geometry.log_size);
            const offset = treeOffset(placement, tree_index);
            const count = treeGeometryColumns(placement.geometry, tree_index);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[cursor..][0..rows];
                cursor = try checkedAdd(cursor, rows);
            }
        }
        if (cursor != storage.len) return error.DestinationShapeMismatch;
        var result = TreeV1{
            .allocator = allocator,
            .manifest_seal = manifest.seal,
            .tree_index = @intCast(tree_index),
            .columns = columns,
            .storage = storage,
        };
        try result.validate(manifest, tree_index);
        return result;
    }

    pub fn validate(
        self: *const TreeV1,
        manifest: *const manifest_mod.Manifest,
        tree_index: usize,
    ) !void {
        try manifest.validate();
        if (self.tree_index != tree_index or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            self.columns.len != try treeColumnCount(manifest, tree_index))
        {
            return error.DestinationShapeMismatch;
        }
        try validateTreeShape(manifest, tree_index, self.columns);
        for (self.columns, 0..) |left, left_index| {
            if (!sliceWithin(M31, left, self.storage))
                return error.DestinationShapeMismatch;
            for (self.columns[left_index + 1 ..]) |right|
                if (slicesOverlap(M31, left, M31, right))
                    return error.DestinationAlias;
        }
    }

    pub fn deinit(self: *TreeV1) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

/// Writes the exact preprocessed columns after every authority, shape,
/// freshness, and alias check has succeeded.
pub fn fillPreprocessedInto(
    materialized: *const materializer_mod.MaterializedV1,
    cohort: *const cohort_mod.CohortV1,
    custody: *const ingress_mod.CustodyV1,
    manifest: *const manifest_mod.Manifest,
    destination: []const []M31,
) !void {
    try validateInputs(materialized, cohort, custody, manifest);
    try preflightFreshTree(
        materialized,
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    errdefer clearTree(destination);
    writePhysical(
        source_air,
        materialized.source_rows,
        manifest.placements[manifest_mod.keyIndex(.link_source)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        projection_air,
        materialized.projection_rows,
        manifest.placements[manifest_mod.keyIndex(.link_projection)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        router_air,
        materialized.child_router_rows,
        manifest.placements[manifest_mod.keyIndex(.child_field_router)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    inline for (manifest_mod.COMPONENT_KEYS[3..11], 0..) |key, ordinal| {
        writePhysical(
            hash_air,
            hashRows(materialized, ordinal),
            manifest.placements[manifest_mod.keyIndex(key)].?,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
    }
    const provider = manifest.placements[manifest_mod.keyIndex(.poseidon2)].?;
    const provider_column = destination[provider.preprocessed_offset];
    @memset(provider_column, M31.zero());
    provider_column[
        framework.committedRow(
            0,
            provider.geometry.log_size,
        )
    ] = M31.one();
}

/// Writes the exact physical main columns, including the shared 445-column
/// Poseidon witness in its final committed storage.
pub fn fillMainInto(
    allocator: std.mem.Allocator,
    materialized: *const materializer_mod.MaterializedV1,
    cohort: *const cohort_mod.CohortV1,
    custody: *const ingress_mod.CustodyV1,
    manifest: *const manifest_mod.Manifest,
    destination: []const []M31,
) !void {
    try validateInputs(materialized, cohort, custody, manifest);
    try preflightFreshTree(
        materialized,
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    errdefer clearTree(destination);
    writePhysical(
        source_air,
        materialized.source_rows,
        manifest.placements[manifest_mod.keyIndex(.link_source)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        projection_air,
        materialized.projection_rows,
        manifest.placements[manifest_mod.keyIndex(.link_projection)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        router_air,
        materialized.child_router_rows,
        manifest.placements[manifest_mod.keyIndex(.child_field_router)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    inline for (manifest_mod.COMPONENT_KEYS[3..11], 0..) |key, ordinal| {
        writePhysical(
            hash_air,
            hashRows(materialized, ordinal),
            manifest.placements[manifest_mod.keyIndex(key)].?,
            manifest_mod.MAIN_TREE_INDEX,
            destination,
        );
    }
    const provider = manifest.placements[manifest_mod.keyIndex(.poseidon2)].?;
    var columns: [poseidon2_air.N_MAIN_COLUMNS][]M31 = undefined;
    for (
        &columns,
        destination[provider.main_offset..][0..poseidon2_air.N_MAIN_COLUMNS],
    ) |*bound, column| bound.* = column;
    try poseidon2_air.generateMainInto(
        allocator,
        &columns,
        materialized.poseidon_calls,
        provider.geometry.log_size,
    );
}

pub fn validateInputs(
    materialized: *const materializer_mod.MaterializedV1,
    cohort: *const cohort_mod.CohortV1,
    custody: *const ingress_mod.CustodyV1,
    manifest: *const manifest_mod.Manifest,
) !void {
    try materialized.validateStructural(custody);
    try cohort.validateMaterialized(materialized, custody);
    try manifest.validate();
    if (!std.meta.eql(manifest.*, materialized.plan.manifest) or
        !std.mem.eql(u8, &cohort.manifest_seal, &manifest.seal) or
        cohort.provider_active_rows != materialized.poseidon_calls.len)
    {
        return error.EthereumPoseidonH1TraceAuthorityMismatch;
    }
    inline for (manifest_mod.COMPONENT_KEYS[3..11], 0..) |key, ordinal| {
        if (hashRows(materialized, ordinal).len !=
            cohort.hashes[ordinal].active_rows or
            cohort.hashes[ordinal].placement != key)
        {
            return error.EthereumPoseidonH1TraceAuthorityMismatch;
        }
    }
}

pub fn clearTree(destination: []const []M31) void {
    for (destination) |column| @memset(column, M31.zero());
}

fn writePhysical(
    comptime Air: type,
    rows: anytype,
    placement: manifest_mod.Placement,
    tree_index: usize,
    destination: []const []M31,
) void {
    const local_count = switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => Air.PREPROCESSED_COLUMN_COUNT,
        manifest_mod.MAIN_TREE_INDEX => Air.PHYSICAL_MAIN_COLUMN_COUNT,
        else => unreachable,
    };
    const input_start = if (tree_index == manifest_mod.PREPROCESSED_TREE_INDEX) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
    const output_start: usize = switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        else => unreachable,
    };
    for (destination[output_start..][0..local_count]) |column|
        @memset(column, M31.zero());
    for (rows, 0..) |row, logical_row| {
        const committed_row = framework.committedRow(
            logical_row,
            placement.geometry.log_size,
        );
        for (0..local_count) |column| {
            destination[output_start + column][committed_row] =
                row[input_start + column];
        }
    }
}

pub fn hashRows(
    materialized: *const materializer_mod.MaterializedV1,
    ordinal: usize,
) []const leaf_witness_mod.HashRow {
    return switch (ordinal) {
        0 => materialized.left.metadata_hash.logical_rows,
        1 => materialized.left.link_hash.logical_rows,
        2 => materialized.left.authority_hash,
        3 => materialized.left.receipt_hash,
        4 => materialized.right.metadata_hash.logical_rows,
        5 => materialized.right.link_hash.logical_rows,
        6 => materialized.right.authority_hash,
        7 => materialized.right.receipt_hash,
        else => unreachable,
    };
}

pub fn preflightFreshTree(
    materialized: *const materializer_mod.MaterializedV1,
    manifest: *const manifest_mod.Manifest,
    tree_index: usize,
    destination: []const []M31,
) !void {
    try validateTreeShape(manifest, tree_index, destination);
    for (destination, 0..) |left, left_index| {
        for (left) |value| if (!value.isZero())
            return error.DestinationNotFresh;
        if (overlapsMaterialized(left, materialized))
            return error.DestinationAlias;
        for (destination[left_index + 1 ..]) |right|
            if (slicesOverlap(M31, left, M31, right))
                return error.DestinationAlias;
    }
}

fn validateTreeShape(
    manifest: *const manifest_mod.Manifest,
    tree_index: usize,
    destination: []const []M31,
) !void {
    try manifest.validate();
    if (destination.len != try treeColumnCount(manifest, tree_index))
        return error.DestinationShapeMismatch;
    for (manifest.roster_rows) |row| {
        const placement = manifest.placements[row] orelse
            return error.ManifestSealMismatch;
        const offset = treeOffset(placement, tree_index);
        const count = treeGeometryColumns(placement.geometry, tree_index);
        const rows = try traceSize(placement.geometry.log_size);
        if (offset > destination.len or count > destination.len - offset)
            return error.DestinationShapeMismatch;
        for (destination[offset..][0..count]) |column|
            if (column.len != rows) return error.DestinationShapeMismatch;
    }
}

fn overlapsMaterialized(
    destination: []M31,
    materialized: *const materializer_mod.MaterializedV1,
) bool {
    if (slicesOverlap(M31, destination, u8, std.mem.asBytes(materialized)) or
        slicesOverlap(M31, destination, source_air.Row, materialized.source_rows) or
        slicesOverlap(M31, destination, projection_air.Row, materialized.projection_rows) or
        slicesOverlap(M31, destination, router_air.Row, materialized.child_router_rows) or
        slicesOverlap(M31, destination, poseidon2_air.Call, materialized.poseidon_calls))
    {
        return true;
    }
    inline for (.{ &materialized.left, &materialized.right }) |leaf| {
        inline for (.{
            leaf.metadata_hash.logical_rows,
            leaf.link_hash.logical_rows,
            leaf.authority_hash,
            leaf.receipt_hash,
        }) |rows| if (slicesOverlap(
            M31,
            destination,
            leaf_witness_mod.HashRow,
            rows,
        )) return true;
    }
    return false;
}

fn slicesOverlap(
    comptime Left: type,
    left: []const Left,
    comptime Right: type,
    right: []const Right,
) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const left_end = left_start + left.len * @sizeOf(Left);
    const right_start = @intFromPtr(right.ptr);
    const right_end = right_start + right.len * @sizeOf(Right);
    return left_start < right_end and right_start < left_end;
}

fn sliceWithin(
    comptime T: type,
    inner: []const T,
    outer: []const T,
) bool {
    if (inner.len == 0) return true;
    if (outer.len == 0) return false;
    const inner_start = @intFromPtr(inner.ptr);
    const inner_end = inner_start + inner.len * @sizeOf(T);
    const outer_start = @intFromPtr(outer.ptr);
    const outer_end = outer_start + outer.len * @sizeOf(T);
    return outer_start <= inner_start and inner_end <= outer_end;
}

fn treeColumnCount(
    manifest: *const manifest_mod.Manifest,
    tree_index: usize,
) !usize {
    return switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => error.InvalidTreeIndex,
    };
}

fn treeOffset(
    placement: manifest_mod.Placement,
    tree_index: usize,
) usize {
    return switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn treeGeometryColumns(
    geometry: manifest_mod.Geometry,
    tree_index: usize,
) usize {
    return switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn checkedAdd(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

comptime {
    if (poseidon2_air.N_MAIN_COLUMNS != 445 or
        manifest_mod.COMPONENT_COUNT != 12 or
        manifest_mod.HASH_PLACEMENT_COUNT != 8)
    {
        @compileError("Ethereum Poseidon h1 Tree0/Tree1 geometry drifted");
    }
}
