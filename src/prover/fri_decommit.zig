//! FRI layer decommitment, witness extraction, and ownership results.

const std = @import("std");
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const secure_column = @import("secure_column.zig");
const packing = @import("fri_packing.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedSecureColumns = packing.PackedSecureColumns;
const shouldPack = packing.shouldPack;
const packedQueryPositions = packing.packedQueryPositions;
const PACKED_LEAF_SIZE: usize =
    @as(usize, 1) << @intCast(core_fri.LOG_PACKED_LEAF_SIZE);

pub const FriDecommitError = error{ QueryOutOfRange, FoldStepTooLarge };
pub const ValueEntry = struct { position: usize, value: QM31 };
pub const DecommitmentPositionsResult = struct {
    decommitment_positions: []usize,
    witness_evals: []QM31,
    value_map: []ValueEntry,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.decommitment_positions);
        allocator.free(self.witness_evals);
        allocator.free(self.value_map);
        self.* = undefined;
    }
};

pub fn LayerDecommitResult(comptime H: type) type {
    return struct {
        decommitment_positions: []usize,
        proof: core_fri.FriLayerProof(H),
        value_map: []ValueEntry,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.decommitment_positions);
            self.proof.deinit(allocator);
            allocator.free(self.value_map);
            self.* = undefined;
        }
    };
}

pub fn FriDecommitResult(comptime H: type) type {
    return struct {
        fri_proof: core_fri.ExtendedFriProof(H),
        query_positions: []usize,
        unsorted_query_locations: []usize,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.fri_proof.deinit(allocator);
            allocator.free(self.query_positions);
            allocator.free(self.unsorted_query_locations);
            self.* = undefined;
        }
    };
}

pub fn decommitLayerExtended(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: anytype,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) !core_fri.ExtendedFriLayerProof(H) {
    return decommitLayerExtendedWithRetainedPacking(
        H,
        allocator,
        merkle_tree,
        column,
        query_positions,
        fold_step,
        null,
    );
}

/// Decommits one FRI layer while borrowing the exact packed columns retained
/// by a backend whose resident queried-value map authenticates host pointer
/// identity.  The ordinary entrypoint above preserves the existing recreate-
/// on-open behavior for host commitments and backends without that contract.
pub fn decommitLayerExtendedWithRetainedPacking(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: anytype,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
    retained_packing: ?*const PackedSecureColumns,
) !core_fri.ExtendedFriLayerProof(H) {
    if (retained_packing != null and !shouldPack(column.len(), fold_step)) {
        return error.InvalidColumnSize;
    }
    const helper = try computeDecommitmentPositionsAndWitnessEvalsFromCoords(
        allocator,
        column,
        query_positions,
        fold_step,
    );
    errdefer {
        allocator.free(helper.decommitment_positions);
        allocator.free(helper.witness_evals);
        allocator.free(helper.value_map);
    }

    const IndexedValue = core_fri.FriLayerProofAux(H).IndexedValue;
    const indexed_values = try allocator.alloc(IndexedValue, helper.value_map.len);
    errdefer allocator.free(indexed_values);
    for (helper.value_map, 0..) |entry, i| {
        indexed_values[i] = .{
            .index = entry.position,
            .value = entry.value,
        };
    }
    const all_values = try allocator.alloc([]IndexedValue, 1);
    // `indexed_values` retains its own preceding error guard until the
    // complete result is returned.  This guard owns only the outer slice;
    // overlapping ownership here double-freed the child on a later resident
    // queried-value rejection.
    errdefer allocator.free(all_values);
    all_values[0] = indexed_values;

    const merkle_decommit = if (shouldPack(column.len(), fold_step)) blk: {
        const packed_positions = try packedQueryPositions(
            allocator,
            helper.decommitment_positions,
        );
        defer allocator.free(packed_positions);
        if (retained_packing) |packed_columns| {
            const packed_len = column.len() / PACKED_LEAF_SIZE;
            for (packed_columns.columns) |values| {
                if (values.len != packed_len) return error.InvalidColumnSize;
            }
            const packed_refs = packed_columns.refs();
            break :blk try merkle_tree.decommit(
                allocator,
                packed_positions,
                packed_refs[0..],
            );
        }

        var packed_columns = try PackedSecureColumns.init(allocator, column);
        defer packed_columns.deinit(allocator);
        const packed_refs = packed_columns.refs();
        break :blk try merkle_tree.decommit(
            allocator,
            packed_positions,
            packed_refs[0..],
        );
    } else blk: {
        const column_refs = [_][]const M31{
            column.columns[0],
            column.columns[1],
            column.columns[2],
            column.columns[3],
        };
        break :blk try merkle_tree.decommit(
            allocator,
            helper.decommitment_positions,
            column_refs[0..],
        );
    };
    defer {
        for (merkle_decommit.queried_values) |col| allocator.free(col);
        allocator.free(merkle_decommit.queried_values);
    }

    allocator.free(helper.decommitment_positions);
    allocator.free(helper.value_map);
    return .{
        .proof = .{
            .fri_witness = helper.witness_evals,
            .decommitment = merkle_decommit.decommitment.decommitment,
            .commitment = merkle_tree.root(),
        },
        .aux = .{
            .all_values = all_values,
            .decommitment = merkle_decommit.decommitment.aux,
        },
    };
}

/// Returns Merkle decommitment positions and witness evals needed for one FRI layer decommitment.
///
/// `query_positions` are expected in sorted ascending order.
pub fn computeDecommitmentPositionsAndWitnessEvals(
    allocator: std.mem.Allocator,
    column: []const QM31,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!DecommitmentPositionsResult {
    if (fold_step >= @bitSizeOf(usize)) return FriDecommitError.FoldStepTooLarge;

    var decommitment_positions = std.ArrayList(usize).empty;
    defer decommitment_positions.deinit(allocator);
    var witness_evals = std.ArrayList(QM31).empty;
    defer witness_evals.deinit(allocator);
    var value_map = std.ArrayList(ValueEntry).empty;
    defer value_map.deinit(allocator);

    const subset_len = @as(usize, 1) << @intCast(fold_step);

    var subset_start_idx: usize = 0;
    while (subset_start_idx < query_positions.len) {
        const subset_key = query_positions[subset_start_idx] >> @intCast(fold_step);
        var subset_end_idx = subset_start_idx + 1;
        while (subset_end_idx < query_positions.len and
            (query_positions[subset_end_idx] >> @intCast(fold_step)) == subset_key)
        {
            subset_end_idx += 1;
        }

        const subset_queries = query_positions[subset_start_idx..subset_end_idx];
        const subset_start = subset_key << @intCast(fold_step);
        var subset_query_at: usize = 0;

        var position = subset_start;
        while (position < subset_start + subset_len) : (position += 1) {
            if (position >= column.len) return FriDecommitError.QueryOutOfRange;

            try decommitment_positions.append(allocator, position);
            const eval = column[position];
            try value_map.append(allocator, .{
                .position = position,
                .value = eval,
            });

            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(allocator, eval);
            }
        }

        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(allocator),
        .witness_evals = try witness_evals.toOwnedSlice(allocator),
        .value_map = try value_map.toOwnedSlice(allocator),
    };
}

fn computeDecommitmentPositionsAndWitnessEvalsFromCoords(
    allocator: std.mem.Allocator,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!DecommitmentPositionsResult {
    if (fold_step >= @bitSizeOf(usize)) return FriDecommitError.FoldStepTooLarge;

    var decommitment_positions = std.ArrayList(usize).empty;
    defer decommitment_positions.deinit(allocator);
    var witness_evals = std.ArrayList(QM31).empty;
    defer witness_evals.deinit(allocator);
    var value_map = std.ArrayList(ValueEntry).empty;
    defer value_map.deinit(allocator);

    const subset_len = @as(usize, 1) << @intCast(fold_step);
    var subset_start_idx: usize = 0;
    while (subset_start_idx < query_positions.len) {
        const subset_key = query_positions[subset_start_idx] >> @intCast(fold_step);
        var subset_end_idx = subset_start_idx + 1;
        while (subset_end_idx < query_positions.len and
            (query_positions[subset_end_idx] >> @intCast(fold_step)) == subset_key)
        {
            subset_end_idx += 1;
        }

        const subset_queries = query_positions[subset_start_idx..subset_end_idx];
        const subset_start = subset_key << @intCast(fold_step);
        var subset_query_at: usize = 0;
        for (subset_start..subset_start + subset_len) |position| {
            if (position >= column.len()) return FriDecommitError.QueryOutOfRange;
            const eval = column.at(position);
            try decommitment_positions.append(allocator, position);
            try value_map.append(allocator, .{ .position = position, .value = eval });
            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(allocator, eval);
            }
        }
        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(allocator),
        .witness_evals = try witness_evals.toOwnedSlice(allocator),
        .value_map = try value_map.toOwnedSlice(allocator),
    };
}

/// Produces a FRI layer decommitment proof for `query_positions`.
pub fn decommitLayer(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: anytype,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) !LayerDecommitResult(H) {
    const helper = try computeDecommitmentPositionsAndWitnessEvalsFromCoords(
        allocator,
        column,
        query_positions,
        fold_step,
    );
    errdefer {
        allocator.free(helper.decommitment_positions);
        allocator.free(helper.witness_evals);
        allocator.free(helper.value_map);
    }

    var merkle_decommit = if (shouldPack(column.len(), fold_step)) blk: {
        var packed_columns = try PackedSecureColumns.init(allocator, column);
        defer packed_columns.deinit(allocator);
        const packed_refs = packed_columns.refs();
        const packed_positions = try packedQueryPositions(
            allocator,
            helper.decommitment_positions,
        );
        defer allocator.free(packed_positions);
        break :blk try merkle_tree.decommit(
            allocator,
            packed_positions,
            packed_refs[0..],
        );
    } else blk: {
        const column_refs = [_][]const M31{
            column.columns[0],
            column.columns[1],
            column.columns[2],
            column.columns[3],
        };
        break :blk try merkle_tree.decommit(
            allocator,
            helper.decommitment_positions,
            column_refs[0..],
        );
    };
    defer {
        for (merkle_decommit.queried_values) |col| allocator.free(col);
        allocator.free(merkle_decommit.queried_values);
        merkle_decommit.decommitment.aux.deinit(allocator);
    }

    return .{
        .decommitment_positions = helper.decommitment_positions,
        .proof = .{
            .fri_witness = helper.witness_evals,
            .decommitment = merkle_decommit.decommitment.decommitment,
            .commitment = merkle_tree.root(),
        },
        .value_map = helper.value_map,
    };
}
