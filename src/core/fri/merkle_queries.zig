//! FRI Merkle query materialization and packed-leaf ordering checks.

const std = @import("std");
const folding = @import("folding.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const LOG_PACKED_LEAF_SIZE = @import("config.zig").LOG_PACKED_LEAF_SIZE;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const SparseEvaluation = folding.SparseEvaluation;

pub const MerkleVerificationInputs = struct {
    positions: []usize,
    columns: [][]M31,

    pub fn deinit(self: *MerkleVerificationInputs, allocator: std.mem.Allocator) void {
        allocator.free(self.positions);
        for (self.columns) |column| allocator.free(column);
        allocator.free(self.columns);
        self.* = undefined;
    }
};

/// Converts reconstructed FRI evaluations into the leaf layout committed by
/// STWO. With packed leaves, four consecutive QM31 values become one Merkle
/// row with coordinates ordered by value first, then extension coordinate.
pub fn build(
    allocator: std.mem.Allocator,
    decommitment_positions: []const usize,
    sparse: SparseEvaluation,
    leaf_log_size: u32,
) !MerkleVerificationInputs {
    if (leaf_log_size >= @bitSizeOf(usize)) return error.ShapeMismatch;
    const leaf_size: usize = @as(usize, 1) << @intCast(leaf_log_size);

    var value_count: usize = 0;
    for (sparse.subset_evals) |subset| value_count += subset.len;
    if (value_count != decommitment_positions.len or
        decommitment_positions.len % leaf_size != 0)
    {
        return error.ShapeMismatch;
    }

    const merkle_position_count = decommitment_positions.len / leaf_size;
    const positions = try allocator.alloc(usize, merkle_position_count);
    errdefer allocator.free(positions);

    var leaf_index: usize = 0;
    while (leaf_index < merkle_position_count) : (leaf_index += 1) {
        const first_index = leaf_index * leaf_size;
        const merkle_position = decommitment_positions[first_index] >> @intCast(leaf_log_size);
        positions[leaf_index] = merkle_position;
        var offset: usize = 0;
        while (offset < leaf_size) : (offset += 1) {
            const position = decommitment_positions[first_index + offset];
            if ((position >> @intCast(leaf_log_size)) != merkle_position or
                (position & (leaf_size - 1)) != offset)
            {
                return error.ShapeMismatch;
            }
        }
        if (leaf_index > 0 and positions[leaf_index - 1] >= merkle_position) {
            return error.ShapeMismatch;
        }
    }

    const flattened_values = try allocator.alloc(QM31, value_count);
    defer allocator.free(flattened_values);
    var value_index: usize = 0;
    for (sparse.subset_evals) |subset| {
        @memcpy(flattened_values[value_index..][0..subset.len], subset);
        value_index += subset.len;
    }

    const column_count = qm31.SECURE_EXTENSION_DEGREE * leaf_size;
    const columns = try allocator.alloc([]M31, column_count);
    errdefer allocator.free(columns);
    var initialized_columns: usize = 0;
    errdefer {
        for (columns[0..initialized_columns]) |column| allocator.free(column);
    }
    while (initialized_columns < columns.len) : (initialized_columns += 1) {
        columns[initialized_columns] = try allocator.alloc(M31, merkle_position_count);
    }

    leaf_index = 0;
    while (leaf_index < merkle_position_count) : (leaf_index += 1) {
        var offset: usize = 0;
        while (offset < leaf_size) : (offset += 1) {
            const coords = flattened_values[leaf_index * leaf_size + offset].toM31Array();
            inline for (coords, 0..) |coord, coordinate| {
                columns[offset * qm31.SECURE_EXTENSION_DEGREE + coordinate][leaf_index] = coord;
            }
        }
    }

    return .{
        .positions = positions,
        .columns = columns,
    };
}

pub fn findSubsetIndex(
    decommitment_positions: []const usize,
    fold_width: usize,
    subset_start: usize,
) ?usize {
    if (fold_width == 0) return null;
    var index: usize = 0;
    while (index * fold_width < decommitment_positions.len) : (index += 1) {
        const at = index * fold_width;
        if (decommitment_positions[at] == subset_start) return index;
        if (decommitment_positions[at] > subset_start) return null;
    }
    return null;
}

pub fn findPosition(positions: []const usize, target: usize) ?usize {
    var left: usize = 0;
    var right: usize = positions.len;
    while (left < right) {
        const middle = left + (right - left) / 2;
        if (positions[middle] < target) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < positions.len and positions[left] == target) return left;
    return null;
}

test "fri: packed Merkle inputs preserve STWO leaf coordinate order" {
    const alloc = std.testing.allocator;
    var first_leaf: [4]QM31 = undefined;
    var second_leaf: [4]QM31 = undefined;
    for (&first_leaf, 0..) |*value, i| {
        const base: u32 = @intCast(i * qm31.SECURE_EXTENSION_DEGREE + 1);
        value.* = QM31.fromU32Unchecked(base, base + 1, base + 2, base + 3);
    }
    for (&second_leaf, 0..) |*value, i| {
        const base: u32 = @intCast((i + first_leaf.len) * qm31.SECURE_EXTENSION_DEGREE + 1);
        value.* = QM31.fromU32Unchecked(base, base + 1, base + 2, base + 3);
    }
    var subsets = [_][]QM31{ first_leaf[0..], second_leaf[0..] };
    var subset_initials = [_]usize{ 0, 0 };
    const sparse = SparseEvaluation{
        .subset_evals = subsets[0..],
        .subset_domain_initial_indexes = subset_initials[0..],
    };
    const decommitment_positions = [_]usize{ 4, 5, 6, 7, 12, 13, 14, 15 };

    var inputs = try build(
        alloc,
        decommitment_positions[0..],
        sparse,
        LOG_PACKED_LEAF_SIZE,
    );
    defer inputs.deinit(alloc);

    try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 3 }, inputs.positions);
    try std.testing.expectEqual(@as(usize, 16), inputs.columns.len);
    for (inputs.columns, 0..) |column, column_index| {
        const offset = column_index / qm31.SECURE_EXTENSION_DEGREE;
        const coordinate = column_index % qm31.SECURE_EXTENSION_DEGREE;
        for (column, 0..) |value, leaf_index| {
            const source_value = leaf_index * 4 + offset;
            const expected: u32 = @intCast(
                source_value * qm31.SECURE_EXTENSION_DEGREE + coordinate + 1,
            );
            try std.testing.expect(value.eql(M31.fromCanonical(expected)));
        }
    }

    const Hasher = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    var opened_leaf_hashes: [2]Hasher.Hash = undefined;
    for (&opened_leaf_hashes, 0..) |*hash, opened_index| {
        var row: [16]M31 = undefined;
        for (inputs.columns, 0..) |column, column_index| row[column_index] = column[opened_index];
        var hasher = Hasher.defaultWithInitialState();
        hasher.updateLeaf(row[0..]);
        hash.* = hasher.finalize();
    }
    var sibling_row = [_]M31{M31.zero()} ** 16;
    var sibling_hasher = Hasher.defaultWithInitialState();
    sibling_hasher.updateLeaf(sibling_row[0..]);
    const leaf_zero = sibling_hasher.finalize();
    @memset(sibling_row[0..], M31.one());
    sibling_hasher = Hasher.defaultWithInitialState();
    sibling_hasher.updateLeaf(sibling_row[0..]);
    const leaf_two = sibling_hasher.finalize();
    const root = Hasher.hashChildren(.{
        .left = Hasher.hashChildren(.{ .left = leaf_zero, .right = opened_leaf_hashes[0] }),
        .right = Hasher.hashChildren(.{ .left = leaf_two, .right = opened_leaf_hashes[1] }),
    });
    var verifier = try vcs_verifier.MerkleVerifierLifted(Hasher).init(
        alloc,
        root,
        &([_]u32{2} ** 16),
    );
    defer verifier.deinit(alloc);
    var decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.dupe(Hasher.Hash, &[_]Hasher.Hash{ leaf_zero, leaf_two }),
    };
    defer decommitment.deinit(alloc);
    try verifier.verify(alloc, inputs.positions, inputs.columns, decommitment);
}
