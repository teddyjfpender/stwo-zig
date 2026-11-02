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

pub const ForField = @import("merkle_queries_family.zig").ForField;
const Default = ForField(QM31);
pub const MerkleVerificationInputs = Default.MerkleVerificationInputs;
pub const build = Default.build;
pub const findSubsetIndex = Default.findSubsetIndex;
pub const findPosition = Default.findPosition;

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
