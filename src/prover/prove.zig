const std = @import("std");
const circle = @import("../core/circle.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const pcs_core = @import("../core/pcs/mod.zig");
const proof_mod = @import("../core/proof.zig");
const pcs_prover = @import("pcs/mod.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const TreeVec = pcs_core.TreeVec;

pub const ProvingError = error{
    MissingPreprocessedTree,
};

/// Proving entrypoint for already-prepared sampled values.
///
/// This is a stepping-stone API until full in-prover sampled-value computation
/// parity is wired through prover/poly modules.
pub fn provePrepared(
    comptime H: type,
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    commitment_scheme: pcs_prover.CommitmentSchemeProver(H, MC),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
) !proof_mod.ExtendedStarkProof(H) {
    if (commitment_scheme.trees.items.len == 0) return ProvingError.MissingPreprocessedTree;

    const commitment_proof = try commitment_scheme.proveValuesFromSamples(
        allocator,
        sampled_points,
        sampled_values,
        channel,
    );

    return .{
        .proof = .{
            .commitment_scheme_proof = commitment_proof.proof,
        },
        .aux = commitment_proof.aux,
    };
}

test "prover prove: prepared proof verifies with core verifier" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Scheme = pcs_prover.CommitmentSchemeProver(Hasher, MerkleChannel);
    const Verifier = @import("../core/pcs/verifier.zig").CommitmentSchemeVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };

    var scheme = try Scheme.init(alloc, config);
    var prover_channel = Channel{};

    const column_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
        M31.fromCanonical(5),
    };
    try scheme.commit(
        alloc,
        &[_]pcs_prover.ColumnEvaluation{
            .{ .log_size = 3, .values = column_values[0..] },
        },
        &prover_channel,
    );

    const sample_point = circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const sample_value = QM31.fromBase(M31.fromCanonical(5));

    const sampled_points_col_prover = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_prover = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_prover});
    const sampled_points_prover = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_prover}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{sample_value});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    var ext_proof = try provePrepared(
        Hasher,
        MerkleChannel,
        alloc,
        &prover_channel,
        scheme,
        sampled_points_prover,
        sampled_values,
    );
    defer ext_proof.aux.deinit(alloc);

    const sampled_points_col_verify = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{sample_point});
    const sampled_points_tree_verify = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col_verify});
    const sampled_points_verify = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree_verify}),
    );

    var verifier = try Verifier.init(alloc, config);
    defer verifier.deinit(alloc);

    var verifier_channel = Channel{};
    try verifier.commit(
        alloc,
        ext_proof.proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{3},
        &verifier_channel,
    );
    try verifier.verifyValues(
        alloc,
        sampled_points_verify,
        ext_proof.proof.commitment_scheme_proof,
        &verifier_channel,
    );
}
