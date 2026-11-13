//! fold commit cases; fixture authority is shared with the other test owners.
//! FRI fold-to-next-tree transaction parity and submission accounting.

const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const channel_blake2s = @import("stwo_core").channel.blake2s;

const Hasher = blake2_merkle.Blake2sMerkleHasher;
const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;

const Support = @import("fri_fold_commit_support.zig");
const checkLineCascade = Support.checkLineCascade;
const checkCircleFri = Support.checkCircleFri;

test "metal: line FRI cascade preserves every root, challenge, and final value" {
    try checkLineCascade(false, Hasher, MerkleChannel, channel_blake2s.Blake2sChannel, 10);
}
test "metal: BLAKE3 FRI cascade preserves roots transcript and folds in one submission" {
    const b3 = @import("stwo_core").vcs_lifted.blake3_merkle;
    try checkLineCascade(true, b3.MerkleHasher, b3.MerkleChannel, @import("stwo_core").channel.blake3.Channel, 10);
}
test "metal: BLAKE3 backend cascade admits resident inverse domains" {
    const b3 = @import("stwo_core").vcs_lifted.blake3_merkle;
    try checkLineCascade(true, b3.MerkleHasher, b3.MerkleChannel, @import("stwo_core").channel.blake3.Channel, 13);
}
test "metal: BLAKE3 circle FRI prover matches CPU commitments and openings" {
    try checkCircleFri(false, true);
}
test "metal: BLAKE3 quotient FRI transaction matches CPU and verifier" {
    try checkCircleFri(true, true);
}
test "metal: BLAKE2s quotient FRI transaction matches CPU and verifier" {
    try checkCircleFri(true, false);
}
