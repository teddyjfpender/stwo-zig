//! Reconstruct the first PCS root from the columns fixed by an example statement.
//!
//! The PCS configuration affects the low-degree extension and Merkle tree, so
//! checking the source columns alone is insufficient. Use the same CPU PCS
//! commitment path as the prover before accepting the proof's first root.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const prover_engine = @import("stwo_prover_engine").engine;
const prover_pcs = @import("stwo_prover_engine").pcs;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = channel_blake2s.Blake2sChannel;
const Engine = prover_engine.ProverEngine(CpuBackend, Hasher, MerkleChannel, Channel);

pub fn root(
    allocator: std.mem.Allocator,
    config: pcs_core.PcsConfig,
    columns: []const prover_pcs.ColumnEvaluation,
) !Hasher.Hash {
    var scheme = try Engine.init(allocator, config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Channel{};
    config.mixInto(&channel);
    try scheme.commit(allocator, columns, &channel);
    return scheme.trees.items[0].commitment.root();
}

pub fn freeColumns(allocator: std.mem.Allocator, columns: []prover_pcs.ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}
