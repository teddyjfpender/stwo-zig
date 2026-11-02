//! Explicit CPU adapter for eight-coordinate FRI. Merkle data is M31 on both
//! fields; arithmetic intentionally uses the shared core OM31 folding authority.
//! No legacy QM31-typed optimized hook is advertised as a wide operation.
const CPU = @import("mod.zig").CpuBackend;
pub const Backend = struct {
    pub const MerkleTree = CPU.MerkleTree;
    pub const commitMerkle = CPU.commitMerkle;
    pub const reuses_constant_merkle_parents = CPU.reuses_constant_merkle_parents;
};
