const std = @import("std");
const core = @import("core");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
pub const ops_per_call: u64 = 32;
pub fn run(seed: u64) u64 {
    var values: [256]core.fields.m31.M31 = undefined;
    for (&values, 0..) |*v, i| v.* = core.fields.m31.M31.fromU64(seed +% i);
    var result = seed;
    for (0..ops_per_call) |i| {
        values[0] = core.fields.m31.M31.fromU64(result +% i);
        var h = H.defaultWithInitialState();
        h.updateLeaf(&values);
        const digest = h.finalize();
        result ^= std.mem.readInt(u64, digest[0..8], .little);
    }
    return result;
}
