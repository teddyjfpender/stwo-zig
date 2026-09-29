//! Host-side packing helpers of `crates/stark_verifier/src/proof_from_stark_proof.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! Only the pure packing lives here. The full `StarkProof` to circuit
//! `Proof` conversion belongs to the circuit prover (M7), which reuses the
//! core proof capture (`ExtendedStarkProof.aux`, `VerifiedProofCapture`)
//! instead of a third raw-query expansion.

const std = @import("std");
const core = @import("stwo_core");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const SECURE_EXTENSION_DEGREE = core.fields.qm31.SECURE_EXTENSION_DEGREE;

/// Number of QM31s `packIntoQm31s` produces for `n_values` values.
pub fn nPackedQm31s(n_values: usize) usize {
    return std.math.divCeil(usize, n_values, SECURE_EXTENSION_DEGREE) catch unreachable;
}

/// `pack_into_qm31s`: four values per QM31, the last one zero-padded. Each
/// value becomes an M31 through `From<u32>` (reduced modulo P). Writes into
/// `out` and returns the written prefix.
pub fn packIntoQm31s(values: []const u32, out: []QM31) []QM31 {
    const n = nPackedQm31s(values.len);
    std.debug.assert(out.len >= n);
    for (out[0..n], 0..) |*packed_value, chunk| {
        var limbs = [_]M31{M31.zero()} ** SECURE_EXTENSION_DEGREE;
        for (&limbs, 0..) |*limb, lane| {
            const index = chunk * SECURE_EXTENSION_DEGREE + lane;
            if (index < values.len) limb.* = M31.fromU64(values[index]);
        }
        packed_value.* = QM31.fromM31Array(limbs);
    }
    return out[0..n];
}

test "proof_from_stark_proof: pack_into_qm31s pads the last QM31 with zeros" {
    var out: [3]QM31 = undefined;
    const values = [_]u32{ 17, 21, 17, 18, 20, 16, 20, 8, 14, 18, 16 };
    const packed_values = packIntoQm31s(&values, &out);
    try std.testing.expectEqual(@as(usize, 3), packed_values.len);
    try std.testing.expect(packed_values[0].eql(QM31.fromU32Unchecked(17, 21, 17, 18)));
    try std.testing.expect(packed_values[2].eql(QM31.fromU32Unchecked(14, 18, 16, 0)));
    try std.testing.expectEqual(@as(usize, 0), packIntoQm31s(&.{}, &out).len);
    // Values at or above P reduce, as `M31::from(u32)` does.
    try std.testing.expect(packIntoQm31s(&.{0x7fffffff}, &out)[0].eql(QM31.zero()));
}
