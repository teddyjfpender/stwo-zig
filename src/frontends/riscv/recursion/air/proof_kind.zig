//! Verifier-owned universal recursion branch selection.

const M31 = @import("stwo_core").fields.m31.M31;

pub const ProofKind = enum(u8) {
    segment_leaf = 0,
    binary_node = 1,
    empty_leaf = 2,

    pub fn selectors(self: ProofKind) [3]M31 {
        var result = [_]M31{M31.zero()} ** 3;
        result[@intFromEnum(self)] = M31.one();
        return result;
    }
};
