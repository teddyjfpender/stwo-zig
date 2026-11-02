//! Versioned state-relation layout. Defaults preserve all existing proofs.
pub const Policy = enum(u32) { inverse_v1 = 1, cyclic_v2 = 2, cyclic_canonical_v3 = 3 };
pub fn interactionCount(policy: Policy) usize {
    return switch (policy) {
        .inverse_v1 => 36,
        .cyclic_v2, .cyclic_canonical_v3 => 12,
    };
}

/// Layout selection only. The v3 byte inference additionally requires a closed
/// authenticated state relation, strict bounded clocks and canonical writes.
pub fn isCyclic(policy: Policy) bool {
    return policy != .inverse_v1;
}
pub fn derivesStateBytes(policy: Policy) bool {
    return policy == .cyclic_canonical_v3;
}
