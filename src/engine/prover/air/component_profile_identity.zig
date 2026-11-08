//! Semantic identities for integrations whose admission policy must bind an
//! exact reviewed component rather than coincidental evaluator geometry.

/// Frontends set these only on the named production components. Derived and
/// unrelated components retain the `null` identity on `ComponentProver`.
pub const ComponentProfileIdentity = enum {
    riscv_guest_poseidon2_caller_v1,
    riscv_guest_poseidon2_provider_v1,
};
