//! Universal version-one layout uses the same native and recursive equations.
//! Its backend programs record those exact equations and independent-prefix lookups.
const shared = @import("stwo_riscv_memory").air_poseidon2_degree3_component.Namespace(@import("stwo_riscv_memory").air_poseidon2_universal_equations, @import("poseidon2_narrow_backend.zig").Universal);
pub const Component = shared.Component;
pub const N_CONSTRAINTS = shared.N_CONSTRAINTS;
