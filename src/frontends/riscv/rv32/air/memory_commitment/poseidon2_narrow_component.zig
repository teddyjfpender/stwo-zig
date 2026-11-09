//! Existing narrow profile, backed by the shared degree-three component.
const shared = @import("stwo_riscv_memory").air_poseidon2_degree3_component.Namespace(@import("poseidon2_narrow_degree3.zig"), @import("poseidon2_narrow_backend.zig"));
pub const Component = shared.Component;
pub const N_CONSTRAINTS = shared.N_CONSTRAINTS;
