//! Universal version-one layout uses the same native and recursive equations.
//! Its backend programs record those exact equations and independent-prefix lookups.
const shared = @import("poseidon2_degree3_component.zig").Namespace(@import("poseidon2_universal_degree3_v1.zig"), @import("poseidon2_narrow_backend_v1.zig").Universal);
pub const Component = shared.Component;
pub const N_CONSTRAINTS = shared.N_CONSTRAINTS;
