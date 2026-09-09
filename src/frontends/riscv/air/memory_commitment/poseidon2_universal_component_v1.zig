//! Universal version-one layout uses the same native and recursive equations.
//! No narrow-only Metal capability is advertised for universal IO relations.
const shared = @import("poseidon2_degree3_component.zig").Namespace(@import("poseidon2_universal_degree3_v1.zig"), null);
pub const Component = shared.Component;
pub const N_CONSTRAINTS = shared.N_CONSTRAINTS;
