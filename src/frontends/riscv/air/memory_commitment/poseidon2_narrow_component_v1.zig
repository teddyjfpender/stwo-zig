//! Existing narrow profile, backed by the shared degree-three component.
const shared = @import("poseidon2_degree3_component.zig").Namespace(@import("poseidon2_narrow_degree3_v1.zig"), @import("poseidon2_narrow_backend_v1.zig"));
pub const Component = shared.Component;
pub const N_CONSTRAINTS = shared.N_CONSTRAINTS;
