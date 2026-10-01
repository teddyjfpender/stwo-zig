//! The provers the device rungs (R7, R9 on Metal) prove with: the Metal
//! circuit provers, against the CPU scalar oracle's fixtures (design §4.6).

const circuit_metal = @import("stwo_circuit_metal_integration");

pub const backend_name = "metal";
pub const Internal = circuit_metal.Internal;
pub const Root = circuit_metal.Root;
pub const provers = &circuit_metal.provers;
