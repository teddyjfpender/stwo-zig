//! The provers the device rungs (R7, R9 with CUDA grinds) prove with,
//! against the CPU scalar oracle's fixtures (design §4.6).

const circuit_cuda = @import("stwo_circuit_cuda_integration");

pub const backend_name = "cuda";
pub const Internal = circuit_cuda.Internal;
pub const Root = circuit_cuda.Root;
pub const provers = &circuit_cuda.provers;
