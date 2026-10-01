//! The R7 provers with both grinds on the host emulation of the CUDA kernel
//! (`emulation.zig`): the kernel's own search code, run on the CPU, driving
//! the circuit prover through the device provider path. Byte equality here
//! checks the kernel's search semantics and the provider wiring on a host
//! without a GPU; it says nothing about device execution or timing.

const circuit_cuda = @import("stwo_circuit_cuda_integration");

const Emulated = circuit_cuda.ProversWith(circuit_cuda.emulation.Provider);

pub const backend_name = "cuda-emulated";
pub const Internal = Emulated.Internal;
pub const Root = Emulated.Root;
pub const provers = &Emulated.provers;
