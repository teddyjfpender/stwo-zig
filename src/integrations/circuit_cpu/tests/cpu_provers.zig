//! The provers this package's R7 and R9 rungs prove with: the CPU scalar
//! parity oracle (design §4.6). `circuit_metal` injects its own.

const circuit_cpu = @import("stwo_circuit_cpu_integration");

pub const backend_name = "cpu";
pub const Internal = circuit_cpu.Internal;
pub const Root = circuit_cpu.Root;
pub const provers = &circuit_cpu.prove.cpu_provers;
