//! Concrete backend implementations for stwo-zig.
//!
//! Each backend is a zero-sized marker type that satisfies the
//! `backend.assertBackend` contract.

pub const cpu_scalar = @import("stwo_cpu_backend");
pub const cuda = @import("cuda/mod.zig");
pub const metal = @import("metal/mod.zig");

/// The default backend: scalar CPU operations on plain slices.
pub const CpuBackend = cpu_scalar.CpuBackend;

/// CUDA GPU backend: operations offloaded to NVIDIA GPUs via libstwo_cuda.
pub const CudaBackend = cuda.CudaBackend;

/// Transaction-oriented Metal runtime. Unlike the legacy operation-level
/// backend contract, this owns device-resident proving resources.
pub const MetalRuntime = metal.Runtime;
