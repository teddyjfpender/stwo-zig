//! CudaBackend conformance against the CPU reference backend.
//!
//! Requires a CUDA machine (the kernels crate builds as a stub without nvcc, and every
//! GPU entry point panics). The decisive gate is proof byte-equality on both channels.

use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use stwo_backend_cuda::CudaBackend;

fn require_cuda() -> bool {
    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return true;
    }
    eprintln!("skipping CUDA conformance: kernels not built (no nvcc)");
    false
}

#[test]
fn cuda_backend_conformance() {
    if !require_cuda() {
        return;
    }
    stwo_backend_testkit::assert_backend_conformance::<CudaBackend, Blake2sMerkleChannel>();
}

#[test]
fn cuda_backend_conformance_m31_channel() {
    if !require_cuda() {
        return;
    }
    stwo_backend_testkit::assert_backend_conformance::<CudaBackend, Blake2sM31MerkleChannel>();
}
