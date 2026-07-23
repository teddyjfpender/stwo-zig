//! Mirrors the nvcc detection in `stwo-backend-cuda-kernels`'s build script so the
//! GPU-requiring unit tests (`#[cfg(stwo_cuda_link)]`) compile only when the kernels
//! were actually built. The stub build stays link-clean everywhere.

use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(stwo_cuda_link)");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_NVCC");
    let nvcc = std::env::var("STWO_CUDA_NVCC").unwrap_or_else(|_| "nvcc".to_string());
    let available = Command::new(&nvcc)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if available {
        println!("cargo:rustc-cfg=stwo_cuda_link");
    }
}
