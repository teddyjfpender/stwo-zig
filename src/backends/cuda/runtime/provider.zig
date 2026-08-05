//! Execution-provider identity for the resident CUDA architecture.
//!
//! NVIDIA CUDA and CuMetal may expose compatible host APIs, but their device
//! evidence is not interchangeable. The provider tag is therefore part of
//! every compiled-plan cache key and frontend admission receipt.

const std = @import("std");

pub const Kind = enum(u8) {
    nvidia_cuda = 1,
    cumetal = 2,

    pub fn isCudaHardware(self: Kind) bool {
        return self == .nvidia_cuda;
    }
};

pub const EvidenceClass = enum(u8) {
    nvidia_device = 1,
    apple_gpu_translation = 2,
};

pub fn evidenceClass(kind: Kind) EvidenceClass {
    return switch (kind) {
        .nvidia_cuda => .nvidia_device,
        .cumetal => .apple_gpu_translation,
    };
}

test "CuMetal evidence is distinct from NVIDIA device evidence" {
    try std.testing.expect(Kind.nvidia_cuda.isCudaHardware());
    try std.testing.expect(!Kind.cumetal.isCudaHardware());
    try std.testing.expect(
        evidenceClass(.nvidia_cuda) != evidenceClass(.cumetal),
    );
}
