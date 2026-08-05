//! Structural Sail RV32IM + CUDA composition with fail-closed execution.

const policy = @import("../graph/product.zig");

pub const descriptor = policy.Descriptor{
    .product = .{
        .name = "stwo-riscv-cuda",
        .frontend = .riscv,
        .backend = .cuda,
        .role = .cli,
        .protocol_features =
            "rv32im-zkvm-v1+cuda-frontend-admission-v1+execution-unavailable",
    },
    .state = .unavailable,
    .target_support = .any,
    .unavailable_reason =
        "the structural RISC-V CUDA integration is present, but executable " ++
        "AOT and end-to-end proof parity evidence are incomplete",
    .build_step = "stwo-riscv-cuda",
    .test_step = null,
    .executable = null,
};
