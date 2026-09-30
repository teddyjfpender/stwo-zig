//! Fail closed (design §4.6): on a host where the CUDA runtime reports no
//! device (here the `native/compile_check/no_device.c` stand-in), the CUDA
//! circuit provers error at their first grind instead of grinding on the
//! CPU.

const std = @import("std");
const core = @import("stwo_core");
const circuit_cuda = @import("stwo_circuit_cuda_integration");

const grindForBackend = @import("stwo_prover_engine").pcs.proof_of_work.grindForBackend;

test "fail closed: no visible device is an error" {
    try std.testing.expectError(error.CudaDeviceUnavailable, circuit_cuda.device_grind.requireDevice());
    try std.testing.expectError(error.CudaDeviceUnavailable, circuit_cuda.device_grind.grind(.m31, [_]u8{0} ** 32, 20));
}

test "fail closed: the provers' grinds (both channels) error without a device" {
    inline for (.{ circuit_cuda.Internal, circuit_cuda.Root }) |P| {
        var channel = P.Channel{};
        channel.mixU64(7);
        try std.testing.expectError(error.CudaDeviceUnavailable, grindForBackend(P.Backend, &channel, 20));
        try std.testing.expectError(error.CudaDeviceUnavailable, grindForBackend(P.Backend, &channel, 26));
    }
}
