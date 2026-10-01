//! Host emulation of the device grind (`native/circuit_grind.cu` compiled
//! as host C++ with `STWO_CIRCUIT_GRIND_HOST_EMULATION`).
//!
//! It runs the kernel's own source, the Blake2s candidate hash of
//! `backends/cuda/native/pow/candidate.cuh`, the M31 reduction and the
//! residue-class scan, on the CPU, one class after another. It is how a host
//! without a GPU checks the kernel's search semantics against the CPU grind
//! and drives the circuit prover through the provider path end to end. It
//! is not a CUDA product and says nothing about device timing.

const std = @import("std");
const device_grind = @import("device_grind.zig");

const Error = device_grind.Error;

extern "c" fn stwo_circuit_cuda_grind_emulate(
    prefix: *const [8]u32,
    pow_bits: u32,
    m31_output: u32,
    search_end: u64,
    workers: u64,
    nonce_out: *u64,
) c_int;

/// Residue classes the emulation walks by default. The result does not
/// depend on it; the device uses `kBlocks * kThreads` = 262144.
pub const default_workers: u64 = 64;

pub fn grind(output: device_grind.Output, prefix: [32]u8, pow_bits: u32, workers: u64) Error!u64 {
    if (pow_bits == 0 or pow_bits > 32) return error.UnsupportedProofOfWorkBits;
    const words = device_grind.prefixWords(prefix);
    var nonce: u64 = std.math.maxInt(u64);
    if (stwo_circuit_cuda_grind_emulate(&words, pow_bits, @intFromEnum(output), device_grind.search_end, workers, &nonce) != 0)
        return error.CudaRuntimeFailure;
    if (nonce == std.math.maxInt(u64)) return error.ProofOfWorkSpaceExhausted;
    return nonce;
}

/// The emulated device as a proof-of-work provider (tests only).
pub const Provider = struct {
    pub fn grindBlake2sProofOfWork(prefix: [32]u8, pow_bits: u32) Error!u64 {
        return grind(.plain, prefix, pow_bits, default_workers);
    }

    pub fn grindBlake2sM31ProofOfWork(prefix: [32]u8, pow_bits: u32) Error!u64 {
        return grind(.m31, prefix, pow_bits, default_workers);
    }

    pub fn admitHostProving(_: anytype) Error!void {
        return error.CudaHostProofOfWorkForbidden;
    }
};

const grind_vectors = @import("grind_vectors.zig");

fn grindWith(comptime workers: u64) type {
    return struct {
        fn grindFn(output: device_grind.Output, prefix: [32]u8, pow_bits: u32) Error!u64 {
            return grind(output, prefix, pow_bits, workers);
        }
    };
}

test "kernel search (emulated): Rust Stwo SimdBackend known answers, both channels, 20/24/26 bits" {
    try grind_vectors.expectRustVectors(grindWith(default_workers).grindFn, 26);
}

test "kernel search (emulated): equals the CPU grind on both channels" {
    try grind_vectors.expectCpuSweep(grindWith(default_workers).grindFn, 24, &.{ 1, 4, 8, 12, 16, 20 });
}

test "kernel search (emulated): the nonce does not depend on the grid shape" {
    // One class, a prime count, and the device's `kBlocks * kThreads`.
    inline for (.{ 1, 7, 262144 }) |workers| {
        try grind_vectors.expectRustVectors(grindWith(workers).grindFn, 20);
        try grind_vectors.expectCpuSweep(grindWith(workers).grindFn, 4, &.{ 8, 20 });
    }
}

test "kernel search (emulated): rejects widths outside 1..32" {
    const prefix = [_]u8{0} ** 32;
    try std.testing.expectError(error.UnsupportedProofOfWorkBits, grind(.plain, prefix, 0, default_workers));
    try std.testing.expectError(error.UnsupportedProofOfWorkBits, grind(.m31, prefix, 33, default_workers));
}
