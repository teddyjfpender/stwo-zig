//! The circuit grind kernel on an NVIDIA device (GPU host,
//! `test-cuda-device`): every nonce must equal the CPU grind's and Rust
//! Stwo's `SimdBackend` known answers, and the provider path must hand the
//! engine a revalidated nonce. Without a visible device every test fails
//! (fail closed: no silent CPU fallback).

const std = @import("std");
const core = @import("stwo_core");
const circuit_cuda = @import("stwo_circuit_cuda_integration");

const device_grind = circuit_cuda.device_grind;
const grind_vectors = circuit_cuda.grind_vectors;

test "device: a CUDA device is visible" {
    try device_grind.requireDevice();
}

test "device: Rust Stwo SimdBackend known answers, both channels, 20/24/26 bits" {
    try grind_vectors.expectRustVectors(device_grind.grind, 32);
}

test "device: equals the CPU grind on both channels" {
    try grind_vectors.expectCpuSweep(device_grind.grind, 64, &.{ 1, 4, 8, 12, 16, 20, 22 });
}

test "device: the production widths (20 and 26 bits) on fresh transcripts" {
    try grind_vectors.expectCpuSweep(device_grind.grind, 3, &.{ 20, 26 });
}

test "device: the provider path returns the CPU channel's nonce" {
    const Backend = circuit_cuda.Backend;
    const Blake2sChannel = core.channel.blake2s.Blake2sChannel;
    const Blake2sM31Channel = core.channel.blake2s.Blake2sM31Channel;
    const grindForBackend = @import("stwo_prover_engine").pcs.proof_of_work.grindForBackend;
    inline for (.{ Blake2sChannel, Blake2sM31Channel }) |Channel| {
        var channel = Channel{};
        channel.mixU64(0x1111_2222_3333_4344);
        for ([_]u32{ 20, 26 }) |bits| {
            try std.testing.expectEqual(channel.grindWithWorkerCount(bits, 8), try grindForBackend(Backend, &channel, bits));
        }
    }
}

test "device: rejects widths outside 1..32" {
    const prefix = [_]u8{0} ** 32;
    try std.testing.expectError(error.UnsupportedProofOfWorkBits, device_grind.grind(.plain, prefix, 0));
    try std.testing.expectError(error.UnsupportedProofOfWorkBits, device_grind.grind(.m31, prefix, 33));
}
