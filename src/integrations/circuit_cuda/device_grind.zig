//! The circuit lane's §4.7 grinds on an NVIDIA device (design 02-design.md
//! §9.2 item 7, milestone M12).
//!
//! Every circuit proof grinds twice: the 20-bit interaction grind and the
//! FRI grind at `fri_config.pow_bits` (26 in production), on
//! `Blake2sM31Channel` for leaves and internal folds and on the plain
//! `Blake2sChannel` for the root. Both walk Rust Stwo's `SimdBackend` order
//! (`core/channel/blake2s_pow_order.zig`). `native/circuit_grind.cu` runs
//! that search with the CUDA backend's PoW lattice kernel pieces; this file
//! binds it as a proof-of-work provider for the CPU PCS
//! (`stwo_cpu_backend.configured(.{ .proof_of_work = Device })`), so the
//! engine's `prover.pcs.proof_of_work.grindForBackend` sends both grinds
//! here and revalidates every nonce through the channel.
//!
//! Fail closed. Without a visible device, or on any CUDA runtime error, the
//! grind returns an error; there is no silent CPU fallback. A channel this
//! provider has no kernel for is refused by `admitHostProving`.

const std = @import("std");
const core = @import("stwo_core");

const pow_order = core.channel.blake2s.pow_order;

pub const Error = error{
    /// No CUDA device is visible (or the driver is missing or too old).
    CudaDeviceUnavailable,
    /// A CUDA runtime call failed; the code is logged.
    CudaRuntimeFailure,
    /// No canonical nonce below the search bound (Rust panics likewise).
    ProofOfWorkSpaceExhausted,
    UnsupportedProofOfWorkBits,
    /// The provider was asked for a grind it has no kernel for.
    CudaHostProofOfWorkForbidden,
};

/// Which Blake2s channel the grind is for.
pub const Output = enum(u32) {
    /// `Blake2sChannel` (the root).
    plain = 0,
    /// `Blake2sM31Channel` (leaves and internal folds): output words are
    /// reduced modulo 2^31 - 1.
    m31 = 1,
};

/// The whole canonical index space (`pow_order.INDEX_LIMIT`).
pub const search_end: u64 = pow_order.INDEX_LIMIT;

extern "c" fn stwo_circuit_cuda_device_count(count: *c_int) c_int;
extern "c" fn stwo_circuit_cuda_blake2s_grind(
    prefix: *const [8]u32,
    pow_bits: u32,
    m31_output: u32,
    search_end: u64,
    nonce_out: *u64,
) c_int;

// `cudaError_t` values that mean "no usable device" rather than a fault.
const cuda_error_insufficient_driver: c_int = 35;
const cuda_error_no_device: c_int = 100;

fn check(status: c_int) Error!void {
    switch (status) {
        0 => {},
        cuda_error_no_device, cuda_error_insufficient_driver => return error.CudaDeviceUnavailable,
        else => {
            std.log.scoped(.circuit_cuda).err("CUDA runtime error {d}", .{status});
            return error.CudaRuntimeFailure;
        },
    }
}

/// The number of visible CUDA devices.
pub fn deviceCount() Error!u32 {
    var count: c_int = 0;
    try check(stwo_circuit_cuda_device_count(&count));
    return @intCast(@max(count, 0));
}

/// The capability check: at least one CUDA device is visible.
pub fn requireDevice() Error!void {
    if (try deviceCount() == 0) return error.CudaDeviceUnavailable;
}

/// A channel's PoW prefix digest (`computePowPrefix`) as the kernel's
/// little-endian message words.
pub fn prefixWords(prefix: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, prefix[index * 4 ..][0..4], .little);
    return words;
}

/// One canonical grind on the device. `pow_bits == 0` is the engine's
/// (`grindForBackend` returns 0 before reaching a provider).
pub fn grind(output: Output, prefix: [32]u8, pow_bits: u32) Error!u64 {
    if (pow_bits == 0 or pow_bits > pow_order.MAX_POW_BITS) return error.UnsupportedProofOfWorkBits;
    const words = prefixWords(prefix);
    var nonce: u64 = std.math.maxInt(u64);
    try check(stwo_circuit_cuda_blake2s_grind(&words, pow_bits, @intFromEnum(output), search_end, &nonce));
    if (nonce == std.math.maxInt(u64)) return error.ProofOfWorkSpaceExhausted;
    return nonce;
}

/// The proof-of-work provider for `stwo_cpu_backend.configured`.
pub const Device = struct {
    pub fn grindBlake2sProofOfWork(prefix: [32]u8, pow_bits: u32) Error!u64 {
        return grind(.plain, prefix, pow_bits);
    }

    pub fn grindBlake2sM31ProofOfWork(prefix: [32]u8, pow_bits: u32) Error!u64 {
        return grind(.m31, prefix, pow_bits);
    }

    pub fn admitHostProving(_: anytype) Error!void {
        return error.CudaHostProofOfWorkForbidden;
    }
};
