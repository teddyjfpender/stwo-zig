//! Shared real guest for register-custody and closed-tiling comparisons.
pub const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
pub fn instructions(iterations: u32) ![20]u32 {
    if (iterations < 4096 or iterations > 1 << 20 or iterations % 4096 != 0) return error.InvalidMixedGuestIterations;
    return .{
        0x001002b7, // Precompile input pointers.
        0x10028293,
        0x08028313,
        @import("../../isa/sha256_compression_v1.zig").encode(5, 6),
        @import("../../isa/custom0.zig").encodeKeccakf(5),
        @import("../../isa/sha256_compression_v1.zig").encode(5, 6),
        0x00100137, // x2 = writable RAM base; x3 = 0.
        0x00000193,
        (iterations & 0xfffff000) | (7 << 7) | 0x37,
        0x00118193, // Increment, store, load, decrement, branch.
        0x02312023,
        0x02012203,
        0xfff38393,
        0xfe0398e3,
        0x00100137, // Publish the output byte, length and halt flag.
        0x00100193,
        0x00312223,
        0x00312423,
        0x00312023,
        0x0000006f,
    };
}
