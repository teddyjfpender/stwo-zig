//! The retained v6 mixed loop and two SHA/one Keccak calls, with a deliberate
//! 43-byte terminal ABI. The suffix has one extra instruction: do not compare
//! timings against the old one-byte ELF without running BOTH protocols on this
//! exact new ELF. There is no hardcoded segment count or program fetch census.
const std = @import("std");
fn validate(iterations: u32) !void {
    if (iterations == 0 or iterations > 1 << 20 or (iterations > 2047 and iterations % 4096 != 0)) return error.InvalidV7ScalingIterations;
}
pub fn instructions(iterations: u32) ![21]u32 {
    try validate(iterations);
    return .{
        0x001002b7,                                                  0x10028293,                                        0x08028313,
        @import("../../isa/sha256_compression_v1.zig").encode(5, 6), @import("../../isa/custom0.zig").encodeKeccakf(5), @import("../../isa/sha256_compression_v1.zig").encode(5, 6),
        0x00100137,                                                  0x00000193,                                        if (iterations <= 2047) (iterations << 20) | (7 << 7) | 0x13 else (iterations & 0xfffff000) | (7 << 7) | 0x37,
        0x00118193,                                                  0x02312023,                                        0x02012203,
        0xfff38393,                                                  0xfe0398e3,                                        0x00100137,
        0x00100193,                                                  0x02b00213,                                        0x00412223,
        0x02312423,                                                  0x00312023,                                        0x0000006f,
    };
}
pub fn cycles(iterations: u32) !u64 {
    try validate(iterations);
    return 5 * @as(u64, iterations) + 15;
}
pub fn output(iterations: u32) ![43]u8 {
    try validate(iterations);
    var bytes: [43]u8 = @splat(0);
    bytes[32] = 1;
    std.mem.writeInt(u32, bytes[24..28], iterations, .little);
    return bytes;
}
pub fn releaseElf(code: *const [21]u32) @TypeOf(@import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(21, code, 256, .rv32im_zkvm_ethereum_sha_v1)) {
    var elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(21, code, 256, .rv32im_zkvm_ethereum_sha_v1);
    // Complete v7 linker policy declares the loadable initialized data and a
    // nonempty aligned private input range, disjoint from terminal ABI cells.
    const table = std.mem.readInt(u32, elf[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value|
        std.mem.writeInt(u32, elf[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    return elf;
}
