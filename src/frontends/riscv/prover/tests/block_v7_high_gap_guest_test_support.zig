//! Sparse RAM access after a real local clock gap; loaded data is deliberately
//! clobbered so the public output alone cannot detect a forged memory chain.
const std = @import("std");
pub const address: u32 = 0x100100;
pub const value: u32 = 17;
pub const forged_value: u32 = 23;
pub const iterations: u32 = 131072;
pub const prefix_cycles: u32 = 4;
pub const suffix_cycles: u32 = 2 * iterations + 9;
pub const cycles: u64 = prefix_cycles + suffix_cycles;
pub const code = [_]u32{
    0x001002b7, // lui x5, 0x100
    0x10028293, // addi x5, x5, 256
    0x01100313, // addi x6, x0, 17
    0x0062a023, // sw x6, 0(x5)
    0x000203b7, // lui x7, 0x20 = 131072
    0xfff38393, // addi x7, x7, -1
    0xfe039ee3, // bne x7, x0, -4
    0x0002a403, // lw x8, 0(x5)
    0x00000413, // clobber x8
    0x00100137, // terminal ABI
    0x00100193,
    0x02b00213,
    0x00412223,
    0x02312423,
    0x00312023,
    0x0000006f,
};
pub const output: [43]u8 = blk: {
    var bytes: [43]u8 = @splat(0);
    bytes[32] = 1;
    break :blk bytes;
};
pub fn elf() @TypeOf(@import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1)) {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, item|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], item, .little);
    return bytes;
}
