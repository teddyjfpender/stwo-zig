//! Genuine guest halt fixture: execute a store to the canonical ELF halt flag.
//! The remaining admitted image is retained; it is not a fabricated leaf proof.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prior = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
pub fn programElf() @TypeOf(prior.programElf()) {
    var elf = prior.programElf();
    const instructions = [_]u32{ 0x001000b7, 0x00100113, 0x0000a223, 0x0020a023, 0x0000006f }; // LUI; ADDI; output_len=0; halt=1; self-loop.
    for (instructions, 0..) |word, index| std.mem.writeInt(u32, elf[640 + 4 * index ..][0..4], word, .little);
    return elf;
}
pub fn run(allocator: std.mem.Allocator) !frontend.runner.EthereumRunResult {
    const elf = programElf();
    return frontend.runner.runEthereumExtensionWithInput(allocator, &elf, &.{}, 8);
}
