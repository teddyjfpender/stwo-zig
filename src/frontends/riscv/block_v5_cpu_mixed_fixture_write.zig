//! Write the exact canonical mixed source from prover/block_v5_cpu_driver_test.
//! Usage: OUTPUT_DIR. The producer uses a maximum of six cycles per segment.
const std = @import("std");
const fixture = @import("runner/guest_precompile/test_elf.zig");
const sha = @import("isa/sha256_compression_v1.zig");
const custom = @import("isa/custom0.zig");
const profile = @import("isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

pub const instructions = [_]u32{
    0x001002b7, 0x10028293, 0x08028313,
} ++ [_]u32{0x00000013} ** 3 ++ [_]u32{
    sha.encode(5, 6), custom.encodeKeccakf(5), sha.encode(5, 6),
} ++ [_]u32{0x00000013} ** 3 ++ [_]u32{
    0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x00312023, 0x0000006f,
};
pub const elf = fixture.buildReleaseProgram(instructions.len, &instructions, 256, profile);
pub const input = [_]u8{};
pub const oracle = [_]u8{1};

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makeDir(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    try write(dir, "mixed.elf", &elf);
    try write(dir, "input.bin", &input);
    try write(dir, "oracle.bin", &oracle);
    try std.fs.File.stdout().writeAll("Canonical mixed source written: mixed.elf input.bin oracle.bin; maximum segment cycles=6.\n");
}
fn write(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
