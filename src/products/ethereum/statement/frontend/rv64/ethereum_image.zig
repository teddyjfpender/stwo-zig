//! Legacy guest-loading adapter above canonical RAM image snapshots.
const std = @import("std");
const image = @import("stwo_riscv_rv64").air.memory.image;
const contract = @import("ethereum_contract.zig");
pub const Initial = image.Initial;
pub const snapshot = image.snapshot;

pub fn fromEthereumElf(a: std.mem.Allocator, symbols: contract.Symbols, elf: []const u8, input: []const u8) !Initial {
    var loaded = try contract.load(a, symbols, elf, input);
    defer loaded.deinit();
    var tree = try snapshot(a, &loaded.memory);
    defer tree.deinit();
    var initial = Initial{ .root = tree.root(), .elf_sha256 = undefined, .input_sha256 = undefined };
    std.crypto.hash.sha2.Sha256.hash(elf, &initial.elf_sha256, .{});
    std.crypto.hash.sha2.Sha256.hash(input, &initial.input_sha256, .{});
    return initial;
}
