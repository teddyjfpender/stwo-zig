//! Ethereum-only word-addressed tree. Zero words are the implicit memory value.
//! Four bytes are injected into nine canonical lanes without lossy field reduction;
//! node kind and height separate memory/program and every internal tree level.
const std = @import("std");
const core = @import("stwo_core");
const node = @import("ethereum_node_v1.zig");
const path = @import("ethereum_path_v1.zig");
const M31 = core.fields.m31.M31;
pub const DEPTH = 30;
pub const Word = struct { address: u32, value: u32 };
pub const Witness = struct { statement: path.Statement, rows: [DEPTH]node.Row(M31) };
const Entry = struct { index: u32, digest: node.Digest };

pub fn wordDigest(word: u32) node.Digest {
    var digest = [_]u32{0} ** node.DIGEST_WORDS;
    for (0..4) |limb| digest[limb] = (word >> @intCast(8 * limb)) & 255;
    return digest;
}

/// One sorted frontier compacts in place. Only the requested path is retained:
/// no hash map, full node trace or second copy of the frontier is needed.
pub fn build(allocator: std.mem.Allocator, kind: node.Kind, words: []const Word, address: u32) !Witness {
    if (address & 3 != 0) return error.MisalignedWord;
    for (words, 0..) |word, i| {
        if (word.address & 3 != 0) return error.MisalignedWord;
        if (i != 0 and words[i - 1].address >= word.address) return error.UnsortedOrDuplicateWord;
    }
    var defaults: [DEPTH + 1]node.Digest = undefined;
    defaults[0] = wordDigest(0);
    for (0..DEPTH) |height| defaults[height + 1] = try hash(kind, @intCast(height), defaults[height], defaults[height]);
    const frontier = try allocator.alloc(Entry, words.len);
    defer allocator.free(frontier);
    var used: usize = 0;
    var value: u32 = 0;
    for (words) |word| {
        if (word.address == address) value = word.value;
        if (word.value == 0) continue;
        frontier[used] = .{ .index = word.address >> 2, .digest = wordDigest(word.value) };
        used += 1;
    }
    var siblings: [DEPTH]node.Digest = undefined;
    for (0..DEPTH) |height| {
        const sibling_index = ((address >> 2) >> @intCast(height)) ^ 1;
        siblings[height] = find(frontier[0..used], sibling_index) orelse defaults[height];
        var read: usize = 0;
        var write: usize = 0;
        while (read < used) {
            const first = frontier[read];
            const parent = first.index >> 1;
            var left = defaults[height];
            var right = defaults[height];
            if (first.index & 1 == 0) left = first.digest else right = first.digest;
            read += 1;
            if (read < used and frontier[read].index >> 1 == parent) {
                right = frontier[read].digest;
                read += 1;
            }
            frontier[write] = .{ .index = parent, .digest = try hash(kind, @intCast(height), left, right) };
            write += 1;
        }
        used = write;
    }
    var result: Witness = undefined;
    result.statement = try path.buildInto(&result.rows, kind, address >> 2, wordDigest(value), &siblings);
    const root = if (used == 0) defaults[DEPTH] else frontier[0].digest;
    if (!std.meta.eql(result.statement.root, root)) return error.PathRootMismatch;
    return result;
}

fn hash(kind: node.Kind, height: u5, left: node.Digest, right: node.Digest) !node.Digest {
    const row = try node.build(kind, height, left, right);
    var result: node.Digest = undefined;
    for (&result, row.digest) |*word, value| word.* = value.toU32();
    return result;
}

fn find(entries: []const Entry, index: u32) ?node.Digest {
    var low: usize = 0;
    var high = entries.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (entries[middle].index < index) low = middle + 1 else high = middle;
    }
    return if (low < entries.len and entries[low].index == index) entries[low].digest else null;
}

/// Public program-image reference path for the rebuilt Ethereum guest. This
/// authenticates an image word, not instruction retirement or an Ethereum block.
pub fn fromElf(allocator: std.mem.Allocator, elf: []const u8, address: u32) !Witness {
    const loader = @import("../../runner/elf_loader.zig");
    const Memory = @import("../../runner/memory.zig").Memory;
    if (elf.len > 8 * 1024 * 1024) return error.ProgramImageTooLarge;
    try loader.validateReleaseAbiForProfile(elf, .rv32im_zkvm_ethereum_v1);
    var memory = try Memory.initFallible(allocator);
    defer memory.deinit();
    const info = try loader.loadElfForProfile(elf, &memory, .rv32im_zkvm_ethereum_v1);
    const start = info.memory_layout.program_base;
    const end = info.memory_layout.program_end;
    if (end <= start or (start | end | address) & 3 != 0 or address < start or address >= end)
        return error.InvalidProgramRange;
    if (end - start > 8 * 1024 * 1024) return error.ProgramImageTooLarge;
    const words = try allocator.alloc(Word, (end - start) / 4);
    defer allocator.free(words);
    for (words, 0..) |*word, i| {
        const at = start + @as(u32, @intCast(i)) * 4;
        word.* = .{ .address = at, .value = memory.readU32(at) };
    }
    return build(allocator, .program, words, address);
}

test "Ethereum node V1 word tree binds values, sparse positions and zero defaults" {
    const allocator = std.testing.allocator;
    const words = [_]Word{ .{ .address = 0, .value = 0xffff_ffff }, .{ .address = 4, .value = 7 }, .{ .address = 0xffff_fffc, .value = 9 } };
    const first = try build(allocator, .memory, &words, 0);
    const high = try build(allocator, .memory, &words, 0xffff_fffc);
    const absent = try build(allocator, .memory, &words, 8);
    try std.testing.expectEqualDeep(first.statement.root, high.statement.root);
    try std.testing.expectEqualDeep(first.statement.root, absent.statement.root);
    try std.testing.expectEqualDeep(wordDigest(0xffff_ffff), first.statement.leaf);
    try std.testing.expectEqualDeep(node.Digest{ 255, 255, 255, 255, 0, 0, 0, 0, 0 }, first.statement.leaf);
    try std.testing.expectEqualDeep(wordDigest(0), absent.statement.leaf);
    for (0..4) |limb| {
        var changed = words;
        changed[0].value ^= @as(u32, 1) << @intCast(8 * limb);
        const different = try build(allocator, .memory, &changed, 0xffff_fffc);
        try std.testing.expect(!std.meta.eql(first.statement.root, different.statement.root));
    }
    const empty = try build(allocator, .memory, &.{}, 0);
    const zero = try build(allocator, .memory, &.{.{ .address = 4, .value = 0 }}, 0);
    try std.testing.expectEqualDeep(empty.statement.root, zero.statement.root);
    const program = try build(allocator, .program, &words, 0);
    try std.testing.expect(!std.meta.eql(first.statement.root, program.statement.root));
    try std.testing.expectError(error.UnsortedOrDuplicateWord, build(allocator, .memory, &.{ words[0], words[0] }, 0));
    try std.testing.expectError(error.MisalignedWord, build(allocator, .memory, &words, 1));
}
