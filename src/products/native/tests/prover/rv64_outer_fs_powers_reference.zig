//! Core OM31 reference, consuming the existing 84-case lookup corpus on stdin.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;

pub fn main() !void {
    var corpus: [84 * 72 * 4]u8 = undefined;
    if (try std.fs.File.stdin().readAll(&corpus) != corpus.len) return error.InvalidCorpusLength;
    const starts = [_]u64{ 0, 1, 19, 4294967297, std.math.maxInt(u64), std.math.maxInt(u64) - 256 };
    const counts = [_]u32{ 6, 19, 257, 6, 1, 257 };
    for (0..84) |case| {
        var alpha_words: [8]M = undefined;
        for (&alpha_words, 0..) |*v, i| {
            const word = std.mem.readInt(u32, corpus[case * 288 + 32 + i * 4 ..][0..4], .little);
            if (word >= 2147483647) return error.NoncanonicalCorpus;
            v.* = M.fromU32Unchecked(word);
        }
        const alpha = O.fromM31Array(alpha_words);
        for (starts, counts) |first, count| {
            var bytes: [44 + 257 * 32]u8 = undefined;
            std.mem.writeInt(u64, bytes[0..8], first, .little);
            std.mem.writeInt(u32, bytes[8..12], count, .little);
            for (alpha_words, 0..) |v, i| std.mem.writeInt(u32, bytes[12 + 4 * i ..][0..4], v.v, .little);
            var power = alpha.pow(first);
            for (0..count) |i| {
                for (power.toM31Array(), 0..) |v, j| std.mem.writeInt(u32, bytes[44 + 32 * i + 4 * j ..][0..4], v.v, .little);
                power = power.mul(alpha);
            }
            try std.fs.File.stdout().writeAll(bytes[0 .. 44 + count * 32]);
        }
    }
}
