//! Read-only cost extractor for compact Ethereum touched-memory tapes.
//!
//! It decodes the canonical STWEMT01 custody wire and counts the exact induced
//! Merkle parents needed to authenticate every touched byte and to update only
//! changed bytes. No proof or execution is performed, so corpus-wide feedback
//! stays comfortably inside the autoresearch time limit.

const std = @import("std");
const ethereum_wire = @import("runner/minimal_trace/ethereum_wire.zig");

const max_artifact_bytes: usize = ethereum_wire.MAX_ENCODED_BYTES;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) return error.MissingCompactArtifact;

    for (args[1..]) |path| {
        const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
        defer file.close();
        const encoded = try file.readToEndAlloc(allocator, max_artifact_bytes);
        defer allocator.free(encoded);
        var artifact = try ethereum_wire.decodeAlloc(allocator, encoded);
        defer artifact.deinit();
        const cost = try transitionCost(allocator, artifact.boundary_words);
        std.debug.print(
            "{{\"segment_index\":{d},\"touched_words\":{d},\"changed_words\":{d},\"changed_bytes\":{d},\"entry_hash_calls\":{d},\"exit_hash_calls\":{d},\"total_hash_calls\":{d},\"provider_log_size\":{d},\"path\":\"{s}\"}}\n",
            .{
                artifact.leaf.segment_index,
                artifact.boundary_words.len,
                cost.changed_words,
                cost.changed_bytes,
                cost.entry_hash_calls,
                cost.exit_hash_calls,
                cost.entry_hash_calls + cost.exit_hash_calls,
                cost.provider_log_size,
                path,
            },
        );
    }
}

const Cost = struct {
    changed_words: u64,
    changed_bytes: u64,
    entry_hash_calls: u64,
    exit_hash_calls: u64,
    provider_log_size: u32,
};

fn transitionCost(allocator: std.mem.Allocator, words: anytype) !Cost {
    const byte_count = try std.math.mul(usize, words.len, 4);
    var entry = try allocator.alloc(u32, byte_count);
    defer allocator.free(entry);
    var changed = try allocator.alloc(u32, byte_count);
    defer allocator.free(changed);
    var changed_count: usize = 0;
    var changed_words: u64 = 0;
    for (words, 0..) |word, word_index| {
        if (word.entry != word.exit) changed_words += 1;
        for (0..4) |limb| {
            const offset: u32 = @intCast(limb);
            const address = word.address + offset;
            entry[word_index * 4 + limb] = address;
            const shift: u5 = @intCast(limb * 8);
            const old_byte: u8 = @truncate(word.entry >> shift);
            const new_byte: u8 = @truncate(word.exit >> shift);
            if (old_byte != new_byte) {
                changed[changed_count] = address;
                changed_count += 1;
            }
        }
    }

    const entry_hash_calls = try inducedParentCount(allocator, entry);
    const exit_hash_calls = try inducedParentCount(
        allocator,
        changed[0..changed_count],
    );
    const total = try std.math.add(u64, entry_hash_calls, exit_hash_calls);
    return .{
        .changed_words = changed_words,
        .changed_bytes = changed_count,
        .entry_hash_calls = entry_hash_calls,
        .exit_hash_calls = exit_hash_calls,
        .provider_log_size = if (total == 0)
            0
        else
            @max(@as(u32, 4), std.math.log2_int_ceil(u64, total)),
    };
}

fn inducedParentCount(
    allocator: std.mem.Allocator,
    leaf_indices: []const u32,
) !u64 {
    if (leaf_indices.len == 0) return 0;
    var current = try allocator.dupe(u32, leaf_indices);
    defer allocator.free(current);
    std.mem.sort(u32, current, {}, std.sort.asc(u32));
    var current_len = uniqueInPlace(current);
    var total: u64 = 0;
    for (0..30) |_| {
        for (current[0..current_len]) |*index| index.* /= 2;
        current_len = uniqueInPlace(current[0..current_len]);
        total = try std.math.add(u64, total, current_len);
    }
    return total;
}

fn uniqueInPlace(values: []u32) usize {
    if (values.len == 0) return 0;
    var write: usize = 1;
    for (values[1..]) |value| {
        if (value == values[write - 1]) continue;
        values[write] = value;
        write += 1;
    }
    return write;
}

test "induced parent cost counts shared paths once" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        @as(u64, 30),
        try inducedParentCount(allocator, &.{0}),
    );
    // Sibling leaves merge at the first level and share all remaining paths.
    try std.testing.expectEqual(
        @as(u64, 30),
        try inducedParentCount(allocator, &.{ 0, 1 }),
    );
    // Adjacent parents remain distinct for one level, then merge.
    try std.testing.expectEqual(
        @as(u64, 31),
        try inducedParentCount(allocator, &.{ 0, 2 }),
    );
}
