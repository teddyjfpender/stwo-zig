//! Exact topology/cell profiler for the changed-only memory transition V2.
//!
//! This read-only tool consumes canonical STWEMT01 compact tapes.  It counts
//! entry authentication hashes, changed exit hashes, and every bridge row
//! using only ordered touched-byte topology.  No witness values, proof, or
//! guest execution are needed, keeping corpus feedback below two seconds.

const std = @import("std");
const ethereum_wire = @import("runner/minimal_trace/ethereum_wire.zig");

const MAX_ARTIFACT_BYTES: usize = ethereum_wire.MAX_ENCODED_BYTES;
const D6_POSEIDON_MAIN_COLUMNS: u64 = 161;
const D6_POSEIDON_INTERACTION_COLUMNS: u64 = 8;
const BRIDGE_MAIN_COLUMNS: u64 = 7;
const BRIDGE_INTERACTION_COLUMNS: u64 = 4;

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
        const encoded = try file.readToEndAlloc(allocator, MAX_ARTIFACT_BYTES);
        defer allocator.free(encoded);
        var artifact = try ethereum_wire.decodeAlloc(allocator, encoded);
        defer artifact.deinit();
        const cost = try transitionCost(allocator, artifact.boundary_words);
        std.debug.print(
            "{{\"schema\":\"stwo.ethereum.incremental-memory-profile-v2\",\"segment_index\":{d},\"touched_words\":{d},\"changed_words\":{d},\"changed_bytes\":{d},\"entry_hash_calls\":{d},\"exit_hash_calls\":{d},\"total_hash_calls\":{d},\"bridge_rows\":{d},\"provider_log_size\":{d},\"bridge_log_size\":{d},\"d6_poseidon_main_cells\":{d},\"bridge_main_cells\":{d},\"d6_committed_cells\":{d},\"production\":false,\"path\":\"{s}\"}}\n",
            .{
                artifact.leaf.segment_index,
                artifact.boundary_words.len,
                cost.changed_words,
                cost.changed_bytes,
                cost.entry_hash_calls,
                cost.exit_hash_calls,
                cost.total_hash_calls,
                cost.bridge_rows,
                cost.provider_log_size,
                cost.bridge_log_size,
                cost.d6_poseidon_main_cells,
                cost.bridge_main_cells,
                cost.d6_committed_cells,
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
    total_hash_calls: u64,
    bridge_rows: u64,
    provider_log_size: u32,
    bridge_log_size: u32,
    d6_poseidon_main_cells: u64,
    bridge_main_cells: u64,
    d6_committed_cells: u64,
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
            const address = word.address + @as(u32, @intCast(limb));
            entry[word_index * 4 + limb] = address;
            const shift: u5 = @intCast(limb * 8);
            const old_byte: u8 = @truncate(word.entry >> shift);
            const new_byte: u8 = @truncate(word.exit >> shift);
            if (old_byte == new_byte) continue;
            changed[changed_count] = address;
            changed_count += 1;
        }
    }
    const topology = try topologyCost(
        allocator,
        entry,
        changed[0..changed_count],
    );
    const total_hash_calls = try std.math.add(
        u64,
        topology.entry_hash_calls,
        topology.exit_hash_calls,
    );
    const provider_log_size = traceLog(total_hash_calls);
    const bridge_log_size = traceLog(topology.bridge_rows);
    const provider_rows = rowsAt(provider_log_size);
    const bridge_rows = rowsAt(bridge_log_size);
    const d6_poseidon_main_cells = try std.math.mul(
        u64,
        provider_rows,
        D6_POSEIDON_MAIN_COLUMNS,
    );
    const bridge_main_cells = try std.math.mul(
        u64,
        bridge_rows,
        BRIDGE_MAIN_COLUMNS,
    );
    const provider_committed = try std.math.mul(
        u64,
        provider_rows,
        D6_POSEIDON_MAIN_COLUMNS + D6_POSEIDON_INTERACTION_COLUMNS,
    );
    const bridge_committed = try std.math.mul(
        u64,
        bridge_rows,
        BRIDGE_MAIN_COLUMNS + BRIDGE_INTERACTION_COLUMNS,
    );
    return .{
        .changed_words = changed_words,
        .changed_bytes = changed_count,
        .entry_hash_calls = topology.entry_hash_calls,
        .exit_hash_calls = topology.exit_hash_calls,
        .total_hash_calls = total_hash_calls,
        .bridge_rows = topology.bridge_rows,
        .provider_log_size = provider_log_size,
        .bridge_log_size = bridge_log_size,
        .d6_poseidon_main_cells = d6_poseidon_main_cells,
        .bridge_main_cells = bridge_main_cells,
        .d6_committed_cells = try std.math.add(
            u64,
            provider_committed,
            bridge_committed,
        ),
    };
}

const Topology = struct {
    entry_hash_calls: u64,
    exit_hash_calls: u64,
    bridge_rows: u64,
};

fn topologyCost(
    allocator: std.mem.Allocator,
    entry_leaves: []const u32,
    changed_leaves: []const u32,
) !Topology {
    if (entry_leaves.len == 0) return .{
        .entry_hash_calls = 0,
        .exit_hash_calls = 0,
        .bridge_rows = 0,
    };
    var entry = try allocator.dupe(u32, entry_leaves);
    defer allocator.free(entry);
    var changed = try allocator.dupe(u32, changed_leaves);
    defer allocator.free(changed);
    std.mem.sort(u32, entry, {}, std.sort.asc(u32));
    std.mem.sort(u32, changed, {}, std.sort.asc(u32));
    var entry_len = uniqueInPlace(entry);
    var changed_len = uniqueInPlace(changed);
    const unchanged_leaf_count = entry_len - changed_len;
    var direct_unchanged_leaves: u64 = 0;
    var reused_internal: u64 = 0;
    var external_frontier: u64 = 0;
    var entry_hash_calls: u64 = 0;
    var exit_hash_calls: u64 = 0;

    for (0..30) |round| {
        const depth = 30 - round;
        const entry_parent_len = parentCount(entry[0..entry_len]);
        external_frontier = try std.math.add(
            u64,
            external_frontier,
            @as(u64, entry_parent_len * 2 - entry_len),
        );
        if (changed_len > 0) {
            var at: usize = 0;
            while (at < changed_len) {
                const first = changed[at];
                const sibling = first ^ 1;
                at += 1;
                if (at < changed_len and changed[at] == sibling) {
                    at += 1;
                    continue;
                }
                if (contains(entry[0..entry_len], sibling)) {
                    if (depth == 30)
                        direct_unchanged_leaves += 1
                    else
                        reused_internal += 1;
                }
            }
        }
        for (entry[0..entry_len]) |*index| index.* /= 2;
        entry_len = uniqueInPlace(entry[0..entry_len]);
        entry_hash_calls = try std.math.add(u64, entry_hash_calls, entry_len);
        if (changed_len > 0) {
            for (changed[0..changed_len]) |*index| index.* /= 2;
            changed_len = uniqueInPlace(changed[0..changed_len]);
            exit_hash_calls = try std.math.add(u64, exit_hash_calls, changed_len);
        }
    }
    if (changed_leaves.len == 0) reused_internal += 1;
    const unchanged_bridges = try std.math.sub(
        u64,
        unchanged_leaf_count,
        direct_unchanged_leaves,
    );
    return .{
        .entry_hash_calls = entry_hash_calls,
        .exit_hash_calls = exit_hash_calls,
        .bridge_rows = try std.math.add(
            u64,
            try std.math.add(u64, external_frontier, reused_internal),
            unchanged_bridges,
        ),
    };
}

fn parentCount(indices: []const u32) usize {
    if (indices.len == 0) return 0;
    var count: usize = 1;
    var previous = indices[0] / 2;
    for (indices[1..]) |index| {
        const parent = index / 2;
        if (parent == previous) continue;
        previous = parent;
        count += 1;
    }
    return count;
}

fn contains(values: []const u32, needle: u32) bool {
    return std.sort.binarySearch(u32, values, needle, struct {
        fn compare(key: u32, value: u32) std.math.Order {
            return std.math.order(key, value);
        }
    }.compare) != null;
}

fn traceLog(row_count: u64) u32 {
    if (row_count == 0) return 0;
    return @max(@as(u32, 4), std.math.log2_int_ceil(u64, row_count));
}

fn rowsAt(log_size: u32) u64 {
    if (log_size == 0) return 0;
    return @as(u64, 1) << @intCast(log_size);
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

test "V2 topology counts direct leaves, reused subtrees, and read-only root" {
    const changed = try topologyCost(
        std.testing.allocator,
        &.{ 0, 1, 2, 3, 8, 9, 10, 11 },
        &.{0},
    );
    try std.testing.expectEqual(@as(u64, 35), changed.entry_hash_calls);
    try std.testing.expectEqual(@as(u64, 30), changed.exit_hash_calls);
    try std.testing.expectEqual(@as(u64, 36), changed.bridge_rows);

    const read_only = try topologyCost(
        std.testing.allocator,
        &.{ 4, 5, 6, 7 },
        &.{},
    );
    try std.testing.expectEqual(@as(u64, 31), read_only.entry_hash_calls);
    try std.testing.expectEqual(@as(u64, 0), read_only.exit_hash_calls);
    try std.testing.expectEqual(@as(u64, 33), read_only.bridge_rows);
}
