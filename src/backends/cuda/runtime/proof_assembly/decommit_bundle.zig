//! Strict decoder for the compact device-produced decommitment bundle.

const std = @import("std");

pub const magic: u32 = 0x4457_5453;
pub const version: u32 = 1;
pub const header_words: usize = 8;
pub const tree_meta_words: usize = 16;
pub const hash_words: usize = 8;
pub const aux_node_words: usize = 10;
pub const secure_words: usize = 4;
pub const indexed_secure_words: usize = 5;
pub const max_protocol_queries: usize = 256;
pub const max_tree_count: usize = 512;

pub const Error = error{
    InvalidHeader,
    InvalidUsedWords,
    InvalidTreeCount,
    InvalidQueryLayout,
    InvalidTreeMetadata,
    InvalidSectionRange,
    NonCanonicalLayout,
    SizeOverflow,
};

pub const TreeKind = enum(u32) {
    trace = 0,
    fri = 1,
};

pub const TreeMeta = struct {
    kind: TreeKind,
    role: u32,
    query_offset: usize,
    query_count: usize,
    values_offset: usize,
    values_count: usize,
    fri_witness_offset: usize,
    fri_witness_count: usize,
    hash_witness_offset: usize,
    hash_witness_count: usize,
    aux_offset: usize,
    aux_count: usize,
    all_values_offset: usize,
    all_values_count: usize,
    leaf_log_size: u32,
    used_words: usize,
};

pub const Bundle = struct {
    storage: []u32,
    owns_storage: bool,
    used_words: usize,
    raw_query_offset: usize,
    raw_query_count: usize,
    unique_query_offset: usize,
    unique_query_count: usize,
    trees: []TreeMeta,

    pub fn decodeOwned(
        allocator: std.mem.Allocator,
        storage: []u32,
    ) (std.mem.Allocator.Error || Error)!Bundle {
        return decode(allocator, storage, true, true);
    }

    /// Caller retains failure cleanup until this decoder accepts ownership.
    pub fn decodeOwnedCallerGuarded(
        allocator: std.mem.Allocator,
        storage: []u32,
    ) (std.mem.Allocator.Error || Error)!Bundle {
        return decode(allocator, storage, true, false);
    }

    /// Decodes an exact subrange owned by a containing proof bundle.
    pub fn decodeBorrowed(
        allocator: std.mem.Allocator,
        storage: []u32,
    ) (std.mem.Allocator.Error || Error)!Bundle {
        return decode(allocator, storage, false, false);
    }

    fn decode(
        allocator: std.mem.Allocator,
        storage: []u32,
        owns_storage: bool,
        free_storage_on_error: bool,
    ) (std.mem.Allocator.Error || Error)!Bundle {
        errdefer if (free_storage_on_error) allocator.free(storage);
        if (storage.len < header_words or
            storage[0] != magic or
            storage[1] != version)
        {
            return error.InvalidHeader;
        }

        const tree_count: usize = storage[2];
        const raw_count: usize = storage[3];
        const unique_count: usize = storage[4];
        const raw_offset: usize = storage[5];
        const unique_offset: usize = storage[6];
        const used: usize = storage[7];
        if (used < header_words or used > storage.len)
            return error.InvalidUsedWords;
        if (tree_count == 0 or tree_count > max_tree_count)
            return error.InvalidTreeCount;

        const metadata_words = std.math.mul(
            usize,
            tree_count,
            tree_meta_words,
        ) catch return error.SizeOverflow;
        const metadata_end = std.math.add(
            usize,
            header_words,
            metadata_words,
        ) catch return error.SizeOverflow;
        if (metadata_end > used) return error.InvalidTreeCount;
        if (raw_count == 0 or raw_count > max_protocol_queries or
            unique_count == 0 or unique_count > raw_count)
            return error.InvalidQueryLayout;
        if (raw_offset != metadata_end) return error.NonCanonicalLayout;
        const raw_end = try sectionEnd(raw_offset, raw_count, used);
        if (unique_offset != raw_end) return error.NonCanonicalLayout;
        const unique_end = try sectionEnd(unique_offset, unique_count, used);

        const unique = storage[unique_offset..unique_end];
        for (unique, 0..) |query, index| {
            if (index != 0 and unique[index - 1] >= query)
                return error.InvalidQueryLayout;
        }
        for (storage[raw_offset..raw_end]) |query| {
            if (!containsSorted(unique, query))
                return error.InvalidQueryLayout;
        }
        const raw = storage[raw_offset..raw_end];
        for (unique) |query| {
            if (!containsUnsorted(raw, query))
                return error.InvalidQueryLayout;
        }

        const trees = try allocator.alloc(TreeMeta, tree_count);
        errdefer allocator.free(trees);
        var ranges = try std.ArrayList(Range).initCapacity(
            allocator,
            std.math.mul(usize, tree_count, 7) catch
                return error.SizeOverflow,
        );
        defer ranges.deinit(allocator);

        for (trees, 0..) |*tree, index| {
            const start = header_words + index * tree_meta_words;
            const metadata = storage[start..][0..tree_meta_words];
            tree.* = .{
                .kind = std.meta.intToEnum(TreeKind, metadata[0]) catch
                    return error.InvalidTreeMetadata,
                .role = metadata[1],
                .query_offset = metadata[2],
                .query_count = metadata[3],
                .values_offset = metadata[4],
                .values_count = metadata[5],
                .fri_witness_offset = metadata[6],
                .fri_witness_count = metadata[7],
                .hash_witness_offset = metadata[8],
                .hash_witness_count = metadata[9],
                .aux_offset = metadata[10],
                .aux_count = metadata[11],
                .all_values_offset = metadata[12],
                .all_values_count = metadata[13],
                .leaf_log_size = metadata[14],
                .used_words = metadata[15],
            };
            if (tree.leaf_log_size >= 31 or tree.used_words == 0 or
                tree.query_count == 0)
                return error.InvalidTreeMetadata;
            const tree_query_end = try sectionEnd(
                tree.query_offset,
                tree.query_count,
                used,
            );
            const tree_queries = storage[tree.query_offset..tree_query_end];
            const leaf_count = @as(u32, 1) << @intCast(tree.leaf_log_size);
            for (tree_queries, 0..) |query, query_index| {
                if (query >= leaf_count or
                    (query_index != 0 and
                        tree_queries[query_index - 1] >= query))
                {
                    return error.InvalidQueryLayout;
                }
            }

            var accounted: usize = 0;
            try appendSection(
                &ranges,
                allocator,
                tree.query_offset,
                tree.query_count,
                unique_end,
                used,
                &accounted,
            );
            try appendSection(
                &ranges,
                allocator,
                tree.values_offset,
                tree.values_count,
                unique_end,
                used,
                &accounted,
            );
            try appendScaledSection(
                &ranges,
                allocator,
                tree.fri_witness_offset,
                tree.fri_witness_count,
                secure_words,
                unique_end,
                used,
                &accounted,
            );
            try appendScaledSection(
                &ranges,
                allocator,
                tree.hash_witness_offset,
                tree.hash_witness_count,
                hash_words,
                unique_end,
                used,
                &accounted,
            );
            try appendScaledSection(
                &ranges,
                allocator,
                tree.aux_offset,
                tree.aux_count,
                aux_node_words,
                unique_end,
                used,
                &accounted,
            );
            try appendScaledSection(
                &ranges,
                allocator,
                tree.all_values_offset,
                tree.all_values_count,
                indexed_secure_words,
                unique_end,
                used,
                &accounted,
            );
            if (accounted != tree.used_words)
                return error.InvalidTreeMetadata;
        }

        std.mem.sort(Range, ranges.items, {}, Range.lessThan);
        var cursor = unique_end;
        for (ranges.items) |range| {
            if (range.start != cursor) return error.NonCanonicalLayout;
            cursor = range.end;
        }
        if (cursor != used) return error.NonCanonicalLayout;

        return .{
            .storage = storage,
            .owns_storage = owns_storage,
            .used_words = used,
            .raw_query_offset = raw_offset,
            .raw_query_count = raw_count,
            .unique_query_offset = unique_offset,
            .unique_query_count = unique_count,
            .trees = trees,
        };
    }

    pub fn deinit(self: *Bundle, allocator: std.mem.Allocator) void {
        allocator.free(self.trees);
        if (self.owns_storage) allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn words(self: Bundle) []const u32 {
        return self.storage[0..self.used_words];
    }

    pub fn rawQueries(self: Bundle) []const u32 {
        return self.storage[self.raw_query_offset .. self.raw_query_offset + self.raw_query_count];
    }

    pub fn uniqueQueries(self: Bundle) []const u32 {
        return self.storage[self.unique_query_offset .. self.unique_query_offset + self.unique_query_count];
    }

    pub fn section(
        self: Bundle,
        offset: usize,
        count: usize,
    ) Error![]const u32 {
        if (count == 0 and offset == 0) return &.{};
        const end = try sectionEnd(offset, count, self.used_words);
        return self.storage[offset..end];
    }
};

const Range = struct {
    start: usize,
    end: usize,

    fn lessThan(_: void, lhs: Range, rhs: Range) bool {
        return lhs.start < rhs.start;
    }
};

fn appendScaledSection(
    ranges: *std.ArrayList(Range),
    allocator: std.mem.Allocator,
    offset: usize,
    count: usize,
    words_per_item: usize,
    payload_start: usize,
    used: usize,
    accounted: *usize,
) (std.mem.Allocator.Error || Error)!void {
    const words = std.math.mul(usize, count, words_per_item) catch
        return error.SizeOverflow;
    return appendSection(
        ranges,
        allocator,
        offset,
        words,
        payload_start,
        used,
        accounted,
    );
}

fn appendSection(
    ranges: *std.ArrayList(Range),
    allocator: std.mem.Allocator,
    offset: usize,
    count: usize,
    payload_start: usize,
    used: usize,
    accounted: *usize,
) (std.mem.Allocator.Error || Error)!void {
    if (count == 0) {
        if (offset != 0) return error.NonCanonicalLayout;
        return;
    }
    if (offset < payload_start) return error.InvalidSectionRange;
    const end = try sectionEnd(offset, count, used);
    accounted.* = std.math.add(usize, accounted.*, count) catch
        return error.SizeOverflow;
    try ranges.append(allocator, .{ .start = offset, .end = end });
}

fn sectionEnd(offset: usize, count: usize, used: usize) Error!usize {
    const end = std.math.add(usize, offset, count) catch
        return error.SizeOverflow;
    if (end > used) return error.InvalidSectionRange;
    return end;
}

fn containsSorted(values: []const u32, needle: u32) bool {
    var low: usize = 0;
    var high = values.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (values[middle] < needle) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low < values.len and values[low] == needle;
}

fn containsUnsorted(values: []const u32, needle: u32) bool {
    for (values) |value| {
        if (value == needle) return true;
    }
    return false;
}

test "compact decommit bundle is canonical and retains allocation extent" {
    const allocator = std.testing.allocator;
    const tree_count = 1;
    const raw = [_]u32{ 7, 3, 7, 1 };
    const unique = [_]u32{ 1, 3, 7 };
    const raw_offset = header_words + tree_count * tree_meta_words;
    const unique_offset = raw_offset + raw.len;
    const query_offset = unique_offset + unique.len;
    const values_offset = query_offset + unique.len;
    const hash_offset = values_offset + 2 * unique.len;
    const aux_offset = hash_offset + hash_words;
    const used = aux_offset + aux_node_words;
    const storage = try allocator.alloc(u32, used + 11);
    @memset(storage, 0);
    storage[0..header_words].* = .{
        magic,
        version,
        tree_count,
        raw.len,
        unique.len,
        raw_offset,
        unique_offset,
        used,
    };
    const meta = storage[header_words..][0..tree_meta_words];
    meta.* = .{
        @intFromEnum(TreeKind.trace),
        1,
        query_offset,
        unique.len,
        values_offset,
        2 * unique.len,
        0,
        0,
        hash_offset,
        1,
        aux_offset,
        1,
        0,
        0,
        5,
        unique.len + 2 * unique.len + hash_words + aux_node_words,
    };
    @memcpy(storage[raw_offset..unique_offset], &raw);
    @memcpy(storage[unique_offset..query_offset], &unique);
    @memcpy(storage[query_offset..values_offset], &unique);

    var bundle = try Bundle.decodeOwned(allocator, storage);
    defer bundle.deinit(allocator);
    try std.testing.expectEqual(used, bundle.words().len);
    try std.testing.expectEqualSlices(u32, &raw, bundle.rawQueries());
    try std.testing.expectEqualSlices(u32, &unique, bundle.uniqueQueries());
    try std.testing.expectEqual(TreeKind.trace, bundle.trees[0].kind);
}

test "compact decommit bundle rejects overlap and malformed query sets" {
    const allocator = std.testing.allocator;
    const make = struct {
        fn bundle(alloc: std.mem.Allocator) ![]u32 {
            const storage = try alloc.alloc(u32, 28);
            @memset(storage, 0);
            storage[0..header_words].* = .{
                magic,
                version,
                1,
                2,
                2,
                24,
                26,
                28,
            };
            storage[header_words + 15] = 1;
            storage[header_words + 14] = 2;
            storage[24..28].* = .{ 1, 2, 1, 2 };
            return storage;
        }
    }.bundle;

    {
        const storage = try make(allocator);
        storage[26] = 2;
        storage[27] = 1;
        try std.testing.expectError(
            error.InvalidQueryLayout,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try make(allocator);
        storage[24] = 1;
        storage[25] = 1;
        storage[26] = 1;
        storage[27] = 2;
        try std.testing.expectError(
            error.InvalidQueryLayout,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try make(allocator);
        storage[header_words + 2] = 24;
        storage[header_words + 3] = 1;
        try std.testing.expectError(
            error.InvalidSectionRange,
            Bundle.decodeOwned(allocator, storage),
        );
    }
}
