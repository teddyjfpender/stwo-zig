//! Strict decoder for the sole device-to-host STARK proof result.
//!
//! This is the runtime counterpart of the Native CUDA SWPC v1 layout. It
//! owns the complete host allocation; the nested decommitment is a borrowed
//! view, so no resident arena address survives proof-session teardown.

const std = @import("std");
const decommit_bundle = @import("decommit_bundle.zig");

pub const magic: u32 = 0x4350_5753;
pub const version: u32 = 1;
pub const fixed_header_words: usize = 16;
pub const section_record_words: usize = 3;
pub const hash_words: usize = 8;
pub const secure_words: usize = 4;
pub const nonce_words: usize = 2;

pub const max_bundle_words: usize = 16 * 1024 * 1024;
pub const max_commitment_roots: usize = 256;
pub const max_sampled_values: usize = 1024 * 1024;
pub const max_statement_width: usize = max_sampled_values;
pub const max_fri_roots: usize = 64;
pub const max_last_layer_log: u32 = 20;

pub const Error = error{
    InvalidHeader,
    InvalidUsedWords,
    InvalidProtocolCounts,
    InvalidSection,
    InvalidNestedDecommitment,
    NonCanonicalLayout,
    PoisonedDegreeVerdict,
    SizeOverflow,
};

pub const SectionKind = enum(u32) {
    trace_commitments = 1,
    sampled_values = 2,
    fri_commitments = 3,
    fri_last_layer = 4,
    proof_of_work = 5,
    decommitment = 6,
};

pub const section_count: usize = @typeInfo(SectionKind).@"enum".fields.len;
pub const header_words: usize =
    fixed_header_words + section_count * section_record_words;

pub const Section = struct {
    kind: SectionKind,
    offset_words: usize,
    words: usize,
};

pub const Protocol = struct {
    log_n_rows: u32,
    sequence_len: u32,
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    fold_step: u32,
    lifting_log_size: ?u32,
    commitment_root_count: u32,
    fri_root_count: u32,
    decommit_tree_count: u32,
};

pub const Bundle = struct {
    storage: []u32,
    sections: [section_count]Section,
    protocol: Protocol,
    decommitment: decommit_bundle.Bundle,

    pub fn decodeOwned(
        allocator: std.mem.Allocator,
        storage: []u32,
    ) (std.mem.Allocator.Error || Error)!Bundle {
        errdefer allocator.free(storage);
        if (storage.len < header_words or storage.len > max_bundle_words or
            storage[0] != magic or storage[1] != version or
            storage[2] != storage.len or storage[3] != section_count)
        {
            return error.InvalidHeader;
        }
        if (storage[15] != 0) return error.PoisonedDegreeVerdict;

        const protocol = try decodeProtocol(storage[0..fixed_header_words]);
        var sections: [section_count]Section = undefined;
        var cursor = header_words;
        inline for (std.meta.fields(SectionKind), 0..) |field, index| {
            const base = fixed_header_words + index * section_record_words;
            const expected_kind: SectionKind = @enumFromInt(field.value);
            if (storage[base] != @intFromEnum(expected_kind))
                return error.NonCanonicalLayout;
            const offset: usize = storage[base + 1];
            const word_count: usize = storage[base + 2];
            if (word_count == 0 or offset != cursor)
                return error.NonCanonicalLayout;
            cursor = try sectionEnd(offset, word_count, storage.len);
            sections[index] = .{
                .kind = expected_kind,
                .offset_words = offset,
                .words = word_count,
            };
        }
        if (cursor != storage.len) return error.InvalidUsedWords;

        try validateCounts(protocol, sections);
        const nested_section = sections[indexOf(.decommitment)];
        const nested_words = storage[nested_section.offset_words .. nested_section.offset_words + nested_section.words];
        var nested = decommit_bundle.Bundle.decodeBorrowed(
            allocator,
            nested_words,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidNestedDecommitment,
        };
        errdefer nested.deinit(allocator);
        if (nested.used_words != nested_words.len or
            nested.trees.len != protocol.decommit_tree_count or
            nested.raw_query_count != protocol.n_queries)
        {
            return error.InvalidNestedDecommitment;
        }
        return .{
            .storage = storage,
            .sections = sections,
            .protocol = protocol,
            .decommitment = nested,
        };
    }

    pub fn deinit(self: *Bundle, allocator: std.mem.Allocator) void {
        self.decommitment.deinit(allocator);
        allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn words(self: Bundle, kind: SectionKind) []const u32 {
        const section = self.sections[indexOf(kind)];
        return self.storage[section.offset_words .. section.offset_words + section.words];
    }

    pub fn commitmentRoots(self: Bundle) []const u32 {
        return self.words(.trace_commitments);
    }

    pub fn sampledValues(self: Bundle) []const u32 {
        return self.words(.sampled_values);
    }

    pub fn friRoots(self: Bundle) []const u32 {
        return self.words(.fri_commitments);
    }

    pub fn lastLayerPolynomial(self: Bundle) []const u32 {
        return self.words(.fri_last_layer);
    }

    pub fn powNonce(self: Bundle) u64 {
        const nonce = self.words(.proof_of_work);
        return @as(u64, nonce[0]) | (@as(u64, nonce[1]) << 32);
    }
};

fn decodeProtocol(header: []const u32) Error!Protocol {
    const lifting = if (header[11] == std.math.maxInt(u32))
        null
    else
        header[11];
    if (header[4] < 3 or header[4] >= 31 or
        header[5] < 2 or header[5] > max_statement_width or
        header[6] > 32 or header[7] > 30 - header[4] or
        header[8] > max_last_layer_log or header[8] > header[4] or
        header[9] == 0 or header[9] > decommit_bundle.max_protocol_queries or
        header[10] == 0 or header[10] > 8 or
        (lifting != null and lifting.? > header[4]) or
        header[12] == 0 or header[12] > max_commitment_roots or
        header[13] == 0 or header[13] > max_fri_roots or
        header[14] == 0 or header[14] > decommit_bundle.max_tree_count)
    {
        return error.InvalidProtocolCounts;
    }
    return .{
        .log_n_rows = header[4],
        .sequence_len = header[5],
        .pow_bits = header[6],
        .log_blowup_factor = header[7],
        .log_last_layer_degree_bound = header[8],
        .n_queries = header[9],
        .fold_step = header[10],
        .lifting_log_size = lifting,
        .commitment_root_count = header[12],
        .fri_root_count = header[13],
        .decommit_tree_count = header[14],
    };
}

fn validateCounts(
    protocol: Protocol,
    sections: [section_count]Section,
) Error!void {
    try expectWords(
        sections[indexOf(.trace_commitments)].words,
        protocol.commitment_root_count,
        hash_words,
        max_commitment_roots,
    );
    const samples = sections[indexOf(.sampled_values)].words;
    if (samples % secure_words != 0 or samples / secure_words == 0 or
        samples / secure_words > max_sampled_values)
    {
        return error.InvalidProtocolCounts;
    }
    try expectWords(
        sections[indexOf(.fri_commitments)].words,
        protocol.fri_root_count,
        hash_words,
        max_fri_roots,
    );
    const coefficient_count = std.math.shl(
        usize,
        1,
        protocol.log_last_layer_degree_bound,
    );
    try expectWords(
        sections[indexOf(.fri_last_layer)].words,
        coefficient_count,
        secure_words,
        @as(usize, 1) << @intCast(max_last_layer_log),
    );
    if (sections[indexOf(.proof_of_work)].words != nonce_words)
        return error.InvalidProtocolCounts;
}

fn expectWords(
    actual: usize,
    count: anytype,
    words_per_item: usize,
    maximum_count: usize,
) Error!void {
    const item_count = std.math.cast(usize, count) orelse
        return error.SizeOverflow;
    if (item_count == 0 or item_count > maximum_count)
        return error.InvalidProtocolCounts;
    const expected = std.math.mul(usize, item_count, words_per_item) catch
        return error.SizeOverflow;
    if (actual != expected) return error.InvalidProtocolCounts;
}

fn sectionEnd(offset: usize, words: usize, used: usize) Error!usize {
    const end = std.math.add(usize, offset, words) catch
        return error.SizeOverflow;
    if (offset < header_words or end > used) return error.InvalidSection;
    return end;
}

fn indexOf(kind: SectionKind) usize {
    return @intFromEnum(kind) - 1;
}

const Fixture = struct {
    fn make(
        allocator: std.mem.Allocator,
        log_n_rows: u32,
        sequence_len: u32,
    ) ![]u32 {
        const query_count: usize = 3;
        const tree_count: usize = 2 + log_n_rows;
        const nested_header = decommit_bundle.header_words +
            tree_count * decommit_bundle.tree_meta_words;
        const nested_used = nested_header + 2 * query_count +
            tree_count * query_count;
        const nested = try allocator.alloc(u32, nested_used);
        defer allocator.free(nested);
        @memset(nested, 0);
        nested[0..decommit_bundle.header_words].* = .{
            decommit_bundle.magic,
            decommit_bundle.version,
            @intCast(tree_count),
            query_count,
            query_count,
            @intCast(nested_header),
            @intCast(nested_header + query_count),
            @intCast(nested_used),
        };
        const raw_offset = nested_header;
        const unique_offset = raw_offset + query_count;
        const queries = [_]u32{ 0, 1, 2 };
        @memcpy(nested[raw_offset .. raw_offset + query_count], &queries);
        @memcpy(
            nested[unique_offset .. unique_offset + query_count],
            &queries,
        );
        var cursor = unique_offset + query_count;
        for (0..tree_count) |tree_index| {
            const base = decommit_bundle.header_words +
                tree_index * decommit_bundle.tree_meta_words;
            const meta = nested[base..][0..decommit_bundle.tree_meta_words];
            meta[0] = @intFromEnum(if (tree_index < 2)
                decommit_bundle.TreeKind.trace
            else
                decommit_bundle.TreeKind.fri);
            meta[1] = @intCast(tree_index);
            meta[2] = @intCast(cursor);
            meta[3] = query_count;
            meta[14] = log_n_rows;
            meta[15] = query_count;
            @memcpy(nested[cursor .. cursor + query_count], &queries);
            cursor += query_count;
        }

        const lengths = [_]usize{
            3 * hash_words,
            (@as(usize, sequence_len) + 8) * secure_words,
            @as(usize, log_n_rows) * hash_words,
            secure_words,
            nonce_words,
            nested_used,
        };
        var total = header_words;
        for (lengths) |length| total += length;
        const storage = try allocator.alloc(u32, total);
        @memset(storage, 0);
        storage[0..fixed_header_words].* = .{
            magic,
            version,
            @intCast(total),
            section_count,
            log_n_rows,
            sequence_len,
            10,
            1,
            0,
            query_count,
            1,
            std.math.maxInt(u32),
            3,
            log_n_rows,
            @intCast(tree_count),
            0,
        };
        cursor = header_words;
        inline for (std.meta.fields(SectionKind), 0..) |field, index| {
            const base = fixed_header_words + index * section_record_words;
            storage[base] = field.value;
            storage[base + 1] = @intCast(cursor);
            storage[base + 2] = @intCast(lengths[index]);
            cursor += lengths[index];
        }
        @memcpy(storage[total - nested_used .. total], nested);
        return storage;
    }
};

test "SWPC v1 decodes wide Fibonacci capacities without arena state" {
    const allocator = std.testing.allocator;
    for ([_]struct { log: u32, width: u32 }{
        .{ .log = 5, .width = 8 },
        .{ .log = 14, .width = 100 },
        .{ .log = 22, .width = 128 },
    }) |shape| {
        var bundle = try Bundle.decodeOwned(
            allocator,
            try Fixture.make(allocator, shape.log, shape.width),
        );
        defer bundle.deinit(allocator);
        try std.testing.expectEqual(shape.log, bundle.protocol.log_n_rows);
        try std.testing.expectEqual(
            @as(usize, shape.width + 8),
            bundle.sampledValues().len / secure_words,
        );
        try std.testing.expectEqual(
            @as(usize, shape.log),
            bundle.friRoots().len / hash_words,
        );
        try std.testing.expectEqual(
            @as(usize, 2 + shape.log),
            bundle.decommitment.trees.len,
        );
    }
}

test "SWPC v1 rejects gaps counts truncation and poisoned degree verdict" {
    const allocator = std.testing.allocator;
    {
        const storage = try Fixture.make(allocator, 5, 8);
        storage[fixed_header_words + 1] += 1;
        try std.testing.expectError(
            error.NonCanonicalLayout,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try Fixture.make(allocator, 5, 8);
        storage[fixed_header_words + 1] -= 1;
        try std.testing.expectError(
            error.NonCanonicalLayout,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try Fixture.make(allocator, 5, 8);
        storage[12] += 1;
        try std.testing.expectError(
            error.InvalidProtocolCounts,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try Fixture.make(allocator, 5, 8);
        storage[2] -= 1;
        try std.testing.expectError(
            error.InvalidHeader,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try Fixture.make(allocator, 5, 8);
        storage[15] = 1;
        try std.testing.expectError(
            error.PoisonedDegreeVerdict,
            Bundle.decodeOwned(allocator, storage),
        );
    }
    {
        const storage = try Fixture.make(allocator, 5, 8);
        storage[14] += 1;
        try std.testing.expectError(
            error.InvalidNestedDecommitment,
            Bundle.decodeOwned(allocator, storage),
        );
    }
}
