//! Exact one-read resident proof-bundle topology.
//!
//! The compact decommitment is only one section. Trace/FRI roots, OODS values,
//! the last-layer polynomial, PoW nonce, and protocol identity must survive the
//! arena teardown as part of the same D2H result.

const std = @import("std");
const layout_mod = @import("layout.zig");
const request = @import("request.zig");
const topology = @import("topology.zig");

pub const magic: u32 = 0x4350_5753; // "SWPC", Stwo whole-proof container.
pub const version: u32 = 1;
pub const fixed_header_words: usize = 16;
pub const section_record_words: usize = 3;

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

    pub fn endWords(self: Section) request.Error!usize {
        return add(self.offset_words, self.words);
    }
};

pub const Bundle = struct {
    sections: [section_count]Section,
    static_header: []u32,
    total_words: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        logical: layout_mod.Layout,
        decommit: topology.Decommit,
    ) (std.mem.Allocator.Error || request.Error)!Bundle {
        const geometry = logical.geometry;
        const last_coefficients = try pow2(
            geometry.protocol.log_last_layer_degree_bound,
        );
        const lengths = [_]usize{
            try mul(geometry.committed_tree_count, 8),
            try mul(geometry.sampled_value_count, 4),
            try mul(geometry.fri_tree_count, 8),
            try mul(last_coefficients, 4),
            2,
            decommit.assembly_words,
        };
        var sections: [section_count]Section = undefined;
        var cursor = header_words;
        inline for (std.meta.fields(SectionKind), 0..) |field, index| {
            const kind: SectionKind = @enumFromInt(field.value);
            sections[index] = .{
                .kind = kind,
                .offset_words = cursor,
                .words = lengths[index],
            };
            cursor = try add(cursor, lengths[index]);
        }
        _ = std.math.cast(u32, cursor) orelse return error.GeometryOverflow;

        const header = try allocator.alloc(u32, header_words);
        errdefer allocator.free(header);
        @memset(header, 0);
        header[0] = magic;
        header[1] = version;
        header[2] = try u32Count(cursor);
        header[3] = section_count;
        header[4] = geometry.statement.log_n_rows;
        header[5] = geometry.statement.sequence_len;
        header[6] = geometry.protocol.pow_bits;
        header[7] = geometry.protocol.log_blowup_factor;
        header[8] = geometry.protocol.log_last_layer_degree_bound;
        header[9] = try u32Count(geometry.protocol.n_queries);
        header[10] = geometry.protocol.fold_step;
        header[11] = if (geometry.protocol.lifting_log_size) |value|
            value
        else
            std.math.maxInt(u32);
        header[12] = try u32Count(geometry.committed_tree_count);
        header[13] = try u32Count(geometry.fri_tree_count);
        header[14] = try u32Count(geometry.decommit_tree_count);
        // The resident finalizer must overwrite this with the GPU degree-check
        // result. Poisoning the template prevents a missing D2D copy from
        // masquerading as a successful degree check.
        header[15] = std.math.maxInt(u32);
        for (sections, 0..) |bundle_section, index| {
            const base = fixed_header_words + index * section_record_words;
            header[base] = @intFromEnum(bundle_section.kind);
            header[base + 1] = try u32Count(bundle_section.offset_words);
            header[base + 2] = try u32Count(bundle_section.words);
        }
        return .{
            .sections = sections,
            .static_header = header,
            .total_words = cursor,
        };
    }

    pub fn deinit(self: *Bundle, allocator: std.mem.Allocator) void {
        allocator.free(self.static_header);
        self.* = undefined;
    }

    pub fn section(self: Bundle, kind: SectionKind) Section {
        return self.sections[@intFromEnum(kind) - 1];
    }

    pub fn validate(self: Bundle, decommit_words: usize) request.Error!void {
        if (self.static_header.len != header_words or
            self.static_header[0] != magic or
            self.static_header[1] != version or
            self.static_header[2] != try u32Count(self.total_words) or
            self.static_header[3] != section_count or
            self.static_header[15] != std.math.maxInt(u32))
        {
            return error.UnsupportedProtocol;
        }
        var cursor = header_words;
        for (self.sections, 0..) |entry, index| {
            if (entry.offset_words != cursor or entry.words == 0)
                return error.UnsupportedProtocol;
            const base = fixed_header_words + index * section_record_words;
            if (self.static_header[base] != @intFromEnum(entry.kind) or
                self.static_header[base + 1] != try u32Count(entry.offset_words) or
                self.static_header[base + 2] != try u32Count(entry.words))
            {
                return error.UnsupportedProtocol;
            }
            cursor = try entry.endWords();
        }
        if (cursor != self.total_words or
            self.section(.decommitment).words != decommit_words)
        {
            return error.UnsupportedProtocol;
        }
    }
};

fn pow2(log_size: u32) request.Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn u32Count(value: anytype) request.Error!u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

fn add(left: anytype, right: anytype) request.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) request.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

test "whole-proof sections are exact gapless and retain non-opening material" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(.{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    var logical = try layout_mod.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var openings = try topology.Decommit.init(allocator, logical);
    defer openings.deinit(allocator);
    var bundle = try Bundle.init(allocator, logical, openings);
    defer bundle.deinit(allocator);
    try bundle.validate(openings.assembly_words);

    try std.testing.expectEqual(
        @as(usize, 3 * 8),
        bundle.section(.trace_commitments).words,
    );
    try std.testing.expectEqual(
        @as(usize, 108 * 4),
        bundle.section(.sampled_values).words,
    );
    try std.testing.expectEqual(
        @as(usize, 14 * 8),
        bundle.section(.fri_commitments).words,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        bundle.section(.fri_last_layer).words,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        bundle.section(.proof_of_work).words,
    );
    try std.testing.expectEqual(
        openings.assembly_words,
        bundle.section(.decommitment).words,
    );
    try std.testing.expectEqual(
        std.math.maxInt(u32),
        bundle.static_header[15],
    );
    try std.testing.expectEqual(
        bundle.total_words,
        try bundle.section(.decommitment).endWords(),
    );
}
