//! Descriptor-driven one-read resident proof bundle.

const std = @import("std");

pub const Error = error{
    GeometryOverflow,
    UnsupportedProtocol,
};

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

    pub fn endWords(self: Section) Error!usize {
        return add(self.offset_words, self.words);
    }
};

/// `Descriptor` owns only frontend statement encoding and exact cardinalities:
///
/// - `sectionLengths(logical, decommit) -> [section_count]usize`
/// - `fixedHeader(logical, decommit, total_words) -> [fixed_header_words]u32`
///
/// The common layer owns gapless layout, section records, the poison degree
/// verdict, total bounds, and validation.
pub fn BundleFor(
    comptime Layout: type,
    comptime Decommit: type,
    comptime Descriptor: type,
) type {
    comptime {
        if (!@hasDecl(Descriptor, "sectionLengths") or
            !@hasDecl(Descriptor, "fixedHeader"))
        {
            @compileError(
                "proof bundle descriptor requires sectionLengths and fixedHeader",
            );
        }
    }
    return struct {
        const Self = @This();

        sections: [section_count]Section,
        static_header: []u32,
        total_words: usize,

        pub fn init(
            allocator: std.mem.Allocator,
            logical: Layout,
            decommit: Decommit,
        ) !Self {
            const lengths = try Descriptor.sectionLengths(
                logical,
                decommit,
            );
            var sections: [section_count]Section = undefined;
            var cursor = header_words;
            inline for (std.meta.fields(SectionKind), 0..) |field, index| {
                if (lengths[index] == 0)
                    return error.UnsupportedProtocol;
                const kind: SectionKind = @enumFromInt(field.value);
                sections[index] = .{
                    .kind = kind,
                    .offset_words = cursor,
                    .words = lengths[index],
                };
                cursor = try add(cursor, lengths[index]);
            }
            _ = std.math.cast(u32, cursor) orelse
                return error.GeometryOverflow;

            const fixed = try Descriptor.fixedHeader(
                logical,
                decommit,
                cursor,
            );
            try validateFixed(fixed, cursor);
            const header = try allocator.alloc(u32, header_words);
            errdefer allocator.free(header);
            @memcpy(header[0..fixed_header_words], &fixed);
            for (sections, 0..) |bundle_section, index| {
                const base =
                    fixed_header_words + index * section_record_words;
                header[base] = @intFromEnum(bundle_section.kind);
                header[base + 1] = try u32Count(
                    bundle_section.offset_words,
                );
                header[base + 2] = try u32Count(bundle_section.words);
            }
            return .{
                .sections = sections,
                .static_header = header,
                .total_words = cursor,
            };
        }

        pub fn deinit(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            allocator.free(self.static_header);
            self.* = undefined;
        }

        pub fn section(self: Self, kind: SectionKind) Section {
            return self.sections[@intFromEnum(kind) - 1];
        }

        pub fn validate(
            self: Self,
            decommit_words: usize,
        ) !void {
            if (self.static_header.len != header_words)
                return error.UnsupportedProtocol;
            var fixed: [fixed_header_words]u32 = undefined;
            @memcpy(&fixed, self.static_header[0..fixed_header_words]);
            try validateFixed(fixed, self.total_words);

            var cursor = header_words;
            for (self.sections, 0..) |entry, index| {
                if (entry.offset_words != cursor or entry.words == 0)
                    return error.UnsupportedProtocol;
                const base =
                    fixed_header_words + index * section_record_words;
                if (self.static_header[base] != @intFromEnum(entry.kind) or
                    self.static_header[base + 1] !=
                        try u32Count(entry.offset_words) or
                    self.static_header[base + 2] !=
                        try u32Count(entry.words))
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
}

fn validateFixed(
    fixed: [fixed_header_words]u32,
    total_words: usize,
) Error!void {
    if (fixed[0] != magic or
        fixed[1] != version or
        fixed[2] != try u32Count(total_words) or
        fixed[3] != section_count or
        fixed[15] != std.math.maxInt(u32))
    {
        return error.UnsupportedProtocol;
    }
}

pub fn u32Count(value: anytype) Error!u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

pub fn pow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn add(left: anytype, right: anytype) Error!usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch error.GeometryOverflow;
}

pub fn mul(left: anytype, right: anytype) Error!usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

test "descriptor cannot create a gap or omit a proof section" {
    const Layout = struct { marker: u32 };
    const Decommit = struct { assembly_words: usize };
    const Descriptor = struct {
        pub fn sectionLengths(
            _: Layout,
            decommit: Decommit,
        ) ![section_count]usize {
            return .{ 8, 4, 8, 4, 2, decommit.assembly_words };
        }
        pub fn fixedHeader(
            _: Layout,
            _: Decommit,
            total_words: usize,
        ) ![fixed_header_words]u32 {
            var header = [_]u32{0} ** fixed_header_words;
            header[0] = magic;
            header[1] = version;
            header[2] = try u32Count(total_words);
            header[3] = section_count;
            header[15] = std.math.maxInt(u32);
            return header;
        }
    };
    const Bundle = BundleFor(Layout, Decommit, Descriptor);
    var bundle = try Bundle.init(
        std.testing.allocator,
        .{ .marker = 7 },
        .{ .assembly_words = 11 },
    );
    defer bundle.deinit(std.testing.allocator);
    try bundle.validate(11);
    try std.testing.expectEqual(
        bundle.total_words,
        try bundle.section(.decommitment).endWords(),
    );

    bundle.sections[2].offset_words += 1;
    try std.testing.expectError(
        error.UnsupportedProtocol,
        bundle.validate(11),
    );
}
