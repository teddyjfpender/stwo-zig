const std = @import("std");
const layout_mod = @import("segment_statement_v2_transcript_layout.zig");
const v2 = @import("segment_statement_v2.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const clocks = @import("ethereum_clock_routing_v1.zig");

test "V2 transcript layout exhaustively classifies every fixed and retained word" {
    for ([_][4]u32{ .{ 0, 0, 0, 0 }, .{ 1, 1, 1, 1 }, .{ 2, 0, 3, 1 } }) |counts| {
        const layout = try layout_mod.Layout.init(counts);
        var fixed_count: usize = 0;
        var geometry_count: usize = 0;
        var data_count: usize = 0;
        for (0..layout.wordCount()) |index| switch (try layout.word(index)) {
            .fixed => fixed_count += 1,
            .geometry => geometry_count += 1,
            .data => data_count += 1,
        };
        try std.testing.expectEqual(@as(usize, 8), fixed_count);
        try std.testing.expectEqual(@as(usize, 16), geometry_count);
        try std.testing.expectEqual(layout.wordCount() - 24, data_count);
        try std.testing.expectError(error.CanonicalLengthMismatch, layout.word(layout.wordCount()));
        try std.testing.expectError(error.CanonicalLengthMismatch, layout.word(std.math.maxInt(usize)));
        for (layout_mod.SECTIONS) |id| {
            const retained = layout.section(id);
            const tag = try layout.word(retained.payload_start - layout_mod.SECTION_HEADER_WORDS);
            try std.testing.expectEqualDeep(layout_mod.Word{ .fixed = @intFromEnum(id.tag()) }, tag);
            for (0..2) |limb| {
                const header_count = try layout.word(id.countHeaderIndex() + limb);
                const section_count = try layout.word(retained.payload_start - 2 + limb);
                try std.testing.expectEqualDeep(header_count, section_count);
                try std.testing.expectEqual(id, section_count.geometry.section);
            }
            for (0..retained.count) |entry| for (0..layout_mod.ENTRY_WORD_COUNT) |word| {
                const classified = (try layout.word(retained.payload_start + entry * layout_mod.ENTRY_WORD_COUNT + word)).data.retained;
                try std.testing.expectEqual(id, classified.section);
                try std.testing.expectEqual(@as(u32, @intCast(entry)), classified.entry);
                try std.testing.expectEqual(@as(u1, @intCast(word % 2)), classified.limb);
                const expected_field: layout_mod.RetainedField = if (word < 2) .address else switch (id) {
                    .entry_snapshot, .exit_snapshot => .value,
                    .entry_memory_clocks, .exit_memory_clocks => .clock,
                };
                try std.testing.expectEqual(expected_field, classified.field);
            };
        }
    }
}

test "V2 transcript layout retains existing span and register clock coordinates" {
    const layout = try layout_mod.Layout.init(.{ 0, 0, 0, 0 });
    for (0..412) |index| try std.testing.expectEqualDeep(layout_mod.Word{ .data = .{ .span_word = @intCast(index) } }, try layout.word(60 + index));
    for (0..clocks.WORD_COUNT) |index| {
        const raw = clocks.WIRE_START + index;
        const word = (try layout.word(raw)).data.register_clock;
        try std.testing.expectEqual(@as(usize, @intFromEnum(word.side)) * 64 + @as(usize, word.register) * 2 + word.limb, clocks.indexFromWire(raw).?);
    }
    for (4..60) |index| try std.testing.expect((try layout.word(index)) == .data);
    for (644..652) |index| try std.testing.expectEqualDeep(layout_mod.Word{ .data = .{ .completion = @enumFromInt(index - 644) } }, try layout.word(index));
    try std.testing.expectEqualDeep(layout_mod.Word{ .data = .{ .continuation_root = .{ .side = .entry, .limb = 0 } } }, try layout.word(482));
    try std.testing.expectEqualDeep(layout_mod.Word{ .data = .{ .continuation_root = .{ .side = .exit, .limb = 1 } } }, try layout.word(495));
}

test "V2 transcript layout validates bounded geometry without allocating payloads" {
    const max = v2.MAX_SPARSE_BOUNDARY_ENTRIES;
    const layout = try layout_mod.Layout.init(.{ max, max, max, max });
    try std.testing.expectEqual(@as(usize, v2.MIN_CANONICAL_WORDS) + @as(usize, max) * 16, layout.wordCount());
    try std.testing.expectEqual(@as(u16, 256), (try layout.word(v2.fixed_layout.entry_snapshot_count + 1)).geometry.value);
    try std.testing.expectEqual(@as(u32, max - 1), (try layout.word(layout.wordCount() - 1)).data.retained.entry);
    try std.testing.expectError(error.ExecutionRangeOutOfBounds, layout_mod.Layout.init(.{ max + 1, 0, 0, 0 }));
}

/// Called by the existing native adjacent-boundary fixture after canonical
/// authentication. Data words are checked against the actual decoded source;
/// no synthetic recording is promoted to authority by these tests.
pub fn expectNativeView(view: *const v2.CanonicalWireViewV2) !void {
    const layout = try layout_mod.Layout.fromView(view);
    for (view.words, 0..) |word, index| switch (try layout.word(index)) {
        .fixed => |value| try std.testing.expectEqual(value, word.toU32()),
        .geometry => |geometry| try std.testing.expectEqual(@as(u32, geometry.value), word.toU32()),
        .data => |data| switch (data) {
            .digest => |coordinate| {
                inline for (std.meta.fields(layout_mod.DigestField)) |field| {
                    if (@intFromEnum(coordinate.field) == field.value)
                        try std.testing.expectEqual(@field(view.statement, field.name)[coordinate.limb], word.toU32());
                }
            },
            .span_word => |offset| try std.testing.expectEqualDeep(view.statement.base_statement_words[offset], word),
            .continuation_root => |coordinate| {
                const value = if (coordinate.side == .entry) view.statement.entry_continuation_root else view.statement.exit_continuation_root;
                try expectLimb(value, coordinate.limb, word);
            },
            .register_clock => |coordinate| {
                const value = if (coordinate.side == .entry) view.statement.entry_register_clocks[coordinate.register] else view.statement.exit_register_clocks[coordinate.register];
                try expectLimb(value, coordinate.limb, word);
            },
            .completion => |field| {
                const expected: u32 = if (view.statement.completion) |completion| switch (field) {
                    .tag => @intFromEnum(v2.Tag.completion_present),
                    .kind => @intFromEnum(completion.kind),
                    .address_low => completion.address & 0xffff,
                    .address_high => completion.address >> 16,
                    .value_low => completion.value & 0xffff,
                    .value_high => completion.value >> 16,
                    .clock_low => completion.clock & 0xffff,
                    .clock_high => completion.clock >> 16,
                } else if (field == .tag) @intFromEnum(v2.Tag.completion_absent) else 0;
                try std.testing.expectEqual(expected, word.toU32());
            },
            .retained => |coordinate| {
                const section = layout.section(coordinate.section);
                const value = switch (coordinate.field) {
                    .address => view.sparseEntry(section, coordinate.entry).address,
                    .value => view.sparseEntry(section, coordinate.entry).value,
                    .clock => view.clockEntry(section, coordinate.entry).clock,
                };
                try expectLimb(value, coordinate.limb, word);
            },
        },
    };
    var malformed = view.*;
    malformed.entry_snapshot.payload_start += 1;
    try std.testing.expectError(error.RetainedBoundaryMismatch, layout_mod.Layout.fromView(&malformed));
    malformed = view.*;
    malformed.words = malformed.words[0 .. malformed.words.len - 1];
    try std.testing.expectError(error.RetainedBoundaryMismatch, layout_mod.Layout.fromView(&malformed));
}

fn expectLimb(value: u32, limb: u1, word: M31) !void {
    try std.testing.expectEqual(@as(u32, @as(u16, @truncate(value >> (@as(u5, limb) * 16)))), word.toU32());
}
