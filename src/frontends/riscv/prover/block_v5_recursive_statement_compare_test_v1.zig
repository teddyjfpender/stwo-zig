//! Original recording parity and exact-frame mutations only. No proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Frames = @import("../recursion/air/block_v5_recursive_statement_frames_v1.zig");
const Compare = @import("../recursion/air/block_v5_recursive_statement_compare_v1.zig");
const offsets = Compare.Offsets{ .sealed_offset = 0, .roots_offset = @splat(0) };
const limits = Compare.Limits{ .max_words = 1024, .max_felts = 8, .max_steps = 128 };
const Mode = enum { normal, omit_empty, split_words, wrong_root_type, wrong_integer_type, extra_empty };

const Emission = struct {
    header: [4]u32 = .{ 0, 0xffff_ffff, 0x8000_0000, 0x7fff_ffff },
    root: [32]u8 = [_]u8{ 0, 255, 128, 127 } ++ ([_]u8{211} ** 28),
    integer: u64 = 0xfedc_ba98_7654_3210,
    fields: [3]Q = .{ Q.fromU32Unchecked(1, 2, 3, 4), Q.fromU32Unchecked(5, 6, 7, 8), Q.fromU32Unchecked(9, 10, 11, 12) },
    mode: Mode = .normal,
    pub fn mix(self: @This(), channel: anytype) !void {
        if (self.mode != .omit_empty) channel.mixU32s(&.{});
        if (self.mode == .split_words) {
            channel.mixU32s(self.header[0..2]);
            channel.mixU32s(self.header[2..]);
        } else channel.mixU32s(&self.header);
        if (self.mode == .wrong_root_type) {
            var words: [8]u32 = undefined;
            for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, self.root[4 * index ..][0..4], .little);
            channel.mixU32s(&words);
        } else channel.mixRoot(self.root);
        if (self.mode == .wrong_integer_type)
            channel.mixU32s(&.{ @as(u32, @truncate(self.integer)), @as(u32, @truncate(self.integer >> 32)) })
        else
            channel.mixU64(self.integer);
        channel.mixFelts(self.fields[0..2]);
        channel.mixU32s(&.{ 19, 23 });
        channel.mixFelts(&.{});
        channel.mixRoot([_]u8{97} ** 32);
        channel.mixU32s(&.{29});
        channel.mixFelts(self.fields[2..]);
        if (self.mode == .extra_empty) channel.mixU32s(&.{});
    }
};

fn record(a: std.mem.Allocator, emission: Emission) !Frames.Statement {
    var builder = Frames.Builder{ .allocator = a, .max_words = limits.max_words, .max_felts = limits.max_felts };
    defer builder.deinit();
    try emission.mix(&builder);
    try builder.check();
    const words = try builder.data.toOwnedSlice(a);
    errdefer a.free(words);
    const fields = try builder.fields.toOwnedSlice(a);
    errdefer a.free(fields);
    const steps = try builder.steps.toOwnedSlice(a);
    errdefer a.free(steps);
    const claims = try a.alloc(Frames.Step, 0);
    return .{ .allocator = a, .words = words, .felts = fields, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) };
}
fn compare(frame: *const Frames.Statement) !void {
    try Compare.compareFirst(frame, limits, offsets, Emission{});
}

test "recursive statement compare: original Builder replay and PUBLIC21 VERSION20 framing oracles match exactly" {
    const a = std.testing.allocator;
    var frame = try record(a, .{});
    defer frame.deinit();
    try compare(&frame);
    var cursor = try Compare.Comparator.initFirst(&frame, limits, offsets);
    try frame.replay(&cursor, frame.first);
    try cursor.finish();
    var public = try @import("../recursion/block_v5_requester_public_source_v1.zig").testing.recordFrame(a, Emission{}, .{ .max_words = limits.max_words, .max_felts = limits.max_felts, .max_steps = limits.max_steps });
    defer public.deinit();
    try compare(&public);
    var memory = try @import("../recursion/block_v5_source_ram_forest_join_source_v1.zig").testing.recordFrame(a, Emission{}, .{ .max_words = limits.max_words, .max_steps = limits.max_steps });
    defer memory.deinit();
    try compare(&memory);
    try std.testing.expectEqualDeep(frame.first, public.first);
    try std.testing.expectEqualDeep(frame.first, memory.first);
    const public_coordinate = try @import("../recursion/block_v5_requester_public_source_v1.zig").testing.transitionCoordinate(&public);
    const memory_coordinate = try @import("../recursion/block_v5_source_ram_forest_join_source_v1.zig").testing.transitionCoordinate(&memory);
    try std.testing.expectEqual(public_coordinate, memory_coordinate);
}

test "recursive statement compare: every raw word and field limb mutation rejects without reduction" {
    var frame = try record(std.testing.allocator, .{});
    defer frame.deinit();
    for (frame.words) |*word| {
        const original = word.*;
        word.* ^= 1;
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
        word.* = original;
    }
    for (frame.felts) |*value| {
        const original = value.*;
        for (0..4) |limb| {
            var words = original.toM31Array();
            words[limb].v += 1;
            value.* = Q.fromM31Array(words);
            try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
            value.* = original;
        }
    }
    try compare(&frame);
    // Field arrays on BOTH sides must be canonical. Equal noncanonical
    // representations cannot pass even when the original bytes match.
    var invalid = Emission{};
    invalid.fields[0].c0.a.v = core.fields.m31.Modulus;
    frame.felts[0] = invalid.fields[0];
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, Compare.compareFirst(&frame, limits, offsets, invalid));
}

test "recursive statement compare: every operation tag offset and span length mutation rejects before slicing" {
    var frame = try record(std.testing.allocator, .{});
    defer frame.deinit();
    for (frame.first) |*step| {
        const original = step.*;
        step.* = switch (original) {
            .words => |span| .{ .felts = span },
            .felts => |span| .{ .words = span },
            .root => |first| .{ .integer = first },
            .integer => |first| .{ .root = first },
        };
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
        step.* = switch (original) {
            .words => |span| .{ .words = .{ .first = std.math.maxInt(u32), .len = span.len } },
            .felts => |span| .{ .felts = .{ .first = std.math.maxInt(u32), .len = span.len } },
            .root => .{ .root = std.math.maxInt(u32) },
            .integer => .{ .integer = std.math.maxInt(u32) },
        };
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
        switch (original) {
            .words => |span| {
                step.* = .{ .words = .{ .first = span.first, .len = std.math.maxInt(u32) } };
                try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
            },
            .felts => |span| {
                step.* = .{ .felts = .{ .first = span.first, .len = std.math.maxInt(u32) } };
                try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
            },
            else => {},
        }
        step.* = original;
    }
    const saved_step = frame.first[1];
    frame.first[1] = frame.first[2];
    frame.first[2] = saved_step;
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&frame));
}

test "recursive statement compare: identical payload regrouping root integer alias and empty-call changes reject" {
    var frame = try record(std.testing.allocator, .{});
    defer frame.deinit();
    inline for (.{ Mode.omit_empty, Mode.split_words, Mode.wrong_root_type, Mode.wrong_integer_type, Mode.extra_empty }) |mode| {
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, Compare.compareFirst(&frame, limits, offsets, Emission{ .mode = mode }));
    }
}

test "recursive statement compare: every truncated inventory and unused words felts steps or claims rejects" {
    const a = std.testing.allocator;
    var frame = try record(a, .{});
    defer frame.deinit();
    for (0..frame.words.len) |length| {
        var altered = frame;
        altered.words = frame.words[0..length];
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    }
    for (0..frame.felts.len) |length| {
        var altered = frame;
        altered.felts = frame.felts[0..length];
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    }
    for (0..frame.first.len) |length| {
        var altered = frame;
        altered.first = frame.first[0..length];
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    }
    const extra_words = try a.alloc(u32, frame.words.len + 1);
    defer a.free(extra_words);
    @memcpy(extra_words[0..frame.words.len], frame.words);
    extra_words[frame.words.len] = 0;
    var altered = frame;
    altered.words = extra_words;
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    const extra_felts = try a.alloc(Q, frame.felts.len + 1);
    defer a.free(extra_felts);
    @memcpy(extra_felts[0..frame.felts.len], frame.felts);
    extra_felts[frame.felts.len] = Q.zero();
    altered = frame;
    altered.felts = extra_felts;
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    const extra_steps = try a.alloc(Frames.Step, frame.first.len + 1);
    defer a.free(extra_steps);
    @memcpy(extra_steps[0..frame.first.len], frame.first);
    extra_steps[frame.first.len] = .{ .words = .{ .first = @intCast(frame.words.len), .len = 0 } };
    altered = frame;
    altered.first = extra_steps;
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    altered = frame;
    altered.claims = frame.first[0..1];
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
}

test "recursive statement compare: independently supplied auxiliary offsets and all limits remain strict" {
    var frame = try record(std.testing.allocator, .{});
    defer frame.deinit();
    var altered = frame;
    altered.sealed_offset = 1;
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    for (0..3) |index| {
        altered = frame;
        altered.roots_offset[index] = 1;
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, compare(&altered));
    }
    try std.testing.expectError(error.RecursiveStatementFrameLimit, Compare.Comparator.initFirst(&frame, .{ .max_words = frame.words.len - 1 }, offsets));
    try std.testing.expectError(error.RecursiveStatementFrameLimit, Compare.Comparator.initFirst(&frame, .{ .max_felts = frame.felts.len - 1 }, offsets));
    try std.testing.expectError(error.RecursiveStatementFrameLimit, Compare.Comparator.initFirst(&frame, .{ .max_steps = frame.first.len - 1 }, offsets));
    inline for (.{ "max_words", "max_felts", "max_steps" }) |field| {
        var zero = limits;
        @field(zero, field) = 0;
        try std.testing.expectError(error.RecursiveStatementFrameLimit, Compare.Comparator.initFirst(&frame, zero, offsets));
    }
    try Compare.compareFirst(&frame, .{ .max_words = frame.words.len, .max_felts = frame.felts.len, .max_steps = frame.first.len }, offsets, Emission{});
}

test "recursive statement compare: bounded admission precedes invalid borrowed storage and cursor errors stay poisoned" {
    var invalid: Frames.Statement = undefined;
    invalid.words = @as([*]u32, @ptrFromInt(@alignOf(u32)))[0..1025];
    invalid.felts = &.{};
    invalid.first = &.{};
    invalid.claims = &.{};
    try std.testing.expectError(error.RecursiveStatementFrameLimit, Compare.Comparator.initFirst(&invalid, limits, offsets));
    var frame = try record(std.testing.allocator, .{});
    defer frame.deinit();
    var cursor = try Compare.Comparator.initFirst(&frame, limits, offsets);
    cursor.mixU64(0); // The original first operation is empty words.
    try (Emission{}).mix(&cursor);
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, cursor.check());
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, cursor.finish());
    const Rejected = struct {
        pub fn mix(_: @This(), channel: anytype) !void {
            channel.mixU32s(&.{});
            return error.OriginalAdmissionRejected;
        }
    };
    try std.testing.expectError(error.OriginalAdmissionRejected, Compare.compareFirst(&frame, limits, offsets, Rejected{}));
}

test "recursive statement compare: repeated comparison uses no allocator and eighty root operations have no fixed root cap" {
    var frame = try record(std.testing.allocator, .{});
    const original_allocator = frame.allocator;
    frame.allocator = std.testing.failing_allocator;
    defer {
        frame.allocator = original_allocator;
        frame.deinit();
    }
    for (0..100) |_| try compare(&frame);
    const Repeated = struct {
        pub fn mix(_: @This(), channel: anytype) !void {
            for (0..80) |_| channel.mixRoot([_]u8{53} ** 32);
        }
    };
    var words: [640]u32 = @splat(0x3535_3535);
    var steps: [80]Frames.Step = undefined;
    for (&steps, 0..) |*step, index| step.* = .{ .root = @intCast(8 * index) };
    const many = Frames.Statement{ .allocator = std.testing.failing_allocator, .words = &words, .felts = &.{}, .first = &steps, .claims = &.{}, .sealed_offset = 0, .roots_offset = @splat(0) };
    try Compare.compareFirst(&many, limits, offsets, Repeated{});
}
