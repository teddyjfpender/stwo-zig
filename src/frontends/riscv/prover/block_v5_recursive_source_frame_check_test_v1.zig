//! Checks the exact frame function used by original Source.validate. Framing
//! proposals only: no fake Source, Fresh, policy acceptance or proof is minted.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Frames = @import("../recursion/air/block_v5_recursive_statement_frames_v1.zig");
const Public = @import("../recursion/block_v5_requester_public_source_v1.zig");
const Memory = @import("../recursion/block_v5_source_ram_forest_join_source_v1.zig");
const Kind = enum { public, memory };
fn Module(comptime kind: Kind) type {
    return if (kind == .public) Public else Memory;
}
fn Limits(comptime kind: Kind) Module(kind).Limits {
    return .{ .max_words = 2048, .max_steps = 256 };
}
fn limitError(comptime kind: Kind) anyerror {
    return if (kind == .public) error.RequesterPublicSourceLimit else error.SourceRamJoinSourceLimit;
}
fn layoutError(comptime kind: Kind) anyerror {
    return if (kind == .public) error.UntrustedRequesterPublicLayout else error.UntrustedSourceRamJoinLayout;
}
fn coordinateError(comptime kind: Kind) anyerror {
    return if (kind == .public) error.MutatedRequesterPublicSource else error.MutatedSourceRamJoinSource;
}
const Emission = struct {
    root_count: usize = 4,
    prefix_felts: usize = 2,
    final: enum { singleton, pair, words } = .singleton,
    pub fn mix(self: @This(), channel: anytype) !void {
        channel.mixU32s(&.{ 0x54455354, 0xffff_ffff });
        for (0..self.root_count) |index| {
            var root: [32]u8 = @splat(0x97);
            std.mem.writeInt(u32, root[0..4], @intCast(index), .little);
            channel.mixRoot(root);
        }
        channel.mixU64(0xabcd_ef01_8000_0001);
        const fields = [_]Q{ Q.fromU32Unchecked(1, 2, 3, 4), Q.fromU32Unchecked(5, 6, 7, 8), Q.fromU32Unchecked(9, 10, 11, 12) };
        channel.mixFelts(fields[0..self.prefix_felts]);
        switch (self.final) {
            .singleton => channel.mixFelts(fields[2..]),
            .pair => channel.mixFelts(fields[1..]),
            .words => channel.mixU32s(&.{17}),
        }
    }
};
fn record(comptime kind: Kind, a: std.mem.Allocator, emission: Emission) !Frames.Statement {
    return Module(kind).testing.recordFrame(a, emission, Limits(kind));
}
fn check(comptime kind: Kind, frame: *const Frames.Statement, coordinate: u32, emission: Emission) !void {
    try Module(kind).testing.checkFrame(frame, coordinate, emission, Limits(kind));
}
/// Original Builder oracle with no Source-specific layout admission. It is
/// used ONLY to demonstrate that exact byte parity cannot waive those guards.
fn looseRecord(a: std.mem.Allocator, emission: Emission) !Frames.Statement {
    var builder = Frames.Builder{ .allocator = a, .max_words = 2048, .max_felts = 8 };
    defer builder.deinit();
    try emission.mix(&builder);
    try builder.check();
    const words = try builder.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try builder.fields.toOwnedSlice(a);
    errdefer a.free(felts);
    const steps = try builder.steps.toOwnedSlice(a);
    errdefer a.free(steps);
    const claims = try a.alloc(Frames.Step, 0);
    return .{ .allocator = a, .words = words, .felts = felts, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) };
}

test "recursive source frame check: original PUBLIC21 VERSION20 recording matches repeated allocation-free validation" {
    inline for (.{ Kind.public, Kind.memory }) |kind| {
        var frame = try record(kind, std.testing.allocator, .{});
        const allocator = frame.allocator;
        frame.allocator = std.testing.failing_allocator;
        defer {
            frame.allocator = allocator;
            frame.deinit();
        }
        const coordinate = try Module(kind).testing.transitionCoordinate(&frame);
        try std.testing.expectEqual(@as(u32, @intCast(frame.words.len + 8)), coordinate);
        for (0..100) |_| try check(kind, &frame, coordinate, .{});
        try std.testing.expectError(coordinateError(kind), check(kind, &frame, coordinate + 1, .{}));
    }
}

test "recursive source frame check: original payload coordinate and canonical mutations reject through actual validation helper" {
    inline for (.{ Kind.public, Kind.memory }) |kind| {
        var frame = try record(kind, std.testing.allocator, .{});
        defer frame.deinit();
        const coordinate = try Module(kind).testing.transitionCoordinate(&frame);
        for (frame.words) |*word| {
            const original = word.*;
            word.* ^= 1;
            try std.testing.expectError(error.InvalidRecursiveStatementFrames, check(kind, &frame, coordinate, .{}));
            word.* = original;
        }
        const field = frame.felts[0];
        frame.felts[0].c1.b.v = core.fields.m31.Modulus;
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, check(kind, &frame, coordinate, .{}));
        frame.felts[0] = field;
        const final = frame.first[frame.first.len - 1];
        frame.first[frame.first.len - 1] = .{ .felts = .{ .first = std.math.maxInt(u32), .len = 1 } };
        // Reject before deriving first+1 or 4*first from this invalid span.
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, check(kind, &frame, coordinate, .{}));
        frame.first[frame.first.len - 1] = final;
        frame.roots_offset[1] = 1;
        try std.testing.expectError(error.InvalidRecursiveStatementFrames, check(kind, &frame, coordinate, .{}));
        frame.roots_offset[1] = 0;
        try check(kind, &frame, coordinate, .{});
    }
}

test "recursive source frame check: identical original calls cannot waive nonempty final-singleton or original felt-count grammar" {
    inline for (.{ Kind.public, Kind.memory }) |kind| {
        for ([_]Emission{ .{ .final = .words }, .{ .prefix_felts = 0, .final = .pair } }) |emission| {
            try std.testing.expectError(layoutError(kind), record(kind, std.testing.allocator, emission));
            var frame = try looseRecord(std.testing.allocator, emission);
            defer frame.deinit();
            try std.testing.expectError(layoutError(kind), check(kind, &frame, 0, emission));
        }
        const Empty = struct {
            pub fn mix(_: @This(), _: anytype) !void {}
        };
        const empty = Frames.Statement{ .allocator = std.testing.failing_allocator, .words = &.{}, .felts = &.{}, .first = &.{}, .claims = &.{}, .sealed_offset = 0, .roots_offset = @splat(0) };
        try std.testing.expectError(limitError(kind), Module(kind).testing.checkFrame(&empty, 0, Empty{}, Limits(kind)));
    }
    for ([_]Emission{ .{ .prefix_felts = 0 }, .{ .prefix_felts = 3 } }) |emission| {
        try std.testing.expectError(error.SourceRamJoinSourceLimit, record(.memory, std.testing.allocator, emission));
        var frame = try looseRecord(std.testing.allocator, emission);
        defer frame.deinit();
        try std.testing.expectError(error.SourceRamJoinSourceLimit, check(.memory, &frame, 0, emission));
    }
}

test "recursive source frame check: scaled PUBLIC21 original record and validation preserve every root without offset inventory" {
    const emission = Emission{ .root_count = 96 };
    var frame = try record(.public, std.testing.allocator, emission);
    const allocator = frame.allocator;
    frame.allocator = std.testing.failing_allocator;
    defer {
        frame.allocator = allocator;
        frame.deinit();
    }
    const coordinate = try Public.testing.transitionCoordinate(&frame);
    try std.testing.expectEqual(@as(usize, 772), frame.words.len);
    try std.testing.expectEqual(@as(usize, 100), frame.first.len);
    for (0..25) |_| try check(.public, &frame, coordinate, emission);
    frame.words[2 + 8 * 95] ^= 1;
    try std.testing.expectError(error.InvalidRecursiveStatementFrames, check(.public, &frame, coordinate, emission));
}

test "recursive source frame check: all source configured word step and public felt limits stay independently pinned" {
    inline for (.{ Kind.public, Kind.memory }) |kind| {
        var frame = try record(kind, std.testing.allocator, .{});
        defer frame.deinit();
        const coordinate = try Module(kind).testing.transitionCoordinate(&frame);
        var bounded = Limits(kind);
        bounded.max_words = frame.words.len - 1;
        try std.testing.expectError(error.RecursiveStatementFrameLimit, Module(kind).testing.checkFrame(&frame, coordinate, Emission{}, bounded));
        bounded = Limits(kind);
        bounded.max_steps = frame.first.len - 1;
        try std.testing.expectError(error.RecursiveStatementFrameLimit, Module(kind).testing.checkFrame(&frame, coordinate, Emission{}, bounded));
        bounded = Limits(kind);
        bounded.max_words = frame.words.len;
        bounded.max_steps = frame.first.len;
        try Module(kind).testing.checkFrame(&frame, coordinate, Emission{}, bounded);
    }
    var frame = try record(.public, std.testing.allocator, .{});
    defer frame.deinit();
    var bounded = Limits(.public);
    bounded.max_felts = frame.felts.len - 1;
    try std.testing.expectError(error.RecursiveStatementFrameLimit, Public.testing.checkFrame(&frame, try Public.testing.transitionCoordinate(&frame), Emission{}, bounded));
}
