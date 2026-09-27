//! One initial-image and sorted-memory witness shared by two execution leaves.
const std = @import("std");
const Replay = @import("block_memory_replay.zig").Replay;
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const Segment = @import("../runner/result.zig").EthereumShaSegmentResult;

pub const Source = struct {
    replay: Replay,
    image: std.fs.File,
    touches: std.fs.File,
    pin: fallback.Pin,
    register_mask: u32,

    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, segments: *[2]Segment) !Source {
        var replay = try Replay.initFromSnapshot(
            a,
            dir,
            segments[0].base.entry_cpu.regs,
            &segments[0].base.rw_memory,
            256,
        );
        errdefer replay.deinit();
        for (segments) |*segment| try replay.appendResult(&segment.base);
        var sorted = try replay.finish();
        sorted.deinit();
        const image = try dir.createFile("initial-image.bin", .{ .read = true, .truncate = true });
        errdefer image.close();
        const touches = try dir.createFile("first-touches.bin", .{ .read = true, .truncate = true });
        errdefer touches.close();
        var image_count: u64 = 0;
        for (replay.words) |word| {
            if (word.value == 0 or word.source == .program_root) continue;
            var record: [8]u8 = undefined;
            std.mem.writeInt(u32, record[0..4], word.address, .little);
            std.mem.writeInt(u32, record[4..8], word.value, .little);
            try image.writeAll(&record);
            image_count += 1;
        }
        var reader = try replay.firstTouches();
        defer reader.deinit();
        var register_mask: u32 = 0;
        while (try reader.next()) |item| {
            if (item.source == .program_root) return error.ProgramFirstTouchNeedsAuthenticatedProvider;
            var record: [10]u8 = undefined;
            record[0] = item.space;
            std.mem.writeInt(u32, record[1..5], item.address, .little);
            std.mem.writeInt(u32, record[5..9], item.value, .little);
            record[9] = @intFromEnum(item.source);
            try touches.writeAll(&record);
            if (item.source == .register) register_mask |= @as(u32, 1) << @intCast(item.address);
        }
        const initial = try replay.initialRwRoot();
        return .{
            .replay = replay,
            .image = image,
            .touches = touches,
            .pin = .{
                .initial_rw_root = initial,
                .layout = replay.layout.?,
                .image_count = image_count,
                .first_touch_count = reader.count,
            },
            .register_mask = register_mask,
        };
    }

    pub fn files(self: *const Source) fallback.Files {
        return .{ .nonzero_image = self.image, .first_touches = self.touches };
    }

    pub fn deinit(self: *Source) void {
        self.touches.close();
        self.image.close();
        self.replay.deinit();
        self.* = undefined;
    }
};
