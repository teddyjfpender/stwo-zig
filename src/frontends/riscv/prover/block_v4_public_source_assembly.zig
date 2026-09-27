//! Streaming public initial-image and source-roster assembly for a block-v4
//! batch. These files remain verifier-visible; the receiver rehashes the full
//! image against an independently pinned initial RW root.
const std = @import("std");
const replay_mod = @import("block_memory_replay.zig");
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const roster = @import("block_memory_source_roster_v2.zig");

pub const HashPin = struct { plan_id: [32]u8, key_id: [32]u8 };
pub const Prepared = struct {
    a: std.mem.Allocator,
    image: std.fs.File,
    touches: std.fs.File,
    pin: fallback.Pin,
    registers: [32]u32,
    register_mask: u32,
    entries: []roster.Entry,
    digest: [32]u8,

    pub fn files(self: *const Prepared) fallback.Files {
        return .{ .nonzero_image = self.image, .first_touches = self.touches };
    }
    pub fn deinit(self: *Prepared) void {
        self.image.close();
        self.touches.close();
        self.a.free(self.entries);
        self.* = undefined;
    }
};

/// The directory is a staging area owned by the caller. File names are fixed
/// and created exclusively so an old batch cannot be mistaken for this one.
pub fn prepare(a: std.mem.Allocator, dir: std.fs.Dir, replay: *replay_mod.Replay, pinned_initial_root: [32]u8, program_root: [32]u8, hashes: []const HashPin) !Prepared {
    if (hashes.len == 0 or hashes.len > roster.MAX_ENTRIES - 2)
        return error.InvalidPreparedHashRoster;
    const root = try replay.initialRwRoot();
    if (!std.mem.eql(u8, &root.bytes, &pinned_initial_root))
        return error.UntrustedBlockInitialImageRoot;
    var image = try dir.createFile("initial-nonzero.bin", .{ .exclusive = true, .read = true });
    errdefer image.close();
    var touches = try dir.createFile("first-touch.bin", .{ .exclusive = true, .read = true });
    errdefer touches.close();
    var image_count: u64 = 0;
    for (replay.words) |word| {
        if (word.value == 0 or word.source == .program_root) continue;
        var row: [fallback.IMAGE_RECORD_BYTES]u8 = undefined;
        std.mem.writeInt(u32, row[0..4], word.address, .little);
        std.mem.writeInt(u32, row[4..8], word.value, .little);
        try image.writeAll(&row);
        image_count = try std.math.add(u64, image_count, 1);
    }
    var first = try replay.firstTouches();
    defer first.deinit();
    var register_mask: u32 = 0;
    while (try first.next()) |item| {
        if (item.source == .program_root) return error.ProgramFirstTouchNeedsAuthenticatedProvider;
        var row: [fallback.TOUCH_RECORD_BYTES]u8 = undefined;
        row[0] = item.space;
        std.mem.writeInt(u32, row[1..5], item.address, .little);
        std.mem.writeInt(u32, row[5..9], item.value, .little);
        row[9] = @intFromEnum(item.source);
        try touches.writeAll(&row);
        if (item.source == .register) register_mask |= @as(u32, 1) << @intCast(item.address);
    }
    try image.sync();
    try touches.sync();
    const pin = fallback.Pin{ .initial_rw_root = root, .layout = replay.layout orelse return error.MissingInitialMemoryLayout, .image_count = image_count, .first_touch_count = first.count };
    try pin.validate();
    const files = fallback.Files{ .nonzero_image = image, .first_touches = touches };
    const rw_digest = try fallback.digestRoster(pin, files);
    const entries = try a.alloc(roster.Entry, hashes.len + 2);
    errdefer a.free(entries);
    entries[0] = .{ .family = .public_rw_fallback, .index = 0, .digest = rw_digest };
    entries[1] = .{ .family = .program, .index = 0, .digest = roster.programDescriptor(program_root) };
    for (hashes, 0..) |hash, index| entries[index + 2] = .{ .family = .hash, .index = @intCast(index), .digest = roster.hashDescriptor(@intCast(index), hash.plan_id, hash.key_id) };
    return .{ .a = a, .image = image, .touches = touches, .pin = pin, .registers = replay.registers, .register_mask = register_mask, .entries = entries, .digest = try roster.digest(entries) };
}
