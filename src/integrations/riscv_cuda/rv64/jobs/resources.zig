//! Job resource units and observation policy. No CUDA or runtime imports.
//! Device scratch exists independently of whether a host mirror is needed.
const std = @import("std");

pub const DeviceBuffer = struct {
    ptr: [*]u32,
    words: usize,
    pub fn slice(self: DeviceBuffer, first: usize, words: usize) !DeviceBuffer {
        if (first > self.words or words > self.words - first) return error.DeviceBufferOutOfRange;
        return .{ .ptr = self.ptr + first, .words = words };
    }
    pub fn bytes(self: DeviceBuffer) usize {
        return self.words * @sizeOf(u32);
    }
};

pub const granule_words: usize = 64;
pub const channel_words: usize = 32;

pub const Placement = enum {
    bottom,
    top,
    pub fn other(self: Placement) Placement {
        return if (self == .bottom) .top else .bottom;
    }
};

pub const Readback = enum {
    /// Worker downloads the private result slab before finish observes it.
    job_slab,
    /// Device checks/encoding publish to the driver's request slab. Private
    /// scratch remains device-only; finish receives no private host words.
    request_slab,
};

pub fn aligned(words: usize) error{ResourceSizeOverflow}!usize {
    const n = std.math.add(usize, words, granule_words - 1) catch return error.ResourceSizeOverflow;
    return n & ~(granule_words - 1);
}

pub const Footprint = struct {
    /// Peak of staged inputs + work allocations, excluding channel and slab.
    device_words: usize,
    staged_words: usize = 0,
    /// Device private result/scratch slab, charged for BOTH readback modes.
    slab_words: usize = 0,
    /// Pinned ingress; host result mirror is accounted separately below.
    pinned_words: usize = 0,
    readback: Readback = .job_slab,

    pub fn hostSlabWords(self: Footprint) usize {
        return if (self.readback == .job_slab) self.slab_words else 0;
    }
    pub fn pinnedWords(self: Footprint) error{ResourceSizeOverflow}!usize {
        return std.math.add(usize, self.pinned_words, self.hostSlabWords()) catch error.ResourceSizeOverflow;
    }
    pub fn peakWords(self: Footprint) error{ResourceSizeOverflow}!usize {
        const slab = try aligned(self.slab_words);
        const scratch = std.math.add(usize, self.device_words, slab) catch return error.ResourceSizeOverflow;
        return std.math.add(usize, scratch, granule_words) catch error.ResourceSizeOverflow;
    }
    /// Validate units before a measured policy replaces device_words. A
    /// policy may increase a deliberately fitted declaration; the resolved
    /// footprint must additionally pass validate() before any staging.
    pub fn validateSizes(self: Footprint) !void {
        _ = std.math.mul(usize, try aligned(self.staged_words), @sizeOf(u32)) catch return error.ResourceSizeOverflow;
        _ = std.math.mul(usize, try self.peakWords(), @sizeOf(u32)) catch return error.ResourceSizeOverflow;
        _ = std.math.mul(usize, try self.pinnedWords(), @sizeOf(u32)) catch return error.ResourceSizeOverflow;
    }
    pub fn validate(self: Footprint) !void {
        try self.validateSizes();
        if (self.staged_words > self.device_words) return error.StagedFootprintExceedsDevice;
    }
};

test "readback policy changes host observation, not device lifetime or peak" {
    const t = std.testing;
    const host = Footprint{ .device_words = 128, .staged_words = 64, .slab_words = 7, .pinned_words = 9 };
    var device = host;
    device.readback = .request_slab;
    try host.validate();
    try device.validate();
    try t.expectEqual(try host.peakWords(), try device.peakWords());
    try t.expectEqual(@as(usize, 16), try host.pinnedWords());
    try t.expectEqual(@as(usize, 9), try device.pinnedWords());
    try t.expectEqual(@as(usize, 0), device.hostSlabWords());
}

test "invalid and overflowing resource declarations fail before allocation" {
    const t = std.testing;
    try t.expectError(error.StagedFootprintExceedsDevice, (Footprint{ .device_words = 64, .staged_words = 65 }).validate());
    try t.expectError(error.ResourceSizeOverflow, (Footprint{ .device_words = std.math.maxInt(usize) }).validate());
    try t.expectError(error.ResourceSizeOverflow, (Footprint{ .device_words = 64, .slab_words = std.math.maxInt(usize) }).validate());
    try t.expectError(error.ResourceSizeOverflow, (Footprint{ .device_words = 64, .pinned_words = std.math.maxInt(usize), .slab_words = 1 }).validate());
    try t.expectError(error.ResourceSizeOverflow, (Footprint{ .device_words = 64, .pinned_words = std.math.maxInt(usize) / 4 + 1 }).validate());
}
