const std = @import("std");

pub const magic = "STWZFED\x00".*;

pub const Destination = struct { name: []u8, words: u64 };
pub const Feed = struct {
    producer: []u8,
    row_count: u32,
    active_row_count: ?u32 = null,
    sub_words_per_row: u32,
    descriptors: []u32,
    luts: [][]u32,
    destinations: []Destination,
};

pub const Bundle = struct {
    allocator: std.mem.Allocator,
    feeds: []Feed,

    pub fn readFile(allocator: std.mem.Allocator, path: []const u8) !Bundle {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        var buffer: [64 * 1024]u8 = undefined;
        var reader = file.reader(&buffer);
        const in = &reader.interface;
        if (!std.mem.eql(u8, try in.takeArray(8), &magic)) return error.InvalidMagic;
        if (try in.takeInt(u32, .little) != 1) return error.UnsupportedVersion;
        const count = try in.takeInt(u32, .little);
        if (count == 0 or count > 256) return error.InvalidCount;
        const feeds = try allocator.alloc(Feed, count);
        var initialized: usize = 0;
        errdefer deinitFeeds(allocator, feeds[0..initialized]);
        while (initialized < feeds.len) : (initialized += 1) {
            const name_len = try in.takeInt(u16, .little);
            if (try in.takeInt(u16, .little) != 0 or name_len == 0) return error.InvalidEntry;
            const row_count = try in.takeInt(u32, .little);
            const sub_words = try in.takeInt(u32, .little);
            const descriptor_words = try in.takeInt(u32, .little);
            const lut_count = try in.takeInt(u32, .little);
            const destination_count = try in.takeInt(u32, .little);
            if (row_count == 0 or sub_words == 0 or descriptor_words == 0 or descriptor_words % 14 != 0 or lut_count > 64 or destination_count == 0 or destination_count > 64)
                return error.InvalidEntry;
            const producer = try allocator.alloc(u8, name_len);
            errdefer allocator.free(producer);
            try in.readSliceAll(producer);
            const descriptors = try allocator.alloc(u32, descriptor_words);
            errdefer allocator.free(descriptors);
            for (descriptors) |*word| word.* = try in.takeInt(u32, .little);
            const luts = try allocator.alloc([]u32, lut_count);
            var luts_initialized: usize = 0;
            errdefer {
                for (luts[0..luts_initialized]) |lut| allocator.free(lut);
                allocator.free(luts);
            }
            while (luts_initialized < luts.len) : (luts_initialized += 1) {
                const words = try in.takeInt(u32, .little);
                if (words == 0 or words > (1 << 24)) return error.InvalidEntry;
                luts[luts_initialized] = try allocator.alloc(u32, words);
                for (luts[luts_initialized]) |*word| word.* = try in.takeInt(u32, .little);
            }
            const destinations = try allocator.alloc(Destination, destination_count);
            var destinations_initialized: usize = 0;
            errdefer {
                for (destinations[0..destinations_initialized]) |destination| allocator.free(destination.name);
                allocator.free(destinations);
            }
            while (destinations_initialized < destinations.len) : (destinations_initialized += 1) {
                const destination_len = try in.takeInt(u16, .little);
                if (try in.takeInt(u16, .little) != 0 or destination_len == 0) return error.InvalidEntry;
                const words = try in.takeInt(u64, .little);
                const name = try allocator.alloc(u8, destination_len);
                try in.readSliceAll(name);
                destinations[destinations_initialized] = .{ .name = name, .words = words };
            }
            feeds[initialized] = .{
                .producer = producer,
                .row_count = row_count,
                .sub_words_per_row = sub_words,
                .descriptors = descriptors,
                .luts = luts,
                .destinations = destinations,
            };
        }
        var trailing: [1]u8 = undefined;
        if (try in.readSliceShort(&trailing) != 0) return error.TrailingData;
        return .{ .allocator = allocator, .feeds = feeds };
    }

    pub fn deinit(self: *Bundle) void {
        deinitFeeds(self.allocator, self.feeds);
        self.* = undefined;
    }
};

fn deinitFeeds(allocator: std.mem.Allocator, feeds: []Feed) void {
    for (feeds) |feed| {
        allocator.free(feed.producer);
        allocator.free(feed.descriptors);
        for (feed.luts) |lut| allocator.free(lut);
        allocator.free(feed.luts);
        for (feed.destinations) |destination| allocator.free(destination.name);
        allocator.free(feed.destinations);
    }
    allocator.free(feeds);
}

test "Cairo feed bundle: canonical SN2 descriptor plans load" {
    var bundle = try Bundle.readFile(std.testing.allocator, "vectors/cairo/sn_pie_2_multiplicity_feeds.bin");
    defer bundle.deinit();
    try std.testing.expectEqual(@as(usize, 33), bundle.feeds.len);
    var descriptors: usize = 0;
    for (bundle.feeds) |feed| descriptors += feed.descriptors.len / 14;
    try std.testing.expect(descriptors > 100);
}
