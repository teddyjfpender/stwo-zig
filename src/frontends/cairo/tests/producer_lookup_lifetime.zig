//! Incremental feed release must preserve both host and backend owners.
const std = @import("std");
const cairo = @import("cairo_frontend");
const Producer = cairo.witness.producer_output.ProducerOutput;

const Owner = struct {
    words: []u32,
    released: usize = 0,
    fn release(context: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(context));
        std.testing.allocator.free(self.words);
        self.released += 1;
    }
};

fn producer(words: []u32, lookup: []u32) Producer {
    return .{ .label = "feed", .row_count = 2, .active_rows = 2, .words_per_row = 1, .words = words, .lookup_words_per_row = 1, .lookup_words = lookup };
}

test "Cairo lookup feed releases host storage before final execution teardown" {
    const allocator = std.testing.allocator;
    var output = producer(try allocator.dupe(u32, &.{ 7, 9 }), try allocator.dupe(u32, &.{ 11, 13 }));
    defer output.deinit(allocator);
    output.releaseLookupWords(allocator);
    output.releaseLookupWords(allocator);
    try std.testing.expectEqual(@as(usize, 0), output.lookup_words.len);
    try std.testing.expect(output.lookupResidency() == null);
    try std.testing.expectEqualSlices(u32, &.{ 7, 9 }, output.words);
}

test "Cairo lookup feed releases the backend owner exactly once without freeing borrowed storage" {
    const allocator = std.testing.allocator;
    var owner = Owner{ .words = try allocator.dupe(u32, &.{ 17, 19 }) };
    var output = producer(try allocator.dupe(u32, &.{ 23, 29 }), owner.words);
    output.lookup_allocation = .{ .words = owner.words, .residency = .{ .identity = 42, .context = &owner }, .context = &owner, .deinit_fn = Owner.release };
    try std.testing.expectEqual(@as(u64, 42), output.lookupResidency().?.identity);
    output.releaseLookupWords(allocator);
    try std.testing.expectEqual(@as(usize, 1), owner.released);
    try std.testing.expect(output.lookupResidency() == null);
    output.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), owner.released);
}
