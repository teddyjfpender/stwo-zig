//! Boundary and packing checks for compiled fixed-table routing.
const std = @import("std");
const cairo = @import("cairo_frontend");
const Plan = cairo.conformance.fixed_feed_plan.Plan;

fn plan(label: []const u8, rows: u32, columns: u32, words: u32) !Plan {
    return Plan.init(.{
        .component = @constCast(label),
        .log_size = 0,
        .row_count = rows,
        .multiplicity_columns = columns,
        .trace_multiplicity_columns = &.{},
        .preprocessed_sources = &.{},
        .lookup_descriptors = &.{},
    }, .{
        .field = "test",
        .instance = 0,
        .target = label,
        .relation = 0,
        .word_base = 0,
        .words_per_instance = words,
    });
}

test "Cairo fixed feed composite keys and malformed limbs" {
    const range = try plan("range_check_3_6_6", 1 << 15, 1, 3);
    try std.testing.expectEqual(@as(u32, 0b101_010101_111000), (try range.key(&.{ 5, 21, 56 })).row);
    try std.testing.expectError(error.InvalidMultiplicityKey, range.key(&.{ 8, 0, 0 }));
    try std.testing.expectError(error.FeedGeometryMismatch, range.key(&.{ 1, 0 }));
    try std.testing.expectError(error.FeedGeometryMismatch, plan("range_check_16_16", 1 << 20, 1, 2));
    try std.testing.expectError(error.FeedGeometryMismatch, plan("range_check_0", 16, 1, 1));
}

test "Cairo fixed feed XOR12 covers exact packed column boundaries" {
    const xor = try plan("verify_bitwise_xor_12", 1 << 20, 16, 3);
    const edge = try xor.key(&.{ 4095, 3072, 1023 });
    try std.testing.expectEqual(@as(u32, 15), edge.relation);
    try std.testing.expectEqual(@as(u32, 1023 << 10), edge.row);
    try std.testing.expectError(error.InvalidMultiplicityKey, xor.key(&.{ 4096, 0, 4096 }));
    try std.testing.expectError(error.InvalidMultiplicityKey, xor.key(&.{ 1, 1, 1 }));
    try std.testing.expectError(error.FixedGeometryMismatch, plan("verify_bitwise_xor_12", 1 << 20, 1, 3));
}

test "Cairo fixed feed histograms reject overflowing counts" {
    const indexed = try plan("blake_round_sigma", 16, 1, 1);
    var dense = [_]u32{0} ** 16;
    try indexed.increment(&dense, &.{15});
    try std.testing.expectEqual(@as(u32, 1), dense[15]);
    try std.testing.expectError(error.InvalidMultiplicityKey, indexed.increment(&dense, &.{16}));
    dense[15] = std.math.maxInt(u32);
    try std.testing.expectError(error.MultiplicityOverflow, indexed.increment(&dense, &.{15}));
}
