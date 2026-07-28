//! Official Stwo-Cairo preprocessed trace geometry and projection checks.

const std = @import("std");
const cairo = @import("cairo_frontend");

const Variant = cairo.preprocessed.trace.Variant;
const Spec = cairo.preprocessed.trace.Spec;

test "official Cairo preprocessed variants preserve source geometry" {
    inline for (std.meta.tags(Variant)) |variant| {
        var spec = try Spec.init(std.testing.allocator, variant);
        defer spec.deinit();
        try std.testing.expectEqual(variant.columnCount(), spec.columns.len);
    }
}

test "official Cairo AIR indices project between preprocessed variants" {
    var canonical = try Spec.init(std.testing.allocator, .canonical);
    defer canonical.deinit();
    var small = try Spec.init(std.testing.allocator, .canonical_small);
    defer small.deinit();

    const source = [_]u32{
        canonical.indexOf("seq_20").?,
        canonical.indexOf("blake_sigma_7").?,
        canonical.indexOf("range_check_9_9_column_1").?,
    };
    const projected = try canonical.projectIndices(
        std.testing.allocator,
        small,
        &source,
    );
    defer std.testing.allocator.free(projected);
    try std.testing.expectEqual(small.indexOf("seq_20").?, projected[0]);
    try std.testing.expectEqual(small.indexOf("blake_sigma_7").?, projected[1]);
    try std.testing.expectEqual(
        small.indexOf("range_check_9_9_column_1").?,
        projected[2],
    );
    const missing = [_]u32{canonical.indexOf("seq_25").?};
    try std.testing.expectError(
        error.PreprocessedColumnMissingFromVariant,
        canonical.projectIndices(std.testing.allocator, small, &missing),
    );
}
