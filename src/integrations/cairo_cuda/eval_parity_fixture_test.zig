const std = @import("std");
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const eval_aot = @import("eval_aot.zig");
const fixture_mod = @import("eval_parity_fixture.zig");

const fixture_path =
    "tests/cuda/fixtures/cairo_eval_sn2_parity_fixture.h";

test "SN2 constraint parity fixture covers canonical placements exactly" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var product = try eval_aot.build(allocator, bundle);
    defer product.deinit();
    var fixture = try fixture_mod.build(allocator, bundle, product);
    defer fixture.deinit();

    try std.testing.expectEqual(@as(usize, 58), fixture.components.len);
    try std.testing.expectEqual(@as(usize, 279), fixture.placements.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.zero_inversions);
    try std.testing.expectEqual(@as(u64, 1 << 24), fixture.max_rows);
    try std.testing.expect(fixture.arena_words > fixture.metadata_offset);
    var placement_index: usize = 0;
    for (bundle.components, 0..) |component, component_index| {
        for (component.parts, 0..) |part, part_index| {
            const placement = fixture.placements[placement_index];
            try std.testing.expectEqual(
                @as(u32, @intCast(component_index)),
                placement.component_index,
            );
            try std.testing.expectEqual(
                @as(u32, @intCast(part_index)),
                placement.part_index,
            );
            try std.testing.expectEqual(
                component.random_coefficient_offset + part.rc_base,
                placement.global_rc_base,
            );
            placement_index += 1;
        }
    }
    try std.testing.expectEqual(fixture.placements.len, placement_index);
}

test "SN2 constraint parity fixture header is byte reproducible" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var product = try eval_aot.build(allocator, bundle);
    defer product.deinit();
    var fixture = try fixture_mod.build(allocator, bundle, product);
    defer fixture.deinit();

    const rendered = try fixture_mod.renderHeader(allocator, fixture);
    defer allocator.free(rendered);
    const checked_in = try std.fs.cwd().readFileAlloc(
        allocator,
        fixture_path,
        8 * 1024 * 1024,
    );
    defer allocator.free(checked_in);
    try std.testing.expectEqualStrings(rendered, checked_in);
}
