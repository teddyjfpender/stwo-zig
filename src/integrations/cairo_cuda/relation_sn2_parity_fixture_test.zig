const std = @import("std");
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const fixture_mod = @import("relation_sn2_parity_fixture.zig");

const fixture_path =
    "tests/cuda/fixtures/cairo_relation_sn2_parity_fixture.h";

test "generate exact-height SN2 relation parity fixture" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(
        allocator,
        "STWO_GENERATE_SN2_RELATION_PARITY",
    ) catch return error.SkipZigTest;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1"))
        return error.SkipZigTest;

    var composition = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();
    var relations = try relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();
    var fixture = try fixture_mod.build(
        allocator,
        composition,
        relations,
    );
    defer fixture.deinit();
    try std.testing.expectEqual(@as(usize, 58), fixture.instances.len);
    try std.testing.expectEqual(@as(u32, 126), fixture.max_alpha_powers);
    try std.testing.expectEqual(@as(usize, 9_072), fixture.descriptors.len);

    const header = try fixture_mod.renderHeader(allocator, fixture);
    defer allocator.free(header);
    try std.fs.cwd().writeFile(.{
        .sub_path = fixture_path,
        .data = header,
    });
    std.debug.print(
        "generated exact SN2 relation oracle: instances={} descriptors={} bytes={}\n",
        .{ fixture.instances.len, fixture.descriptors.len, header.len },
    );
}
