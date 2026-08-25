const std = @import("std");
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const codegen = @import("eval_codegen.zig");
const eval_aot = @import("eval_aot.zig");

const manifest_path =
    "src/backends/cuda/aot/native/cairo_eval/aot_manifest.json";

test "SN2 CUDA eval AOT product covers every part with unique bodies" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var product = try eval_aot.build(allocator, bundle);
    defer product.deinit();

    try std.testing.expectEqual(@as(usize, 271), product.bodies.len);
    try std.testing.expectEqual(@as(usize, 279), product.occurrence_count);
    var seen = [_]bool{false} ** 279;
    var component_starts: [58]usize = undefined;
    var cursor: usize = 0;
    for (bundle.components, 0..) |component, component_index| {
        component_starts[component_index] = cursor;
        cursor += component.parts.len;
    }
    try std.testing.expectEqual(seen.len, cursor);

    for (product.bodies) |body| {
        const source_identity = codegen.sourceIdentity(body.source);
        try std.testing.expectEqualSlices(
            u8,
            &source_identity,
            &body.source_identity,
        );
        const catalog_identity = try eval_aot.catalogIdentity(
            allocator,
            body.occurrences,
        );
        try std.testing.expectEqualSlices(
            u8,
            &catalog_identity,
            &body.catalog_identity,
        );
        try std.testing.expectEqual(
            codegen.productCacheKey(
                body.program_identity,
                body.source_identity,
                body.catalog_identity,
            ),
            body.cache_key,
        );
        for (body.occurrences) |occurrence| {
            const component =
                bundle.components[occurrence.component_index];
            const part = component.parts[occurrence.part_index];
            const flat = component_starts[occurrence.component_index] +
                occurrence.part_index;
            try std.testing.expect(!seen[flat]);
            seen[flat] = true;
            try std.testing.expectEqualStrings(
                component.label,
                occurrence.component_label,
            );
            try std.testing.expectEqual(
                component.instance,
                occurrence.instance,
            );
            try std.testing.expectEqual(
                component.random_coefficient_offset + part.rc_base,
                occurrence.global_rc_base,
            );
            try std.testing.expectEqual(
                part.program.header.n_constraints,
                occurrence.rc_count,
            );
            const exact_program_identity =
                codegen.programIdentity(part.program);
            try std.testing.expectEqualSlices(
                u8,
                &exact_program_identity,
                &occurrence.program_identity,
            );
            const component_source_identity =
                eval_aot.componentSourceIdentity(component);
            try std.testing.expectEqualSlices(
                u8,
                &component_source_identity,
                &occurrence.component_source_identity,
            );
        }
    }
    for (seen) |present| try std.testing.expect(present);
}

test "SN2 CUDA eval AOT manifest is reproducible" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var product = try eval_aot.build(allocator, bundle);
    defer product.deinit();

    const first = try eval_aot.renderManifest(allocator, product);
    defer allocator.free(first);
    const second = try eval_aot.renderManifest(allocator, product);
    defer allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    const checked_in = try std.fs.cwd().readFileAlloc(
        allocator,
        manifest_path,
        4 * 1024 * 1024,
    );
    defer allocator.free(checked_in);
    try std.testing.expectEqualStrings(first, checked_in);
}

test "CUDA eval exact program identity detects semantic input drift" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    const program = &bundle.components[0].parts[0].program;
    const before = codegen.programIdentity(program.*);
    program.header.n_base_params += 1;
    const after = codegen.programIdentity(program.*);
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
}
