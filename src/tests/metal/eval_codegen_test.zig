const std = @import("std");
const eval_program = @import("stwo_cairo_frontend").witness.eval_program;
const eval_codegen = @import("../../integrations/cairo_metal/eval_codegen.zig");
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const eval_source_options = @import("../../tools/cairo_metal_codegen/eval_source_options.zig");

test {
    _ = eval_program;
    _ = eval_codegen;
    _ = composition_bundle;
    _ = eval_source_options;
}

test "Metal evaluation codegen: hybrid fusion uses the exact emitted source cap" {
    const allocator = std.testing.allocator;
    var bundle = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    const component = bundle.components[29];
    try std.testing.expectEqualStrings("pedersen_aggregator_window_bits_18", component.label);

    const parts = try allocator.alloc(eval_codegen.FusedPart, component.parts.len);
    defer allocator.free(parts);
    for (component.parts, parts) |part, *fused| fused.* = .{
        .program = part.program,
        .rc_base = part.rc_base,
    };

    var admitted = try eval_codegen.hybridFusionPartition(allocator, parts, .{});
    defer admitted.deinit();
    try std.testing.expectEqual(@as(usize, 1), admitted.slices.len);
    try std.testing.expectEqual(@as(usize, 2097), admitted.slices[0].operations);
    try std.testing.expect(admitted.slices[0].source_bytes <= eval_codegen.hybrid_fusion_source_cap);

    var repeated = try eval_codegen.hybridFusionPartition(allocator, parts, .{});
    defer repeated.deinit();
    try std.testing.expectEqualSlices(
        eval_codegen.FusionSlice,
        admitted.slices,
        repeated.slices,
    );
    for (admitted.slices) |slice| {
        const group = parts[slice.start..slice.end];
        const resolved_name = try eval_codegen.fusionSliceKernelName(allocator, parts, slice);
        defer allocator.free(resolved_name);
        const emitted_source = if (group.len == 1)
            try eval_codegen.generateKernel(allocator, group[0].program, false)
        else
            try eval_codegen.generateFusedKernel(allocator, group, false);
        defer allocator.free(emitted_source);
        try std.testing.expect(std.mem.indexOf(u8, emitted_source, resolved_name) != null);
    }

    var rejected = try eval_codegen.hybridFusionPartition(allocator, parts, .{
        .maximum_source_bytes = admitted.slices[0].source_bytes - 1,
    });
    defer rejected.deinit();
    try std.testing.expectEqual(@as(usize, 2), rejected.slices.len);
    var expected_start: usize = 0;
    for (rejected.slices) |slice| {
        try std.testing.expectEqual(expected_start, slice.start);
        expected_start = try eval_codegen.fusionGroupEnd(parts, expected_start, 2048);
        try std.testing.expectEqual(expected_start, slice.end);
    }
    try std.testing.expectEqual(parts.len, expected_start);
}

test "Metal evaluation codegen: hybrid fusion minimizes exact maximum source size" {
    const allocator = std.testing.allocator;
    var bundle = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    const component = bundle.components[0];
    try std.testing.expectEqualStrings("add_opcode", component.label);

    const parts = try allocator.alloc(eval_codegen.FusedPart, component.parts.len);
    defer allocator.free(parts);
    for (component.parts, parts) |part, *fused| fused.* = .{
        .program = part.program,
        .rc_base = part.rc_base,
    };
    var partition = try eval_codegen.hybridFusionPartition(allocator, parts, .{
        .baseline_operation_cap = 1,
        .maximum_operation_cap = 815,
    });
    defer partition.deinit();

    try std.testing.expectEqual(@as(usize, 2), partition.slices.len);
    try std.testing.expectEqual(@as(usize, 1), partition.slices[0].end);
    try std.testing.expectEqual(@as(usize, 3), partition.slices[1].end);
    const competing_source = try eval_codegen.generateFusedKernel(allocator, parts[0..2], false);
    defer allocator.free(competing_source);
    try std.testing.expect(partition.slices[1].source_bytes < competing_source.len);

    var oversize_single = try eval_codegen.hybridFusionPartition(allocator, parts[0..1], .{
        .baseline_operation_cap = 1,
        .maximum_operation_cap = 2,
    });
    defer oversize_single.deinit();
    try std.testing.expectEqual(@as(usize, 1), oversize_single.slices.len);
    try std.testing.expectEqual(@as(usize, 0), oversize_single.slices[0].start);
    try std.testing.expectEqual(@as(usize, 1), oversize_single.slices[0].end);
}

test "Metal evaluation codegen: hybrid fusion rejects invalid policy" {
    try std.testing.expectError(
        error.InvalidFusionPolicy,
        eval_codegen.hybridFusionPartition(std.testing.allocator, &.{}, .{
            .baseline_operation_cap = 2049,
            .maximum_operation_cap = 2048,
        }),
    );
}
