//! Build-cache generation of every current upstream Cairo AIR body.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const eval_aot = @import("eval_aot.zig");
const parametric = @import("parametric_eval.zig");

pub fn loadLibrary(allocator: std.mem.Allocator, manifest_path: []const u8) !cairo.air.template_library.Library {
    return parametric.loadLibrary(allocator, manifest_path);
}

pub fn build(allocator: std.mem.Allocator, library: cairo.air.template_library.Library) !eval_aot.Product {
    var components = std.ArrayList(cairo.witness.composition_bundle.Component).empty;
    defer components.deinit(allocator);
    var constraints: u64 = 0;
    var maximum_log: u32 = 0;
    for (library.sources) |source| {
        try components.appendSlice(allocator, source.bundle.components);
        constraints = std.math.add(u64, constraints, source.bundle.total_constraints) catch return error.ConstraintOverflow;
        maximum_log = @max(maximum_log, source.bundle.max_evaluation_log_size);
    }
    const bundle = cairo.witness.composition_bundle.Bundle{
        .allocator = allocator,
        .format_version = cairo.witness.composition_bundle.version,
        .max_kernel_instructions = 1_000_000,
        .total_constraints = constraints,
        .max_evaluation_log_size = maximum_log,
        .plan_hash = std.mem.readInt(u64, parametric.source_authority[0..8], .little),
        .components = components.items,
    };
    return eval_aot.buildParametric(allocator, bundle, parametric.source_authority);
}

pub fn generate(allocator: std.mem.Allocator, manifest_path: []const u8, output_path: []const u8) !void {
    var library = try loadLibrary(allocator, manifest_path);
    defer library.deinit();
    var product = try build(allocator, library);
    defer product.deinit();
    try std.fs.cwd().makePath(output_path);
    var directory = try std.fs.cwd().openDir(output_path, .{});
    defer directory.close();
    for (product.bodies) |body| {
        const filename = try body.filename(allocator);
        defer allocator.free(filename);
        try directory.writeFile(.{ .sub_path = filename, .data = body.source });
    }
    const manifest = try eval_aot.renderParametricManifest(allocator, product);
    defer allocator.free(manifest);
    try directory.writeFile(.{ .sub_path = "aot_manifest.json", .data = manifest });
    var receipt = std.Io.Writer.Allocating.init(allocator);
    defer receipt.deinit();
    try std.json.Stringify.value(.{
        .schema = "stwo_cairo_canonical_cuda_air_generation_v1",
        .source_authority_sha256 = parametric.authority_hex,
        .family_count = cairo.claim_registry.claim_field_count,
        .body_count = product.bodies.len,
        .template_placement_count = product.occurrence_count,
        .codegen_version = @import("eval_codegen.zig").parametric_version,
        .slice_minimum_instructions = @import("eval_codegen.zig").slice_minimum_instructions,
        .slice_roots = @import("eval_codegen.zig").slice_roots,
        .device_qualified = false,
        .full_proof_verified = false,
    }, .{ .whitespace = .indent_2 }, &receipt.writer);
    try directory.writeFile(.{ .sub_path = "generation-receipt.json", .data = receipt.written() });
    std.debug.print("Canonical CUDA AIR generated: {} families, {} bodies, {} template placements\n", .{ cairo.claim_registry.claim_field_count, product.bodies.len, product.occurrence_count });
}

test "canonical CUDA parametric catalogue covers live all-opcode and builtin AIR" {
    var library = try loadLibrary(std.testing.allocator, "vectors/cairo/official/air_template_library_v1.json");
    defer library.deinit();
    var product = try build(std.testing.allocator, library);
    defer product.deinit();
    for ([_]struct { name: []const u8, variant: cairo.claim_generator.PreprocessedVariant }{
        .{ .name = "all_opcodes", .variant = .canonical_small },
        .{ .name = "all_builtins", .variant = .canonical },
    }) |case| {
        const input_path = try std.fmt.allocPrint(std.testing.allocator, "vectors/cairo/official/{s}.prover_input.json", .{case.name});
        defer std.testing.allocator.free(input_path);
        var input = try cairo.adapter.input.readFile(std.testing.allocator, input_path);
        defer input.deinit(std.testing.allocator);
        var claim = try cairo.claim_generator.deriveFromProverInput(std.testing.allocator, &input, .{ .preprocessed_variant = case.variant });
        defer claim.deinit();
        var topology = try cairo.witness.feed_topology.readOfficial(std.testing.allocator, "vectors/cairo/official/witness_feed_topology_v1.json");
        defer topology.deinit();
        var geometry = try @import("canonical_geometry.zig").resolve(std.testing.allocator, &input, &claim, topology);
        defer geometry.deinit();
        var live = try library.instantiate(std.testing.allocator, &claim, @enumFromInt(@intFromEnum(case.variant)), input.builtin_segments);
        defer live.deinit();
        var current = try eval_aot.buildParametric(std.testing.allocator, live, parametric.source_authority);
        defer current.deinit();
        var admitted = try @import("request_compiler/constraint_admission.zig").Catalog.initCanonical(std.testing.allocator, live);
        defer admitted.deinit();
        for (live.components, 0..) |component, ci| for (component.parts, 0..) |part, pi| {
            try std.testing.expect(admitted.admits(component, @intCast(ci), part, @intCast(pi)));
        };
        for (current.bodies) |body| {
            var found = false;
            for (product.bodies) |compiled| {
                if (compiled.cache_key == body.cache_key and std.mem.eql(u8, &compiled.source_identity, &body.source_identity)) {
                    found = true;
                    break;
                }
            }
            try std.testing.expect(found);
        }
    }
}
