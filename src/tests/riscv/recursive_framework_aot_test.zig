//! Maintained AOT catalog for the exact current detached leaf and parent AIRs.
//! Native Poseidon/range providers remain explicit unsupported coverage.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const metal = @import("stwo_metal_backend");
const backend = @import("stwo_prover_engine").air.component_prover;
const codegen = metal.riscv_polynomial_codegen.framework;
const allocator = std.testing.allocator;

const Generated = struct {
    source: []u8,
    inventory: []u8,
    coverage: []u8,
    fn deinit(self: *@This()) void {
        allocator.free(self.source);
        allocator.free(self.inventory);
        allocator.free(self.coverage);
    }
};

fn generate() !Generated {
    @setEvalBranchQuota(1_000_000);
    var source: std.ArrayList(u8) = .empty;
    errdefer source.deinit(allocator);
    var inventory: std.ArrayList(u8) = .empty;
    errdefer inventory.deinit(allocator);
    var coverage: std.ArrayList(u8) = .empty;
    errdefer coverage.deinit(allocator);
    var names = std.StringHashMap(void).init(allocator);
    defer {
        var iterator = names.keyIterator();
        while (iterator.next()) |name| allocator.free(name.*);
        names.deinit();
    }
    const writer = source.writer(allocator);
    const table = inventory.writer(allocator);
    const report = coverage.writer(allocator);
    try writer.writeAll("// Generated recursive framework profile v1. Shared field helpers come from core_v2.\n// Regenerate: STWO_RECURSIVE_FRAMEWORK_AOT_GENERATE=<directory> zig build test-riscv-metal-recursive-aot\n");
    try table.writeAll("// Generated from the production leaf and parent typed AIR catalogs.\npub const entries = .{\n");
    try report.writeAll("{\n  \"format\": \"recursive-framework-aot-coverage-v1\",\n  \"strict_coverage_complete\": false,\n  \"profiles\": [\n");
    inline for (.{ air.segment_leaf_catalog_v2.LOGICAL_ROWS, air.detached_parent_catalog_v1.LOGICAL_ROWS }, .{ "leaf", "parent" }, 0..) |catalog, profile, profile_index| {
        if (profile_index != 0) try report.writeAll(",\n");
        try report.print("    {{\"name\":\"{s}\",\"typed_components\":{},\"total_components\":{},\"unsupported\":[{{\"row\":34,\"reason\":\"native universal Poseidon provider\"}},{{\"row\":35,\"reason\":\"native range provider\"}}],\"rows\":[", .{ profile, catalog.len, catalog.len + 2 });
        inline for (catalog, 0..) |entry, entry_index| {
            const Air = entry.Air;
            var definition = if (entry.requires_location) try Air.build(allocator, .generated) else try Air.build(allocator);
            defer definition.deinit();
            const direct = try air.direct_constraint_program.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
            const relations = try air.universal_relation_binding.Binding(Air).authenticate(&definition);
            const parameter_start = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
            const parameter_count = Air.LOGICAL_INPUT_COUNT - parameter_start;
            var inputs: [Air.LOGICAL_INPUT_COUNT]backend.TypedPolynomialInputV1 = undefined;
            for (&inputs, 0..) |*input, index| input.* = if (index < Air.PHYSICAL_MAIN_COLUMN_COUNT)
                .{ .trace_column = .{ .tree_index = 1, .column_index = @intCast(index) } }
            else if (index < parameter_start)
                .{ .trace_column = .{ .tree_index = 0, .column_index = @intCast(index - Air.PHYSICAL_MAIN_COLUMN_COUNT) } }
            else
                .{ .profile_parameter = @intCast(index - parameter_start) };
            var interaction: [Air.INTERACTION_COLUMN_COUNT]backend.TypedPolynomialColumnV1 = undefined;
            for (&interaction, 0..) |*column, index| column.* = .{ .tree_index = 2, .column_index = @intCast(index) };
            const tree_counts = [_]usize{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
            var program = try air.framework_polynomial_export_v1.exportPrepared(Air, allocator, &direct, &relations, &inputs, &interaction, parameter_count, &tree_counts);
            defer program.deinit();
            const selected = codegen.Entry{ .program = &program, .tree_column_counts = &tree_counts };
            const name = try codegen.kernelName(allocator, selected);
            defer allocator.free(name);
            if (entry_index != 0) try report.writeAll(",");
            try report.print("{{\"row\":{},\"semantic_digest\":\"{s}\",\"kernel\":\"{s}\"}}", .{ @intFromEnum(entry.row), std.fmt.bytesToHex(Air.SEMANTIC_DIGEST, .lower), name });
            if (!names.contains(name)) {
                const owned_name = try allocator.dupe(u8, name);
                names.put(owned_name, {}) catch |err| {
                    allocator.free(owned_name);
                    return err;
                };
                const start = source.items.len;
                try codegen.emitKernel(allocator, writer, name, selected);
                const digest = try metal.shaders.declaration_digest.declarationDigestHex(source.items[start..], name);
                try table.print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n", .{ name, digest });
            }
        }
        try report.writeAll("]}");
    }
    try report.print("\n  ],\n  \"kernel_count\": {}\n}}\n", .{names.count()});
    try table.writeAll("};\n");
    const source_bytes = try source.toOwnedSlice(allocator);
    errdefer allocator.free(source_bytes);
    const inventory_bytes = try inventory.toOwnedSlice(allocator);
    errdefer allocator.free(inventory_bytes);
    return .{ .source = source_bytes, .inventory = inventory_bytes, .coverage = try coverage.toOwnedSlice(allocator) };
}

test "recursive framework AOT matches complete current typed catalogs with explicit native provider gaps" {
    try std.testing.expectEqual(@as(usize, 37), air.segment_leaf_catalog_v2.LOGICAL_ROWS.len);
    try std.testing.expectEqual(@as(usize, 29), air.detached_parent_catalog_v1.LOGICAL_ROWS.len);
    inline for (air.segment_leaf_catalog_v2.LOGICAL_ROWS, 0..) |entry, index|
        try std.testing.expectEqual(if (index < 34) index else index + 2, @as(usize, @intFromEnum(entry.row)));
    inline for (air.detached_parent_catalog_v1.LOGICAL_ROWS, 0..) |entry, index|
        try std.testing.expectEqual(if (index < 15) index else index + 5, @as(usize, @intFromEnum(entry.row)));
    var generated = try generate();
    defer generated.deinit();
    const directory_path = std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_GENERATE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            const profile = metal.shaders.aot_profile;
            try std.testing.expectEqualStrings(profile.recursive_extension_source, generated.source);
            try std.testing.expectEqualStrings(profile.recursive_inventory_source, generated.inventory);
            try std.testing.expectEqualStrings(profile.recursive_coverage_source, generated.coverage);
            return;
        },
        else => return err,
    };
    defer allocator.free(directory_path);
    var directory = try std.fs.cwd().makeOpenPath(directory_path, .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = "recursive_framework_v1.metal", .data = generated.source });
    try directory.writeFile(.{ .sub_path = "recursive_framework_v1_exports.zig", .data = generated.inventory });
    try directory.writeFile(.{ .sub_path = "recursive_framework_v1_coverage.json", .data = generated.coverage });
    std.debug.print("RECURSIVE_FRAMEWORK_AOT typed_leaf=37/39 typed_parent=29/31 strict_coverage_complete=false bytes={}\n", .{generated.source.len});
}
