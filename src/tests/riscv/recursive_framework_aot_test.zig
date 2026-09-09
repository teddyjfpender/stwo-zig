//! Maintained AOT catalog for the exact current detached leaf and parent AIRs.
//! Native providers share production DAGs and the authenticated range bridge.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const metal = @import("stwo_metal_backend");
const backend = @import("stwo_prover_engine").air.component_prover;
const codegen = metal.riscv_polynomial_codegen.framework;
const interaction_codegen = metal.riscv_polynomial_codegen.framework_interaction;
const allocator = std.testing.allocator;
const memory = frontend.air.memory_commitment;

const LegacyPoseidon = struct {
    const runtime = memory.hash_runtime_program;
    const DIRECT_PARTITION_COUNT = runtime.DIRECT_PARTITION_COUNT;
    fn buildDirect(a: std.mem.Allocator, partition: usize) !backend.OwnedBasePolynomialProgram {
        return runtime.buildPoseidonDirectRange(a, .universal, runtime.directPartitionRange(.universal, partition));
    }
    fn buildLookup(a: std.mem.Allocator) !backend.OwnedLookupPolynomialProgram {
        return runtime.buildPoseidonLookups(a);
    }
};

/// Reuse core kernels only when their complete emitted body is identical.
/// Additional inventory contains only declarations appended by this profile.
fn appendProviderKernel(comptime emitter: type, program: anytype, source: *std.ArrayList(u8), inventory: *std.ArrayList(u8), names: *std.StringHashMap(void)) ![]u8 {
    try program.validate();
    const name = try emitter.kernelName(allocator, program);
    errdefer allocator.free(name);
    var emitted: std.ArrayList(u8) = .empty;
    defer emitted.deinit(allocator);
    try emitter.emitKernel(allocator, emitted.writer(allocator), name, program);
    for (metal.shaders.manifest.native_exports) |entry| {
        if (std.mem.eql(u8, entry.name, name)) {
            try std.testing.expect(std.mem.indexOf(u8, metal.shaders.manifest.native_amalgamated_source, emitted.items) != null);
            return name;
        }
    }
    if (!names.contains(name)) {
        const owned_name = try allocator.dupe(u8, name);
        names.put(owned_name, {}) catch |err| {
            allocator.free(owned_name);
            return err;
        };
        try source.appendSlice(allocator, emitted.items);
        const digest = try metal.shaders.declaration_digest.declarationDigestHex(emitted.items, name);
        try inventory.writer(allocator).print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n", .{ name, digest });
    }
    return name;
}

fn appendProvider(comptime Provider: type, source: *std.ArrayList(u8), inventory: *std.ArrayList(u8), coverage: *std.ArrayList(u8), names: *std.StringHashMap(void)) !void {
    const report = coverage.writer(allocator);
    try report.writeAll(",\"native_providers\":[{\"row\":34,\"layout\":\"independent-prefix-v1\",\"direct_kernels\":[");
    for (0..Provider.DIRECT_PARTITION_COUNT) |partition| {
        var program = try Provider.buildDirect(allocator, partition);
        defer program.deinit();
        const name = try appendProviderKernel(metal.riscv_polynomial_codegen.base, program, source, inventory, names);
        defer allocator.free(name);
        if (partition != 0) try report.writeAll(",");
        try report.print("\"{s}\"", .{name});
    }
    var lookup = try Provider.buildLookup(allocator);
    defer lookup.deinit();
    const name = try appendProviderKernel(metal.riscv_polynomial_codegen.lookup, lookup, source, inventory, names);
    defer allocator.free(name);
    try report.print("],\"lookup_kernel\":\"{s}\"}}", .{name});
}

fn appendFrameworkKernel(selected: codegen.Entry, source: *std.ArrayList(u8), inventory: *std.ArrayList(u8), names: *std.StringHashMap(void)) ![]u8 {
    const name = try codegen.kernelName(allocator, selected);
    errdefer allocator.free(name);
    if (!names.contains(name)) {
        const owned_name = try allocator.dupe(u8, name);
        names.put(owned_name, {}) catch |err| {
            allocator.free(owned_name);
            return err;
        };
        const start = source.items.len;
        try codegen.emitKernel(allocator, source.writer(allocator), name, selected);
        const digest = try metal.shaders.declaration_digest.declarationDigestHex(source.items[start..], name);
        try inventory.writer(allocator).print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n", .{ name, digest });
    }
    return name;
}

fn appendRangeProvider(source: *std.ArrayList(u8), inventory: *std.ArrayList(u8), coverage: *std.ArrayList(u8), names: *std.StringHashMap(void)) !void {
    const range = air.range_check_8_8_bridge;
    const relations = frontend.air.relation_challenges.Relations.dummy();
    const component = try frontend.air.lookups.tables.component.LookupTableComponent.initProver(
        range.TABLE_KIND,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        @import("stwo_core").fields.qm31.QM31.zero(),
    );
    const counts = [_]usize{ range.FRAMEWORK_PREPROCESSED_COLUMN_COUNT, range.PHYSICAL_MAIN_COLUMN_COUNT, range.INTERACTION_COLUMN_COUNT };
    var program = try range.exportFrameworkProgram(allocator, &component, &counts);
    defer program.deinit();
    const name = try appendFrameworkKernel(.{ .program = &program, .tree_column_counts = &counts }, source, inventory, names);
    defer allocator.free(name);
    try coverage.writer(allocator).print(",{{\"row\":35,\"layout\":\"independent-prefix-v1\",\"semantic_digest\":\"{s}\",\"kernel\":\"{s}\"}}]", .{ std.fmt.bytesToHex(range.SEMANTIC_DIGEST, .lower), name });
}

fn appendNativeTables(source: *std.ArrayList(u8), inventory: *std.ArrayList(u8), coverage: *std.ArrayList(u8), names: *std.StringHashMap(void)) !void {
    const tables = frontend.air.lookups.tables;
    const relations = frontend.air.relation_challenges.Relations.dummy();
    const report = coverage.writer(allocator);
    try report.writeAll(",\n  \"native_fixed_tables\": {\"covered_tables\":6,\"total_tables\":6,\"native_composition_coverage_complete\":false,\"unsupported_infrastructure\":[\"program\",\"memory\",\"merkle\",\"clock_update\"],\"tables\":[");
    for (std.meta.tags(tables.schema.Kind), 0..) |kind, index| {
        const arity = tables.schema.arity(kind);
        const tuple_columns = [_]usize{ 1, 2, 3, 4 };
        const component = try tables.component.LookupTableComponent.initProver(kind, 0, tuple_columns[0..arity], 0, 0, &relations, @import("stwo_core").fields.qm31.QM31.zero());
        const counts = [_]usize{ 1 + arity, 1, 4 };
        var program = try tables.framework_export.exportProgram(allocator, &component, &counts);
        defer program.deinit();
        const name = try appendFrameworkKernel(.{ .program = &program, .tree_column_counts = &counts }, source, inventory, names);
        defer allocator.free(name);
        if (index != 0) try report.writeAll(",");
        try report.print("{{\"kind\":\"{s}\",\"log_size\":{},\"tuple_arity\":{},\"kernel\":\"{s}\"}}", .{ @tagName(kind), tables.schema.logSize(kind), arity, name });
    }
    try report.writeAll("]}");
}

fn appendNativeTableInteractions(source: *std.ArrayList(u8), inventory: *std.ArrayList(u8), coverage: *std.ArrayList(u8), names: *std.StringHashMap(void)) !void {
    const tables = frontend.air.lookups.tables;
    const relations = frontend.air.relation_challenges.Relations.dummy();
    const report = coverage.writer(allocator);
    try source.appendSlice(allocator, interaction_codegen.scan_source);
    const scan_names = [_][]const u8{
        "stwo_zig_framework_interaction_block_scan_v1",
        "stwo_zig_framework_interaction_scan_blocks_v1",
        "stwo_zig_framework_interaction_finalize_v1",
    };
    try report.writeAll(",\n  \"native_table_interaction\": {\"covered_tables\":6,\"total_tables\":6,\"pipeline_integration_complete\":false,\"scan_kernels\":[");
    for (scan_names, 0..) |name, index| {
        try std.testing.expect(!names.contains(name));
        const owned_name = try allocator.dupe(u8, name);
        names.put(owned_name, {}) catch |err| {
            allocator.free(owned_name);
            return err;
        };
        const digest = try metal.shaders.declaration_digest.declarationDigestHex(interaction_codegen.scan_source, name);
        try inventory.writer(allocator).print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n", .{ name, digest });
        if (index != 0) try report.writeAll(",");
        try report.print("\"{s}\"", .{name});
    }
    try report.writeAll("],\"tables\":[");
    for (std.meta.tags(tables.schema.Kind), 0..) |kind, index| {
        const arity = tables.schema.arity(kind);
        const tuple_columns = [_]usize{ 1, 2, 3, 4 };
        const component = try tables.component.LookupTableComponent.initProver(kind, 0, tuple_columns[0..arity], 0, 0, &relations, @import("stwo_core").fields.qm31.QM31.zero());
        const counts = [_]usize{ 1 + arity, 1, 4 };
        var program = try tables.framework_export.exportProgram(allocator, &component, &counts);
        defer program.deinit();
        const selected = interaction_codegen.Entry{ .program = &program, .tree_column_counts = &counts };
        const name = try interaction_codegen.kernelName(allocator, selected);
        defer allocator.free(name);
        if (!names.contains(name)) {
            const owned_name = try allocator.dupe(u8, name);
            names.put(owned_name, {}) catch |err| {
                allocator.free(owned_name);
                return err;
            };
            const start = source.items.len;
            try interaction_codegen.emitKernel(allocator, source.writer(allocator), name, selected);
            const digest = try metal.shaders.declaration_digest.declarationDigestHex(source.items[start..], name);
            try inventory.writer(allocator).print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n", .{ name, digest });
        }
        if (index != 0) try report.writeAll(",");
        try report.print("{{\"kind\":\"{s}\",\"kernel\":\"{s}\"}}", .{ @tagName(kind), name });
    }
    try report.writeAll("]}");
}

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
    try report.writeAll("{\n  \"format\": \"recursive-framework-aot-coverage-v1\",\n  \"composition_coverage_scope\": \"detached_recursive_leaf_and_parent\",\n  \"composition_coverage_complete\": true,\n  \"strict_coverage_complete\": false,\n  \"profiles\": [\n");
    inline for (.{ air.segment_leaf_catalog_v2.LOGICAL_ROWS, air.detached_parent_catalog_v1.LOGICAL_ROWS }, .{ "leaf", "parent" }, 0..) |catalog, profile, profile_index| {
        if (profile_index != 0) try report.writeAll(",\n");
        try report.print("    {{\"name\":\"{s}\",\"typed_components\":{},\"covered_components\":{},\"total_components\":{},\"unsupported\":[],\"rows\":[", .{ profile, catalog.len, catalog.len + 2, catalog.len + 2 });
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
            const name = try appendFrameworkKernel(selected, &source, &inventory, &names);
            defer allocator.free(name);
            if (entry_index != 0) try report.writeAll(",");
            try report.print("{{\"row\":{},\"semantic_digest\":\"{s}\",\"kernel\":\"{s}\"}}", .{ @intFromEnum(entry.row), std.fmt.bytesToHex(Air.SEMANTIC_DIGEST, .lower), name });
        }
        try report.writeAll("]");
        try appendProvider(if (profile_index == 0) LegacyPoseidon else memory.poseidon2_universal_backend_v1, &source, &inventory, &coverage, &names);
        try appendRangeProvider(&source, &inventory, &coverage, &names);
        try report.writeAll("}");
    }
    try report.writeAll("\n  ]");
    try appendNativeTables(&source, &inventory, &coverage, &names);
    try appendNativeTableInteractions(&source, &inventory, &coverage, &names);
    try report.print(",\n  \"kernel_count\": {}\n}}\n", .{names.count()});
    try table.writeAll("};\n");
    const source_bytes = try source.toOwnedSlice(allocator);
    errdefer allocator.free(source_bytes);
    const inventory_bytes = try inventory.toOwnedSlice(allocator);
    errdefer allocator.free(inventory_bytes);
    return .{ .source = source_bytes, .inventory = inventory_bytes, .coverage = try coverage.toOwnedSlice(allocator) };
}

test "recursive framework AOT matches complete current typed and native provider composition catalogs" {
    try std.testing.expectEqual(@as(usize, 37), air.segment_leaf_catalog_v2.LOGICAL_ROWS.len);
    try std.testing.expectEqual(@as(usize, 29), air.detached_parent_catalog_v1.LOGICAL_ROWS.len);
    try std.testing.expectEqual(@as(usize, 6), std.meta.tags(frontend.air.lookups.tables.schema.Kind).len);
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
    std.debug.print("RECURSIVE_FRAMEWORK_AOT covered_leaf=39/39 covered_parent=31/31 native_fixed_tables=6/6 recursive_composition_coverage_complete=true native_composition_coverage_complete=false strict_coverage_complete=false bytes={}\n", .{generated.source.len});
}
