//! Explicit Ethereum-only extension. Does not regenerate the core/CSP roster.
const std = @import("std");
const backend = @import("stwo_metal_backend");
const codegen = backend.riscv_polynomial_codegen;
const narrow = @import("stwo_riscv_frontend").testing.component_proof.narrow_backend;

pub fn generate(allocator: std.mem.Allocator) !struct { source: []u8, inventory: []u8 } {
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    var inventory = std.ArrayList(u8).empty;
    errdefer inventory.deinit(allocator);
    const writer = source.writer(allocator);
    const table = inventory.writer(allocator);
    try writer.writeAll("// Generated Ethereum fixed-program/narrow-Poseidon profile v1.\n// Generator: src/tests/riscv/ethereum_narrow_aot_generator_test.zig\n// Regenerate: STWO_ETHEREUM_NARROW_AOT_GENERATE=<directory> python3 scripts/zig_protocol_test.py src/tests/riscv/ethereum_narrow_aot_generator_test.zig -O ReleaseSafe\n");
    try table.writeAll("// Generated Ethereum-only export/declaration authority.\npub const entries = .{\n");
    for (0..narrow.DIRECT_PARTITION_COUNT) |partition| {
        var program = try narrow.buildDirect(allocator, partition);
        defer program.deinit();
        const name = try codegen.base.kernelName(allocator, program);
        defer allocator.free(name);
        const start = source.items.len;
        try codegen.base.emitKernel(allocator, writer, name, program);
        const digest = try backend.shaders.declaration_digest.declarationDigestHex(source.items[start..], name);
        try table.print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n", .{ name, digest });
    }
    var lookup = try narrow.buildLookup(allocator);
    defer lookup.deinit();
    const name = try codegen.lookup.kernelName(allocator, lookup);
    defer allocator.free(name);
    const start = source.items.len;
    try codegen.lookup.emitKernel(allocator, writer, name, lookup);
    const digest = try backend.shaders.declaration_digest.declarationDigestHex(source.items[start..], name);
    try table.print("    .{{ .name = \"{s}\", .declaration_sha256 = \"{s}\" }},\n}};\n", .{ name, digest });
    const source_bytes = try source.toOwnedSlice(allocator);
    errdefer allocator.free(source_bytes);
    return .{ .source = source_bytes, .inventory = try inventory.toOwnedSlice(allocator) };
}

test "Ethereum narrow AOT extension matches production DAG authority" {
    const allocator = std.testing.allocator;
    const generated = try generate(allocator);
    defer allocator.free(generated.source);
    defer allocator.free(generated.inventory);
    const directory_path = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_NARROW_AOT_GENERATE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            try std.testing.expectEqualStrings(backend.shaders.aot_profile.ethereum_extension_source, generated.source);
            try std.testing.expectEqualStrings(backend.shaders.aot_profile.ethereum_inventory_source, generated.inventory);
            return;
        },
        else => return err,
    };
    defer allocator.free(directory_path);
    var directory = try std.fs.cwd().makeOpenPath(directory_path, .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = "ethereum_fixed_program_narrow_v1.metal", .data = generated.source });
    try directory.writeFile(.{ .sub_path = "ethereum_fixed_program_narrow_v1_exports.zig", .data = generated.inventory });
    std.debug.print("ETHEREUM_AOT_EXTENSION kernels=5 bytes={} core_roster_unchanged=true\n", .{generated.source.len});
}
