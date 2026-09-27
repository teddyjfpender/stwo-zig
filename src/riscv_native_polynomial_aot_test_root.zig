//! Bounded source-only admission of actual native GPU capability exports.
const std = @import("std");
const exporter = @import("riscv_native_polynomial_aot_export.zig");
const codegen = exporter.codegen;
const trace = @import("frontends/riscv/runner/trace.zig");
const semantic_eval = @import("frontends/riscv/air/semantic_eval.zig");
const embedded = @embedFile("backends/metal/shaders/core/riscv_polynomials.metal");
const runtime = @embedFile("backends/metal/runtime.m");
const shader_manifest = @import("backends/metal/shaders/manifest.zig");

test "native GPU inventory: actual capability exports cover every legacy and local-zero family" {
    const a = std.testing.allocator;
    var inventory = try exporter.Inventory.init(a);
    defer inventory.deinit();
    var families: usize = 0;
    for (0..trace.N_FAMILIES) |i| {
        const family: trace.OpcodeFamily = @enumFromInt(i);
        if (!semantic_eval.isTraceCompatible(family)) continue;
        families += 1;
        for ([_]u64{ 1, 7 }) |namespace| {
            const id = (namespace << 32) | i;
            var found: usize = 0;
            for (inventory.base.items) |entry| {
                if (entry.program_id != id) continue;
                found += 1;
                try entry.program.validate();
                const name = try codegen.base.kernelName(a, entry.program);
                defer a.free(name);
                try expectAdmitted(name);
            }
            try std.testing.expectEqual(@as(usize, 1), found);
        }
        for ([_]u64{ 2, 8 }) |namespace| {
            const id = (namespace << 32) | i;
            var found: usize = 0;
            for (inventory.lookup.items) |entry| {
                if (entry.program_id != id) continue;
                found += 1;
                try entry.program.validate();
                const name = try codegen.lookup.kernelName(a, entry.program);
                defer a.free(name);
                try expectAdmitted(name);
            }
            try std.testing.expectEqual(@as(usize, 1), found);
        }
    }
    try std.testing.expect(families != 0);
    try std.testing.expectEqual(families, inventory.lookup_v2.items.len);
    const source = try codegen.aot.generateLibrary(a, inventory.base.items, inventory.lookup.items, inventory.lookup_v2.items);
    defer a.free(source);
    try std.testing.expectEqualStrings(embedded, source);
    var manifest_count: usize = 0;
    for (shader_manifest.exports) |entry| {
        if (!nativeKernel(entry.name)) continue;
        manifest_count += 1;
        try expectAdmitted(entry.name);
    }
    const count = std.mem.count(u8, source, "kernel void ");
    try std.testing.expectEqual(count, manifest_count);
    try std.testing.expectEqual(count, std.mem.count(u8, runtime, "NSString *riscvPolynomialName"));
}

test "native GPU inventory: cache namespaces reject retained-provider aliasing" {
    var inventory = try exporter.Inventory.init(std.testing.allocator);
    defer inventory.deinit();
    try inventory.validateProgramIds();
    const original_base = inventory.base.items[0].program_id;
    inventory.base.items[0].program_id = inventory.base.items[inventory.base.items.len - 1].program_id;
    try std.testing.expectError(error.DuplicateBasePolynomialProgramId, inventory.validateProgramIds());
    inventory.base.items[0].program_id = original_base;
    const original_lookup = inventory.lookup.items[0].program_id;
    inventory.lookup.items[0].program_id = inventory.lookup.items[inventory.lookup.items.len - 1].program_id;
    try std.testing.expectError(error.DuplicateLookupPolynomialProgramId, inventory.validateProgramIds());
    inventory.lookup.items[0].program_id = original_lookup;
    try inventory.validateProgramIds();
}

test "native GPU inventory: altered local-zero DAG cannot reuse admitted kernel identity" {
    const a = std.testing.allocator;
    var inventory = try exporter.Inventory.init(a);
    defer inventory.deinit();
    var altered: usize = 0;
    for (inventory.base.items) |*entry| {
        if (entry.program_id >> 32 != 7) continue;
        const original = try codegen.base.kernelName(a, entry.program);
        defer a.free(original);
        try expectAdmitted(original);
        for (entry.program.nodes) |*node| {
            if (node.op != .constant) continue;
            const saved = node.value;
            node.value = (saved + 1) % @import("stwo_core").fields.m31.Modulus;
            defer node.value = saved;
            const changed = try codegen.base.kernelName(a, entry.program);
            defer a.free(changed);
            try std.testing.expect(!std.mem.eql(u8, original, changed));
            try std.testing.expect(!shader_manifest.testing.manifestContains(changed));
            try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, runtime, changed));
            altered += 1;
            break;
        }
    }
    try std.testing.expect(altered != 0);
}

test "native GPU inventory: executable deduplication still validates every authority" {
    const a = std.testing.allocator;
    var inventory = try exporter.Inventory.init(a);
    defer inventory.deinit();
    // Repeated placement/program IDs may share a kernel. A second V2 entry
    // must nevertheless prove its own pinned authority before deduplication.
    var duplicate = inventory.lookup_v2.items[0];
    duplicate.authority.component_identity[0] ^= 1;
    const repeated = [_]codegen.lookup_v2.Entry{ inventory.lookup_v2.items[0], duplicate };
    try std.testing.expectError(error.InvalidComponentIdentity, codegen.aot.generateLibrary(a, inventory.base.items[0..1], inventory.lookup.items[0..1], &repeated));
}

fn expectAdmitted(name: []const u8) !void {
    try std.testing.expect(shader_manifest.testing.manifestContains(name));
    try std.testing.expectEqual(@as(usize, 1), shader_manifest.testing.countKernelDeclarations(embedded, name));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, runtime, name));
}

fn nativeKernel(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "stwo_zig_base_poly_") or std.mem.startsWith(u8, name, "stwo_zig_lookup_poly_");
}
