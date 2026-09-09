//! Explicit shader authorities. The core/CSP inventory remains byte-identical;
//! Ethereum's additional DAGs require a separate authenticated bundle.
const std = @import("std");
const manifest = @import("manifest.zig");
const abi = @import("abi_contract.zig");
const generated = @import("ethereum_fixed_program_narrow_v1_exports.zig");
const recursive_generated = @import("recursive_framework_v1_exports.zig");
pub const maximum_additional_exports = @max(generated.entries.len, recursive_generated.entries.len);
pub const recursive_inventory_source = @embedFile("recursive_framework_v1_exports.zig");
pub const recursive_extension_source = @embedFile("recursive_framework_v1.metal");
pub const recursive_coverage_source = @embedFile("recursive_framework_v1_coverage.json");
pub const ethereum_inventory_source = @embedFile("ethereum_fixed_program_narrow_v1_exports.zig");
pub const ethereum_extension_source = @embedFile("ethereum_fixed_program_narrow_v1.metal");
const core_source = manifest.native_amalgamated_source[0 .. manifest.native_amalgamated_source.len - 1];
const ethereum_source = core_source ++ "\n" ++ ethereum_extension_source;
const recursive_source = core_source ++ "\n" ++ recursive_extension_source;

pub const Profile = enum(u16) {
    core_v2 = 0,
    ethereum_fixed_program_narrow_v1 = 1,
    recursive_framework_v1 = 2,

    pub fn source(self: Profile) []const u8 {
        return switch (self) {
            .core_v2 => core_source,
            .ethereum_fixed_program_narrow_v1 => ethereum_source,
            .recursive_framework_v1 => recursive_source,
        };
    }
    pub fn sourceDigest(self: Profile) [32]u8 {
        var result: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.source(), &result, .{});
        return result;
    }
    pub fn exports(self: Profile) []const manifest.Export {
        return switch (self) {
            .core_v2 => &manifest.native_exports,
            .ethereum_fixed_program_narrow_v1 => &ethereum_exports,
            .recursive_framework_v1 => &recursive_exports,
        };
    }
    pub fn additionalPolynomialExports(self: Profile) []const manifest.Export {
        return self.exports()[manifest.native_exports.len..];
    }
    pub fn kernelAbi(self: Profile) []const abi.KernelAbi {
        return switch (self) {
            .core_v2 => &abi.native_kernel_abi,
            .ethereum_fixed_program_narrow_v1 => &ethereum_abi,
            .recursive_framework_v1 => &recursive_abi,
        };
    }
};

const ethereum_exports = build: {
    var result: [manifest.native_exports.len + generated.entries.len]manifest.Export = undefined;
    @memcpy(result[0..manifest.native_exports.len], &manifest.native_exports);
    for (generated.entries, manifest.native_exports.len..) |entry, index| result[index] = .{ .name = entry.name, .owner = .riscv_polynomials };
    break :build result;
};
const ethereum_abi = build: {
    var result: [abi.native_kernel_abi.len + generated.entries.len]abi.KernelAbi = undefined;
    @memcpy(result[0..abi.native_kernel_abi.len], &abi.native_kernel_abi);
    for (generated.entries, abi.native_kernel_abi.len..) |entry, index| result[index] = .{ .name = entry.name, .owner = .riscv_polynomials, .minimum_core_shader_abi = manifest.core_shader_abi, .declaration_sha256 = entry.declaration_sha256, .function_constants = &.{} };
    break :build result;
};

test "Ethereum AOT profile preserves exact core authority and admits five separate declarations" {
    try std.testing.expectEqualStrings(core_source, Profile.core_v2.source());
    try std.testing.expectEqualDeep(manifest.nativeAmalgamatedSourceDigest(), Profile.core_v2.sourceDigest());
    // Pin the previously measured baseline, not merely two views of new code.
    try std.testing.expectEqualStrings("c2daaaf7dab998e6c542651dec73323973eafceee6ccf9d56fce6094ccac2786", &std.fmt.bytesToHex(Profile.core_v2.sourceDigest(), .lower));
    try std.testing.expectEqual(@as(usize, 166), Profile.core_v2.exports().len);
    try std.testing.expectEqualDeep(manifest.native_exports[0..], Profile.core_v2.exports());
    try std.testing.expectEqualDeep(abi.native_kernel_abi[0..], Profile.core_v2.kernelAbi());
    try std.testing.expectEqual(@as(usize, 171), Profile.ethereum_fixed_program_narrow_v1.exports().len);
    try std.testing.expect(!std.meta.eql(Profile.core_v2.sourceDigest(), Profile.ethereum_fixed_program_narrow_v1.sourceDigest()));
    inline for (generated.entries) |entry| {
        const digest = try @import("abi_declaration_digest.zig").declarationDigestHex(ethereum_extension_source, entry.name);
        try std.testing.expectEqualStrings(entry.declaration_sha256, &digest);
        for (manifest.native_exports) |old| try std.testing.expect(!std.mem.eql(u8, old.name, entry.name));
    }
}

const recursive_exports = build: {
    var result: [manifest.native_exports.len + recursive_generated.entries.len]manifest.Export = undefined;
    @memcpy(result[0..manifest.native_exports.len], &manifest.native_exports);
    for (recursive_generated.entries, manifest.native_exports.len..) |entry, index| result[index] = .{ .name = entry.name, .owner = .riscv_polynomials };
    break :build result;
};
const recursive_abi = build: {
    var result: [abi.native_kernel_abi.len + recursive_generated.entries.len]abi.KernelAbi = undefined;
    @memcpy(result[0..abi.native_kernel_abi.len], &abi.native_kernel_abi);
    for (recursive_generated.entries, abi.native_kernel_abi.len..) |entry, index| result[index] = .{ .name = entry.name, .owner = .riscv_polynomials, .minimum_core_shader_abi = manifest.core_shader_abi, .declaration_sha256 = entry.declaration_sha256, .function_constants = &.{} };
    break :build result;
};

test "recursive framework AOT profile preserves core authority and exact declaration coverage" {
    try std.testing.expectEqualDeep(manifest.native_exports[0..], Profile.recursive_framework_v1.exports()[0..manifest.native_exports.len]);
    try std.testing.expectEqualDeep(abi.native_kernel_abi[0..], Profile.recursive_framework_v1.kernelAbi()[0..abi.native_kernel_abi.len]);
    try std.testing.expect(recursive_generated.entries.len > 0);
    inline for (recursive_generated.entries) |entry| {
        const digest = try @import("abi_declaration_digest.zig").declarationDigestHex(recursive_extension_source, entry.name);
        try std.testing.expectEqualStrings(entry.declaration_sha256, &digest);
        for (manifest.native_exports) |old| try std.testing.expect(!std.mem.eql(u8, old.name, entry.name));
    }
    const coverage = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, recursive_coverage_source, .{});
    defer coverage.deinit();
    try std.testing.expect(!coverage.value.object.get("strict_coverage_complete").?.bool);
    try std.testing.expect(coverage.value.object.get("composition_coverage_complete").?.bool);
    try std.testing.expectEqual(@as(i64, recursive_generated.entries.len), coverage.value.object.get("kernel_count").?.integer);
    const native_tables = coverage.value.object.get("native_fixed_tables").?.object;
    try std.testing.expectEqual(@as(i64, 6), native_tables.get("covered_tables").?.integer);
    try std.testing.expectEqual(@as(i64, 6), native_tables.get("total_tables").?.integer);
    try std.testing.expectEqual(@as(usize, 6), native_tables.get("tables").?.array.items.len);
    try std.testing.expect(!native_tables.get("native_composition_coverage_complete").?.bool);
    const interactions = coverage.value.object.get("native_table_interaction").?.object;
    try std.testing.expectEqual(@as(i64, 6), interactions.get("covered_tables").?.integer);
    try std.testing.expectEqual(@as(i64, 6), interactions.get("total_tables").?.integer);
    try std.testing.expect(!interactions.get("pipeline_integration_complete").?.bool);
    const scan_kernels = interactions.get("scan_kernels").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), scan_kernels.len);
    for (scan_kernels) |kernel| try expectRecursiveOnlyExport(kernel.string);
    const interaction_tables = interactions.get("tables").?.array.items;
    try std.testing.expectEqual(@as(usize, 6), interaction_tables.len);
    for (interaction_tables) |table| try expectRecursiveOnlyExport(table.object.get("kernel").?.string);
    for (coverage.value.object.get("profiles").?.array.items) |profile| {
        try std.testing.expectEqual(profile.object.get("total_components").?.integer, profile.object.get("covered_components").?.integer);
        try std.testing.expectEqual(@as(usize, 0), profile.object.get("unsupported").?.array.items.len);
        const providers = profile.object.get("native_providers").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), providers.len);
        for (providers, 34..) |provider, row|
            try std.testing.expectEqual(@as(i64, @intCast(row)), provider.object.get("row").?.integer);
    }
}

fn expectRecursiveOnlyExport(name: []const u8) !void {
    var found = false;
    for (Profile.recursive_framework_v1.exports()) |entry| if (std.mem.eql(u8, entry.name, name)) {
        found = true;
        break;
    };
    try std.testing.expect(found);
    for (Profile.core_v2.exports()) |entry| try std.testing.expect(!std.mem.eql(u8, entry.name, name));
    for (Profile.ethereum_fixed_program_narrow_v1.exports()) |entry| try std.testing.expect(!std.mem.eql(u8, entry.name, name));
}
