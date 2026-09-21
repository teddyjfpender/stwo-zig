//! Native Metal kernel ABI authority derived from the shader declarations.

const std = @import("std");
const manifest = @import("manifest.zig");

pub const FunctionConstant = struct {
    index: u16,
    name: []const u8,
    msl_type: []const u8,
    specialization_value: []const u8,
};

pub const KernelAbi = struct {
    name: []const u8,
    owner: manifest.Unit,
    minimum_core_shader_abi: u32,
    declaration_sha256: []const u8,
    function_constants: []const FunctionConstant,
};

const empty_function_constants = [_]FunctionConstant{};

const declaration_digest = @import("abi_declaration_digest.zig");
const generated = @import("abi_declaration_digests.zig");

// The digest table is generated natively (`zig build update-abi-declaration-
// digests`) instead of at comptime: searching the amalgamated shader source
// once per export in the comptime interpreter cost about nine minutes per
// build. Name alignment is enforced here at comptime, which is 166 short
// string comparisons; digest freshness is enforced by the runtime test below.
comptime {
    if (generated.entries.len != manifest.native_exports.len) {
        @compileError("abi_declaration_digests.zig is stale: run `zig build update-abi-declaration-digests` in src/backends/metal");
    }
    for (manifest.native_exports, generated.entries) |entry, row| {
        if (!std.mem.eql(u8, entry.name, row.name)) {
            @compileError("abi_declaration_digests.zig is stale: run `zig build update-abi-declaration-digests` in src/backends/metal");
        }
    }
}

/// Ordered ABI table serialized into the authenticated core-library manifest.
/// There are currently no Native function constants; each empty inventory is
/// intentional and makes adding a specialization an explicit ABI change.
pub const native_kernel_abi: [manifest.native_exports.len]KernelAbi = build: {
    var result: [manifest.native_exports.len]KernelAbi = undefined;
    for (manifest.native_exports, 0..) |entry, index| {
        result[index] = .{
            .name = entry.name,
            .owner = entry.owner,
            .minimum_core_shader_abi = manifest.core_shader_abi,
            .declaration_sha256 = generated.entries[index].declaration_sha256[0..],
            .function_constants = empty_function_constants[0..],
        };
    }
    break :build result;
};

test "generated declaration digests match the amalgamated shader source" {
    for (manifest.native_exports, native_kernel_abi) |entry, abi| {
        const expected = try declaration_digest.declarationDigestHex(
            manifest.native_amalgamated_source,
            entry.name,
        );
        try std.testing.expectEqualStrings(&expected, abi.declaration_sha256);
    }
}

test "every Native export has exactly one ordered ABI entry" {
    try std.testing.expectEqual(manifest.native_exports.len, native_kernel_abi.len);
    for (manifest.native_exports, native_kernel_abi, 0..) |entry, abi, index| {
        try std.testing.expectEqualStrings(entry.name, abi.name);
        try std.testing.expectEqual(entry.owner, abi.owner);
        try std.testing.expectEqual(manifest.core_shader_abi, abi.minimum_core_shader_abi);
        try std.testing.expectEqual(@as(usize, 64), abi.declaration_sha256.len);
        try std.testing.expectEqual(@as(usize, 0), abi.function_constants.len);
        for (native_kernel_abi[index + 1 ..]) |other|
            try std.testing.expect(!std.mem.eql(u8, abi.name, other.name));
    }
}

test "function-constant authority is explicitly empty" {
    try std.testing.expectEqual(
        @as(usize, 0),
        std.mem.count(u8, manifest.native_amalgamated_source, "function_constant"),
    );
    for (native_kernel_abi) |abi|
        try std.testing.expectEqual(@as(usize, 0), abi.function_constants.len);
}
