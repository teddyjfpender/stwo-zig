//! Typed waist consumer records shared by build construction and catalog projection.

const std = @import("std");
const ownership = @import("../graph/package_ownership.zig");

pub const Consumer = struct {
    id: []const u8,
    root: []const u8,
    route: []const u8,
    imports: []const []const u8,
    tests: []const []const u8,
    owner_module: ?[]const u8 = null,
};

pub const waist_providers = [_]struct { name: []const u8, directory: []const u8 }{
    .{ .name = "stwo_core", .directory = "core" },
    .{ .name = "stwo_backend_contracts", .directory = "backend" },
    .{ .name = "stwo_prover_api", .directory = "prover_api" },
    .{ .name = "stwo_proof_wire", .directory = "proof_wire" },
    .{ .name = "stwo_circuit_recursion_wire", .directory = "recursion_wire" },
};

pub fn consumerAliasName(b: *std.Build, provider: []const u8, consumer: []const u8) []const u8 {
    // Keep underscores to distinguish provider and consumer tuple boundaries.
    const name = b.allocator.dupe(u8, b.fmt("test-cdc-one-{s}-{s}", .{ provider, consumer })) catch @panic("OOM");
    for (name) |*character| if (character.* == ':') {
        character.* = '-';
    };
    return name;
}

pub fn providerConsumers(b: *std.Build, directory: []const u8) []const Consumer {
    const bytes = std.fs.cwd().readFileAlloc(b.allocator, b.pathFromRoot(b.fmt("src/waist/{s}/package.contract.json", .{directory})), 1 << 20) catch @panic("read waist consumer metadata");
    const parsed = std.json.parseFromSlice(std.json.Value, b.allocator, bytes, .{}) catch @panic("parse waist consumer metadata");
    const rows = parsed.value.object.get("consumers") orelse @panic("waist consumer metadata missing");
    return (std.json.parseFromValue([]Consumer, b.allocator, rows, .{}) catch @panic("invalid waist consumer records")).value;
}

pub fn withWaistConsumerRoots(b: *std.Build, roots: []const []const u8, kind: enum { package_roots, product_roots }) []const []const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    result.appendSlice(b.allocator, roots) catch @panic("OOM");
    for (waist_providers) |provider| {
        for (providerConsumers(b, provider.directory)) |consumer| {
            const is_product = std.mem.startsWith(u8, consumer.id, "product:");
            if (is_product != (kind == .product_roots)) continue;
            if (is_product) {
                result.append(b.allocator, consumer.root) catch @panic("OOM");
                continue;
            }
            const owner = ownership.resolve(consumer.root) orelse @panic("unowned waist consumer");
            const directory = consumer.root[0 .. consumer.root.len - owner.sub_path.len - 1];
            result.append(b.allocator, b.fmt("dependency:../{s}:{s}", .{ directory, owner.sub_path })) catch @panic("OOM");
        }
    }
    return result.toOwnedSlice(b.allocator) catch @panic("OOM");
}
