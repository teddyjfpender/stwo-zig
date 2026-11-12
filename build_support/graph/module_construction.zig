//! Canonical package-root construction shared by product assemblers.
const std = @import("std");
const package_ownership = @import("package_ownership.zig");
const ModuleSpec = @import("product_spec.zig").ModuleSpec;
const Product = @import("product_spec.zig").Product;
const ProtocolModules = @import("protocol_modules.zig").ProtocolModules;

pub fn create(b: *std.Build, spec: ModuleSpec) *std.Build.Module {
    spec.product.validate() catch |err| std.debug.panic(
        "invalid build product {s}: {s}",
        .{ spec.product.name, @errorName(err) },
    );
    return b.createModule(.{
        .root_source_file = ownedRootSource(b, spec),
        .target = spec.target,
        .optimize = spec.optimize,
    });
}

pub fn addPublic(b: *std.Build, name: []const u8, spec: ModuleSpec) *std.Build.Module {
    spec.product.validate() catch |err| std.debug.panic(
        "invalid public build product {s}: {s}",
        .{ spec.product.name, @errorName(err) },
    );
    return b.addModule(name, .{
        .root_source_file = ownedRootSource(b, spec),
        .target = spec.target,
        .optimize = spec.optimize,
    });
}

/// Resolves package-owned roots; other roots remain aggregate-relative.
fn ownedRootSource(b: *std.Build, spec: ModuleSpec) std.Build.LazyPath {
    return source(
        b,
        spec.root_source_file,
        spec.target,
        spec.optimize,
    );
}

pub fn source(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) std.Build.LazyPath {
    const owned = package_ownership.resolve(root_source_file) orelse
        return b.path(root_source_file);
    const dependency_options = .{
        .target = target,
        .optimize = optimize,
    };
    const dependency_name = package_ownership.dependencyName(owned.package);
    return b.dependency(dependency_name, dependency_options).path(owned.sub_path);
}

pub fn createProofWire(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const proof_wire = create(b, .{
        .product = product,
        .root_source_file = "src/waist/proof_wire/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    proof_wire.addImport("stwo_core", protocol.core);
    return proof_wire;
}
