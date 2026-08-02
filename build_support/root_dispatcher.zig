//! Public build-step registry and focused delegation boundary.

const std = @import("std");
const catalog = @import("products/catalog.zig");
const libraries = @import("products/libraries.zig");
const matrix = @import("products/matrix.zig");
const delegation = @import("graph/delegation.zig");

pub fn add(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // Dependency builds need the package's public module table. Root command
    // dispatch builds no module until its selected delegated scope runs.
    if (b.pkg_hash.len != 0) {
        _ = libraries.addPublicModules(.{ .b = b, .target = target, .optimize = optimize });
    } else {
        addPackageDistribution(b);
    }
    const options = delegation.Options.read(b);
    matrix.addRootProxies(b, target, optimize, options);
    for (catalog.steps) |spec| delegation.addProxy(
        b,
        target,
        optimize,
        options,
        spec.name,
        spec.description,
        @tagName(spec.scope),
    );
    delegation.addInstallProxy(b, target, optimize, options);
}

fn addPackageDistribution(b: *std.Build) void {
    const output = b.option(
        []const u8,
        "package-dist-dir",
        "Directory for deterministic Zig source package archives",
    ) orelse "zig-out/packages";
    const allow_dirty = b.option(
        bool,
        "package-dist-allow-dirty",
        "Allow local diagnostic archives from a dirty source tree",
    ) orelse false;
    const command = b.addSystemCommand(&.{
        "python3",
        "scripts/package_release.py",
        "--output",
        output,
    });
    if (allow_dirty) command.addArg("--allow-dirty");
    b.step(
        "package-dist",
        "Build deterministic dependency-closed Zig package archives",
    ).dependOn(&command.step);
}
