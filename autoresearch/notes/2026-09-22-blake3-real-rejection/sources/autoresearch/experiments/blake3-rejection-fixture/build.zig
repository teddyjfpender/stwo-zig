const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.createModule(.{ .root_source_file = b.path("../../../src/core/mod.zig"), .target = target, .optimize = optimize });
    const main = b.createModule(.{ .root_source_file = b.path("main.zig"), .target = target, .optimize = optimize });
    main.addImport("core", core);
    const exe = b.addExecutable(.{ .name = "blake3-rejection-fixture", .root_module = main });
    b.step("search", "Bounded native rejection fixture search").dependOn(&b.addRunArtifact(exe).step);
}
