const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const opts = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", opts).module("stwo_core");
    const cpu = b.dependency("stwo_cpu_backend", opts).module("stwo_cpu_backend");
    const backend = b.dependency("stwo_bend_backend", opts).module("stwo_bend_backend");
    const prover = b.dependency("stwo_prover_engine", opts).module("stwo_prover_engine");
    const frontend = b.dependency("stwo_riscv_frontend", opts).module("stwo_riscv_frontend");
    const integration = b.addModule("stwo_riscv_bend_integration", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    integration.addImport("stwo_bend_backend", backend);
    integration.addImport("stwo_cpu_backend", cpu);
    integration.addImport("stwo_riscv_frontend", frontend);
    const options = b.addOptions();
    options.addOption([]const u8, "executable", b.option([]const u8, "bend-executable", "Pinned Bend native runner") orelse "/not-installed/stwo-bend");
    const csp = b.createModule(.{ .root_source_file = b.path("csp_benchmark.zig"), .target = target, .optimize = optimize });
    csp.addOptions("config", options);
    csp.addImport("stwo_core", core);
    csp.addImport("postcard", frontend.import_table.get("interop_postcard").?);
    csp.addImport("stwo_prover_engine", prover);
    csp.addImport("stwo_riscv_frontend", frontend);
    csp.addImport("stwo_cpu_backend", cpu);
    csp.addImport("stwo_bend_backend", backend);
    b.installArtifact(b.addExecutable(.{ .name = "bend-csp-bench", .root_module = csp }));
    b.step("test", "Test the experimental engine binding").dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = integration })).step);
}
