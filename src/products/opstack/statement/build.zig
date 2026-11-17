const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const pipeline_package = b.dependency("stwo_riscv_rv64_pipeline", options);
    const template = pipeline_package.module("stwo_riscv_rv64_pipeline");
    // Declare the full published dependency closure; concrete instances come
    // from the pipeline template, which reads them from the CPU integration.
    _ = b.dependency("stwo_riscv_cpu_integration", options);
    _ = b.dependency("stwo_riscv_frontend", options);
    _ = b.dependency("stwo_riscv_rv64", options);
    const rv64 = template.import_table.get("stwo_riscv_rv64") orelse @panic("pipeline template lacks stwo_riscv_rv64");

    const frontend_component = b.createModule(.{ .root_source_file = b.path("frontend.zig"), .target = target, .optimize = optimize });
    frontend_component.addImport("stwo_riscv_rv64", rv64);
    const hooks = b.createModule(.{ .root_source_file = b.path("hooks.zig"), .target = target, .optimize = optimize });
    hooks.addImport("opstack_frontend_component", frontend_component);
    hooks.addImport("stwo_riscv_rv64", rv64);
    const pipeline = @import("stwo_riscv_rv64_pipeline").instantiate(b, template, hooks);
    const cpu_component = b.createModule(.{ .root_source_file = b.path("cpu.zig"), .target = target, .optimize = optimize });
    cpu_component.addImport("stwo_riscv_rv64_pipeline", pipeline);
    cpu_component.addImport("rv64_pipeline_hooks", hooks);
    const product = b.createModule(.{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    product.addImport("opstack_cpu_component", cpu_component);
    product.addImport("opstack_frontend_component", frontend_component);
    product.addImport("rv64_pipeline_hooks", hooks);
    product.addImport("stwo_riscv_rv64_pipeline", pipeline);
    b.modules.put("stwo_opstack_statement", product) catch @panic("OOM");

    const floor = @import("stwo_riscv_frontend").TestCountFloor;
    const owner = b.step("test", "Run OP Stack guest ABI, statement and hook contract suites");
    const unit = b.addRunArtifact(b.addTest(.{ .root_module = product }));
    unit.has_side_effects = true;
    owner.dependOn(&unit.step);
    owner.dependOn(floor.addMany(b, &.{unit}, 13));

    const fixture_paths = b.addOptions();
    fixture_paths.addOption([]const u8, "vectors_root", b.pathFromRoot("../../../../vectors/opstack"));
    const probe_root = b.createModule(.{ .root_source_file = b.path("tests/e2e_probe_test.zig"), .target = target, .optimize = optimize });
    probe_root.addImport("opstack_fixture_paths", fixture_paths.createModule());
    probe_root.addImport("opstack_frontend_component", frontend_component);
    probe_root.addImport("stwo_riscv_rv64", rv64);
    const probe = b.addRunArtifact(b.addTest(.{ .root_module = probe_root }));
    probe.has_side_effects = true;
    const probe_step = b.step("test-e2e-probe", "Pin the golden OP ABI probe, prove it, receive it in a fresh process and reject three corruptions");
    probe_step.dependOn(&probe.step);
    probe_step.dependOn(floor.addMany(b, &.{probe}, 4));

    const native_root = b.createModule(.{ .root_source_file = b.path("cpu/native_main.zig"), .target = target, .optimize = optimize });
    native_root.addImport("opstack_cpu_component", cpu_component);
    const native = b.addExecutable(.{ .name = "stwo-opstack-native", .root_module = native_root });
    // Production and every reception run as separate `stwo-opstack-native`
    // processes, so pipeline reports never reach the test runner's stdout.
    const driver_root = b.createModule(.{ .root_source_file = b.path("tests/e2e_probe_prove.zig"), .target = target, .optimize = optimize });
    const prove = b.addRunArtifact(b.addExecutable(.{ .name = "opstack-e2e-probe-prove", .root_module = driver_root }));
    prove.addArtifactArg(native);
    prove.addArg(b.pathFromRoot("../../../../vectors/opstack"));
    _ = prove.addOutputDirectoryArg("probe-work");
    prove.has_side_effects = true;
    probe_step.dependOn(&prove.step);
    const install = b.addInstallArtifact(native, .{});
    b.step("opstack-native", "Build stwo-opstack-native (native CPU production and fresh reception)").dependOn(&install.step);
    const check = b.addExecutable(.{ .name = "stwo-opstack-native-check", .root_module = native_root });
    b.step("check-opstack-native", "Compile stwo-opstack-native without installing it").dependOn(&check.step);
}
