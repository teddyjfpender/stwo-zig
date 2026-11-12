const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const neutral_frontend = b.dependency("stwo_riscv_frontend", options).module("stwo_riscv_frontend");
    const neutral_cpu = b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration");
    const neutral_cuda = b.dependency("stwo_riscv_cuda_integration", options).module("stwo_riscv_cuda_integration");
    const frontend_component = b.createModule(.{ .root_source_file = b.path("frontend.zig"), .target = target, .optimize = optimize });
    frontend_component.addImport("stwo_riscv_frontend", neutral_frontend);
    frontend_component.addImport("interop_postcard", neutral_cpu.import_table.get("interop_postcard").?);
    const cpu_component = b.createModule(.{ .root_source_file = b.path("cpu.zig"), .target = target, .optimize = optimize });
    cpu_component.addImport("stwo_riscv_cpu_integration", neutral_cpu);
    cpu_component.addImport("ethereum_frontend_component", frontend_component);
    const cuda_component = b.createModule(.{ .root_source_file = b.path("cuda.zig"), .target = target, .optimize = optimize });
    cuda_component.addImport("stwo_riscv_cuda_integration", neutral_cuda);
    cuda_component.addImport("ethereum_frontend_component", frontend_component);
    cuda_component.addImport("ethereum_cpu_component", cpu_component);
    const product = b.addModule("stwo_ethereum_statement", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    product.addImport("stwo_riscv_frontend", neutral_frontend);
    product.addImport("ethereum_frontend_component", frontend_component);
    product.addImport("ethereum_cpu_component", cpu_component);
    product.addImport("ethereum_cuda_component", cuda_component);
    b.modules.put(b.allocator, "legacy_riscv_frontend", frontend_component) catch @panic("OOM");
    b.modules.put(b.allocator, "legacy_riscv_cpu_integration", cpu_component) catch @panic("OOM");
    product.addImport("legacy_riscv_frontend", frontend_component);
    product.addImport("legacy_riscv_cpu_integration", cpu_component);
    if (b.modules.get("legacy_riscv_frontend") != frontend_component or
        b.modules.get("legacy_riscv_cpu_integration") != cpu_component or
        product.import_table.get("ethereum_frontend_component") != frontend_component or
        product.import_table.get("ethereum_cpu_component") != cpu_component or
        cpu_component.import_table.get("ethereum_frontend_component") != frontend_component or
        cuda_component.import_table.get("ethereum_cpu_component") != cpu_component)
        @panic("Ethereum component identity drift");
    const tests = b.addTest(.{ .root_module = product });
    b.step("test", "Run Ethereum product contracts").dependOn(&b.addRunArtifact(tests).step);
}
