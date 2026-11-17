const std = @import("std");
const Module = std.Build.Module;

/// Shared owners the pipeline reads from the selected CPU integration; one
/// concrete instance each, never rebuilt against another protocol graph.
const cpu_owned = [_][]const u8{ "stwo_circuit_cpu_integration", "stwo_prover_engine", "stwo_riscv_frontend" };
const frontend_owned = [_][]const u8{ "stwo_riscv_precompiles", "stwo_riscv_rv64" };

/// BUILD-only: bind one pipeline instance to one product's hooks module. Each
/// product owns its instance; the published template is never compiled alone.
pub fn instantiate(b: *std.Build, template: *Module, hooks: *Module) *Module {
    const result = b.createModule(.{ .root_source_file = template.root_source_file, .target = template.resolved_target, .optimize = template.optimize });
    for (template.import_table.keys(), template.import_table.values()) |name, dependency| result.addImport(name, dependency);
    result.addImport("rv64_pipeline_hooks", hooks);
    return result;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const riscv_cpu = b.dependency("stwo_riscv_cpu_integration", options).module("stwo_riscv_cpu_integration");
    // Declare the full published dependency closure; instances are read below.
    _ = b.dependency("stwo_circuit_cpu_integration", options);
    _ = b.dependency("stwo_prover_engine", options);
    _ = b.dependency("stwo_riscv_frontend", options);
    _ = b.dependency("stwo_riscv_precompiles", options);
    _ = b.dependency("stwo_riscv_rv64", options);
    const module = b.addModule("stwo_riscv_rv64_pipeline", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    module.addImport("stwo_riscv_cpu_integration", riscv_cpu);
    for (cpu_owned) |name| module.addImport(name, riscv_cpu.import_table.get(name) orelse @panic("selected CPU integration lacks a pipeline owner"));
    const frontend = riscv_cpu.import_table.get("stwo_riscv_frontend").?;
    for (frontend_owned) |name| module.addImport(name, frontend.import_table.get(name) orelse @panic("selected RISC-V frontend lacks a pipeline owner"));

    const example = b.createModule(.{ .root_source_file = b.path("tests/example_hooks.zig"), .target = target, .optimize = optimize });
    example.addImport("stwo_riscv_rv64", module.import_table.get("stwo_riscv_rv64").?);
    const instance = instantiate(b, module, example);
    const run = b.addRunArtifact(b.addTest(.{ .root_module = instance }));
    run.has_side_effects = true;
    const step = b.step("test", "Run the pipeline hook contract, terminal, receiver, resource and plan suites against the reference hooks");
    step.dependOn(&run.step);
    step.dependOn(@import("stwo_riscv_frontend").TestCountFloor.addMany(b, &.{run}, 20));
}
