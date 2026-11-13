const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const dep0 = b.dependency("stwo_core", options).module("stwo_core");
    const dep1 = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const dep2 = b.dependency("stwo_riscv_air_lang", options).module("stwo_riscv_air_lang");
    const dep3 = b.dependency("stwo_riscv_memory", options).module("stwo_riscv_memory");
    const dep4 = b.dependency("stwo_riscv_isa", options).module("stwo_riscv_isa");
    const module = b.addModule("stwo_riscv_recursion_air", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    module.addImport("stwo_core", dep0);
    module.addImport("stwo_prover_engine", dep1);
    module.addImport("stwo_riscv_air_lang", dep2);
    module.addImport("stwo_riscv_memory", dep3);
    module.addImport("stwo_riscv_isa", dep4);
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;
    run.setEnvironmentVariable("STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS", "1");
    b.step("test", "Run the owned contract and behavior suite").dependOn(&run.step);
}
