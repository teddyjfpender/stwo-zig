const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const dep0 = b.dependency("stwo_core", options).module("stwo_core");
    const dep1 = b.dependency("stwo_prover_api", options).module("stwo_prover_api");
    const dep2 = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const dep3 = b.dependency("stwo_riscv_air_lang", options).module("stwo_riscv_air_lang");
    const dep4 = b.dependency("stwo_riscv_isa", options).module("stwo_riscv_isa");
    const dep5 = b.dependency("stwo_riscv_memory", options).module("stwo_riscv_memory");
    const dep6 = b.dependency("stwo_riscv_precompiles", options).module("stwo_riscv_precompiles");
    const dep7 = b.dependency("stwo_riscv_recursion_air", options).module("stwo_riscv_recursion_air");
    const dep8 = b.dependency("stwo_riscv_rv32", options).module("stwo_riscv_rv32");
    const module = b.addModule("stwo_riscv_recursion", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    module.addImport("stwo_core", dep0);
    module.addImport("stwo_prover_api", dep1);
    module.addImport("stwo_prover_engine", dep2);
    module.addImport("stwo_riscv_air_lang", dep3);
    module.addImport("stwo_riscv_isa", dep4);
    module.addImport("stwo_riscv_memory", dep5);
    module.addImport("stwo_riscv_precompiles", dep6);
    module.addImport("stwo_riscv_recursion_air", dep7);
    module.addImport("stwo_riscv_rv32", dep8);
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;
    run.setEnvironmentVariable("STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS", "1");
    b.step("test", "Run the owned contract and behavior suite").dependOn(&run.step);
}
