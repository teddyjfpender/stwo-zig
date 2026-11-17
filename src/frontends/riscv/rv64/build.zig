const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const dep0 = b.dependency("stwo_core", options).module("stwo_core");
    const dep1 = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const dep2 = b.dependency("stwo_riscv_air_lang", options).module("stwo_riscv_air_lang");
    const dep3 = b.dependency("stwo_riscv_memory", options).module("stwo_riscv_memory");
    const dep4 = b.dependency("stwo_riscv_precompiles", options).module("stwo_riscv_precompiles");
    const dep5 = b.dependency("stwo_riscv_rv32", options).module("stwo_riscv_rv32");
    const module = b.addModule("stwo_riscv_rv64", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    module.addImport("stwo_core", dep0);
    module.addImport("stwo_prover_engine", dep1);
    module.addImport("stwo_riscv_air_lang", dep2);
    module.addImport("stwo_riscv_memory", dep3);
    module.addImport("stwo_riscv_precompiles", dep4);
    module.addImport("stwo_riscv_rv32", dep5);
    const dword_owner = b.createModule(.{ .root_source_file = b.path("dword_owner_test_root.zig"), .target = target, .optimize = optimize });
    dword_owner.addImport("stwo_core", dep0);
    const dword_tests = b.addTest(.{ .root_module = dword_owner });
    const dword_run = b.addRunArtifact(dword_tests);
    dword_run.has_side_effects = true;
    b.step("test-dword-owner-projection", "Check high-residue LS-D64 OWNER coordinates against independent integer residues").dependOn(&dword_run.step);
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;
    run.setEnvironmentVariable("STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS", "1");
    b.step("test", "Run the owned contract and behavior suite").dependOn(&run.step);
}
