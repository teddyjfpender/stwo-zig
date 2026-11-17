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
    const module = b.addModule("stwo_riscv_rv32", .{ .root_source_file = b.path("mod.zig"), .target = target, .optimize = optimize });
    module.addImport("stwo_core", dep0);
    module.addImport("stwo_prover_api", dep1);
    module.addImport("stwo_prover_engine", dep2);
    module.addImport("stwo_riscv_air_lang", dep3);
    module.addImport("stwo_riscv_isa", dep4);
    module.addImport("stwo_riscv_memory", dep5);
    module.addImport("stwo_riscv_precompiles", dep6);
    module.addImport("stwo_riscv_recursion_air", dep7);
    const wire = b.createModule(.{ .root_source_file = b.path("../../../waist/proof_wire/mod.zig"), .target = target, .optimize = optimize });
    wire.addImport("stwo_core", dep0);
    const postcard = b.createModule(.{ .root_source_file = b.path("../../../waist/recursion_wire/postcard/mod.zig"), .target = target, .optimize = optimize });
    postcard.addImport("stwo_core", dep0);
    postcard.addImport("stwo_proof_wire", wire);
    module.addImport("interop_postcard", postcard);
    const export_step = b.step("export-refinement-ir", "Export the exact production family and unsigned opcode AIR without the product SDK");
    inline for (.{
        .{ "refinement_ir_export_test.zig", "riscv-refinement-ir-dir", "RISCV_AIR_IR_DIR", "refinement export: emit production symbolic AIR", "zig-out/uniqueness-ir" },
        .{ "refinement_program_export_test.zig", "riscv-air-program-ir-dir", "RISCV_AIR_PROGRAM_IR_DIR", "refinement AIR IR v2 export: emit every unsigned production program", "zig-out/refinement-air-ir-v2" },
    }) |spec| {
        const destination = b.option([]const u8, spec[1], "Fresh output directory for the unchanged production AIR exporter") orelse spec[4];
        const exporter = b.createModule(.{ .root_source_file = b.path(spec[0]), .target = target, .optimize = optimize });
        for (module.import_table.keys(), module.import_table.values()) |name, dependency| exporter.addImport(name, dependency);
        const export_run = b.addRunArtifact(b.addTest(.{ .root_module = exporter, .filters = &.{spec[3]} }));
        export_run.has_side_effects = true;
        export_run.setEnvironmentVariable(spec[2], destination);
        export_step.dependOn(&export_run.step);
    }
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    run.has_side_effects = true;
    run.setEnvironmentVariable("STWO_ZIG_RISCV_AUDIT_OPCODE_WITNESS", "1");
    b.step("test", "Run the owned contract and behavior suite").dependOn(&run.step);
}
