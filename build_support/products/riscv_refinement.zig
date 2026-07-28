//! Public build gates for the RISC-V AIR-to-Sail refinement pilot.

const std = @import("std");
const graph = @import("../graph/modules.zig");

const product = graph.Product{
    .name = "stwo-riscv-refinement-ir",
    .frontend = .riscv,
    .backend = .none,
    .role = .@"test",
    .protocol_features = "rv32im-zkvm-v1+symbolic-air-extraction",
};

pub fn addPilot(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    protocol: graph.ProtocolModules,
) void {
    const configured_ir_dir = b.option(
        []const u8,
        "riscv-refinement-ir-dir",
        "Fresh output directory for the RISC-V symbolic AIR extractor",
    );
    const export_ir_dir = configured_ir_dir orelse "zig-out/uniqueness-ir";
    const root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/frontends/riscv/refinement_ir_export_test.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(root);
    const ir_exports = b.addTest(.{
        .root_module = root,
        .filters = &.{"refinement export: emit production symbolic AIR"},
    });
    const export_run = b.addRunArtifact(ir_exports);
    export_run.setEnvironmentVariable("RISCV_AIR_IR_DIR", export_ir_dir);
    if (configured_ir_dir == null) {
        const clear_default_ir = b.addRemoveDirTree(.{
            .cwd_relative = export_ir_dir,
        });
        export_run.step.dependOn(&clear_default_ir.step);
    }
    b.step(
        "riscv-refinement-ir",
        "Export the production symbolic AIR used by the Lean refinement pilot",
    ).dependOn(&export_run.step);

    const pilot_ir_dir = "zig-out/refinement-pilot-ir";
    const clear_pilot_ir = b.addRemoveDirTree(.{
        .cwd_relative = pilot_ir_dir,
    });
    const pilot_export_run = b.addRunArtifact(ir_exports);
    pilot_export_run.setEnvironmentVariable("RISCV_AIR_IR_DIR", pilot_ir_dir);
    pilot_export_run.step.dependOn(&clear_pilot_ir.step);
    const verify = b.addSystemCommand(&.{
        "python3",
        "scripts/riscv_refinement.py",
        "verify",
        "--no-export-air",
        "--air-ir-dir",
        pilot_ir_dir,
    });
    verify.step.dependOn(&pilot_export_run.step);
    b.step(
        "riscv-refinement-pilot",
        "Verify the LUI/ADDI normalized AIR-to-Sail Lean pilot",
    ).dependOn(&verify.step);
}
