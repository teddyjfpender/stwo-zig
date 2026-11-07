const std = @import("std");

// Stream m9-native-cells: standalone build for the M9 native cells census (no edit to build.zig).
//   zig build --build-file build_m9_native_cells.zig m9-native-cells       (tool)
//   zig build --build-file build_m9_native_cells.zig test-m9-native-cells  (unit test)
// Module plumbing mirrors build.zig's native-layout-census step.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", dependency_options).module("stwo_prover_engine");
    const prover_api = b.dependency("stwo_prover_api", dependency_options).module("stwo_prover_api");
    const cpu_backend = b.dependency("stwo_cpu_backend", dependency_options).module("stwo_cpu_backend");
    const frontend = b.dependency("stwo_riscv_frontend", dependency_options).module("stwo_riscv_frontend");
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");

    const root = b.createModule(.{ .root_source_file = b.path("rv64_m9_native_cells_main.zig"), .target = target, .optimize = optimize });
    root.addImport("stwo_core", core);
    root.addImport("stwo_cpu_backend", cpu_backend);
    root.addImport("stwo_prover_api", prover_api);
    root.addImport("interop_postcard", postcard);
    root.addImport("stwo_proof_wire", postcard.import_table.get("stwo_proof_wire") orelse @panic("missing wire"));
    root.addImport("stwo_prover_engine", prover);
    root.addImport("stwo_riscv_frontend", frontend);

    const exe = b.addExecutable(.{ .name = "rv64-m9-native-cells", .root_module = root });
    b.step("m9-native-cells", "Build the M9 native cells census (today/logup3/v1/v2share)").dependOn(&b.addInstallArtifact(exe, .{}).step);
    const tests = b.addTest(.{ .root_module = root });
    b.step("test-m9-native-cells", "Unit-test the shared-binding column plan").dependOn(&b.addRunArtifact(tests).step);
}
