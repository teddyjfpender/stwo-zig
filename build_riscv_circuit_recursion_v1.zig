//! Focused opt-in build. Does not add a default product or alter live drivers.
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const api = b.dependency("stwo_prover_api", options).module("stwo_prover_api");
    const cpu = b.dependency("stwo_cpu_backend", options).module("stwo_cpu_backend");
    const cairo = b.dependency("stwo_cairo_frontend", options).module("stwo_cairo_frontend");
    const circuit = b.dependency("stwo_circuit_frontend", options).module("stwo_circuit_frontend");
    const integration = b.dependency("stwo_circuit_cpu_integration", options).module("stwo_circuit_cpu_integration");
    const proof_wire = b.dependency("stwo_proof_wire", options).module("stwo_proof_wire");
    const recursion_wire = b.createModule(.{ .root_source_file = b.path("src/interop/circuit_recursion/mod.zig"), .target = target, .optimize = optimize });
    recursion_wire.addImport("stwo_core", core);
    inline for (.{ "interop_felt_json", "interop_cairo_prover_parameters" }) |name| recursion_wire.addImport(name, cairo.import_table.get(name) orelse @panic("missing Cairo interop dependency"));
    const postcard = b.createModule(.{ .root_source_file = b.path("src/interop/postcard.zig"), .target = target, .optimize = optimize });
    postcard.addImport("stwo_core", core);
    postcard.addImport("stwo_proof_wire", proof_wire);
    const test_root = b.option([]const u8, "test-root", "Focused test root (default native-parent root)") orelse "src/riscv_circuit_native_parent_test_root.zig";
    const root = b.createModule(.{ .root_source_file = b.path(test_root), .target = target, .optimize = optimize });
    root.addImport("stwo_core", core);
    root.addImport("stwo_prover_engine", prover);
    root.addImport("stwo_prover_api", api);
    root.addImport("stwo_cpu_backend", cpu);
    root.addImport("stwo_cairo_frontend", cairo);
    root.addImport("stwo_circuit_frontend", circuit);
    root.addImport("stwo_circuit_recursion_wire", recursion_wire);
    root.addImport("interop_postcard", postcard);
    root.addImport("circuit_composition_cpu_aot", integration.import_table.get("circuit_composition_cpu_aot") orelse @panic("missing canonical circuit CPU AOT module"));
    const test_filter = b.option([]const u8, "test-filter", "Focused filter (default RISC)") orelse "RISC";
    const tests = b.addTest(.{ .name = "riscv-circuit-recursion-v1-tests", .root_module = root, .filters = &.{test_filter} });
    const install = b.addInstallArtifact(tests, .{});
    b.step("compile", "Compile and install focused tests without executing them").dependOn(&install.step);
    const run = b.addRunArtifact(tests);
    run.setCwd(b.path("."));
    b.step("test", "Run focused tests; genuine proof gates require explicit env flags").dependOn(&run.step);
}
