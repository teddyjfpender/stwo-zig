const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const opts = .{ .target = target, .optimize = optimize };
    const cpu = b.dependency("stwo_circuit_cpu_integration", opts).module("stwo_circuit_cpu_integration");
    const core = cpu.import_table.get("stwo_core") orelse @panic("circuit CPU module is missing core");
    const circuit = cpu.import_table.get("stwo_circuit_frontend") orelse @panic("circuit CPU module is missing frontend");
    const wire = cpu.import_table.get("stwo_circuit_recursion_wire") orelse @panic("circuit CPU module is missing wire");
    const source_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-source", "Absolute path to a normalized S31 source file")) |path|
        .{ .cwd_relative = path }
    else
        b.path("examples/affine4.s31.json");
    const program_name = b.option([]const u8, "s31-name", "Build artifact name for the selected program") orelse "affine4";
    const source_version = b.option(u32, "s31-version", "Normalized source version (0 or 1)") orelse 0;
    const lowering = b.option([]const u8, "s31-lowering", "gate, chip, sparse-gate, sparse-chip, sparse-wide-gate, direct-gate, or direct-chip proof lowering") orelse "gate";
    if (!std.mem.eql(u8, lowering, "gate") and !std.mem.eql(u8, lowering, "chip") and
        !std.mem.eql(u8, lowering, "sparse-gate") and !std.mem.eql(u8, lowering, "sparse-chip") and
        !std.mem.eql(u8, lowering, "sparse-wide-gate") and
        !std.mem.eql(u8, lowering, "direct-gate") and !std.mem.eql(u8, lowering, "direct-chip"))
        @panic("invalid s31-lowering");
    const s31_options = b.addOptions();
    s31_options.addOption(bool, "chip_mode", std.mem.eql(u8, lowering, "chip") or std.mem.eql(u8, lowering, "sparse-chip") or std.mem.eql(u8, lowering, "direct-chip"));
    s31_options.addOption(bool, "sparse_mode", std.mem.startsWith(u8, lowering, "sparse-"));
    s31_options.addOption(bool, "wide_mode", std.mem.eql(u8, lowering, "sparse-wide-gate"));
    s31_options.addOption(bool, "direct_mode", std.mem.startsWith(u8, lowering, "direct-"));
    s31_options.addOption([]const u8, "stdlib_lock_sha256", b.option([]const u8, "s31-stdlib-sha256", "Pinned S31 standard library lock digest") orelse "");

    const frontend = b.addModule("stwo_s31_prototype", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_circuit_frontend", circuit);
    const poseidon_ref = b.createModule(.{
        .root_source_file = b.path("../riscv/s31_poseidon_ref.zig"),
        .target = target,
        .optimize = optimize,
    });
    poseidon_ref.addImport("stwo_core", core);
    frontend.addImport("s31_poseidon_ref", poseidon_ref);
    const sha256_ref = b.createModule(.{
        .root_source_file = b.path("../riscv/air/guest_precompile/sha256_compression.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("s31_sha256_ref", sha256_ref);

    const tests = b.addRunArtifact(b.addTest(.{ .root_module = frontend }));
    b.step("test", "Test the S31 prototype parser, evaluator and circuit compiler").dependOn(&tests.step);

    if (source_version == 1) {
        const cairo = cpu.import_table.get("stwo_cairo_frontend") orelse @panic("circuit CPU module is missing Cairo AIR runtime");
        const postcard = b.createModule(.{ .root_source_file = .{ .cwd_relative = b.pathFromRoot("../../interop/postcard.zig") }, .target = target, .optimize = optimize });
        postcard.addImport("stwo_core", core);
        const prover_root = b.createModule(.{
            .root_source_file = b.path("mvp_runtime.zig"),
            .target = target,
            .optimize = optimize,
        });
        prover_root.addImport("stwo_s31_prototype", frontend);
        prover_root.addImport("stwo_core", core);
        prover_root.addImport("stwo_circuit_frontend", circuit);
        prover_root.addImport("stwo_circuit_cpu_integration", cpu);
        prover_root.addImport("stwo_cairo_frontend", cairo);
        prover_root.addImport("interop_postcard", postcard);
        prover_root.addImport("stwo_circuit_recursion_wire", wire);
        prover_root.addOptions("s31_options", s31_options);
        prover_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
        const projection_asset: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") };
        const programs_asset: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/circuit_air.air_programs_v1.bin") };
        prover_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
        prover_root.addAnonymousImport("s31_air_programs", .{ .root_source_file = programs_asset });
        const prover_exe = b.addExecutable(.{ .name = b.fmt("s31-{s}-prover", .{program_name}), .root_module = prover_root });
        b.installArtifact(prover_exe);

        const native_root = b.createModule(.{
            .root_source_file = b.path("mvp_verifier_main.zig"),
            .target = target,
            .optimize = optimize,
        });
        native_root.addImport("stwo_s31_prototype", frontend);
        native_root.addImport("stwo_core", core);
        native_root.addImport("stwo_circuit_frontend", circuit);
        native_root.addImport("stwo_circuit_cpu_integration", cpu);
        native_root.addImport("stwo_cairo_frontend", cairo);
        native_root.addImport("interop_postcard", postcard);
        native_root.addImport("stwo_circuit_recursion_wire", wire);
        native_root.addOptions("s31_options", s31_options);
        native_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
        native_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
        native_root.addAnonymousImport("s31_air_programs", .{ .root_source_file = programs_asset });
        const key_asset: std.Build.LazyPath = if (b.option([]const u8, "s31-key", "Absolute path to the sealed verification key")) |path|
            .{ .cwd_relative = path }
        else
            b.path("examples/placeholder-verification-key.json");
        native_root.addAnonymousImport("s31_verification_key", .{ .root_source_file = key_asset });
        const native_exe = b.addExecutable(.{ .name = b.fmt("s31-{s}-native-verifier", .{program_name}), .root_module = native_root });
        b.installArtifact(native_exe);
        const run = b.addRunArtifact(prover_exe);
        if (b.args) |args| run.addArgs(args);
        b.step("program", "Run the S31 v1 program compiler/prover").dependOn(&run.step);
        return;
    }
    if (source_version != 0) @panic("unsupported S31 source version");

    const showcase_root = b.createModule(.{
        .root_source_file = b.path("showcase.zig"),
        .target = target,
        .optimize = optimize,
    });
    showcase_root.addImport("stwo_s31_prototype", frontend);
    showcase_root.addImport("stwo_core", core);
    showcase_root.addImport("stwo_circuit_frontend", circuit);
    showcase_root.addImport("stwo_circuit_cpu_integration", cpu);
    showcase_root.addImport("stwo_circuit_recursion_wire", wire);
    showcase_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
    const projection_asset: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/compiled_air_constraints_v1.bin") };
    const programs_asset: std.Build.LazyPath = .{ .cwd_relative = b.pathFromRoot("../../../vectors/circuit/official/circuit_air.air_programs_v1.bin") };
    showcase_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
    showcase_root.addAnonymousImport("s31_air_programs", .{ .root_source_file = programs_asset });
    const executable = b.addExecutable(.{ .name = "s31-showcase", .root_module = showcase_root });
    b.installArtifact(executable);

    const verifier_root = b.createModule(.{
        .root_source_file = b.path("verifier_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    verifier_root.addImport("stwo_s31_prototype", frontend);
    verifier_root.addImport("stwo_core", core);
    verifier_root.addImport("stwo_circuit_frontend", circuit);
    verifier_root.addImport("stwo_circuit_cpu_integration", cpu);
    verifier_root.addImport("stwo_circuit_recursion_wire", wire);
    verifier_root.addAnonymousImport("s31_program_source", .{ .root_source_file = source_asset });
    verifier_root.addAnonymousImport("s31_air_projection", .{ .root_source_file = projection_asset });
    verifier_root.addAnonymousImport("s31_air_programs", .{ .root_source_file = programs_asset });
    const verifier = b.addExecutable(.{ .name = b.fmt("s31-{s}-verifier", .{program_name}), .root_module = verifier_root });
    b.installArtifact(verifier);

    const showcase = b.addRunArtifact(executable);
    showcase.setCwd(.{ .cwd_relative = b.pathFromRoot("../../..") });
    if (b.args) |args| showcase.addArgs(args);
    const showcase_step = b.step("showcase", "Prove and natively verify the S31 affine-four example");
    showcase_step.dependOn(&showcase.step);
    showcase_step.dependOn(b.getInstallStep());
}
