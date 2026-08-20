//! Build ownership for the opt-in C-013 semantic guest-pair preflight.

const std = @import("std");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");

pub fn add(context: anytype, product: graph.Product) void {
    const b: *std.Build = context.b;
    const root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/tools/riscv/poseidon2_pair/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        root,
    );
    const checker = b.addExecutable(.{
        .name = "riscv-poseidon2-pair-check",
        .root_module = root,
    });
    const install = b.addInstallArtifact(checker, .{});
    b.step(
        "riscv-poseidon2-pair-check",
        "Build the C-013 software/precompile semantic checker",
    ).dependOn(&install.step);
    const semantic_check = addPreflight(
        b,
        checker,
        context.target,
        context.optimize,
    );

    const proof_root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/tools/riscv/poseidon2_pair/proof_main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(proof_root);
    _ = graph.addProofWireImport(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        proof_root,
    );
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        proof_root,
    );
    const proof_checker = b.addExecutable(.{
        .name = "riscv-poseidon2-pair-proof",
        .root_module = proof_root,
    });
    b.step(
        "riscv-poseidon2-pair-proof",
        "Build the one-shot C-013 CPU proof comparison",
    ).dependOn(&b.addInstallArtifact(proof_checker, .{}).step);
    addProofPreflight(b, proof_checker, semantic_check);

    const child_root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/tools/riscv/poseidon2_pair/proof_child.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(child_root);
    child_root.addOptions(
        "build_identity",
        graph_identity.buildOptions(b, context.identity),
    );
    _ = graph.addProofWireImport(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        child_root,
    );
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        child_root,
    );
    const proof_child = b.addExecutable(.{
        .name = "riscv-poseidon2-proof-child",
        .root_module = child_root,
    });
    b.step(
        "riscv-poseidon2-proof-child",
        "Build the fresh-process single-arm C-013 CPU proof child",
    ).dependOn(&b.addInstallArtifact(proof_child, .{}).step);
    addProofChildSmoke(b, proof_child, semantic_check);

    const calibration_root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/tools/riscv/poseidon2_pair/calibration_child.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(calibration_root);
    calibration_root.addOptions(
        "build_identity",
        graph_identity.buildOptions(b, context.identity),
    );
    _ = graph.addProofWireImport(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        calibration_root,
    );
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        calibration_root,
    );
    const calibration_child = b.addExecutable(.{
        .name = "riscv-c013-aa-proof-child",
        .root_module = calibration_root,
    });
    b.step(
        "riscv-c013-aa-proof-child",
        "Build the fresh-process C-013 A/A admission child",
    ).dependOn(&b.addInstallArtifact(calibration_child, .{}).step);
    addCalibrationChildSmoke(b, calibration_child);

    const corpus_manifest_root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/tools/riscv/poseidon2_pair/corpus_manifest.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(corpus_manifest_root);
    integration_graph.addRiscVCpuStack(
        b,
        context.protocol,
        product,
        context.target,
        context.optimize,
        corpus_manifest_root,
    );
    const corpus_manifest = b.addExecutable(.{
        .name = "riscv-c013-corpus-manifest",
        .root_module = corpus_manifest_root,
    });
    b.step(
        "riscv-c013-corpus-manifest",
        "Build the exact C-013 host-native corpus manifest generator",
    ).dependOn(&b.addInstallArtifact(corpus_manifest, .{}).step);
    b.step(
        "check-c013-corpus-manifest",
        "Generate all frozen C-013 input and output identities",
    ).dependOn(&b.addRunArtifact(corpus_manifest).step);
}

fn addPreflight(
    b: *std.Build,
    checker: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const guest_root = b.path("vectors/riscv_guests/poseidon2_m31_permute_v1");
    const corpus_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/riscv/poseidon2_pair/test_root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_corpus_tests = b.addRunArtifact(corpus_tests);
    const check = b.step(
        "check-c013-poseidon2-pair",
        "Build and semantically validate all exact C-013 guest shapes",
    );
    check.dependOn(&run_corpus_tests.step);
    const shapes = [_]GuestShape{
        .{
            .name = "poseidon2_dominant",
            .software_target = "target",
            .precompile_target = "target-precompile",
            .software_features = null,
            .precompile_features = "precompile",
        },
        .{
            .name = "balanced_core_and_poseidon2",
            .software_target = "target-balanced",
            .precompile_target = "target-balanced-precompile",
            .software_features = "shape-balanced",
            .precompile_features = "precompile,shape-balanced",
        },
        .{
            .name = "core_only",
            .software_target = "target-core-only",
            .precompile_target = "target-core-only-precompile",
            .software_features = "shape-core-only",
            .precompile_features = "precompile,shape-core-only",
        },
    };
    for (shapes) |shape| {
        const software_build = addGuestBuild(
            b,
            guest_root,
            shape.software_target,
            shape.software_features,
        );
        const precompile_build = addGuestBuild(
            b,
            guest_root,
            shape.precompile_target,
            shape.precompile_features,
        );
        const run = b.addRunArtifact(checker);
        run.setCwd(b.path("."));
        run.addArgs(&.{
            "--software-elf",
            guestElfPath(b, shape.software_target),
            "--precompile-elf",
            guestElfPath(b, shape.precompile_target),
            "--shape",
            shape.name,
            "--calls",
            "1",
        });
        run.step.dependOn(&software_build.step);
        run.step.dependOn(&precompile_build.step);
        check.dependOn(&run.step);
    }
    return check;
}

const GuestShape = struct {
    name: []const u8,
    software_target: []const u8,
    precompile_target: []const u8,
    software_features: ?[]const u8,
    precompile_features: []const u8,
};

fn addGuestBuild(
    b: *std.Build,
    guest_root: std.Build.LazyPath,
    target_dir: []const u8,
    features: ?[]const u8,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{ "cargo", "build", "--release" });
    if (features) |enabled| command.addArgs(&.{ "--features", enabled });
    command.setCwd(guest_root);
    command.setEnvironmentVariable("CARGO_TARGET_DIR", target_dir);
    return command;
}

fn guestElfPath(b: *std.Build, target_dir: []const u8) []const u8 {
    return b.fmt(
        "vectors/riscv_guests/poseidon2_m31_permute_v1/{s}/" ++
            "riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1",
        .{target_dir},
    );
}

fn addProofPreflight(
    b: *std.Build,
    proof_checker: *std.Build.Step.Compile,
    semantic_check: *std.Build.Step,
) void {
    const run = b.addRunArtifact(proof_checker);
    run.setCwd(b.path("."));
    run.addArgs(&.{
        "--software-elf",
        "vectors/riscv_guests/poseidon2_m31_permute_v1/target/" ++
            "riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1",
        "--precompile-elf",
        "vectors/riscv_guests/poseidon2_m31_permute_v1/target-precompile/" ++
            "riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1",
        "--calls",
        "1",
    });
    run.step.dependOn(semantic_check);
    b.step(
        "check-c013-poseidon2-cpu-proof",
        "Run one functional verified CPU proof for each exact C-013 arm",
    ).dependOn(&run.step);
}

fn addProofChildSmoke(
    b: *std.Build,
    proof_child: *std.Build.Step.Compile,
    semantic_check: *std.Build.Step,
) void {
    const input_digest =
        "eb07af873dd1211b8e033da3093a2c51c1a8dee325e13e9497dbda1549222d4b";
    const output_digest =
        "0c425365ef3800a7bcd30f37b94cdf08f1ab3028a87b7dbc00749b6bb5087d06";
    const software = b.addRunArtifact(proof_child);
    software.setCwd(b.path("."));
    software.addArgs(&.{
        "--arm",
        "software",
        "--security",
        "functional",
        "--phase",
        "diagnostic",
        "--shape",
        "poseidon2_dominant",
        "--elf",
        "vectors/riscv_guests/poseidon2_m31_permute_v1/target/" ++
            "riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1",
        "--calls",
        "1",
        "--sample-index",
        "0",
        "--expected-input-sha256",
        input_digest,
        "--expected-output-sha256",
        output_digest,
    });
    software.step.dependOn(semantic_check);
    const precompile = b.addRunArtifact(proof_child);
    precompile.setCwd(b.path("."));
    precompile.addArgs(&.{
        "--arm",
        "precompile",
        "--security",
        "functional",
        "--phase",
        "diagnostic",
        "--shape",
        "poseidon2_dominant",
        "--elf",
        "vectors/riscv_guests/poseidon2_m31_permute_v1/target-precompile/" ++
            "riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1",
        "--calls",
        "1",
        "--sample-index",
        "1",
        "--expected-input-sha256",
        input_digest,
        "--expected-output-sha256",
        output_digest,
    });
    precompile.step.dependOn(semantic_check);
    const step = b.step(
        "check-c013-poseidon2-proof-child",
        "Run one fresh functional CPU child for each exact C-013 arm",
    );
    step.dependOn(&software.step);
    step.dependOn(&precompile.step);
}

fn addCalibrationChildSmoke(
    b: *std.Build,
    child: *std.Build.Step.Compile,
) void {
    const run = b.addRunArtifact(child);
    run.setCwd(b.path("."));
    run.addArgs(&.{
        "--label",
        "a",
        "--security",
        "functional",
        "--phase",
        "diagnostic",
        "--elf",
        "vectors/riscv_elfs/multi_shard_addi.elf",
        "--sample-index",
        "0",
    });
    b.step(
        "check-c013-aa-proof-child",
        "Run one fresh functional C-013 A/A child diagnostic",
    ).dependOn(&run.step);
}
