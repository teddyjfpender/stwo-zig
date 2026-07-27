//! Exact CPU parity and official-Rust acceptance for Cairo Metal.

const std = @import("std");

pub fn add(
    b: *std.Build,
    metal_executable: *std.Build.Step.Compile,
    cpu_executable: *std.Build.Step.Compile,
    aot_bundle_path: []const u8,
) void {
    const gate = b.step(
        "test-cairo-metal-oracle",
        "Require exact CPU parity, fallback-free Metal, and Rust acceptance",
    );
    const cargo = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        b.pathFromRoot(
            "tools/stwo-cairo-official-verifier-rs/Cargo.toml",
        ),
    });

    const cpu = addProofRun(
        b,
        cpu_executable,
        "cairo-metal-reference-cpu.proof.json",
        "cairo-metal-reference-cpu.report.json",
    );
    const metal = addProofRun(
        b,
        metal_executable,
        "cairo-metal-candidate.proof.json",
        "cairo-metal-candidate.report.json",
    );
    metal.run.setEnvironmentVariable(
        "STWO_CAIRO_METAL_AOT_BUNDLE",
        aot_bundle_path,
    );
    metal.run.step.dependOn(&cpu.run.step);

    const compare = b.addSystemCommand(&.{"cmp"});
    compare.addFileArg(cpu.proof);
    compare.addFileArg(metal.proof);
    compare.setName("compare exact Cairo CPU and Metal proof bytes");

    const report = b.addSystemCommand(&.{
        "python3",
        "scripts/check_cairo_metal_report.py",
        "--report",
    });
    report.addFileArg(metal.report);
    report.addArg("--proof");
    report.addFileArg(metal.proof);
    report.addArgs(&.{ "--runtime-mode", "authenticated-aot" });

    const verify = b.addSystemCommand(&.{
        oraclePath(b),
        "verify",
        "--proof",
    });
    verify.step.dependOn(&cargo.step);
    verify.step.dependOn(&compare.step);
    verify.step.dependOn(&report.step);
    verify.addFileArg(metal.proof);
    verify.addArgs(&.{
        "--channel",
        "blake2s",
        "--proof-format",
        "json",
        "--result",
    });
    _ = verify.addOutputFileArg("cairo-metal-rust-verdict.json");
    verify.setName("verify Cairo Metal proof with official Rust");
    gate.dependOn(&verify.step);
}

const ProofRun = struct {
    run: *std.Build.Step.Run,
    proof: std.Build.LazyPath,
    report: std.Build.LazyPath,
};

fn addProofRun(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    proof_name: []const u8,
    report_name: []const u8,
) *ProofRun {
    const command = b.addRunArtifact(executable);
    command.addArgs(&.{ "prove", "--prover-input" });
    command.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.prover_input.json",
    ));
    command.addArg("--params");
    command.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.params.json",
    ));
    command.addArg("--proof");
    const proof = command.addOutputFileArg(proof_name);
    command.addArg("--report-out");
    const report = command.addOutputFileArg(report_name);
    command.addArg("--verify");
    const result = b.allocator.create(ProofRun) catch @panic("out of memory");
    result.* = .{ .run = command, .proof = proof, .report = report };
    return result;
}

fn oraclePath(b: *std.Build) []const u8 {
    return b.pathFromRoot(
        "tools/stwo-cairo-official-verifier-rs/target/debug/" ++
            "stwo-cairo-official-verifier",
    );
}
