//! Build-command constructors used by the Cairo Metal release gate.

const std = @import("std");
const corpus = @import("../cairo/oracle_corpus.zig");

pub const ProofRun = struct {
    run: *std.Build.Step.Run,
    proof: std.Build.LazyPath,
    report: std.Build.LazyPath,
};

pub fn addDirectProof(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    case: corpus.DirectCase,
    lane: []const u8,
    aot_bundle_path: ?[]const u8,
) ProofRun {
    const run = b.addRunArtifact(executable);
    configureMetal(run, aot_bundle_path);
    run.addArgs(&.{ "prove", "--prover-input" });
    run.addFileArg(b.path(case.input));
    run.addArg("--params");
    run.addFileArg(b.path(case.params));
    run.addArg("--proof");
    const proof = run.addOutputFileArg(b.fmt(
        "cairo-{s}-{s}.proof.json",
        .{ case.name, lane },
    ));
    run.addArg("--report-out");
    const report = run.addOutputFileArg(b.fmt(
        "cairo-{s}-{s}.report.json",
        .{ case.name, lane },
    ));
    run.addArg("--verify");
    return .{ .run = run, .proof = proof, .report = report };
}

pub fn addTransportProof(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    lane: []const u8,
    proof_format: []const u8,
    suffix: []const u8,
    aot_bundle_path: ?[]const u8,
) ProofRun {
    const run = b.addRunArtifact(executable);
    configureMetal(run, aot_bundle_path);
    run.addArgs(&.{ "prove", "--prover-input" });
    run.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.prover_input.json",
    ));
    run.addArg("--params");
    run.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.params.json",
    ));
    run.addArg("--proof");
    const proof = run.addOutputFileArg(b.fmt(
        "cairo-all-opcodes-{s}.{s}",
        .{ lane, suffix },
    ));
    run.addArg("--report-out");
    const report = run.addOutputFileArg(b.fmt(
        "cairo-all-opcodes-{s}-{s}.report.json",
        .{ lane, proof_format },
    ));
    run.addArgs(&.{ "--proof-format", proof_format, "--verify" });
    return .{ .run = run, .proof = proof, .report = report };
}

pub fn addProgramProof(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    case: corpus.ProgramCase,
    lane: []const u8,
    aot_bundle_path: ?[]const u8,
) ProofRun {
    const run = b.addRunArtifact(executable);
    configureMetal(run, aot_bundle_path);
    run.setEnvironmentVariable(
        "STWO_CAIRO_VM_ADAPTER",
        cargoDebugTool(b, "tools/stwo-cairo-vm-adapter-rs", "stwo-cairo-vm-adapter"),
    );
    run.addArgs(&.{ "run-and-prove", "--program" });
    run.addFileArg(b.path(case.program));
    run.addArgs(&.{ "--program-type", case.program_type });
    if (case.arguments) |arguments| {
        run.addArg("--arguments");
        run.addFileArg(b.path(arguments));
    }
    run.addArg("--params");
    run.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.params.json",
    ));
    run.addArg("--proof");
    const proof = run.addOutputFileArg(b.fmt(
        "cairo-{s}-{s}-program.{s}",
        .{
            case.name,
            lane,
            if (std.mem.eql(u8, case.proof_format, "binary"))
                "binary.bz2"
            else
                "proof.json",
        },
    ));
    run.addArg("--report-out");
    const report = run.addOutputFileArg(b.fmt(
        "cairo-{s}-{s}-program.report.json",
        .{ case.name, lane },
    ));
    run.addArgs(&.{ "--proof-format", case.proof_format, "--verify" });
    return .{ .run = run, .proof = proof, .report = report };
}

pub fn addExactComparison(
    b: *std.Build,
    expected: std.Build.LazyPath,
    actual: std.Build.LazyPath,
    name: []const u8,
) *std.Build.Step {
    const compare = b.addSystemCommand(&.{"cmp"});
    compare.addFileArg(expected);
    compare.addFileArg(actual);
    compare.setName(name);
    return &compare.step;
}

pub fn addReportCheck(
    b: *std.Build,
    proof: ProofRun,
    proof_format: []const u8,
    require_execution: bool,
) *std.Build.Step {
    const report = b.addSystemCommand(&.{
        "python3",
        "scripts/check_cairo_metal_report.py",
        "--report",
    });
    report.addFileArg(proof.report);
    report.addArg("--proof");
    report.addFileArg(proof.proof);
    report.addArgs(&.{
        "--runtime-mode",
        "authenticated-aot",
        "--proof-format",
        proof_format,
    });
    if (require_execution) report.addArg("--require-execution");
    return &report.step;
}

pub fn addRustVerification(
    b: *std.Build,
    cargo: *std.Build.Step.Run,
    proof: std.Build.LazyPath,
    proof_format: []const u8,
    verdict_name: []const u8,
    step_name: []const u8,
) *std.Build.Step {
    const verify = b.addSystemCommand(&.{
        oraclePath(b),
        "verify",
        "--proof",
    });
    verify.step.dependOn(&cargo.step);
    verify.addFileArg(proof);
    verify.addArgs(&.{
        "--channel",
        "blake2s",
        "--proof-format",
        proof_format,
        "--result",
    });
    _ = verify.addOutputFileArg(verdict_name);
    verify.setName(step_name);
    return &verify.step;
}

pub fn addCargoBuild(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        b.pathFromRoot(
            "tools/stwo-cairo-official-verifier-rs/Cargo.toml",
        ),
    });
}

pub fn addAdapterTests(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        b.pathFromRoot(
            "tools/stwo-cairo-vm-adapter-rs/Cargo.toml",
        ),
    });
}


/// A cargo-built tool honoring CARGO_TARGET_DIR (the focused CI lanes point
/// it into the lane cache); the manifest-relative default only holds when
/// that override is absent.
fn cargoDebugTool(b: *std.Build, comptime tool_dir: []const u8, comptime name: []const u8) []const u8 {
    if (b.graph.env_map.get("CARGO_TARGET_DIR")) |dir|
        return b.fmt("{s}/debug/" ++ name, .{dir});
    return b.pathFromRoot(tool_dir ++ "/target/debug/" ++ name);
}

pub fn oraclePath(b: *std.Build) []const u8 {
    return cargoDebugTool(b, "tools/stwo-cairo-official-verifier-rs", "stwo-cairo-official-verifier");
}

fn configureMetal(
    run: *std.Build.Step.Run,
    aot_bundle_path: ?[]const u8,
) void {
    if (aot_bundle_path) |path| run.setEnvironmentVariable(
        "STWO_CAIRO_METAL_AOT_BUNDLE",
        path,
    );
}
