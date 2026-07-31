//! Serial official-Rust release gate for Cairo CPU proof transports.

const std = @import("std");
const corpus = @import("../cairo/oracle_corpus.zig");

const OracleCase = corpus.DirectCase;

const OracleResult = struct {
    step: *std.Build.Step,
    proof: std.Build.LazyPath,
};

const ProgramCase = corpus.ProgramCase;

pub fn add(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
) void {
    const cargo = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        b.pathFromRoot(
            "tools/stwo-cairo-official-verifier-rs/Cargo.toml",
        ),
    });
    const adapter_tests = b.addSystemCommand(&.{
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        b.pathFromRoot(
            "tools/stwo-cairo-vm-adapter-rs/Cargo.toml",
        ),
    });
    const gate = b.step(
        "test-cairo-cpu-oracle",
        "Prove the official Cairo corpus and require Rust acceptance",
    );
    var previous: ?*std.Build.Step = null;
    var transport_source: ?std.Build.LazyPath = null;
    for (corpus.direct_cases) |case| {
        const result = addOracleCase(
            b,
            executable,
            cargo,
            case,
            previous,
        );
        previous = result.step;
        if (std.mem.eql(u8, case.name, "all-opcodes"))
            transport_source = result.proof;
    }
    const transport = addCairoSerdeGate(
        b,
        executable,
        cargo,
        transport_source.?,
        previous.?,
    );
    const binary_transport = addBinaryGate(
        b,
        executable,
        cargo,
        transport_source.?,
        transport,
    );
    gate.dependOn(addRunAndProveGate(
        b,
        executable,
        cargo,
        adapter_tests,
        binary_transport,
    ));
}

fn addOracleCase(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    case: OracleCase,
    previous: ?*std.Build.Step,
) OracleResult {
    const prove = b.addRunArtifact(executable);
    if (previous) |dependency| prove.step.dependOn(dependency);
    prove.addArgs(&.{ "prove", "--prover-input" });
    prove.addFileArg(b.path(case.input));
    prove.addArg("--params");
    prove.addFileArg(b.path(case.params));
    prove.addArg("--proof");
    const proof = prove.addOutputFileArg(case.proof);
    prove.addArg("--report-out");
    _ = prove.addOutputFileArg(case.report);
    prove.addArg("--verify");

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
        "json",
        "--result",
    });
    _ = verify.addOutputFileArg(case.verdict);
    verify.setName(b.fmt(
        "verify official Cairo {s} proof",
        .{case.name},
    ));
    return .{ .step = &verify.step, .proof = proof };
}

fn addCairoSerdeGate(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    json_proof: std.Build.LazyPath,
    previous: *std.Build.Step,
) *std.Build.Step {
    const serialize_oracle = b.addSystemCommand(&.{
        oraclePath(b),
        "serialize-cairo",
        "--proof",
    });
    serialize_oracle.step.dependOn(&cargo.step);
    serialize_oracle.addFileArg(json_proof);
    serialize_oracle.addArgs(&.{ "--proof-format", "json", "--result" });
    const expected = serialize_oracle.addOutputFileArg(
        "all-opcodes-proof.cairo-serde.oracle.json",
    );

    const prove = b.addRunArtifact(executable);
    prove.step.dependOn(previous);
    const actual = addTransportProofArgs(
        b,
        prove,
        "all-opcodes-proof.cairo-serde.json",
    );
    prove.addArgs(&.{ "--proof-format", "cairo-serde", "--verify" });

    const compare = b.addSystemCommand(&.{"cmp"});
    compare.addFileArg(expected);
    compare.addFileArg(actual);
    compare.setName("compare Zig and official Cairo-serde proof bytes");
    return &compare.step;
}

fn addBinaryGate(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    json_proof: std.Build.LazyPath,
    previous: *std.Build.Step,
) *std.Build.Step {
    const serialize_oracle = b.addSystemCommand(&.{
        oraclePath(b),
        "serialize-binary-raw",
        "--proof",
    });
    serialize_oracle.step.dependOn(&cargo.step);
    serialize_oracle.addFileArg(json_proof);
    serialize_oracle.addArgs(&.{ "--proof-format", "json", "--result" });
    const expected = serialize_oracle.addOutputFileArg(
        "all-opcodes-proof.binary.oracle.raw",
    );

    const prove = b.addRunArtifact(executable);
    prove.step.dependOn(previous);
    const compressed = addTransportProofArgs(
        b,
        prove,
        "all-opcodes-proof.binary.bz2",
    );
    prove.addArgs(&.{ "--proof-format", "binary", "--verify" });

    const decompress = b.addSystemCommand(&.{
        oraclePath(b),
        "decompress-binary",
        "--proof",
    });
    decompress.step.dependOn(&cargo.step);
    decompress.addFileArg(compressed);
    decompress.addArg("--result");
    const actual = decompress.addOutputFileArg(
        "all-opcodes-proof.binary.zig.raw",
    );

    const compare = b.addSystemCommand(&.{"cmp"});
    compare.addFileArg(expected);
    compare.addFileArg(actual);
    compare.setName("compare Zig and official bincode proof bytes");

    const verify = b.addSystemCommand(&.{
        oraclePath(b),
        "verify",
        "--proof",
    });
    verify.step.dependOn(&cargo.step);
    verify.step.dependOn(&compare.step);
    verify.addFileArg(compressed);
    verify.addArgs(&.{
        "--channel",
        "blake2s",
        "--proof-format",
        "binary",
        "--result",
    });
    _ = verify.addOutputFileArg("all-opcodes-binary-rust-verdict.json");
    verify.setName("verify official Cairo compressed binary proof");
    return &verify.step;
}

fn addRunAndProveGate(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    verifier_cargo: *std.Build.Step.Run,
    adapter_tests: *std.Build.Step.Run,
    previous: *std.Build.Step,
) *std.Build.Step {
    var completed = previous;
    for (corpus.program_cases) |case| {
        completed = addRunAndProveCase(
            b,
            executable,
            verifier_cargo,
            adapter_tests,
            completed,
            case,
        );
    }
    return completed;
}

fn addRunAndProveCase(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    verifier_cargo: *std.Build.Step.Run,
    adapter_tests: *std.Build.Step.Run,
    previous: *std.Build.Step,
    case: ProgramCase,
) *std.Build.Step {
    const prove = b.addRunArtifact(executable);
    prove.step.dependOn(previous);
    prove.step.dependOn(&adapter_tests.step);
    prove.setEnvironmentVariable(
        "STWO_CAIRO_VM_ADAPTER",
        cargoDebugTool(b, "tools/stwo-cairo-vm-adapter-rs", "stwo-cairo-vm-adapter"),
    );
    prove.addArgs(&.{ "run-and-prove", "--program" });
    prove.addFileArg(b.path(case.program));
    prove.addArgs(&.{ "--program-type", case.program_type });
    if (case.arguments) |arguments| {
        prove.addArg("--arguments");
        prove.addFileArg(b.path(arguments));
    }
    prove.addArg("--params");
    prove.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.params.json",
    ));
    prove.addArg("--proof");
    const proof = prove.addOutputFileArg(b.fmt(
        "{s}-run-and-prove.{s}",
        .{
            case.name,
            if (std.mem.eql(u8, case.proof_format, "binary"))
                "binary.bz2"
            else
                "proof.json",
        },
    ));
    prove.addArg("--report-out");
    _ = prove.addOutputFileArg(b.fmt(
        "{s}-run-and-prove.report.json",
        .{case.name},
    ));
    prove.addArgs(&.{ "--proof-format", case.proof_format, "--verify" });

    const verify = b.addSystemCommand(&.{
        oraclePath(b),
        "verify",
        "--proof",
    });
    verify.step.dependOn(&verifier_cargo.step);
    verify.addFileArg(proof);
    verify.addArgs(&.{
        "--channel",
        "blake2s",
        "--proof-format",
        case.proof_format,
        "--result",
    });
    _ = verify.addOutputFileArg(b.fmt(
        "{s}-run-and-prove-rust-verdict.json",
        .{case.name},
    ));
    verify.setName(b.fmt(
        "verify official Cairo {s} run-and-prove proof",
        .{case.name},
    ));
    return &verify.step;
}

fn addTransportProofArgs(
    b: *std.Build,
    prove: *std.Build.Step.Run,
    output_name: []const u8,
) std.Build.LazyPath {
    prove.addArgs(&.{ "prove", "--prover-input" });
    prove.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.prover_input.json",
    ));
    prove.addArg("--params");
    prove.addFileArg(b.path(
        "vectors/cairo/official/all_opcodes.params.json",
    ));
    prove.addArg("--proof");
    return prove.addOutputFileArg(output_name);
}

/// A cargo-built tool honoring CARGO_TARGET_DIR (the focused CI lanes point
/// it into the lane cache); the manifest-relative default only holds when
/// that override is absent.
fn cargoDebugTool(b: *std.Build, comptime tool_dir: []const u8, comptime name: []const u8) []const u8 {
    if (b.graph.env_map.get("CARGO_TARGET_DIR")) |dir|
        return b.fmt("{s}/debug/" ++ name, .{dir});
    return b.pathFromRoot(tool_dir ++ "/target/debug/" ++ name);
}

fn oraclePath(b: *std.Build) []const u8 {
    // Cargo honors CARGO_TARGET_DIR (the focused CI lanes point it into the
    // lane cache); the manifest-relative default only holds when that
    // override is absent. Spawn the binary from wherever cargo wrote it.
    if (b.graph.env_map.get("CARGO_TARGET_DIR")) |dir|
        return b.fmt("{s}/debug/stwo-cairo-official-verifier", .{dir});
    return b.pathFromRoot(
        "tools/stwo-cairo-official-verifier-rs/target/debug/" ++
            "stwo-cairo-official-verifier",
    );
}
