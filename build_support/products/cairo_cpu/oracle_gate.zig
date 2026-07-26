//! Serial official-Rust release gate for Cairo CPU proof transports.

const std = @import("std");

const OracleCase = struct {
    name: []const u8,
    input: []const u8,
    params: []const u8,
    proof: []const u8,
    report: []const u8,
    verdict: []const u8,
};

const OracleResult = struct {
    step: *std.Build.Step,
    proof: std.Build.LazyPath,
};

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
    const gate = b.step(
        "test-cairo-cpu-oracle",
        "Prove the official Cairo corpus and require Rust acceptance",
    );
    var previous: ?*std.Build.Step = null;
    var transport_source: ?std.Build.LazyPath = null;
    for ([_]OracleCase{
        .{
            .name = "all-opcodes",
            .input = "vectors/cairo/official/all_opcodes.prover_input.json",
            .params = "vectors/cairo/official/all_opcodes.params.json",
            .proof = "all-opcodes-proof.json",
            .report = "all-opcodes-report.json",
            .verdict = "all-opcodes-rust-verdict.json",
        },
        .{
            .name = "all-builtins",
            .input = "vectors/cairo/official/all_builtins.prover_input.json",
            .params = "vectors/cairo/official/all_builtins.params.json",
            .proof = "all-builtins-proof.json",
            .report = "all-builtins-report.json",
            .verdict = "all-builtins-rust-verdict.json",
        },
    }) |case| {
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
    gate.dependOn(addBinaryGate(
        b,
        executable,
        cargo,
        transport_source.?,
        transport,
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

fn oraclePath(b: *std.Build) []const u8 {
    return b.pathFromRoot(
        "tools/stwo-cairo-official-verifier-rs/target/debug/" ++
            "stwo-cairo-official-verifier",
    );
}
