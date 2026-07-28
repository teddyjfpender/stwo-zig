//! Serial CPU/Metal parity and official-Rust release gate for Cairo.

const std = @import("std");
const corpus = @import("../cairo/oracle_corpus.zig");
const commands = @import("oracle_commands.zig");

const PairResult = struct {
    step: *std.Build.Step,
    cpu_proof: std.Build.LazyPath,
    metal_proof: std.Build.LazyPath,
};

pub fn add(
    b: *std.Build,
    metal_executable: *std.Build.Step.Compile,
    cpu_executable: *std.Build.Step.Compile,
    aot_bundle_path: []const u8,
) void {
    const cargo = commands.addCargoBuild(b);
    const adapter_tests = commands.addAdapterTests(b);
    const gate = b.step(
        "test-cairo-metal-oracle",
        "Require full-corpus CPU parity, fallback-free Metal, and Rust acceptance",
    );
    var previous: ?*std.Build.Step = null;
    var all_opcodes_json: ?std.Build.LazyPath = null;
    for (corpus.direct_cases) |case| {
        const pair = addDirectPair(
            b,
            cpu_executable,
            metal_executable,
            cargo,
            aot_bundle_path,
            case,
            previous,
        );
        previous = pair.step;
        if (std.mem.eql(u8, case.name, "all-opcodes"))
            all_opcodes_json = pair.metal_proof;
    }
    previous = addCairoSerdePair(
        b,
        cpu_executable,
        metal_executable,
        cargo,
        aot_bundle_path,
        all_opcodes_json.?,
        previous.?,
    );
    previous = addBinaryPair(
        b,
        cpu_executable,
        metal_executable,
        cargo,
        aot_bundle_path,
        all_opcodes_json.?,
        previous.?,
    );
    for (corpus.program_cases) |case| {
        previous = addProgramPair(
            b,
            cpu_executable,
            metal_executable,
            cargo,
            adapter_tests,
            aot_bundle_path,
            case,
            previous.?,
        );
    }
    gate.dependOn(previous.?);
}

fn addDirectPair(
    b: *std.Build,
    cpu_executable: *std.Build.Step.Compile,
    metal_executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    aot_bundle_path: []const u8,
    case: corpus.DirectCase,
    previous: ?*std.Build.Step,
) PairResult {
    const cpu = commands.addDirectProof(
        b,
        cpu_executable,
        case,
        "cpu",
        null,
    );
    if (previous) |dependency| cpu.run.step.dependOn(dependency);
    const metal = commands.addDirectProof(
        b,
        metal_executable,
        case,
        "metal",
        aot_bundle_path,
    );
    metal.run.step.dependOn(&cpu.run.step);
    const compare = commands.addExactComparison(
        b,
        cpu.proof,
        metal.proof,
        b.fmt("compare exact Cairo {s} CPU and Metal proof bytes", .{
            case.name,
        }),
    );
    const report = commands.addReportCheck(
        b,
        metal,
        "json",
        false,
    );
    const verify = commands.addRustVerification(
        b,
        cargo,
        metal.proof,
        "json",
        b.fmt("cairo-metal-{s}-rust-verdict.json", .{case.name}),
        b.fmt("verify Cairo Metal {s} proof with official Rust", .{
            case.name,
        }),
    );
    verify.dependOn(compare);
    verify.dependOn(report);
    return .{
        .step = verify,
        .cpu_proof = cpu.proof,
        .metal_proof = metal.proof,
    };
}

fn addCairoSerdePair(
    b: *std.Build,
    cpu_executable: *std.Build.Step.Compile,
    metal_executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    aot_bundle_path: []const u8,
    json_proof: std.Build.LazyPath,
    previous: *std.Build.Step,
) *std.Build.Step {
    const cpu = commands.addTransportProof(
        b,
        cpu_executable,
        "cpu",
        "cairo-serde",
        "cairo-serde.json",
        null,
    );
    cpu.run.step.dependOn(previous);
    const metal = commands.addTransportProof(
        b,
        metal_executable,
        "metal",
        "cairo-serde",
        "cairo-serde.json",
        aot_bundle_path,
    );
    metal.run.step.dependOn(&cpu.run.step);
    const exact = commands.addExactComparison(
        b,
        cpu.proof,
        metal.proof,
        "compare exact Cairo-serde CPU and Metal proof bytes",
    );
    const serialize_oracle = b.addSystemCommand(&.{
        commands.oraclePath(b),
        "serialize-cairo",
        "--proof",
    });
    serialize_oracle.step.dependOn(&cargo.step);
    serialize_oracle.addFileArg(json_proof);
    serialize_oracle.addArgs(&.{ "--proof-format", "json", "--result" });
    const expected = serialize_oracle.addOutputFileArg(
        "cairo-metal-cairo-serde.oracle.json",
    );
    const official = commands.addExactComparison(
        b,
        expected,
        metal.proof,
        "compare Metal Cairo-serde bytes with official Rust",
    );
    official.dependOn(exact);
    official.dependOn(commands.addReportCheck(
        b,
        metal,
        "cairo-serde",
        false,
    ));
    return official;
}

fn addBinaryPair(
    b: *std.Build,
    cpu_executable: *std.Build.Step.Compile,
    metal_executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    aot_bundle_path: []const u8,
    json_proof: std.Build.LazyPath,
    previous: *std.Build.Step,
) *std.Build.Step {
    const cpu = commands.addTransportProof(
        b,
        cpu_executable,
        "cpu",
        "binary",
        "binary.bz2",
        null,
    );
    cpu.run.step.dependOn(previous);
    const metal = commands.addTransportProof(
        b,
        metal_executable,
        "metal",
        "binary",
        "binary.bz2",
        aot_bundle_path,
    );
    metal.run.step.dependOn(&cpu.run.step);
    const exact = commands.addExactComparison(
        b,
        cpu.proof,
        metal.proof,
        "compare exact compressed-binary CPU and Metal proof bytes",
    );

    const serialize_oracle = b.addSystemCommand(&.{
        commands.oraclePath(b),
        "serialize-binary-raw",
        "--proof",
    });
    serialize_oracle.step.dependOn(&cargo.step);
    serialize_oracle.addFileArg(json_proof);
    serialize_oracle.addArgs(&.{ "--proof-format", "json", "--result" });
    const expected = serialize_oracle.addOutputFileArg(
        "cairo-metal-binary.oracle.raw",
    );
    const decompress = b.addSystemCommand(&.{
        commands.oraclePath(b),
        "decompress-binary",
        "--proof",
    });
    decompress.step.dependOn(&cargo.step);
    decompress.addFileArg(metal.proof);
    decompress.addArg("--result");
    const actual = decompress.addOutputFileArg("cairo-metal-binary.raw");
    const raw = commands.addExactComparison(
        b,
        expected,
        actual,
        "compare Metal bincode bytes with official Rust",
    );
    const verify = commands.addRustVerification(
        b,
        cargo,
        metal.proof,
        "binary",
        "cairo-metal-binary-rust-verdict.json",
        "verify Cairo Metal compressed-binary proof with official Rust",
    );
    verify.dependOn(exact);
    verify.dependOn(raw);
    verify.dependOn(commands.addReportCheck(b, metal, "binary", false));
    return verify;
}

fn addProgramPair(
    b: *std.Build,
    cpu_executable: *std.Build.Step.Compile,
    metal_executable: *std.Build.Step.Compile,
    cargo: *std.Build.Step.Run,
    adapter_tests: *std.Build.Step.Run,
    aot_bundle_path: []const u8,
    case: corpus.ProgramCase,
    previous: *std.Build.Step,
) *std.Build.Step {
    const cpu = commands.addProgramProof(
        b,
        cpu_executable,
        case,
        "cpu",
        null,
    );
    cpu.run.step.dependOn(previous);
    cpu.run.step.dependOn(&adapter_tests.step);
    const metal = commands.addProgramProof(
        b,
        metal_executable,
        case,
        "metal",
        aot_bundle_path,
    );
    metal.run.step.dependOn(&cpu.run.step);
    const compare = commands.addExactComparison(
        b,
        cpu.proof,
        metal.proof,
        b.fmt("compare exact Cairo {s} program CPU and Metal proof bytes", .{
            case.name,
        }),
    );
    const report = commands.addReportCheck(
        b,
        metal,
        case.proof_format,
        true,
    );
    const verify = commands.addRustVerification(
        b,
        cargo,
        metal.proof,
        case.proof_format,
        b.fmt("cairo-metal-{s}-program-rust-verdict.json", .{
            case.name,
        }),
        b.fmt("verify Cairo Metal {s} program proof with official Rust", .{
            case.name,
        }),
    );
    verify.dependOn(compare);
    verify.dependOn(report);
    return verify;
}
