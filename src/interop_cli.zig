const std = @import("std");
const stwo = @import("stwo.zig");

const m31 = stwo.core.fields.m31;
const fri = stwo.core.fri;
const pcs = stwo.core.pcs;
const state_machine = stwo.examples.state_machine;
const xor = stwo.examples.xor;
const examples_artifact = stwo.interop.examples_artifact;
const proof_wire = stwo.interop.proof_wire;

const M31 = m31.M31;

const Mode = enum {
    generate,
    verify,
};

const Example = enum {
    state_machine,
    xor,
};

const Cli = struct {
    mode: Mode,
    example: ?Example = null,
    artifact_path: []const u8,

    pow_bits: u32 = 0,
    fri_log_blowup: u32 = 1,
    fri_log_last_layer: u32 = 0,
    fri_n_queries: usize = 3,

    sm_log_n_rows: u32 = 5,
    sm_initial_0: u32 = 9,
    sm_initial_1: u32 = 3,

    xor_log_size: u32 = 5,
    xor_log_step: u32 = 2,
    xor_offset: usize = 3,
};

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    const cli = parseArgs(args) catch |err| {
        printUsage();
        return err;
    };

    switch (cli.mode) {
        .generate => try runGenerate(gpa, cli),
        .verify => try runVerify(gpa, cli),
    }
}

fn runGenerate(allocator: std.mem.Allocator, cli: Cli) !void {
    const example = cli.example orelse return error.MissingExample;
    const config = try pcsConfigFromCli(cli);

    switch (example) {
        .state_machine => {
            const initial_state: state_machine.State = .{
                try m31FromCanonical(cli.sm_initial_0),
                try m31FromCanonical(cli.sm_initial_1),
            };
            const output = try state_machine.prove(
                allocator,
                config,
                cli.sm_log_n_rows,
                initial_state,
            );

            var proof = output.proof;
            defer proof.deinit(allocator);

            const proof_bytes = try proof_wire.encodeProofBytes(allocator, proof);
            defer allocator.free(proof_bytes);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(allocator, proof_bytes);
            defer allocator.free(proof_bytes_hex);

            try examples_artifact.writeArtifact(allocator, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "state_machine",
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .state_machine_statement = examples_artifact.stateMachineStatementToWire(output.statement),
                .xor_statement = null,
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
        .xor => {
            const statement: xor.Statement = .{
                .log_size = cli.xor_log_size,
                .log_step = cli.xor_log_step,
                .offset = cli.xor_offset,
            };
            const output = try xor.prove(allocator, config, statement);

            var proof = output.proof;
            defer proof.deinit(allocator);

            const proof_bytes = try proof_wire.encodeProofBytes(allocator, proof);
            defer allocator.free(proof_bytes);
            const proof_bytes_hex = try examples_artifact.bytesToHexAlloc(allocator, proof_bytes);
            defer allocator.free(proof_bytes_hex);

            try examples_artifact.writeArtifact(allocator, cli.artifact_path, .{
                .schema_version = examples_artifact.SCHEMA_VERSION,
                .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
                .exchange_mode = examples_artifact.EXCHANGE_MODE,
                .generator = "zig",
                .example = "xor",
                .pcs_config = examples_artifact.pcsConfigToWire(config),
                .state_machine_statement = null,
                .xor_statement = examples_artifact.xorStatementToWire(output.statement),
                .proof_bytes_hex = proof_bytes_hex,
            });
        },
    }
}

fn runVerify(allocator: std.mem.Allocator, cli: Cli) !void {
    const parsed = try examples_artifact.readArtifact(allocator, cli.artifact_path);
    defer parsed.deinit();

    const artifact = parsed.value;
    if (artifact.schema_version != examples_artifact.SCHEMA_VERSION) {
        return error.UnsupportedSchemaVersion;
    }
    if (!std.mem.eql(u8, artifact.exchange_mode, examples_artifact.EXCHANGE_MODE)) {
        return error.UnsupportedExchangeMode;
    }
    if (!std.mem.eql(u8, artifact.upstream_commit, examples_artifact.UPSTREAM_COMMIT)) {
        return error.UnsupportedUpstreamCommit;
    }
    if (!isSupportedGenerator(artifact.generator)) {
        return error.UnsupportedGenerator;
    }

    const config = try examples_artifact.pcsConfigFromWire(artifact.pcs_config);
    const proof_bytes = try examples_artifact.hexToBytesAlloc(allocator, artifact.proof_bytes_hex);
    defer allocator.free(proof_bytes);

    const proof = try proof_wire.decodeProofBytes(allocator, proof_bytes);

    if (std.mem.eql(u8, artifact.example, "state_machine")) {
        const statement_wire = artifact.state_machine_statement orelse return error.MissingStateMachineStatement;
        const statement = try examples_artifact.stateMachineStatementFromWire(statement_wire);
        try state_machine.verify(allocator, config, statement, proof);
        return;
    }
    if (std.mem.eql(u8, artifact.example, "xor")) {
        const statement_wire = artifact.xor_statement orelse return error.MissingXorStatement;
        const statement = try examples_artifact.xorStatementFromWire(statement_wire);
        try xor.verify(allocator, config, statement, proof);
        return;
    }
    return error.UnknownExample;
}

fn isSupportedGenerator(generator: []const u8) bool {
    return std.mem.eql(u8, generator, "rust") or std.mem.eql(u8, generator, "zig");
}

fn parseArgs(args: []const []const u8) !Cli {
    var mode: ?Mode = null;
    var example: ?Example = null;
    var artifact_path: ?[]const u8 = null;

    var pow_bits: u32 = 0;
    var fri_log_blowup: u32 = 1;
    var fri_log_last_layer: u32 = 0;
    var fri_n_queries: usize = 3;

    var sm_log_n_rows: u32 = 5;
    var sm_initial_0: u32 = 9;
    var sm_initial_1: u32 = 3;

    var xor_log_size: u32 = 5;
    var xor_log_step: u32 = 2;
    var xor_offset: usize = 3;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const flag = args[i];
        if (!std.mem.startsWith(u8, flag, "--")) return error.InvalidArgument;
        if (i + 1 >= args.len) return error.MissingArgumentValue;

        const value = args[i + 1];
        i += 1;

        if (std.mem.eql(u8, flag, "--mode")) {
            mode = parseMode(value) orelse return error.InvalidMode;
        } else if (std.mem.eql(u8, flag, "--example")) {
            example = parseExample(value) orelse return error.InvalidExample;
        } else if (std.mem.eql(u8, flag, "--artifact")) {
            artifact_path = value;
        } else if (std.mem.eql(u8, flag, "--pow-bits")) {
            pow_bits = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--fri-log-blowup")) {
            fri_log_blowup = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--fri-log-last-layer")) {
            fri_log_last_layer = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--fri-n-queries")) {
            fri_n_queries = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--sm-log-n-rows")) {
            sm_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--sm-initial-0")) {
            sm_initial_0 = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--sm-initial-1")) {
            sm_initial_1 = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-log-size")) {
            xor_log_size = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-log-step")) {
            xor_log_step = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-offset")) {
            xor_offset = try parseInt(usize, value);
        } else {
            return error.InvalidArgument;
        }
    }

    return .{
        .mode = mode orelse return error.MissingMode,
        .example = example,
        .artifact_path = artifact_path orelse return error.MissingArtifactPath,
        .pow_bits = pow_bits,
        .fri_log_blowup = fri_log_blowup,
        .fri_log_last_layer = fri_log_last_layer,
        .fri_n_queries = fri_n_queries,
        .sm_log_n_rows = sm_log_n_rows,
        .sm_initial_0 = sm_initial_0,
        .sm_initial_1 = sm_initial_1,
        .xor_log_size = xor_log_size,
        .xor_log_step = xor_log_step,
        .xor_offset = xor_offset,
    };
}

fn parseMode(value: []const u8) ?Mode {
    if (std.mem.eql(u8, value, "generate")) return .generate;
    if (std.mem.eql(u8, value, "verify")) return .verify;
    return null;
}

fn parseExample(value: []const u8) ?Example {
    if (std.mem.eql(u8, value, "state_machine")) return .state_machine;
    if (std.mem.eql(u8, value, "xor")) return .xor;
    return null;
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10);
}

fn pcsConfigFromCli(cli: Cli) !pcs.PcsConfig {
    return .{
        .pow_bits = cli.pow_bits,
        .fri_config = try fri.FriConfig.init(
            cli.fri_log_last_layer,
            cli.fri_log_blowup,
            cli.fri_n_queries,
        ),
    };
}

fn m31FromCanonical(value: u32) !M31 {
    if (value >= m31.Modulus) return error.NonCanonicalM31;
    return M31.fromCanonical(value);
}

fn printUsage() void {
    std.debug.print(
        "usage:\n" ++
            "  zig run src/interop_cli.zig -- --mode generate --example <state_machine|xor> --artifact <path> [options]\n" ++
            "  zig run src/interop_cli.zig -- --mode verify --artifact <path>\n",
        .{},
    );
}
