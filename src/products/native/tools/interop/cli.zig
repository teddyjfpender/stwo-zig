//! Interop command-line schema, parsing, and proof configuration.

const std = @import("std");
const stwo = @import("root").stwo;

const m31 = stwo.core.fields.m31;
const fri = stwo.core.fri;
const pcs = stwo.core.pcs;
const blake2_hash = stwo.core.vcs.blake2_hash;
const M31 = m31.M31;

pub const Mode = enum {
    generate,
    verify,
    verify_std_shims,
    bench,
};

pub const Example = enum {
    blake,
    plonk,
    poseidon,
    state_machine,
    wide_fibonacci,
    xor,
};

pub const ProveMode = enum {
    prove,
    prove_ex,
};

pub const BenchProofCodec = enum {
    json,
    binary,
};

pub const Cli = struct {
    mode: Mode,
    example: ?Example = null,
    artifact_path: []const u8,
    stage_profile_out: ?[]const u8 = null,
    prove_mode: ProveMode = .prove,
    blake2_backend: blake2_hash.BackendMode = .auto,
    include_all_preprocessed_columns: bool = false,

    pow_bits: u32 = 0,
    fri_log_blowup: u32 = 1,
    fri_log_last_layer: u32 = 0,
    fri_n_queries: usize = 3,

    sm_log_n_rows: u32 = 5,
    sm_initial_0: u32 = 9,
    sm_initial_1: u32 = 3,

    blake_log_n_rows: u32 = 5,
    blake_n_rounds: u32 = 10,

    plonk_log_n_rows: u32 = 5,

    poseidon_log_n_instances: u32 = 8,

    wf_log_n_rows: u32 = 5,
    wf_sequence_len: u32 = 16,

    xor_log_size: u32 = 5,
    xor_log_step: u32 = 2,
    xor_offset: usize = 3,

    bench_warmups: usize = 1,
    bench_repeats: usize = 5,
    bench_proof_codec: BenchProofCodec = .json,
};

pub fn isSupportedGenerator(generator: []const u8) bool {
    return std.mem.eql(u8, generator, "rust") or std.mem.eql(u8, generator, "zig");
}

pub fn isSupportedProveMode(mode: []const u8) bool {
    return std.mem.eql(u8, mode, "prove") or std.mem.eql(u8, mode, "prove_ex");
}

pub fn proveModeToString(mode: ProveMode) []const u8 {
    return switch (mode) {
        .prove => "prove",
        .prove_ex => "prove_ex",
    };
}

pub fn parseArgs(args: []const []const u8) !Cli {
    var mode: ?Mode = null;
    var example: ?Example = null;
    var artifact_path: ?[]const u8 = null;
    var stage_profile_out: ?[]const u8 = null;
    var prove_mode: ProveMode = .prove;
    var blake2_backend: blake2_hash.BackendMode = .auto;
    var include_all_preprocessed_columns = false;

    var pow_bits: u32 = 0;
    var fri_log_blowup: u32 = 1;
    var fri_log_last_layer: u32 = 0;
    var fri_n_queries: usize = 3;

    var sm_log_n_rows: u32 = 5;
    var sm_initial_0: u32 = 9;
    var sm_initial_1: u32 = 3;

    var blake_log_n_rows: u32 = 5;
    var blake_n_rounds: u32 = 10;

    var plonk_log_n_rows: u32 = 5;

    var poseidon_log_n_instances: u32 = 8;

    var wf_log_n_rows: u32 = 5;
    var wf_sequence_len: u32 = 16;

    var xor_log_size: u32 = 5;
    var xor_log_step: u32 = 2;
    var xor_offset: usize = 3;

    var bench_warmups: usize = 1;
    var bench_repeats: usize = 5;
    var bench_proof_codec: BenchProofCodec = .json;

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
        } else if (std.mem.eql(u8, flag, "--stage-profile-out")) {
            stage_profile_out = value;
        } else if (std.mem.eql(u8, flag, "--prove-mode")) {
            prove_mode = parseProveMode(value) orelse return error.InvalidProveMode;
        } else if (std.mem.eql(u8, flag, "--blake2-backend")) {
            blake2_backend = parseBlake2Backend(value) orelse return error.InvalidBlake2Backend;
        } else if (std.mem.eql(u8, flag, "--include-all-preprocessed-columns")) {
            include_all_preprocessed_columns = try parseBool(value);
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
        } else if (std.mem.eql(u8, flag, "--blake-log-n-rows")) {
            blake_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--blake-n-rounds")) {
            blake_n_rounds = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--plonk-log-n-rows")) {
            plonk_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--poseidon-log-n-instances")) {
            poseidon_log_n_instances = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--wf-log-n-rows")) {
            wf_log_n_rows = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--wf-sequence-len")) {
            wf_sequence_len = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-log-size")) {
            xor_log_size = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-log-step")) {
            xor_log_step = try parseInt(u32, value);
        } else if (std.mem.eql(u8, flag, "--xor-offset")) {
            xor_offset = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--bench-warmups")) {
            bench_warmups = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--bench-repeats")) {
            bench_repeats = try parseInt(usize, value);
        } else if (std.mem.eql(u8, flag, "--bench-proof-codec")) {
            bench_proof_codec = parseBenchProofCodec(value) orelse return error.InvalidBenchProofCodec;
        } else {
            return error.InvalidArgument;
        }
    }

    return .{
        .mode = mode orelse return error.MissingMode,
        .example = example,
        .artifact_path = artifact_path orelse return error.MissingArtifactPath,
        .stage_profile_out = stage_profile_out,
        .prove_mode = prove_mode,
        .blake2_backend = blake2_backend,
        .include_all_preprocessed_columns = include_all_preprocessed_columns,
        .pow_bits = pow_bits,
        .fri_log_blowup = fri_log_blowup,
        .fri_log_last_layer = fri_log_last_layer,
        .fri_n_queries = fri_n_queries,
        .sm_log_n_rows = sm_log_n_rows,
        .sm_initial_0 = sm_initial_0,
        .sm_initial_1 = sm_initial_1,
        .blake_log_n_rows = blake_log_n_rows,
        .blake_n_rounds = blake_n_rounds,
        .plonk_log_n_rows = plonk_log_n_rows,
        .poseidon_log_n_instances = poseidon_log_n_instances,
        .wf_log_n_rows = wf_log_n_rows,
        .wf_sequence_len = wf_sequence_len,
        .xor_log_size = xor_log_size,
        .xor_log_step = xor_log_step,
        .xor_offset = xor_offset,
        .bench_warmups = bench_warmups,
        .bench_repeats = bench_repeats,
        .bench_proof_codec = bench_proof_codec,
    };
}

fn parseMode(value: []const u8) ?Mode {
    if (std.mem.eql(u8, value, "generate")) return .generate;
    if (std.mem.eql(u8, value, "verify")) return .verify;
    if (std.mem.eql(u8, value, "verify_std_shims")) return .verify_std_shims;
    if (std.mem.eql(u8, value, "bench")) return .bench;
    return null;
}

fn parseExample(value: []const u8) ?Example {
    if (std.mem.eql(u8, value, "blake")) return .blake;
    if (std.mem.eql(u8, value, "plonk")) return .plonk;
    if (std.mem.eql(u8, value, "poseidon")) return .poseidon;
    if (std.mem.eql(u8, value, "state_machine")) return .state_machine;
    if (std.mem.eql(u8, value, "wide_fibonacci")) return .wide_fibonacci;
    if (std.mem.eql(u8, value, "xor")) return .xor;
    return null;
}

fn parseProveMode(value: []const u8) ?ProveMode {
    if (std.mem.eql(u8, value, "prove")) return .prove;
    if (std.mem.eql(u8, value, "prove_ex")) return .prove_ex;
    return null;
}

fn parseBlake2Backend(value: []const u8) ?blake2_hash.BackendMode {
    if (std.mem.eql(u8, value, "auto")) return .auto;
    if (std.mem.eql(u8, value, "scalar")) return .scalar;
    if (std.mem.eql(u8, value, "simd")) return .simd;
    return null;
}

fn parseBenchProofCodec(value: []const u8) ?BenchProofCodec {
    if (std.mem.eql(u8, value, "json")) return .json;
    if (std.mem.eql(u8, value, "binary")) return .binary;
    return null;
}

fn parseBool(value: []const u8) !bool {
    if (std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "0") or std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBoolean;
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10);
}

pub fn pcsConfigFromCli(cli: Cli) !pcs.PcsConfig {
    return .{
        .pow_bits = cli.pow_bits,
        .fri_config = try fri.FriConfig.init(
            cli.fri_log_last_layer,
            cli.fri_log_blowup,
            cli.fri_n_queries,
        ),
    };
}

pub fn m31FromCanonical(value: u32) !M31 {
    if (value >= m31.Modulus) return error.NonCanonicalM31;
    return M31.fromCanonical(value);
}

pub fn printUsage() void {
    std.debug.print(
        "usage:\n" ++
            "  zig build interop-cli && zig-out/bin/interop_cli --mode generate --example <blake|plonk|poseidon|state_machine|wide_fibonacci|xor> --artifact <path> [options]\n" ++
            "    [--stage-profile-out <path>] (wide_fibonacci only)\n" ++
            "    [--prove-mode <prove|prove_ex>] [--blake2-backend <auto|scalar|simd>] [--include-all-preprocessed-columns <0|1>]\n" ++
            "  zig-out/bin/interop_cli --mode verify --artifact <path>\n" ++
            "  zig-out/bin/interop_cli --mode verify_std_shims --artifact <path>\n" ++
            "  zig-out/bin/interop_cli --mode bench --example <blake|plonk|poseidon|state_machine|wide_fibonacci|xor> --artifact <ignored> [options]\n" ++
            "    [--bench-warmups <n>] [--bench-repeats <n>] [--bench-proof-codec <json|binary>] [--blake2-backend <auto|scalar|simd>]\n",
        .{},
    );
}
