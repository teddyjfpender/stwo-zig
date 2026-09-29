//! Rung R7, multiverifier: the Zig circuit prover reproduces
//! `test_data/circuit_multiverifier/proof.bin` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 byte for byte from its inputs.
//!
//! Upstream's `test_prove_multiverifier_of_two_cairo_subcircuits` proves the
//! multiverifier of two privacy Cairo verifier proofs under
//! `PCS_CONFIG = get_pcs_config(21, 3)` (27 PoW bits, blowup 3, 23 queries,
//! fold step 4) and serializes `prepare_circuit_proof_for_circuit_verifier`.
//! The oracle's `multiverifier-inputs` subcommand writes that circuit and its
//! value table (179 MB, `STWZCIRC/1`); the checkpoint
//! `vectors/circuit/r7/multiverifier_inputs.json` pins the file, the
//! circuit's digests and the preprocessed root. The file is too large for the
//! tree: this test reads it from `STWO_CIRCUIT_MULTIVERIFIER_INPUTS` and is
//! skipped without it.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const circuit_inputs = @import("circuit_inputs.zig");
const rust_verifier = @import("rust_verifier.zig");

const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const preprocessed = circuit.common.preprocessed;
const Step = circuit_cpu.prove.Step;

const checkpoint_path = "vectors/circuit/r7/multiverifier_inputs.json";
const proof_path = "vectors/circuit/official/circuit_multiverifier/proof.bin";
const inputs_env = "STWO_CIRCUIT_MULTIVERIFIER_INPUTS";

const Json = std.json.Value;

fn field(value: Json, name: []const u8) Json {
    return value.object.get(name) orelse std.debug.panic("checkpoint is missing {s}", .{name});
}

fn int(value: Json, name: []const u8) u32 {
    return @intCast(field(value, name).integer);
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Wall time of each transcript step since the previous one.
const StepTimer = struct {
    timer: std.time.Timer,
    last: u64 = 0,
    elapsed: [std.enums.values(Step).len]u64 = .{0} ** std.enums.values(Step).len,

    pub fn onStep(self: *StepTimer, which: Step, _: [32]u8) void {
        const now = self.timer.read();
        self.elapsed[@intFromEnum(which)] = now - self.last;
        self.last = now;
    }
};

test "R7: the multiverifier proof.bin is reproduced byte for byte" {
    const allocator = std.heap.smp_allocator;
    const inputs_path = std.process.getEnvVarOwned(allocator, inputs_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            std.debug.print("skipped: set {s} to the oracle's multiverifier-inputs file\n", .{inputs_env});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer allocator.free(inputs_path);

    const checkpoint_bytes = try std.fs.cwd().readFileAlloc(allocator, checkpoint_path, 1 << 20);
    defer allocator.free(checkpoint_bytes);
    var parsed = try std.json.parseFromSlice(Json, allocator, checkpoint_bytes, .{});
    defer parsed.deinit();
    const body = field(parsed.value, "body");

    var load_timer = try std.time.Timer.start();
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, inputs_path, 1 << 30);
    defer allocator.free(input_bytes);
    try std.testing.expectEqualStrings(field(field(body, "inputs_file"), "sha256").string, &sha256Hex(input_bytes));
    var inputs = try circuit_inputs.parse(allocator, input_bytes);
    defer inputs.deinit();
    try std.testing.expectEqual(@as(usize, int(body, "n_values")), inputs.values.len);

    var pp = try preprocessed.PreprocessedCircuit.fromCircuit(allocator, inputs.view);
    defer pp.deinit(allocator);
    const preprocess_ns = load_timer.read();
    try std.testing.expectEqual(@as(usize, int(body, "first_permutation_row")), pp.first_permutation_row);
    try std.testing.expectEqual(@as(usize, int(body, "n_outputs")), pp.n_outputs);
    try std.testing.expectEqual(int(body, "trace_log_size"), pp.traceLogSize());

    const pcs_json = field(body, "pcs_config");
    const fri_json = field(pcs_json, "fri_config");
    const pcs_config = PcsConfigV2{
        .fri_config = try FriConfigV2.init(
            int(fri_json, "pow_bits"),
            int(fri_json, "log_last_layer_degree_bound"),
            int(fri_json, "log_blowup_factor"),
            int(fri_json, "n_queries"),
            int(fri_json, "fold_step"),
        ),
        .trace_lifting_log_size = int(pcs_json, "trace_lifting_log_size"),
        .preprocessed_lifting_log_size = int(pcs_json, "preprocessed_lifting_log_size"),
    };

    const bundle_bytes = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 1 << 20);
    defer allocator.free(bundle_bytes);
    try std.testing.expectEqualStrings(circuit_cpu.air.bundle_sha256, &sha256Hex(bundle_bytes));
    var bundle = try circuit_cpu.air.parse(allocator, bundle_bytes);
    defer bundle.deinit();

    var recorder = prover.stage_profile.Recorder.init(allocator, "cpu", "circuit-multiverifier");
    defer recorder.deinit();
    var steps = StepTimer{ .timer = try std.time.Timer.start() };
    var proof = try circuit_cpu.Internal.prove(allocator, inputs.values, &pp, &bundle, pcs_config, .{
        .recorder = &recorder,
        .compact_polynomial_min_log = compactThreshold(),
    }, &steps);
    defer proof.deinit();
    const prove_ns = steps.last;

    var verifier_proof = try circuit_cpu.verifier_proof.prepare(allocator, &proof);
    defer verifier_proof.deinit();
    const encoded = try verifier_proof.serialize(allocator);
    defer allocator.free(encoded);
    const expected = try std.fs.cwd().readFileAlloc(allocator, proof_path, 1 << 20);
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(field(field(body, "proof"), "sha256").string, &sha256Hex(expected));

    std.debug.print(
        "multiverifier: load+preprocess {d} ms, prove {d} ms (interaction grind {d} ms, prove_ex {d} ms), nonces interaction 0x{x} fri 0x{x}\n",
        .{
            preprocess_ns / std.time.ns_per_ms,
            prove_ns / std.time.ns_per_ms,
            steps.elapsed[@intFromEnum(Step.mix_interaction_pow_nonce)] / std.time.ns_per_ms,
            steps.elapsed[@intFromEnum(Step.prove_ex)] / std.time.ns_per_ms,
            proof.interaction_pow_nonce,
            proof.stark_proof.proof.commitment_scheme_proof.proof_of_work,
        },
    );
    if (std.process.hasEnvVarConstant("STWO_CIRCUIT_STAGE_PROFILE")) try printStages(&recorder);

    try rust_verifier.emit(allocator, "multiverifier", encoded, &proof, &pp);
    try std.testing.expectEqual(expected.len, encoded.len);
    if (std.mem.indexOfDiff(u8, expected, encoded)) |offset| {
        std.debug.print("proof.bin differs from byte {d}\n", .{offset});
        return error.TestExpectedEqual;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    try rust_verifier.expectAccepted(allocator, "multiverifier", &digest);
}

/// `STWO_CIRCUIT_COMPACT_MIN_LOG`: compact storage threshold (default 18);
/// `off` keeps every blown-up evaluation resident.
fn compactThreshold() ?u32 {
    const value = std.posix.getenv("STWO_CIRCUIT_COMPACT_MIN_LOG") orelse return 18;
    if (std.mem.eql(u8, value, "off")) return null;
    return std.fmt.parseInt(u32, value, 10) catch 18;
}

fn printStages(recorder: *prover.stage_profile.Recorder) !void {
    var profile = try recorder.snapshot(std.heap.smp_allocator);
    defer profile.deinit(std.heap.smp_allocator);
    for (profile.stages) |stage| printStage(stage, 0);
}

fn printStage(stage: prover.stage_profile.StageNode, depth: usize) void {
    std.debug.print("{s: >[3]}{s} {d:.3} s\n", .{ "", stage.id, stage.seconds, depth * 2 });
    if (stage.children) |children| for (children) |child| printStage(child, depth + 1);
}
