//! Matched in-process benchmark for the Bitcoin S31 source and assignment.
//! Run this test directly: Zig's build run cache may replay timing output.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const relation = @import("../../language/relation.zig");
const compiler = @import("../../language/relation_compiler.zig");
const generic_native = @import("../../runtime/native_verifier.zig");
const shift = @import("../../sha/proving/sha_shift_circuit_prover.zig");
const shift_native = @import("../../sha/verification/sha_shift_circuit_native_verifier.zig");
const shift_profile = @import("../../sha/config/sha_shift_private_join_profile.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const source = @embedFile("../../examples/bitcoin_header_pow.s31.json");
const assignment_source = @embedFile("../../examples/bitcoin_header_pow.valid.json");

fn trials() !usize {
    const raw = std.posix.getenv("S31_BITCOIN_MATCHED_TRIALS") orelse return 3;
    const count = try std.fmt.parseInt(usize, raw, 10);
    if (count == 0 or count > 9) return error.InvalidBenchmarkTrialCount;
    return count;
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

fn equalOutputs(expected: []const QM31, actual: []const QM31) bool {
    if (expected.len != actual.len) return false;
    for (expected, actual) |left, right| if (!left.eql(right)) return false;
    return true;
}

const Timings = struct {
    total_ns: u64 = 0,
    fixed_setup_ns: u64 = 0,
    interaction_pow_ns: u64 = 0,
    fri_pow_ns: u64 = 0,
    verify_ns: u64 = 0,
    proof_bytes: usize = 0,
    stages: ?shift.Metrics = null,

    fn excludingPow(self: Timings) !u64 {
        return std.math.sub(u64, try std.math.sub(u64, self.total_ns, self.interaction_pow_ns), self.fri_pow_ns);
    }
};

fn printTrial(label: []const u8, ordinal: usize, timing: Timings) !void {
    std.debug.print("S31_MATCHED profile={s} trial={d} prove_ns={d} prove_excluding_pow_ns={d} verify_ns={d} fixed_setup_ns={d} interaction_pow_ns={d} fri_pow_ns={d} proof_bytes={d}\n", .{
        label,                 ordinal,                   timing.total_ns,   try timing.excludingPow(), timing.verify_ns,
        timing.fixed_setup_ns, timing.interaction_pow_ns, timing.fri_pow_ns, timing.proof_bytes,
    });
    if (timing.stages) |stages| {
        std.debug.print("S31_MATCHED_SHIFT_STAGES profile={s} trial={d} witness_ns={d} fixed_commit_ns={d} main_commit_ns={d} interaction_ns={d} interaction_pow_ns={d} interaction_commit_ns={d} fri_ns={d} fri_pow_ns={d} composition_eval_ns={d} composition_interpolate_ns={d} composition_commit_ns={d} sampled_value_eval_ns={d} fri_quotient_commit_ns={d} fri_decommit_ns={d} trace_decommit_ns={d}\n", .{
            label,                      ordinal,                           stages.witness_ns,            stages.fixed_commit_ns,       stages.main_commit_ns,
            stages.interaction_ns,      stages.interaction_pow_ns,         stages.interaction_commit_ns, stages.fri_ns,                stages.fri_pow_ns,
            stages.composition_eval_ns, stages.composition_interpolate_ns, stages.composition_commit_ns, stages.sampled_value_eval_ns, stages.fri_quotient_commit_ns,
            stages.fri_decommit_ns,     stages.trace_decommit_ns,
        });
    }
}

pub fn runBenchmark() !void {
    // Match the packaged CLI's allocator in both test and executable modes.
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const n = try trials();
    var program = try relation.parseProgram(allocator, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(allocator, assignment_source);
    defer assignment.deinit();
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_digest, .{});
    const public_words = try relation.claimedWords(allocator, program.value, assignment.value);
    var output_values: [8]QM31 = undefined;
    for (public_words, &output_values) |word, *value| {
        value.* = QM31.fromM31(M31.fromCanonical(word & 0xffff), M31.fromCanonical(word >> 16), M31.zero(), M31.zero());
    }
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();

    // Generic lowering: all SHA256d bit logic stays in the sparse-wide circuit.
    var generic_values = try compiler.compileWithSpans(QM31, allocator, program.value, assignment.value, null);
    defer generic_values.deinit();
    var generic_topology = try compiler.compileWithSpans(circuit.builder.NoValue, allocator, program.value, null, null);
    defer generic_topology.deinit();
    const generic_raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&generic_topology.circuit));
    const generic_targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(generic_raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(generic_raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(generic_raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(QM31, &generic_values, generic_targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &generic_topology, generic_targets);
    var generic_pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &generic_topology.circuit);
    defer generic_pp.deinit(allocator);
    const generic_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, generic_pp.traceLogSize());
    var generic_fixed = try cpu.sparse_wide.PreprocessedCommitment.build(allocator, &generic_pp, generic_pcs);
    defer generic_fixed.deinit(allocator);
    const generic_layout = generic_pp.layout();
    const generic_root = generic_fixed.root();
    const generic_hash = cpu.sparse_wide.identityHash(source_digest, generic_root, .{
        generic_layout.logSize("eq_in0_address").?,
        generic_layout.logSize("qm31_ops_in0_address").?,
        generic_layout.logSize("m31_to_u32_input_addr").?,
        16,
    }, generic_pcs.fri_config.log_blowup_factor);

    // Shift lowering: same relation and witness; SHA arithmetic is in three
    // schedule/round/feed AIR calls, with the digest private and Gate bus closed.
    var shift_value_maps = compiler.Maps{};
    defer shift_value_maps.deinit(allocator);
    var shift_values = try compiler.compileShaChipWithSpans(QM31, allocator, program.value, assignment.value, &shift_value_maps);
    defer shift_values.deinit();
    var shift_topology_maps = compiler.Maps{};
    defer shift_topology_maps.deinit(allocator);
    var shift_topology = try compiler.compileShaChipWithSpans(circuit.builder.NoValue, allocator, program.value, null, &shift_topology_maps);
    defer shift_topology.deinit();
    const addresses = shift_value_maps.sha_boundaries.items[0].addresses;
    if (!std.mem.eql(u32, &addresses, &shift_topology_maps.sha_boundaries.items[0].addresses)) return error.ShaBoundaryAddressMismatch;
    const shift_raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&shift_topology.circuit));
    const shift_targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(shift_raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(shift_raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(shift_raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(QM31, &shift_values, shift_targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &shift_topology, shift_targets);
    var shift_pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(allocator, &shift_topology.circuit, .{ .addresses = addresses });
    defer shift_pp.deinit(allocator);
    const input_words = try relation.inputValues(allocator, assignment.value, program.value.inputs[0]);
    defer allocator.free(input_words);
    if (input_words.len != 40) return error.WrongBitcoinHeaderWidth;
    var header: [80]u8 = undefined;
    for (input_words, 0..) |word, i| std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    const statement = shift_profile.PublicStatement{
        .digest_visibility = .private,
        .config = .{ .gate_addresses = addresses, .first_call_id = 1 },
    };
    const shift_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(shift_pp.traceLogSize(), 7));
    const shift_key = try shift_native.deriveKey(allocator, source_digest, &shift_pp, @intCast(shift_values.circuit.n_vars), statement, shift_pcs);
    var shift_fixed = try shift.PreparedFixed.build(allocator, &shift_pp, statement, shift_pcs);
    defer shift_fixed.deinit(allocator);
    if (!std.meta.eql(shift_key.fixed_root, shift_fixed.root())) return error.PreparedShaFixedRootMismatch;
    std.debug.print("S31_MATCHED_SETUP execution_mode={s} generic_vars={d} generic_trace_log={d} shift_vars={d} shift_trace_log={d} fri_pow_bits=26 queries=70 interaction_pow_bits=20 trials={d} warm_fixed_cached=true cold_fixed_in_timer=true\n", .{
        if (builtin.is_test) "test" else "production", generic_values.circuit.n_vars, generic_pp.traceLogSize(), shift_values.circuit.n_vars, shift_pp.traceLogSize(), n,
    });

    const generic_samples = try allocator.alloc(Timings, n);
    defer allocator.free(generic_samples);
    const shift_samples = try allocator.alloc(Timings, n);
    defer allocator.free(shift_samples);
    for (0..n) |trial| {
        for (0..2) |position| {
            const run_generic = ((trial + position) & 1) == 0;
            if (run_generic) {
                var interaction_pow_ns: u64 = 0;
                var fri_pow_ns: u64 = 0;
                var timer = try std.time.Timer.start();
                var proof = try cpu.sparse_wide.prove(allocator, generic_values.values(), &generic_pp, &bundle, generic_pcs, .{
                    .source_digest = source_digest,
                    .preprocessed_commitment = &generic_fixed,
                    .pow_time_ns = &interaction_pow_ns,
                    .fri_pow_time_ns = &fri_pow_ns,
                });
                const prove_ns = timer.read();
                defer proof.deinit();
                if (!equalOutputs(&output_values, proof.output_values)) return error.GenericPublicRootMismatch;
                const encoded = try generic_native.serializeSparseWide(allocator, &proof);
                defer allocator.free(encoded);
                timer.reset();
                try generic_native.verifySparseWide(allocator, &generic_layout, &bundle, generic_pcs, generic_root, generic_hash, public_words, encoded, source_digest);
                const sample = Timings{ .total_ns = prove_ns, .interaction_pow_ns = interaction_pow_ns, .fri_pow_ns = fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = encoded.len };
                generic_samples[trial] = sample;
                try printTrial("generic_warm", trial, sample);
            } else {
                var metrics = shift.Metrics{};
                var timer = try std.time.Timer.start();
                var proof = try shift.prove(allocator, shift_values.values(), &shift_pp, &bundle, shift_pcs, .{
                    .source_digest = source_digest,
                    .n_vars = @intCast(shift_values.circuit.n_vars),
                    .statement = statement,
                    .header = header,
                    .prepared_fixed = &shift_fixed,
                    .metrics = &metrics,
                });
                const prove_ns = timer.read();
                defer proof.deinit();
                if (!std.meta.eql(shift_key.fixed_root, proof.key.fixed_root)) return error.ShiftFixedRootMismatch;
                if (!equalOutputs(&output_values, proof.outputs)) return error.ShiftPublicRootMismatch;
                const encoded = try shift.serialize(allocator, &proof);
                defer allocator.free(encoded);
                timer.reset();
                try shift_native.verifyBytes(allocator, .{ .key = shift_key, .public_outputs = &output_values }, encoded);
                const sample = Timings{ .total_ns = prove_ns, .interaction_pow_ns = metrics.interaction_pow_ns, .fri_pow_ns = metrics.fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = encoded.len, .stages = metrics };
                shift_samples[trial] = sample;
                try printTrial("sha_shift_warm", trial, sample);
            }
        }
    }
    // One-shot generic policy: charge the canonical fixed commitment to the
    // same timer as proving. The packaged sparse-wide path normally caches it.
    const generic_cold_samples = try allocator.alloc(Timings, n);
    defer allocator.free(generic_cold_samples);
    for (0..n) |trial| {
        var interaction_pow_ns: u64 = 0;
        var fri_pow_ns: u64 = 0;
        var timer = try std.time.Timer.start();
        var cold_fixed = try cpu.sparse_wide.PreprocessedCommitment.build(allocator, &generic_pp, generic_pcs);
        defer cold_fixed.deinit(allocator);
        const fixed_setup_ns = timer.read();
        if (!std.meta.eql(generic_root, cold_fixed.root())) return error.GenericColdFixedRootMismatch;
        var proof = try cpu.sparse_wide.prove(allocator, generic_values.values(), &generic_pp, &bundle, generic_pcs, .{
            .source_digest = source_digest,
            .preprocessed_commitment = &cold_fixed,
            .pow_time_ns = &interaction_pow_ns,
            .fri_pow_time_ns = &fri_pow_ns,
        });
        const prove_ns = timer.read();
        defer proof.deinit();
        if (!equalOutputs(&output_values, proof.output_values)) return error.GenericPublicRootMismatch;
        const encoded = try generic_native.serializeSparseWide(allocator, &proof);
        defer allocator.free(encoded);
        timer.reset();
        try generic_native.verifySparseWide(allocator, &generic_layout, &bundle, generic_pcs, generic_root, generic_hash, public_words, encoded, source_digest);
        const sample = Timings{ .total_ns = prove_ns, .fixed_setup_ns = fixed_setup_ns, .interaction_pow_ns = interaction_pow_ns, .fri_pow_ns = fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = encoded.len };
        generic_cold_samples[trial] = sample;
        try printTrial("generic_cold", trial, sample);
    }
    // One-shot shift policy keeps its fixed commit inside prove().
    const shift_cold_samples = try allocator.alloc(Timings, n);
    defer allocator.free(shift_cold_samples);
    for (0..n) |trial| {
        var metrics = shift.Metrics{};
        var timer = try std.time.Timer.start();
        var proof = try shift.prove(allocator, shift_values.values(), &shift_pp, &bundle, shift_pcs, .{
            .source_digest = source_digest,
            .n_vars = @intCast(shift_values.circuit.n_vars),
            .statement = statement,
            .header = header,
            .metrics = &metrics,
        });
        const prove_ns = timer.read();
        defer proof.deinit();
        if (!std.meta.eql(shift_key.fixed_root, proof.key.fixed_root)) return error.ShiftFixedRootMismatch;
        if (!equalOutputs(&output_values, proof.outputs)) return error.ShiftPublicRootMismatch;
        const encoded = try shift.serialize(allocator, &proof);
        defer allocator.free(encoded);
        timer.reset();
        try shift_native.verifyBytes(allocator, .{ .key = shift_key, .public_outputs = &output_values }, encoded);
        const sample = Timings{ .total_ns = prove_ns, .fixed_setup_ns = metrics.fixed_commit_ns, .interaction_pow_ns = metrics.interaction_pow_ns, .fri_pow_ns = metrics.fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = encoded.len, .stages = metrics };
        shift_cold_samples[trial] = sample;
        try printTrial("sha_shift_cold", trial, sample);
    }
    const generic_net = try allocator.alloc(u64, n);
    defer allocator.free(generic_net);
    const generic_cold_net = try allocator.alloc(u64, n);
    defer allocator.free(generic_cold_net);
    const shift_net = try allocator.alloc(u64, n);
    defer allocator.free(shift_net);
    const shift_cold_net = try allocator.alloc(u64, n);
    defer allocator.free(shift_cold_net);
    const generic_verify = try allocator.alloc(u64, n);
    defer allocator.free(generic_verify);
    const shift_verify = try allocator.alloc(u64, n);
    defer allocator.free(shift_verify);
    for (0..n) |i| {
        generic_net[i] = try generic_samples[i].excludingPow();
        generic_cold_net[i] = try generic_cold_samples[i].excludingPow();
        shift_net[i] = try shift_samples[i].excludingPow();
        shift_cold_net[i] = try shift_cold_samples[i].excludingPow();
        generic_verify[i] = generic_samples[i].verify_ns;
        shift_verify[i] = shift_samples[i].verify_ns;
    }
    std.debug.print("S31_MATCHED_MEDIAN generic_warm_prove_excluding_pow_ns={d} shift_warm_prove_excluding_pow_ns={d} generic_cold_prove_excluding_pow_ns={d} shift_cold_prove_excluding_pow_ns={d} generic_verify_ns={d} shift_verify_ns={d} generic_proof_bytes={d} shift_proof_bytes={d}\n", .{
        median(generic_net), median(shift_net), median(generic_cold_net), median(shift_cold_net), median(generic_verify), median(shift_verify), generic_samples[0].proof_bytes, shift_samples[0].proof_bytes,
    });
}

pub fn main() !void {
    try runBenchmark();
}

test "matched Bitcoin generic sparse-wide versus shift SHA proof" {
    try runBenchmark();
}
