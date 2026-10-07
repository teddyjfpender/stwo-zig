//! In-process matched v3/v4 Bitcoin benchmark under production FRI settings.
//! Run the production executable directly; build-system run caching replays logs.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const relation = @import("../../language/relation.zig");
const compiler = @import("../../language/relation_compiler.zig");
const shift = @import("../proving/sha_shift_circuit_prover.zig");
const shift_native = @import("../verification/sha_shift_circuit_native_verifier.zig");
const fused = @import("../proving/sha_fused_circuit_prover.zig");
const fused_native = @import("../verification/sha_fused_circuit_native_verifier.zig");
const profile = @import("../config/sha_fused_private_join_profile.zig");
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;

const Stages = struct {
    witness_ns: u64,
    fixed_commit_ns: u64,
    main_commit_ns: u64,
    interaction_ns: u64,
    interaction_commit_ns: u64,
    fri_ns: u64,
    composition_eval_ns: u64,
    composition_interpolate_ns: u64,
    composition_commit_ns: u64,
    sampled_value_eval_ns: u64,
    fri_quotient_commit_ns: u64,
    fri_decommit_ns: u64,
    trace_decommit_ns: u64,
    fn from(m: anytype) Stages {
        return .{
            .witness_ns = m.witness_ns,
            .fixed_commit_ns = m.fixed_commit_ns,
            .main_commit_ns = m.main_commit_ns,
            .interaction_ns = m.interaction_ns,
            .interaction_commit_ns = m.interaction_commit_ns,
            .fri_ns = m.fri_ns,
            .composition_eval_ns = m.composition_eval_ns,
            .composition_interpolate_ns = m.composition_interpolate_ns,
            .composition_commit_ns = m.composition_commit_ns,
            .sampled_value_eval_ns = m.sampled_value_eval_ns,
            .fri_quotient_commit_ns = m.fri_quotient_commit_ns,
            .fri_decommit_ns = m.fri_decommit_ns,
            .trace_decommit_ns = m.trace_decommit_ns,
        };
    }
};
const Sample = struct {
    prove: u64,
    interaction_pow: u64,
    fri_pow: u64,
    verify: u64,
    proof_bytes: usize,
    metrics: Stages,
    fn net(self: Sample) !u64 {
        return std.math.sub(u64, try std.math.sub(u64, self.prove, self.interaction_pow), self.fri_pow);
    }
};
fn countTrials() !usize {
    const raw = std.posix.getenv("S31_SHA_FUSED_MATCHED_TRIALS") orelse return 5;
    const count = try std.fmt.parseInt(usize, raw, 10);
    if (count == 0 or count > 9) return error.InvalidBenchmarkTrialCount;
    return count;
}
fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}
fn printSample(name: []const u8, trial: usize, sample: Sample) !void {
    const m = sample.metrics;
    std.debug.print("S31_FUSED_MATCHED profile={s} trial={d} prove_ns={d} net_ns={d} verify_ns={d} interaction_pow_ns={d} fri_pow_ns={d} proof_bytes={d} witness_ns={d} fixed_commit_ns={d} main_commit_ns={d} interaction_ns={d} interaction_commit_ns={d} fri_ns={d} composition_eval_ns={d} composition_interpolate_ns={d} composition_commit_ns={d} sampled_value_eval_ns={d} quotient_commit_ns={d} fri_decommit_ns={d} trace_decommit_ns={d}\n", .{
        name,                  trial,                        sample.prove,            try sample.net(),        sample.verify,            sample.interaction_pow,  sample.fri_pow,
        sample.proof_bytes,    m.witness_ns,                 m.fixed_commit_ns,       m.main_commit_ns,        m.interaction_ns,         m.interaction_commit_ns, m.fri_ns,
        m.composition_eval_ns, m.composition_interpolate_ns, m.composition_commit_ns, m.sampled_value_eval_ns, m.fri_quotient_commit_ns, m.fri_decommit_ns,       m.trace_decommit_ns,
    });
}

fn ensure(ok: bool) !void {
    if (!ok) return error.BenchmarkProofMismatch;
}
fn equalOutputs(expected: []const QM31, actual: []const QM31) bool {
    if (expected.len != actual.len) return false;
    for (expected, actual) |a, b| {
        if (!a.eql(b)) return false;
    }
    return true;
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const a = gpa_state.allocator();
    const n = try countTrials();
    const cold_fixed = std.posix.getenv("S31_SHA_FUSED_MATCHED_COLD") != null;
    const source = @embedFile("../../examples/bitcoin_header_pow.s31.json");
    const assignment_source = @embedFile("../../examples/bitcoin_header_pow.valid.json");
    var program = try relation.parseProgram(a, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(a, assignment_source);
    defer assignment.deinit();
    var value_maps = compiler.Maps{};
    defer value_maps.deinit(a);
    var values = try compiler.compileShaChipWithSpans(QM31, a, program.value, assignment.value, &value_maps);
    defer values.deinit();
    var topology_maps = compiler.Maps{};
    defer topology_maps.deinit(a);
    var topology = try compiler.compileShaChipWithSpans(circuit.builder.NoValue, a, program.value, null, &topology_maps);
    defer topology.deinit();
    const addresses = value_maps.sha_boundaries.items[0].addresses;
    try ensure(std.mem.eql(u32, &addresses, &topology_maps.sha_boundaries.items[0].addresses));
    const raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&topology.circuit));
    const targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(QM31, &values, targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, targets);
    var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(a, &topology.circuit, .{ .addresses = addresses });
    defer pp.deinit(a);
    const input_words = try relation.inputValues(a, assignment.value, program.value.inputs[0]);
    defer a.free(input_words);
    if (input_words.len != 40) return error.WrongBitcoinHeaderWidth;
    var header: [80]u8 = undefined;
    for (input_words, 0..) |word, i| std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    const statement = profile.PublicStatement{ .digest_visibility = .private, .config = .{ .gate_addresses = addresses, .first_call_id = 1 } };
    const words = try relation.claimedWords(a, program.value, assignment.value);
    var outputs: [8]QM31 = undefined;
    for (words, &outputs) |word, *value| value.* = QM31.fromM31(M31.fromCanonical(word & 0xffff), M31.fromCanonical(word >> 16), M31.zero(), M31.zero());
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_digest, .{});
    var assignment_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(assignment_source, &assignment_digest, .{});
    var outputs_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(&words), &outputs_digest, .{});
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    const shift_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), 7));
    const fused_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), 8));
    try ensure(std.meta.eql(shift_pcs, fused_pcs));
    const shift_key = try shift_native.deriveKey(a, source_digest, &pp, @intCast(values.circuit.n_vars), statement, shift_pcs);
    const fused_key = try fused_native.deriveKey(a, source_digest, &pp, @intCast(values.circuit.n_vars), statement, fused_pcs);
    var shift_fixed = try shift.PreparedFixed.build(a, &pp, statement, shift_pcs);
    defer shift_fixed.deinit(a);
    var fused_fixed = try fused.PreparedFixed.build(a, &pp, statement, fused_pcs);
    defer fused_fixed.deinit(a);
    try ensure(std.meta.eql(shift_key.fixed_root, shift_fixed.root()));
    try ensure(std.meta.eql(fused_key.fixed_root, fused_fixed.root()));
    var bundle = try cpu.air.parse(a, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    const shift_samples = try a.alloc(Sample, n);
    defer a.free(shift_samples);
    const fused_samples = try a.alloc(Sample, n);
    defer a.free(fused_samples);
    std.debug.print("S31_FUSED_MATCHED_SETUP trials={d} fri_pow_bits=26 queries=70 interaction_pow_bits=20 warm_fixed={} shift_columns={any} fused_columns={any} source_sha256={s} assignment_sha256={s} outputs_u32le_sha256={s}\n", .{
        n,                                          !cold_fixed,                                    @import("../config/sha_shift_circuit_profile.zig").debugWidths(), @import("../config/sha_fused_circuit_profile.zig").debugWidths(),
        &std.fmt.bytesToHex(source_digest, .lower), &std.fmt.bytesToHex(assignment_digest, .lower), &std.fmt.bytesToHex(outputs_digest, .lower),
    });
    for (0..n) |trial| {
        for (0..2) |position| {
            const run_shift = ((trial + position) & 1) == 0;
            var timer = try std.time.Timer.start();
            if (run_shift) {
                var metrics = shift.Metrics{};
                var proof = try shift.prove(a, values.values(), &pp, &bundle, shift_pcs, .{
                    .source_digest = source_digest,
                    .n_vars = @intCast(values.circuit.n_vars),
                    .statement = statement,
                    .header = header,
                    .prepared_fixed = if (cold_fixed) null else &shift_fixed,
                    .metrics = &metrics,
                });
                defer proof.deinit();
                const prove_ns = timer.read();
                try ensure(std.meta.eql(shift_key.fixed_root, proof.key.fixed_root));
                try ensure(equalOutputs(&outputs, proof.outputs));
                const bytes = try shift.serialize(a, &proof);
                defer a.free(bytes);
                timer.reset();
                try shift_native.verifyBytes(a, .{ .key = shift_key, .public_outputs = &outputs }, bytes);
                shift_samples[trial] = .{ .prove = prove_ns, .interaction_pow = metrics.interaction_pow_ns, .fri_pow = metrics.fri_pow_ns, .verify = timer.read(), .proof_bytes = bytes.len, .metrics = Stages.from(metrics) };
                try printSample("shift_v3", trial, shift_samples[trial]);
            } else {
                var metrics = fused.Metrics{};
                var proof = try fused.prove(a, values.values(), &pp, &bundle, fused_pcs, .{
                    .source_digest = source_digest,
                    .n_vars = @intCast(values.circuit.n_vars),
                    .statement = statement,
                    .header = header,
                    .prepared_fixed = if (cold_fixed) null else &fused_fixed,
                    .metrics = &metrics,
                });
                defer proof.deinit();
                const prove_ns = timer.read();
                try ensure(std.meta.eql(fused_key.fixed_root, proof.key.fixed_root));
                try ensure(equalOutputs(&outputs, proof.outputs));
                const bytes = try fused.serialize(a, &proof);
                defer a.free(bytes);
                timer.reset();
                try fused_native.verifyBytes(a, .{ .key = fused_key, .public_outputs = &outputs }, bytes);
                fused_samples[trial] = .{ .prove = prove_ns, .interaction_pow = metrics.interaction_pow_ns, .fri_pow = metrics.fri_pow_ns, .verify = timer.read(), .proof_bytes = bytes.len, .metrics = Stages.from(metrics) };
                try printSample("fused_v4", trial, fused_samples[trial]);
            }
        }
    }
    const shift_net = try a.alloc(u64, n);
    defer a.free(shift_net);
    const fused_net = try a.alloc(u64, n);
    defer a.free(fused_net);
    const shift_verify = try a.alloc(u64, n);
    defer a.free(shift_verify);
    const fused_verify = try a.alloc(u64, n);
    defer a.free(fused_verify);
    for (0..n) |i| {
        shift_net[i] = try shift_samples[i].net();
        fused_net[i] = try fused_samples[i].net();
        shift_verify[i] = shift_samples[i].verify;
        fused_verify[i] = fused_samples[i].verify;
    }
    std.debug.print("S31_FUSED_MATCHED_MEDIAN trials={d} shift_net_ns={d} fused_net_ns={d} shift_verify_ns={d} fused_verify_ns={d} shift_proof_bytes={d} fused_proof_bytes={d}\n", .{
        n,                            median(shift_net),            median(fused_net), median(shift_verify), median(fused_verify),
        shift_samples[0].proof_bytes, fused_samples[0].proof_bytes,
    });
}
