//! Production in-process benchmark: three valid mainnet headers, same S31
//! source, generic sparse-wide versus SHA shift v3 versus fused SHA v4.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const relation = @import("../../language/relation.zig");
const compiler = @import("../../language/relation_compiler.zig");
const poseidon2 = @import("../../library/hash/poseidon2.zig");
const generic_native = @import("../../runtime/native_verifier.zig");
const shift = @import("../../sha/proving/sha_shift_circuit_prover.zig");
const shift_native = @import("../../sha/verification/sha_shift_circuit_native_verifier.zig");
const fused = @import("../../sha/proving/sha_fused_circuit_prover.zig");
const fused_native = @import("../../sha/verification/sha_fused_circuit_native_verifier.zig");
const sha_profile = @import("../../sha/config/sha_fused_private_join_profile.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const source = @embedFile("../../examples/bitcoin/bitcoin_header_pow.s31.json");
const genesis_assignment = @embedFile("../../examples/bitcoin/bitcoin_header_pow.valid.json");
const block_one_fixture = @embedFile("../../examples/bitcoin/bitcoin_header_link.valid.json");
const block_two_fixture = @embedFile("../../examples/bitcoin/bitcoin_block2_header.valid.json");
const n_headers = 3;
const n_profiles = 3;
const names = [_][]const u8{ "genesis", "height_1", "height_2" };
const profiles = [_][]const u8{ "generic", "shift_v3", "fused_v4" };

const Sample = struct {
    prove_ns: u64,
    interaction_pow_ns: u64,
    fri_pow_ns: u64,
    verify_ns: u64,
    proof_bytes: usize,
    proof_digest: [32]u8,
    composition_eval_ns: u64 = 0,
    quotient_commit_ns: u64 = 0,

    fn nonPow(self: Sample) !u64 {
        return std.math.sub(u64, try std.math.sub(u64, self.prove_ns, self.interaction_pow_ns), self.fri_pow_ns);
    }
};

fn equalOutputs(expected: []const QM31, actual: []const QM31) bool {
    if (expected.len != actual.len) return false;
    for (expected, actual) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn rounds() !usize {
    const raw = std.posix.getenv("S31_BITCOIN_MULTI_WITNESS_ROUNDS") orelse return 3;
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0 or value > 9) return error.InvalidMultiWitnessRounds;
    return value;
}

fn readHeader(allocator: std.mem.Allocator, assignment: relation.Assignment, program: relation.Program) ![80]u8 {
    const words = try relation.inputValues(allocator, assignment, program.inputs[0]);
    defer allocator.free(words);
    if (words.len != 40) return error.WrongBitcoinHeaderWidth;
    var header: [80]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    return header;
}

fn fixtureHeaders(allocator: std.mem.Allocator, genesis: [80]u8) ![n_headers][80]u8 {
    const Link = struct { private_inputs: struct { child: [40]u16 } };
    var linked = try std.json.parseFromSlice(Link, allocator, block_one_fixture, .{ .ignore_unknown_fields = true });
    defer linked.deinit();
    var first: [80]u8 = undefined;
    for (linked.value.private_inputs.child, 0..) |word, i| std.mem.writeInt(u16, first[2 * i ..][0..2], word, .little);
    const BlockTwo = struct { header_hex: []const u8 };
    var block_two = try std.json.parseFromSlice(BlockTwo, allocator, block_two_fixture, .{ .ignore_unknown_fields = true });
    defer block_two.deinit();
    var second: [80]u8 = undefined;
    if (block_two.value.header_hex.len != 160) return error.WrongBitcoinHeaderWidth;
    _ = try std.fmt.hexToBytes(&second, block_two.value.header_hex);
    return .{ genesis, first, second };
}

fn derivedRoot(header: [80]u8) !struct { digest: [32]u8, root: [8]u32 } {
    var first: [32]u8 = undefined;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&header, &first, .{});
    std.crypto.hash.sha2.Sha256.hash(&first, &digest, .{});
    const compact = std.mem.readInt(u32, header[72..76], .little);
    const target = try relation.mainnetTarget(compact);
    if (std.mem.readInt(u256, &digest, .little) > target) return error.InvalidBitcoinProofOfWork;
    var limbs: [16]M31 = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = M31.fromCanonical(std.mem.readInt(u16, digest[2 * i ..][0..2], .little));
    const root = poseidon2.leafWords(&limbs);
    var words: [8]u32 = undefined;
    for (root, &words) |value, *word| word.* = value.toU32();
    return .{ .digest = digest, .root = words };
}

fn setAssignment(assignment: *relation.Assignment, header: [80]u8, root: [8]u32) !void {
    const private = if (assignment.private_inputs) |*value| value else return error.MissingPrivateInputs;
    if (private.* != .object or assignment.public_outputs != .object) return error.InvalidBitcoinAssignment;
    const header_json = private.object.getPtr("header") orelse return error.InvalidBitcoinAssignment;
    const root_json = assignment.public_outputs.object.getPtr("root") orelse return error.InvalidBitcoinAssignment;
    if (header_json.* != .array or header_json.array.items.len != 40 or root_json.* != .array or root_json.array.items.len != 8)
        return error.InvalidBitcoinAssignment;
    for (header_json.array.items, 0..) |*item, i| item.* = .{ .integer = std.mem.readInt(u16, header[2 * i ..][0..2], .little) };
    for (root_json.array.items, root) |*item, word| item.* = .{ .integer = word };
}

fn publicQM31(words: [8]u32) [8]QM31 {
    var output: [8]QM31 = undefined;
    for (words, &output) |word, *value| value.* = QM31.fromM31(M31.fromCanonical(word & 0xffff), M31.fromCanonical(word >> 16), M31.zero(), M31.zero());
    return output;
}

fn printSample(profile: usize, witness: usize, round: usize, sample: Sample) !void {
    std.debug.print("S31_MULTI_SAMPLE profile={s} witness={s} round={d} prove_ns={d} nonpow_ns={d} interaction_pow_ns={d} fri_pow_ns={d} verify_ns={d} proof_bytes={d} proof_sha256={s} composition_eval_ns={d} quotient_commit_ns={d}\n", .{
        profiles[profile], names[witness],     round,                                            sample.prove_ns,            try sample.nonPow(),       sample.interaction_pow_ns, sample.fri_pow_ns,
        sample.verify_ns,  sample.proof_bytes, &std.fmt.bytesToHex(sample.proof_digest, .lower), sample.composition_eval_ns, sample.quotient_commit_ns,
    });
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const n_rounds = try rounds();
    var program = try relation.parseProgram(allocator, source);
    defer program.deinit();
    var assignments: [n_headers]relation.ParsedAssignment = undefined;
    var assignment_count: usize = 0;
    defer for (assignments[0..assignment_count]) |*assignment| assignment.deinit();
    for (&assignments) |*assignment| {
        assignment.* = try relation.parseAssignment(allocator, genesis_assignment);
        assignment_count += 1;
    }
    const headers = try fixtureHeaders(allocator, try readHeader(allocator, assignments[0].value, program.value));
    var roots: [n_headers][8]u32 = undefined;
    var outputs: [n_headers][8]QM31 = undefined;
    for (headers, 0..) |header, i| {
        const derived = try derivedRoot(header);
        roots[i] = derived.root;
        outputs[i] = publicQM31(derived.root);
        try setAssignment(&assignments[i].value, header, derived.root);
        const interpreted = try relation.evaluate(allocator, program.value, assignments[i].value);
        if (!std.meta.eql(interpreted, derived.root)) return error.InterpreterPublicRootMismatch;
        var display_hash = derived.digest;
        std.mem.reverse(u8, &display_hash);
        std.debug.print("S31_MULTI_WITNESS name={s} header_sha256d_display={s} root_u32le_hex={s}\n", .{
            names[i], &std.fmt.bytesToHex(display_hash, .lower), &std.fmt.bytesToHex(std.mem.asBytes(&derived.root), .lower),
        });
    }

    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_digest, .{});
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();

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
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &generic_topology, generic_targets);
    var generic_pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &generic_topology.circuit);
    defer generic_pp.deinit(allocator);
    const generic_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, generic_pp.traceLogSize());
    var generic_fixed = try cpu.sparse_wide.PreprocessedCommitment.build(allocator, &generic_pp, generic_pcs);
    defer generic_fixed.deinit(allocator);
    const generic_layout = generic_pp.layout();
    const generic_root = generic_fixed.root();
    const generic_hash = cpu.sparse_wide.identityHash(source_digest, generic_root, .{
        generic_layout.logSize("eq_in0_address").?,        generic_layout.logSize("qm31_ops_in0_address").?,
        generic_layout.logSize("m31_to_u32_input_addr").?, 16,
    }, generic_pcs.fri_config.log_blowup_factor);

    var sha_topology_maps = compiler.Maps{};
    defer sha_topology_maps.deinit(allocator);
    var sha_topology = try compiler.compileShaChipWithSpans(circuit.builder.NoValue, allocator, program.value, null, &sha_topology_maps);
    defer sha_topology.deinit();
    const addresses = sha_topology_maps.sha_boundaries.items[0].addresses;
    const sha_raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&sha_topology.circuit));
    const sha_targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(sha_raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(sha_raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(sha_raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &sha_topology, sha_targets);
    var sha_pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(allocator, &sha_topology.circuit, .{ .addresses = addresses });
    defer sha_pp.deinit(allocator);
    const statement = sha_profile.PublicStatement{ .digest_visibility = .private, .config = .{ .gate_addresses = addresses, .first_call_id = 1 } };
    const shift_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(sha_pp.traceLogSize(), 7));
    const fused_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(sha_pp.traceLogSize(), 8));
    if (!std.meta.eql(shift_pcs, fused_pcs)) return error.UnmatchedShaPcs;

    var generic_values: [n_headers]circuit.builder.Context(QM31) = undefined;
    var sha_values: [n_headers]circuit.builder.Context(QM31) = undefined;
    var generic_count: usize = 0;
    var sha_count: usize = 0;
    defer for (generic_values[0..generic_count]) |*value| value.deinit();
    defer for (sha_values[0..sha_count]) |*value| value.deinit();
    for (0..n_headers) |i| {
        generic_values[i] = try compiler.compileWithSpans(QM31, allocator, program.value, assignments[i].value, null);
        generic_count += 1;
        try circuit.common.finalize.padToTargets(QM31, &generic_values[i], generic_targets);
        var maps = compiler.Maps{};
        defer maps.deinit(allocator);
        sha_values[i] = try compiler.compileShaChipWithSpans(QM31, allocator, program.value, assignments[i].value, &maps);
        sha_count += 1;
        if (!std.meta.eql(addresses, maps.sha_boundaries.items[0].addresses)) return error.UnmatchedShaBoundary;
        try circuit.common.finalize.padToTargets(QM31, &sha_values[i], sha_targets);
        if (i != 0 and (generic_values[i].circuit.n_vars != generic_values[0].circuit.n_vars or sha_values[i].circuit.n_vars != sha_values[0].circuit.n_vars))
            return error.WitnessDependentCircuitTopology;
    }

    const shift_key = try shift_native.deriveKey(allocator, source_digest, &sha_pp, @intCast(sha_values[0].circuit.n_vars), statement, shift_pcs);
    const fused_key = try fused_native.deriveKey(allocator, source_digest, &sha_pp, @intCast(sha_values[0].circuit.n_vars), statement, fused_pcs);
    var shift_fixed = try shift.PreparedFixed.build(allocator, &sha_pp, statement, shift_pcs);
    defer shift_fixed.deinit(allocator);
    var fused_fixed = try fused.PreparedFixed.build(allocator, &sha_pp, statement, fused_pcs);
    defer fused_fixed.deinit(allocator);
    if (!std.meta.eql(shift_key.fixed_root, shift_fixed.root()) or !std.meta.eql(fused_key.fixed_root, fused_fixed.root()))
        return error.NoncanonicalShaFixedRoot;
    std.debug.print("S31_MULTI_SETUP execution_mode={s} witnesses=3 rounds={d} samples_per_profile={d} fri_pow_bits=26 fri_log_last_layer_degree_bound=0 fri_last_layer_degree_bound=1 fri_queries=70 fri_log_blowup_factor=1 fri_fold_step=1 interaction_pow_bits=20 fixed_policy=warm source_sha256={s} generic_vars={d} sha_vars={d}\n", .{
        if (builtin.is_test) "test" else "production", n_rounds,                         n_rounds * n_headers,
        &std.fmt.bytesToHex(source_digest, .lower),    generic_values[0].circuit.n_vars, sha_values[0].circuit.n_vars,
    });

    var first_proof: [n_profiles][n_headers]?[32]u8 = .{
        .{ null, null, null }, .{ null, null, null }, .{ null, null, null },
    };
    for (0..n_rounds) |round| {
        for (0..n_headers) |witness| {
            for (0..n_profiles) |position| {
                const profile = (round + witness + position) % n_profiles;
                var timer = try std.time.Timer.start();
                var sample: Sample = undefined;
                if (profile == 0) {
                    var interaction_pow_ns: u64 = 0;
                    var fri_pow_ns: u64 = 0;
                    var proof = try cpu.sparse_wide.prove(allocator, generic_values[witness].values(), &generic_pp, &bundle, generic_pcs, .{
                        .source_digest = source_digest,
                        .preprocessed_commitment = &generic_fixed,
                        .pow_time_ns = &interaction_pow_ns,
                        .fri_pow_time_ns = &fri_pow_ns,
                    });
                    defer proof.deinit();
                    const prove_ns = timer.read();
                    if (!equalOutputs(&outputs[witness], proof.output_values)) return error.GenericPublicRootMismatch;
                    const bytes = try generic_native.serializeSparseWide(allocator, &proof);
                    defer allocator.free(bytes);
                    timer.reset();
                    try generic_native.verifySparseWide(allocator, &generic_layout, &bundle, generic_pcs, generic_root, generic_hash, roots[witness], bytes, source_digest);
                    sample = .{ .prove_ns = prove_ns, .interaction_pow_ns = interaction_pow_ns, .fri_pow_ns = fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = bytes.len, .proof_digest = undefined };
                    std.crypto.hash.sha2.Sha256.hash(bytes, &sample.proof_digest, .{});
                } else if (profile == 1) {
                    var metrics = shift.Metrics{};
                    var proof = try shift.prove(allocator, sha_values[witness].values(), &sha_pp, &bundle, shift_pcs, .{
                        .source_digest = source_digest,
                        .n_vars = @intCast(sha_values[witness].circuit.n_vars),
                        .statement = statement,
                        .header = headers[witness],
                        .prepared_fixed = &shift_fixed,
                        .metrics = &metrics,
                    });
                    defer proof.deinit();
                    const prove_ns = timer.read();
                    if (!std.meta.eql(shift_key.fixed_root, proof.key.fixed_root) or !equalOutputs(&outputs[witness], proof.outputs)) return error.ShiftProofMismatch;
                    const bytes = try shift.serialize(allocator, &proof);
                    defer allocator.free(bytes);
                    timer.reset();
                    try shift_native.verifyBytes(allocator, .{ .key = shift_key, .public_outputs = &outputs[witness] }, bytes);
                    sample = .{ .prove_ns = prove_ns, .interaction_pow_ns = metrics.interaction_pow_ns, .fri_pow_ns = metrics.fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = bytes.len, .proof_digest = undefined, .composition_eval_ns = metrics.composition_eval_ns, .quotient_commit_ns = metrics.fri_quotient_commit_ns };
                    std.crypto.hash.sha2.Sha256.hash(bytes, &sample.proof_digest, .{});
                } else {
                    var metrics = fused.Metrics{};
                    var proof = try fused.prove(allocator, sha_values[witness].values(), &sha_pp, &bundle, fused_pcs, .{
                        .source_digest = source_digest,
                        .n_vars = @intCast(sha_values[witness].circuit.n_vars),
                        .statement = statement,
                        .header = headers[witness],
                        .prepared_fixed = &fused_fixed,
                        .metrics = &metrics,
                    });
                    defer proof.deinit();
                    const prove_ns = timer.read();
                    if (!std.meta.eql(fused_key.fixed_root, proof.key.fixed_root) or !equalOutputs(&outputs[witness], proof.outputs)) return error.FusedProofMismatch;
                    const bytes = try fused.serialize(allocator, &proof);
                    defer allocator.free(bytes);
                    timer.reset();
                    try fused_native.verifyBytes(allocator, .{ .key = fused_key, .public_outputs = &outputs[witness] }, bytes);
                    sample = .{ .prove_ns = prove_ns, .interaction_pow_ns = metrics.interaction_pow_ns, .fri_pow_ns = metrics.fri_pow_ns, .verify_ns = timer.read(), .proof_bytes = bytes.len, .proof_digest = undefined, .composition_eval_ns = metrics.composition_eval_ns, .quotient_commit_ns = metrics.fri_quotient_commit_ns };
                    std.crypto.hash.sha2.Sha256.hash(bytes, &sample.proof_digest, .{});
                }
                if (first_proof[profile][witness]) |prior| {
                    if (!std.meta.eql(prior, sample.proof_digest)) return error.NondeterministicBitcoinProofBytes;
                } else first_proof[profile][witness] = sample.proof_digest;
                try printSample(profile, witness, round, sample);
            }
        }
    }
}
