//! Experimental fixed-key recursive verifier circuit. The root of the fold
//! circuit is supplied as a witness and bound by its public output; the
//! topology therefore does not need a cryptographic fixed point. A constrained
//! u32 step counter and base selector make the recursion well founded.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const recursion_gate = @import("recursion_gate.zig");
const recursion_counter = @import("recursion_counter.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const NoValue = circuit.builder.NoValue;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

pub const personalization: [8]u8 = "S31FOL2!".*;

pub const Mutation = enum {
    base_selector,
    zero_test_inverse,
    previous_counter,
    borrow,
    trace_root,
    interaction_root,
    composition_root,
    claimed_sum,
    channel_salt,
    preprocessed_oods,
    trace_oods,
    interaction_oods,
    composition_oods,
    sampled_trace_value,
    trace_auth_path,
    fri_commitment,
    fri_witness,
    fri_auth_path,
    fri_last_layer,
    interaction_pow_nonce,
    fri_pow_nonce,
};
const WitnessIndices = struct { base: usize, inverse: usize, previous: usize, borrow: usize };

fn wordsFromBytes(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}

pub fn statementDigest(root: [32]u8, step: u32, leaf_words: [8]u32) [8]u32 {
    var preimage: [68]u8 = undefined;
    @memcpy(preimage[0..32], &root);
    std.mem.writeInt(u32, preimage[32..36], step, .little);
    for (leaf_words, 0..) |word, i|
        std.mem.writeInt(u32, preimage[36 + 4 * i ..][0..4], word, .little);
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&preimage, &digest, .{ .context = personalization });
    return wordsFromBytes(digest);
}

fn selectU32(comptime V: type, ctx: *circuit.builder.Context(V), choose_right: Var, left: U32, right: U32) !U32 {
    const delta = try ctx.sub(right.get(), left.get());
    const chosen_delta = try ctx.mul(choose_right, delta);
    return .newUnsafe(try ctx.add(left.get(), chosen_delta));
}

fn digestWires(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    root: Blake.HashValue(Var),
    step: U32,
    leaf: Blake.HashValue(Var),
) !Blake.HashValue(Var) {
    var message: [17]U32 = undefined;
    @memcpy(message[0..8], &root.words);
    message[8] = step;
    @memcpy(message[9..17], &leaf.words);
    return Blake.blake2sU32sPersonalized(V, ctx, &message, 68, personalization);
}

pub fn buildCircuit(
    comptime V: type,
    allocator: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    config: *const circuit.statements.circuit_statement.CircuitConfig,
    base_root: [32]u8,
    self_root_value: Blake.HashValue(V),
    leaf_value: Blake.HashValue(V),
    step_value: u32,
    input: *const circuit.stark_verifier.proof.Proof(V),
    witness_indices: ?*WitnessIndices,
    stages: anytype,
) !circuit.builder.Context(V) {
    var ctx = try circuit.builder.Context(V).init(allocator, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const self_root = try Blake.guessHash(V, &ctx, self_root_value);
    const leaf = try Blake.guessHash(V, &ctx, leaf_value);
    const counter = try recursion_counter.constrainStepCounter(V, &ctx, step_value);
    if (witness_indices) |indices| indices.* = .{
        .base = counter.base.idx,
        .inverse = counter.inverse.idx,
        .previous = counter.previous_low.idx,
        .borrow = counter.borrow.idx,
    };

    const fixed_base_root = try Blake.constantHash(V, &ctx, Blake.hashValue(QM31, wordsFromBytes(base_root)));
    const previous_digest = try digestWires(V, &ctx, self_root, counter.previous, leaf);
    var child_root: Blake.HashValue(Var) = undefined;
    var child_output: Blake.HashValue(Var) = undefined;
    for (0..Blake.digest_n_words) |i| {
        child_root.words[i] = try selectU32(V, &ctx, counter.recurse, fixed_base_root.words[i], self_root.words[i]);
        child_output.words[i] = try selectU32(V, &ctx, counter.recurse, leaf.words[i], previous_digest.words[i]);
    }
    const statement = try circuit.statements.circuit_statement.CircuitStatement(V).init(
        &ctx,
        table,
        config,
        child_root,
        child_output,
    );
    var proof_config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(allocator, &config.preprocessed_column_log_sizes, config.config);
    defer proof_config.deinit(allocator);
    const proof_start = ctx.circuit.n_vars;
    const proof_vars = try circuit.stark_verifier.proof.guess(V, &ctx, input);
    const proof_end = ctx.circuit.n_vars;
    try stages.mark(&ctx.circuit, .{ .name = "proof_witness" });
    try circuit.stark_verifier.verify.verify(V, &ctx, &proof_vars, proof_config, &statement, stages);

    const output_hash = try digestWires(V, &ctx, self_root, counter.step, leaf);
    var outputs: [Blake.digest_n_words]Var = undefined;
    for (&outputs, output_hash.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    try stages.mark(&ctx.circuit, .{ .name = "fixed_fold_digest" });
    const StageType = switch (@typeInfo(@TypeOf(stages))) {
        .pointer => |pointer| pointer.child,
        else => @TypeOf(stages),
    };
    if (comptime @hasDecl(StageType, "auditProofWitness"))
        try stages.auditProofWitness(allocator, &ctx.circuit, ctx.constants.values(), proof_start, proof_end);
    try ctx.finalize(false);
    try stages.mark(&ctx.circuit, .{ .name = "finalize" });
    return ctx;
}

pub fn topology(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    child_layout: circuit.common.preprocessed.ColumnLayout,
    child_pcs: core.pcs.config_v2.PcsConfigV2,
    base_root: [32]u8,
) !circuit.builder.Context(NoValue) {
    return topologyWithStages(allocator, projection_bytes, child_layout, child_pcs, base_root, circuit.stark_verifier.verify.NoStages{});
}

pub fn topologyWithStages(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    child_layout: circuit.common.preprocessed.ColumnLayout,
    child_pcs: core.pcs.config_v2.PcsConfigV2,
    base_root: [32]u8,
    stages: anytype,
) !circuit.builder.Context(NoValue) {
    return topologyAtStepWithStages(allocator, projection_bytes, child_layout, child_pcs, base_root, 0, stages);
}

/// Audit the exact witness-free AIR at any u32 counter value. The sealed
/// recursive key must authenticate the same topology for every step.
pub fn topologyAtStepWithStages(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    child_layout: circuit.common.preprocessed.ColumnLayout,
    child_pcs: core.pcs.config_v2.PcsConfigV2,
    base_root: [32]u8,
    step: u32,
    stages: anytype,
) !circuit.builder.Context(NoValue) {
    try recursion_gate.authenticateProjection(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    const config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = child_pcs,
        .preprocessed_column_log_sizes = child_layout,
    };
    var proof_config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(allocator, &child_layout, child_pcs);
    defer proof_config.deinit(allocator);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const empty = try circuit.stark_verifier.proof.emptyProof(scratch.allocator(), proof_config);
    return buildCircuit(NoValue, allocator, &table, &config, base_root, undefined, undefined, step, &empty, null, stages);
}

pub fn verifyPrepared(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    child_layout: circuit.common.preprocessed.ColumnLayout,
    child_pcs: core.pcs.config_v2.PcsConfigV2,
    adapted: *const cpu.verifier_proof.VerifierProof,
    base_root: [32]u8,
    self_root: [32]u8,
    leaf_words: [8]u32,
    step: u32,
) !circuit.builder.Context(QM31) {
    return verifyPreparedWithMutation(allocator, projection_bytes, child_layout, child_pcs, adapted, base_root, self_root, leaf_words, step, null);
}

pub fn verifyPreparedWithMutation(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    child_layout: circuit.common.preprocessed.ColumnLayout,
    child_pcs: core.pcs.config_v2.PcsConfigV2,
    adapted: *const cpu.verifier_proof.VerifierProof,
    base_root: [32]u8,
    self_root: [32]u8,
    leaf_words: [8]u32,
    step: u32,
    mutation: ?Mutation,
) !circuit.builder.Context(QM31) {
    if (adapted.config.n_preprocessed_columns != child_layout.entries.len or
        adapted.config.log_trace_size != child_layout.traceLogSize() or
        !std.meta.eql(adapted.config.fri, child_pcs.fri_config)) return error.ChildProofConfigMismatch;
    try recursion_gate.authenticateProjection(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var proof_values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &adapted.proof, adapted.config);
    if (mutation) |kind| switch (kind) {
        .trace_root => proof_values.trace_root = Blake.hashValue(QM31, @splat(0)),
        .interaction_root => proof_values.interaction_root = Blake.hashValue(QM31, @splat(0)),
        .composition_root => proof_values.composition_polynomial_root = Blake.hashValue(QM31, @splat(0)),
        .claimed_sum => proof_values.claimed_sums[0] = proof_values.claimed_sums[0].add(QM31.one()),
        .channel_salt => proof_values.channel_salt = proof_values.channel_salt.add(QM31.one()),
        .preprocessed_oods => proof_values.preprocessed_columns_at_oods[0] = proof_values.preprocessed_columns_at_oods[0].add(QM31.one()),
        .trace_oods => proof_values.trace_at_oods[0] = proof_values.trace_at_oods[0].add(QM31.one()),
        .interaction_oods => proof_values.interaction_at_oods[0].at_oods = proof_values.interaction_at_oods[0].at_oods.add(QM31.one()),
        .composition_oods => proof_values.composition_eval_at_oods[0] = proof_values.composition_eval_at_oods[0].add(QM31.one()),
        .sampled_trace_value => proof_values.eval_domain_samples.data[0][0].inner =
            proof_values.eval_domain_samples.data[0][0].inner.add(QM31.one()),
        .trace_auth_path => proof_values.eval_domain_auth_paths.trees[0][0] = Blake.hashValue(QM31, @splat(0)),
        .fri_commitment => proof_values.fri.layer_commitments[0] = Blake.hashValue(QM31, @splat(0)),
        .fri_witness => proof_values.fri.witness[0][0] = proof_values.fri.witness[0][0].add(QM31.one()),
        .fri_auth_path => proof_values.fri.auth_paths.trees[0][0] = Blake.hashValue(QM31, @splat(0)),
        .fri_last_layer => proof_values.fri.last_layer_coefs[0] = proof_values.fri.last_layer_coefs[0].add(QM31.one()),
        .interaction_pow_nonce => proof_values.interaction_pow_nonce = proof_values.interaction_pow_nonce.add(QM31.one()),
        .fri_pow_nonce => proof_values.pow_nonce = proof_values.pow_nonce.add(QM31.one()),
        else => {},
    };
    const config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = child_pcs,
        .preprocessed_column_log_sizes = child_layout,
    };
    var indices: WitnessIndices = undefined;
    var ctx = try buildCircuit(
        QM31,
        allocator,
        &table,
        &config,
        base_root,
        Blake.hashValue(QM31, wordsFromBytes(self_root)),
        Blake.hashValue(QM31, leaf_words),
        step,
        &proof_values,
        &indices,
        circuit.stark_verifier.verify.NoStages{},
    );
    errdefer ctx.deinit();
    if (mutation) |kind| switch (kind) {
        .base_selector => ctx.value_table.items[indices.base] = if (step == 0) QM31.zero() else QM31.one(),
        .zero_test_inverse => ctx.value_table.items[indices.inverse] = QM31.zero(),
        .previous_counter => ctx.value_table.items[indices.previous] = QM31.fromBase(M31.fromCanonical(if (step == 0) 1 else step & 0xffff)),
        .borrow => ctx.value_table.items[indices.borrow] = QM31.fromBase(M31.fromCanonical(if (step != 0 and (step & 0xffff) == 0) 0 else 1)),
        else => {},
    };
    if (!try ctx.isCircuitValid()) return error.VerificationFailed;
    return ctx;
}

test "fixed-fold digest binds the full u32 counter" {
    const root = [_]u8{0x42} ** 32;
    const leaf = [8]u32{ 0, 1, 0xffffffff, 3, 4, 5, 6, 7 };
    for ([_]u32{ 0, 1, 65535, 65536, 65537, 0x80000000, 0xffffffff }) |step| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, circuit.common.component_list.N_RESERVED);
        defer ctx.deinit();
        const root_wires = try Blake.guessHash(QM31, &ctx, Blake.hashValue(QM31, wordsFromBytes(root)));
        const leaf_wires = try Blake.guessHash(QM31, &ctx, Blake.hashValue(QM31, leaf));
        const counter = try recursion_counter.constrainStepCounter(QM31, &ctx, step);
        const hash = try digestWires(QM31, &ctx, root_wires, counter.step, leaf_wires);
        var outputs: [8]Var = undefined;
        for (&outputs, hash.words) |*out, word| out.* = word.get();
        try ctx.setOutputs(&outputs);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        const expected = statementDigest(root, step, leaf);
        for (hash.words, expected) |word, expected_word|
            try std.testing.expectEqual(expected_word, circuit.builder.ivalue.unpackU32(QM31, ctx.get(word.get())));
    }
}
