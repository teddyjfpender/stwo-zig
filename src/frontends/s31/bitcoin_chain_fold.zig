//! Candidate fixed-key Bitcoin hash-chain fold. One child STARK authenticates
//! the previous state; the fresh 80-byte header is checked directly here.
//! This module builds the circuit and its witness-free topology. Native proof
//! generation, a sealed key, and a base proof are separate integration work.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const s31 = @import("stwo_s31_prototype");
const recursion_counter = @import("recursion_counter.zig");
const recursion_gate = @import("recursion_gate.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const NoValue = circuit.builder.NoValue;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

fn wordsFromBytes(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}

fn selectU32(comptime V: type, ctx: *circuit.builder.Context(V), choose_right: Var, left: U32, right: U32) !U32 {
    return .newUnsafe(try ctx.add(left.get(), try ctx.mul(choose_right, try ctx.sub(right.get(), left.get()))));
}

const ChildClaim = struct {
    self_root: Blake.HashValue(Var),
    counter: recursion_counter.CounterRelation,
    prior_root: [8]Var,
    child_root: Blake.HashValue(Var),
    child_output: Blake.HashValue(Var),
};

fn prepareChild(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    base_root: [32]u8,
    checkpoint: [8]u32,
    self_root_value: Blake.HashValue(V),
    prior_root_values: [8]V,
    step_value: u32,
) !ChildClaim {
    for (checkpoint) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalCheckpoint;
    const self_root = try Blake.guessHash(V, ctx, self_root_value);
    const counter = try recursion_counter.constrainStepCounter(V, ctx, step_value);
    var prior_root: [8]Var = undefined;
    for (prior_root_values, checkpoint, &prior_root) |value, fixed, *wire| {
        wire.* = try ctx.guessM31(value);
        const checkpoint_word = try ctx.constant(QM31.fromBase(M31.fromCanonical(fixed)));
        // Step zero opens the trusted checkpoint. Every later step opens the
        // prior fold's output digest through the verified child statement.
        try ctx.eq(try ctx.mul(counter.base, try ctx.sub(wire.*, checkpoint_word)), ctx.zero());
    }
    const base_root_wire = try Blake.constantHash(V, ctx, Blake.hashValue(QM31, wordsFromBytes(base_root)));
    const base_output = try Blake.constantHash(V, ctx, Blake.hashValue(QM31, checkpoint));
    const previous_output = try s31.bitcoin_fold_digest.digestWires(V, ctx, self_root, counter.previous, checkpoint, prior_root);
    var child_root: Blake.HashValue(Var) = undefined;
    var child_output: Blake.HashValue(Var) = undefined;
    for (0..Blake.digest_n_words) |i| {
        child_root.words[i] = try selectU32(V, ctx, counter.recurse, base_root_wire.words[i], self_root.words[i]);
        child_output.words[i] = try selectU32(V, ctx, counter.recurse, base_output.words[i], previous_output.words[i]);
    }
    return .{
        .self_root = self_root,
        .counter = counter,
        .prior_root = prior_root,
        .child_root = child_root,
        .child_output = child_output,
    };
}

pub fn buildCircuit(
    comptime V: type,
    allocator: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    config: *const circuit.statements.circuit_statement.CircuitConfig,
    base_root: [32]u8,
    checkpoint: [8]u32,
    self_root_value: Blake.HashValue(V),
    prior_root_values: [8]V,
    prior_hash_values: [16]V,
    header_values: [40]V,
    step_value: u32,
    input: *const circuit.stark_verifier.proof.Proof(V),
    stages: anytype,
) !circuit.builder.Context(V) {
    var ctx = try circuit.builder.Context(V).init(allocator, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const claim = try prepareChild(V, &ctx, base_root, checkpoint, self_root_value, prior_root_values, step_value);

    const statement = try circuit.statements.circuit_statement.CircuitStatement(V).init(
        &ctx,
        table,
        config,
        claim.child_root,
        claim.child_output,
    );
    var proof_config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(
        allocator,
        &config.preprocessed_column_log_sizes,
        config.config,
    );
    defer proof_config.deinit(allocator);
    const proof_vars = try circuit.stark_verifier.proof.guess(V, &ctx, input);
    try stages.mark(&ctx.circuit, .{ .name = "proof_witness" });
    try circuit.stark_verifier.verify.verify(V, &ctx, &proof_vars, proof_config, &statement, stages);

    const new_root = try s31.bitcoin_fold_step.constrainMainnetPowLinkStep(
        V,
        &ctx,
        prior_hash_values,
        header_values,
        claim.prior_root,
    );
    try stages.mark(&ctx.circuit, .{ .name = "bitcoin_header_step" });
    const digest = try s31.bitcoin_fold_digest.digestWires(V, &ctx, claim.self_root, claim.counter.step, checkpoint, new_root);
    var outputs: [Blake.digest_n_words]Var = undefined;
    for (digest.words, &outputs) |word, *out| out.* = word.get();
    try ctx.setOutputs(&outputs);
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
    checkpoint: [8]u32,
    step: u32,
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
    return buildCircuit(
        NoValue,
        allocator,
        &table,
        &config,
        base_root,
        checkpoint,
        Blake.hashValue(NoValue, @splat(0)),
        [_]NoValue{.{}} ** 8,
        [_]NoValue{.{}} ** 16,
        [_]NoValue{.{}} ** 40,
        step,
        &empty,
        circuit.stark_verifier.verify.NoStages{},
    );
}

test "Bitcoin fold chooses a trusted base or the authenticated previous digest" {
    const base_bytes = [_]u8{0x42} ** 32;
    const self_bytes = [_]u8{0x57} ** 32;
    const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
    const successor = [8]u32{ 1230097977, 338045265, 582454319, 1194138423, 159136005, 2049036807, 17165835, 883545160 };
    for ([_]u32{ 0, 1, 65536 }) |step| {
        const prior = if (step == 0) checkpoint else successor;
        var values: [8]QM31 = undefined;
        for (prior, &values) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
        defer ctx.deinit();
        const claim = try prepareChild(
            QM31,
            &ctx,
            base_bytes,
            checkpoint,
            Blake.hashValue(QM31, wordsFromBytes(self_bytes)),
            values,
            step,
        );
        var outputs: [8]Var = undefined;
        for (claim.child_output.words, &outputs) |word, *out| out.* = word.get();
        try ctx.setOutputs(&outputs);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        const expected_root = if (step == 0) wordsFromBytes(base_bytes) else wordsFromBytes(self_bytes);
        const expected_output = if (step == 0) checkpoint else try s31.bitcoin_fold_digest.statementDigest(self_bytes, step - 1, checkpoint, prior);
        for (claim.child_root.words, expected_root) |wire, want|
            try std.testing.expectEqual(want, circuit.builder.ivalue.unpackU32(QM31, ctx.get(wire.get())));
        for (claim.child_output.words, expected_output) |wire, want|
            try std.testing.expectEqual(want, circuit.builder.ivalue.unpackU32(QM31, ctx.get(wire.get())));

        const original = ctx.value_table.items[claim.prior_root[0].idx];
        ctx.value_table.items[claim.prior_root[0].idx] = QM31.fromBase(M31.fromCanonical(prior[0] + 1));
        try std.testing.expect(!try ctx.isCircuitValid());
        ctx.value_table.items[claim.prior_root[0].idx] = original;
        try std.testing.expect(try ctx.isCircuitValid());
    }
}
