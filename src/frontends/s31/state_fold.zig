//! A fixed-key recursive fold that adds one four-lane M31 recurrence step.
//! The source's statically recognized `iterate` body supplies the transition.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const recursion_gate = @import("recursion_gate.zig");
const relation = @import("stwo_s31_prototype").relation;

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const NoValue = circuit.builder.NoValue;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

pub const personalization: [8]u8 = "S31STF1!".*;
pub const Mutation = enum { base_selector, zero_test_inverse, previous_counter, current_state };
const WitnessIndices = struct { base: usize, inverse: usize, previous_counter: usize, current_state: usize };

pub const StageStats = struct {
    name: []const u8,
    raw_vars: u32,
    eq: usize,
    qm31_ops: usize,
    triple_xor: usize,
    m31_to_u32: usize,
    blake_g: usize,
};

/// Records witness-free circuit growth at each verifier phase. The recorder
/// changes no gate or proof value and is used only by AIR inspection.
pub const StageCapture = struct {
    entries: [32]StageStats = undefined,
    len: usize = 0,

    pub fn mark(self: *StageCapture, gates: *const circuit.builder.Circuit, stage: circuit.stark_verifier.verify.Stage) !void {
        if (self.len == self.entries.len) return error.TooManyVerifierStages;
        self.entries[self.len] = .{
            .name = stage.name,
            .raw_vars = gates.n_vars,
            .eq = gates.eq.items.len,
            .qm31_ops = gates.nQm31OpsRows(),
            .triple_xor = gates.triple_xor.items.len,
            .m31_to_u32 = gates.m31_to_u32.items.len,
            .blake_g = gates.blake_g_gate.items.len,
        };
        self.len += 1;
    }

    pub fn slice(self: *const StageCapture) []const StageStats {
        return self.entries[0..self.len];
    }
};

fn wordsFromBytes(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}

pub fn statementDigest(root: [32]u8, step: u16, leaf_words: [8]u32, initial: [4]u32, current: [4]u32) [8]u32 {
    var preimage: [100]u8 = undefined;
    @memcpy(preimage[0..32], &root);
    std.mem.writeInt(u32, preimage[32..36], step, .little);
    for (leaf_words, 0..) |word, i| std.mem.writeInt(u32, preimage[36 + 4 * i ..][0..4], word, .little);
    for (initial, 0..) |word, i| std.mem.writeInt(u32, preimage[68 + 4 * i ..][0..4], word, .little);
    for (current, 0..) |word, i| std.mem.writeInt(u32, preimage[84 + 4 * i ..][0..4], word, .little);
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&preimage, &digest, .{ .context = personalization });
    return wordsFromBytes(digest);
}

pub fn nextState(previous: [4]u32, body: []const relation.Step) ![4]u32 {
    if (body.len == 0 or body.len > 16) return error.InvalidStepBody;
    var result: [4]u32 = undefined;
    for (previous, &result) |word, *out| {
        if (word >= core.fields.m31.Modulus) return error.NoncanonicalState;
        var x = M31.fromCanonical(word);
        for (body) |step| switch (step.op) {
            .square => {
                if (step.constant != null) return error.InvalidStepBody;
                x = x.mul(x);
            },
            .add_const, .mul_const => {
                const constant = step.constant orelse return error.InvalidStepBody;
                if (constant >= core.fields.m31.Modulus) return error.InvalidStepConstant;
                const rhs = M31.fromCanonical(constant);
                x = if (step.op == .add_const) x.add(rhs) else x.mul(rhs);
            },
        };
        out.* = x.v;
    }
    return result;
}

fn stateValue(comptime V: type, word: u32) V {
    if (V == NoValue) return .{};
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(word)));
}

fn selectWord(comptime V: type, ctx: *circuit.builder.Context(V), choose_right: Var, left: Var, right: Var) !Var {
    return ctx.add(left, try ctx.mul(choose_right, try ctx.sub(right, left)));
}

fn selectU32(comptime V: type, ctx: *circuit.builder.Context(V), choose_right: Var, left: U32, right: U32) !U32 {
    return .newUnsafe(try selectWord(V, ctx, choose_right, left.get(), right.get()));
}

fn digestWires(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    root: Blake.HashValue(Var),
    step: Var,
    leaf: Blake.HashValue(Var),
    initial: [4]Var,
    current: [4]Var,
) !Blake.HashValue(Var) {
    var message: [25]U32 = undefined;
    @memcpy(message[0..8], &root.words);
    message[8] = .newUnsafe(step);
    @memcpy(message[9..17], &leaf.words);
    for (initial, 0..) |word, i| message[17 + i] = try Blake.m31ToU32(V, ctx, word);
    for (current, 0..) |word, i| message[21 + i] = try Blake.m31ToU32(V, ctx, word);
    return Blake.blake2sU32sPersonalized(V, ctx, &message, 100, personalization);
}

pub fn buildCircuit(
    comptime V: type,
    allocator: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    config: *const circuit.statements.circuit_statement.CircuitConfig,
    base_root: [32]u8,
    step_body: []const relation.Step,
    self_root_value: Blake.HashValue(V),
    leaf_value: Blake.HashValue(V),
    initial_value: [4]u32,
    current_value: [4]u32,
    previous_value: [4]u32,
    step_value: u16,
    input: *const circuit.stark_verifier.proof.Proof(V),
    witness_indices: ?*WitnessIndices,
    stages: anytype,
) !circuit.builder.Context(V) {
    if (step_body.len == 0 or step_body.len > 16) return error.InvalidStepBody;
    var ctx = try circuit.builder.Context(V).init(allocator, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const self_root = try Blake.guessHash(V, &ctx, self_root_value);
    const leaf = try Blake.guessHash(V, &ctx, leaf_value);
    var initial: [4]Var = undefined;
    var current: [4]Var = undefined;
    var previous: [4]Var = undefined;
    for (0..4) |i| {
        initial[i] = try ctx.guessM31(stateValue(V, initial_value[i]));
        current[i] = try ctx.guessM31(stateValue(V, current_value[i]));
        previous[i] = try ctx.guessM31(stateValue(V, previous_value[i]));
    }
    const step_qm31 = QM31.fromBase(M31.fromCanonical(step_value));
    const step = try circuit.builder.wrappers.guessU16(V, &ctx, .newUnsafe(circuit.builder.ivalue.fromQm31(V, step_qm31)));
    const base_value = QM31.fromBase(M31.fromCanonical(if (step_value == 0) 1 else 0));
    const base = try ctx.guessM31(circuit.builder.ivalue.fromQm31(V, base_value));
    try ctx.eq(try ctx.mul(base, try ctx.sub(base, ctx.one())), ctx.zero());
    try ctx.eq(try ctx.mul(step.get(), base), ctx.zero());
    const inverse = try ctx.inv(try ctx.add(step.get(), base));
    const recurse = try ctx.sub(ctx.one(), base);
    const prev_difference = try ctx.sub(step.get(), recurse);
    const prev_step = try circuit.builder.wrappers.guessU16(V, &ctx, .newUnsafe(ctx.get(prev_difference)));
    try ctx.eq(prev_step.get(), prev_difference);
    if (witness_indices) |indices| indices.* = .{
        .base = base.idx,
        .inverse = inverse.idx,
        .previous_counter = prev_step.get().idx,
        .current_state = current[0].idx,
    };

    var constants: [16]?Var = .{null} ** 16;
    for (step_body, 0..) |op, j| switch (op.op) {
        .square => if (op.constant != null) return error.InvalidStepBody,
        .add_const, .mul_const => {
            const constant = op.constant orelse return error.InvalidStepBody;
            if (constant >= core.fields.m31.Modulus) return error.InvalidStepConstant;
            constants[j] = try ctx.constant(QM31.fromBase(M31.fromCanonical(constant)));
        },
    };
    for (0..4) |i| {
        var next = previous[i];
        for (step_body, 0..) |op, j| next = switch (op.op) {
            .square => try ctx.mul(next, next),
            .add_const => try ctx.add(next, constants[j].?),
            .mul_const => try ctx.mul(next, constants[j].?),
        };
        try ctx.eq(current[i], try selectWord(V, &ctx, recurse, initial[i], next));
    }
    const fixed_base_root = try Blake.constantHash(V, &ctx, Blake.hashValue(QM31, wordsFromBytes(base_root)));
    const previous_digest = try digestWires(V, &ctx, self_root, prev_step.get(), leaf, initial, previous);
    var child_root: Blake.HashValue(Var) = undefined;
    var child_output: Blake.HashValue(Var) = undefined;
    for (0..Blake.digest_n_words) |i| {
        child_root.words[i] = try selectU32(V, &ctx, recurse, fixed_base_root.words[i], self_root.words[i]);
        child_output.words[i] = try selectU32(V, &ctx, recurse, leaf.words[i], previous_digest.words[i]);
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
    const proof_vars = try circuit.stark_verifier.proof.guess(V, &ctx, input);
    try stages.mark(&ctx.circuit, .{ .name = "proof_witness" });
    try circuit.stark_verifier.verify.verify(V, &ctx, &proof_vars, proof_config, &statement, stages);

    const output_hash = try digestWires(V, &ctx, self_root, step.get(), leaf, initial, current);
    var outputs: [Blake.digest_n_words]Var = undefined;
    for (&outputs, output_hash.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    try stages.mark(&ctx.circuit, .{ .name = "state_fold_digest" });
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
    step_body: []const relation.Step,
) !circuit.builder.Context(NoValue) {
    return topologyWithStages(allocator, projection_bytes, child_layout, child_pcs, base_root, step_body, circuit.stark_verifier.verify.NoStages{});
}

pub fn topologyWithStages(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    child_layout: circuit.common.preprocessed.ColumnLayout,
    child_pcs: core.pcs.config_v2.PcsConfigV2,
    base_root: [32]u8,
    step_body: []const relation.Step,
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
    return buildCircuit(NoValue, allocator, &table, &config, base_root, step_body, undefined, undefined, undefined, undefined, undefined, 0, &empty, null, stages);
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
    initial: [4]u32,
    current: [4]u32,
    previous: [4]u32,
    step: u16,
    step_body: []const relation.Step,
) !circuit.builder.Context(QM31) {
    return verifyPreparedWithMutation(
        allocator,
        projection_bytes,
        child_layout,
        child_pcs,
        adapted,
        base_root,
        self_root,
        leaf_words,
        initial,
        current,
        previous,
        step,
        step_body,
        null,
    );
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
    initial: [4]u32,
    current: [4]u32,
    previous: [4]u32,
    step: u16,
    step_body: []const relation.Step,
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
    const proof_values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &adapted.proof, adapted.config);
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
        step_body,
        Blake.hashValue(QM31, wordsFromBytes(self_root)),
        Blake.hashValue(QM31, leaf_words),
        initial,
        current,
        previous,
        step,
        &proof_values,
        &indices,
        circuit.stark_verifier.verify.NoStages{},
    );
    errdefer ctx.deinit();
    if (mutation) |kind| switch (kind) {
        .base_selector => ctx.value_table.items[indices.base] = if (step == 0) QM31.zero() else QM31.one(),
        .zero_test_inverse => ctx.value_table.items[indices.inverse] = QM31.zero(),
        .previous_counter => ctx.value_table.items[indices.previous_counter] = QM31.fromBase(M31.fromCanonical(if (step == 0) 1 else step)),
        .current_state => ctx.value_table.items[indices.current_state] = QM31.fromBase(M31.fromCanonical(if (current[0] == 0) 1 else 0)),
    };
    if (!try ctx.isCircuitValid()) return error.VerificationFailed;
    return ctx;
}
