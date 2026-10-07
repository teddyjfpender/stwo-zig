//! A sealed-key recursive verifier circuit for S31 sparse-wide-v5 proofs.
//! It verifies the child STARK directly, rather than trusting the native
//! conversion. Native verification is only a safe way to obtain witness data.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const recursion_gate = @import("recursion_gate.zig");

const QM31 = core.fields.qm31.QM31;
const NoValue = circuit.builder.NoValue;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);
const WideStatement = circuit.statements.sparse_wide_statement;

pub const Mutation = enum { profile_prefix, circuit_identity, output_word, trace_root, claimed_sum, channel_salt, trace_auth_path, fri_witness, fri_auth_path, fri_last_layer };

pub const Expected = struct {
    key_digest: [32]u8,
    source_digest: [32]u8,
    preprocessed_root: [32]u8,
    circuit_hash: [32]u8,
    public_words: [8]u32,
};

fn logsFor(layout: *const circuit.common.sparse_wide.Layout) ![4]u32 {
    return .{
        layout.logSize("eq_in0_address") orelse return error.InvalidSparseLayout,
        layout.logSize("qm31_ops_in0_address") orelse return error.InvalidSparseLayout,
        layout.logSize("m31_to_u32_input_addr") orelse return error.InvalidSparseLayout,
        16,
    };
}

fn checkIdentity(layout: *const circuit.common.sparse_wide.Layout, pcs: core.pcs.config_v2.PcsConfigV2, expected: Expected) !void {
    const hash = cpu.sparse_wide.identityHash(expected.source_digest, expected.preprocessed_root, try logsFor(layout), pcs.fri_config.log_blowup_factor);
    if (!std.mem.eql(u8, &hash, &expected.circuit_hash)) return error.ChildCircuitHashMismatch;
    const trace_log = std.math.sub(u32, pcs.trace_lifting_log_size, pcs.fri_config.log_blowup_factor) catch
        return error.ChildProofConfigMismatch;
    if (layout.traceLogSize() != trace_log)
        return error.ChildProofConfigMismatch;
}

fn buildCircuit(
    comptime V: type,
    allocator: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    layout: *const circuit.common.sparse_wide.Layout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    expected: Expected,
    input: *const circuit.stark_verifier.proof.Proof(V),
    output_value: Blake.HashValue(V),
    source_prefix: [32]u8,
    identity: [32]u8,
) !circuit.builder.Context(V) {
    try checkIdentity(layout, pcs, expected);
    var ctx = try circuit.builder.Context(V).init(allocator, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const output = try Blake.guessHash(V, &ctx, output_value);
    const statement = try WideStatement.SparseWideStatement(V).init(
        &ctx,
        table,
        layout,
        expected.preprocessed_root,
        identity,
        output,
        source_prefix,
    );
    var config = try WideStatement.proofConfig(allocator, layout, pcs);
    defer config.deinit(allocator);
    const proof_vars = try circuit.stark_verifier.proof.guess(V, &ctx, input);
    try circuit.stark_verifier.verify.verify(V, &ctx, &proof_vars, config, &statement, circuit.stark_verifier.verify.NoStages{});
    var preimage: [16]U32 = undefined;
    for (0..8) |i| {
        const word = std.mem.readInt(u32, expected.key_digest[4 * i ..][0..4], .little);
        preimage[i] = try circuit.builder.wrappers.constU32(V, &ctx, word);
    }
    @memcpy(preimage[8..], &output.words);
    const digest = try Blake.blake2sU32sPersonalized(V, &ctx, &preimage, 64, "S31RCV2!".*);
    var outputs: [8]Var = undefined;
    for (&outputs, digest.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    return ctx;
}

pub fn topology(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.sparse_wide.Layout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    expected: Expected,
) !circuit.builder.Context(NoValue) {
    try recursion_gate.authenticateProjection(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    var config = try WideStatement.proofConfig(allocator, &layout, pcs);
    defer config.deinit(allocator);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const empty = try circuit.stark_verifier.proof.emptyProof(scratch.allocator(), config);
    return buildCircuit(NoValue, allocator, &table, &layout, pcs, expected, &empty, undefined, expected.source_digest, expected.circuit_hash);
}

pub fn verifyPrepared(
    allocator: std.mem.Allocator,
    projection_bytes: []const u8,
    layout: circuit.common.sparse_wide.Layout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    adapted: *const cpu.verifier_proof.VerifierProof,
    expected: Expected,
    mutation: ?Mutation,
) !circuit.builder.Context(QM31) {
    try checkIdentity(&layout, pcs, expected);
    if (adapted.config.n_preprocessed_columns != layout.entries.len or
        adapted.config.log_trace_size != layout.traceLogSize() or
        !std.meta.eql(adapted.config.fri, pcs.fri_config) or
        adapted.config.component_shapes.len != WideStatement.shapes.len)
        return error.ChildProofConfigMismatch;
    for (adapted.config.component_shapes, &WideStatement.shapes) |actual, shape|
        if (actual.trace_columns != shape.trace_columns or actual.interaction_columns != shape.interaction_columns)
            return error.ChildProofConfigMismatch;
    try recursion_gate.authenticateProjection(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &adapted.proof, adapted.config);
    var output_words = expected.public_words;
    var source_prefix = expected.source_digest;
    var identity = expected.circuit_hash;
    if (mutation) |change| switch (change) {
        .profile_prefix => source_prefix[0] ^= 1,
        .circuit_identity => identity[0] ^= 1,
        .output_word => output_words[0] ^= 1,
        .trace_root => values.trace_root = Blake.hashValue(QM31, @splat(0)),
        .claimed_sum => values.claimed_sums[0] = values.claimed_sums[0].add(QM31.one()),
        .channel_salt => values.channel_salt = values.channel_salt.add(QM31.one()),
        .trace_auth_path => values.eval_domain_auth_paths.trees[0][0] = Blake.hashValue(QM31, @splat(0)),
        .fri_witness => values.fri.witness[0][0] = values.fri.witness[0][0].add(QM31.one()),
        .fri_auth_path => values.fri.auth_paths.trees[0][0] = Blake.hashValue(QM31, @splat(0)),
        .fri_last_layer => values.fri.last_layer_coefs[0] = values.fri.last_layer_coefs[0].add(QM31.one()),
    };
    var ctx = try buildCircuit(QM31, allocator, &table, &layout, pcs, expected, &values, Blake.hashValue(QM31, output_words), source_prefix, identity);
    errdefer ctx.deinit();
    if (!try ctx.isCircuitValid()) return error.VerificationFailed;
    return ctx;
}
