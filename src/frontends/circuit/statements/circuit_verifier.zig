//! The single-proof circuit verifier: the circuit that verifies one proof of
//! another circuit, and the out-of-circuit check that it is satisfied.
//!
//! Ports `crates/circuit_verifier/src/verify.rs` (`CircuitPublicData`,
//! `build_verification_circuit`, `verify_circuit`) of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230. The circuit guesses the
//! verified circuit's output digest and preprocessed root, builds the
//! `CircuitStatement`, guesses the proof, runs the in-circuit STARK
//! verifier, and outputs Blake2s of `preprocessed_root || output_digest`
//! at the reserved output wires. `verifyCircuit` builds it with values and
//! accepts the proof exactly when the finalized circuit is satisfied.
//!
//! The multiverifier (`multiverifier.zig`) is the `k`-proof version of the
//! same steps; this one is what a single proof is checked with.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("../common/component_list.zig");
const proof = @import("../stark_verifier/proof.zig");
const verify_mod = @import("../stark_verifier/verify.zig");
const component_table = @import("../air_eval/component_table.zig");
const circuit_statement = @import("circuit_statement.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const U32Wrapper = builder.wrappers.U32Wrapper;

pub const CircuitConfig = circuit_statement.CircuitConfig;

/// `CircuitPublicData<Value>`: the verified circuit's output, the unreduced
/// Blake2s digest at its reserved output wires.
pub fn CircuitPublicData(comptime V: type) type {
    return struct {
        output_digest: HashValue(V),
    };
}

/// `build_verification_circuit`: the finalized circuit verifying `input`
/// against `config`, `preprocessed_root` and `public_data`. `table` is the
/// circuit-AIR evaluator table. The context owns everything; `deinit` it.
pub fn buildVerificationCircuit(
    comptime V: type,
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    config: *const CircuitConfig,
    preprocessed_root: HashValue(V),
    input: *const proof.Proof(V),
    public_data: CircuitPublicData(V),
) !builder.Context(V) {
    var ctx = try builder.Context(V).init(gpa, component_list.N_RESERVED);
    errdefer ctx.deinit();
    // The guessed root enters the output hash: the outermost (honest)
    // verifier must rebuild the chain of output hashes.
    const output_digest = try builder.blake.guessHash(V, &ctx, public_data.output_digest);
    const root = try builder.blake.guessHash(V, &ctx, preprocessed_root);
    const statement = try circuit_statement.CircuitStatement(V).init(&ctx, table, config, root, output_digest);

    var proof_config = try circuit_statement.circuitVerifierProofConfig(gpa, &config.preprocessed_column_log_sizes, config.config);
    defer proof_config.deinit(gpa);
    const proof_vars = try proof.guess(V, &ctx, input);
    try verify_mod.verify(V, &ctx, &proof_vars, proof_config, &statement, verify_mod.NoStages{});

    // Outputs: Blake2s of the preprocessed root and the verified circuit's
    // output digest (`u`, the last output, is checked by the logup sum).
    const statement_root = try statement.preprocessedRoot(&ctx);
    var preimage: [2 * builder.blake.digest_n_words]U32Wrapper(Var) = undefined;
    @memcpy(preimage[0..builder.blake.digest_n_words], &statement_root.words);
    @memcpy(preimage[builder.blake.digest_n_words..], &statement.output_digest.words);
    const output_hash = try builder.blake.blake2sU32s(V, &ctx, &preimage, 4 * preimage.len);
    var outputs: [builder.blake.digest_n_words]Var = undefined;
    for (&outputs, output_hash.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    return ctx;
}

pub const VerifyError = error{
    /// `verify_circuit`'s `Err("Verification failed")`: the verification
    /// circuit is not satisfied.
    VerificationFailed,
};

/// `verify_circuit`: builds the verification circuit with values and
/// requires it to be satisfied. Returns the finalized context (its outputs
/// are the verifier's output digest); `deinit` it.
pub fn verifyCircuit(
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    config: *const CircuitConfig,
    preprocessed_root: HashValue(QM31),
    input: *const proof.Proof(QM31),
    public_data: CircuitPublicData(QM31),
) !builder.Context(QM31) {
    var ctx = try buildVerificationCircuit(QM31, gpa, table, config, preprocessed_root, input, public_data);
    errdefer ctx.deinit();
    if (!try ctx.isCircuitValid()) return error.VerificationFailed;
    return ctx;
}
