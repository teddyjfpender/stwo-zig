//! The multiverifier (fold) circuit: a `k`-to-1 node verifying `k` circuit
//! proofs that share one configuration.
//!
//! Ports `crates/circuit_multiverifier/src/verify.rs` (`SharedConfig`,
//! `shared_config`, `build_multiverifier_circuit`,
//! `build_multiverifier_context_from_shared_config`) and step 1 of
//! `CanonicalCircuit::build` in
//! `crates/stwo_run_and_prove_recursive_tree/src/canonical.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The fold topology depends only
//! on the registry's target sizes and circuit FRI config (design §3.5): the
//! children's roots and digests are guessed, not interned.
//!
//! One context verifies the children left to right, so constants are shared
//! across them; each child contributes `[circuit_hash (8 words), output
//! digest (8 words)]` to the Blake2s preimage whose digest becomes the
//! node's output. That preimage order is a byte contract with every
//! out-of-circuit recomputation of the digest.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("../common/component_list.zig");
const finalize = @import("../common/finalize.zig");
const preprocessed = @import("../common/preprocessed.zig");
const proof = @import("../stark_verifier/proof.zig");
const verify_mod = @import("../stark_verifier/verify.zig");
const component_table = @import("../air_eval/component_table.zig");
const circuit_statement = @import("circuit_statement.zig");

const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const U32Wrapper = builder.wrappers.U32Wrapper;

const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

/// `SharedConfig`: the configuration shared by every circuit a
/// multiverifier verifies and by their proofs.
pub const SharedConfig = struct {
    pcs_config: PcsConfigV2,
    proof_config: proof.ProofConfig,
    preprocessed_column_log_sizes: preprocessed.ColumnLayout,

    pub fn deinit(self: *SharedConfig, allocator: std.mem.Allocator) void {
        self.proof_config.deinit(allocator);
        self.* = undefined;
    }
};

/// `shared_config`.
pub fn sharedConfig(
    allocator: std.mem.Allocator,
    layout: preprocessed.ColumnLayout,
    pcs_config: PcsConfigV2,
) proof.ConfigError!SharedConfig {
    return .{
        .pcs_config = pcs_config,
        .proof_config = try circuit_statement.circuitVerifierProofConfig(allocator, &layout, pcs_config),
        .preprocessed_column_log_sizes = layout,
    };
}

/// `CanonicalCircuit::build` step 1: the shared config of a fold tree whose
/// circuits are all padded to `target_sizes` and proven with `fri_config`.
pub fn foldSharedConfig(
    allocator: std.mem.Allocator,
    target_sizes: finalize.ComponentSizes,
    fri_config: FriConfigV2,
) (preprocessed.Error || proof.ConfigError)!SharedConfig {
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(target_sizes);
    const pcs_config = PcsConfigV2.fromFriAndTraceSize(fri_config, layout.traceLogSize());
    return sharedConfig(allocator, layout, pcs_config);
}

/// `MultiverifierInput<Value>`: a child proof with its circuit's
/// preprocessed root and output digest.
pub fn MultiverifierInput(comptime V: type) type {
    return struct {
        proof: *const proof.Proof(V),
        preprocessed_root: HashValue(V),
        output_digest: HashValue(V),
    };
}

/// Forwards a child's `verify` stages to the node's observer.
fn ChildStages(comptime Inner: type) type {
    return struct {
        inner: Inner,
        child: usize,

        pub fn mark(self: @This(), circuit: *const builder.Circuit, stage: verify_mod.Stage) !void {
            try self.inner.mark(circuit, .{ .child = self.child, .in_verify = true, .name = stage.name });
        }
    };
}

/// `build_multiverifier_circuit`: the finalized (unpadded) node circuit
/// verifying `inputs` left to right. `table` is the circuit-AIR evaluator
/// table; `stages` observes the circuit after every stage (see
/// `verify_mod.NoStages`).
pub fn buildMultiverifierCircuit(
    comptime V: type,
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    inputs: []const MultiverifierInput(V),
    shared: *const SharedConfig,
    stages: anytype,
) !builder.Context(V) {
    if (inputs.len == 0) return error.NoMultiverifierInputs;
    var ctx = try builder.Context(V).init(gpa, component_list.N_RESERVED);
    errdefer ctx.deinit();
    const config: circuit_statement.CircuitConfig = .{
        .config = shared.pcs_config,
        .preprocessed_column_log_sizes = shared.preprocessed_column_log_sizes,
    };

    const preimage = try ctx.scratch().alloc(U32Wrapper(Var), inputs.len * 2 * builder.blake.digest_n_words);
    for (inputs, 0..) |input, child| {
        const output_digest = try builder.blake.guessHash(V, &ctx, input.output_digest);
        const preprocessed_root = try builder.blake.guessHash(V, &ctx, input.preprocessed_root);
        try stages.mark(&ctx.circuit, .{ .child = child, .name = "guess_output_digest_and_root" });
        const statement = try circuit_statement.CircuitStatement(V).init(&ctx, table, &config, preprocessed_root, output_digest);
        try stages.mark(&ctx.circuit, .{ .child = child, .name = "statement" });
        const proof_vars = try proof.guess(V, &ctx, input.proof);
        try stages.mark(&ctx.circuit, .{ .child = child, .name = "guess_proof" });

        const child_stages: ChildStages(@TypeOf(stages)) = .{ .inner = stages, .child = child };
        try verify_mod.verify(V, &ctx, &proof_vars, shared.proof_config, &statement, child_stages);

        const words = preimage[child * 16 ..][0..16];
        @memcpy(words[0..8], &statement.circuit_hash.words);
        @memcpy(words[8..], &statement.output_digest.words);
    }
    const output_hash = try builder.blake.blake2sU32s(V, &ctx, preimage, 4 * preimage.len);
    try stages.mark(&ctx.circuit, .{ .name = "preimage_hash" });
    var outputs: [builder.blake.digest_n_words]Var = undefined;
    for (&outputs, output_hash.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    try stages.mark(&ctx.circuit, .{ .name = "set_outputs" });
    try ctx.finalize(false);
    try stages.mark(&ctx.circuit, .{ .name = "finalize" });
    return ctx;
}

/// `build_multiverifier_context_from_shared_config`: the topology of the
/// node verifying two proofs described by `shared`.
pub fn buildMultiverifierTopology(
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    shared: *const SharedConfig,
    stages: anytype,
) !builder.Context(builder.NoValue) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const empty = try proof.emptyProof(arena.allocator(), shared.proof_config);
    const input: MultiverifierInput(builder.NoValue) = .{ .proof = &empty, .preprocessed_root = undefined, .output_digest = undefined };
    return buildMultiverifierCircuit(builder.NoValue, gpa, table, &.{ input, input }, shared, stages);
}
