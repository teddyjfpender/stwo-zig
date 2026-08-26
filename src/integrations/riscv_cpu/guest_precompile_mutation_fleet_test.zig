//! C-012 adversarial fleet for one real Poseidon2 profile proof.
//!
//! The expensive proof is produced exactly once. Every arm starts from a fresh
//! decode of the same canonical artifact, changes one authority, and transfers
//! proof ownership to the verifier on both success and failure. Structural
//! mutations assert their precise pre-transcript error. The two semantically
//! well-formed mutations first prove that admission still succeeds and then
//! require a cryptographic verifier error.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const QM31 = core.fields.qm31.QM31;
const pcs = core.pcs;
const public_data = frontend.air.public_data;
const proof_admission = frontend.air.guest_precompile.proof_admission;
const test_elf = frontend.testing.guest_precompile_test_elf;
const runner = frontend.runner;
const prover_types = frontend.prover_mod;
const artifact_wire = riscv_cpu.poseidon2_proof_artifact;
const profile_types = frontend.prover_mod.guest_precompile.types;

const test_config = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
    .lifting_log_size = null,
};

const test_limits = artifact_wire.Limits{
    .max_artifact_bytes = 256 * 1024 * 1024,
    .max_proof_bytes = 128 * 1024 * 1024,
    .max_input_bytes = 16 * 1024 * 1024,
    .max_output_bytes = 16 * 1024 * 1024,
    .max_queries = 1024,
    .max_pow_bits = 128,
};

test "C-012 one-proof mutation fleet rejects every profile forgery" {
    const allocator = std.testing.allocator;
    const encoded = try produceHonestArtifact(allocator);
    defer allocator.free(encoded);

    // Establish the positive control through precisely the decode and verifier
    // path used by every negative arm.
    var honest = try decodeHonest(allocator, encoded);
    try consumeAndExpectSuccess(allocator, &honest);

    // Public input authority: even an empty input region authenticates its
    // base address. The changed declaration remains structurally valid, so the
    // extension artifact's statement digest is the first rejection boundary.
    var public_input = try decodeHonest(allocator, encoded);
    public_input.statement.public_data.io_entries.input_start += 4;
    try consumeAndExpectError(
        allocator,
        &public_input,
        error.StatementDigestMismatch,
    );

    // Public output authority: an empty output region still authenticates the
    // address at which a non-empty result would begin.
    var public_output = try decodeHonest(allocator, encoded);
    public_output.statement.public_data.io_entries.output_data_addr += 4;
    try consumeAndExpectError(
        allocator,
        &public_output,
        error.StatementDigestMismatch,
    );

    // Execution mode is selected independently of the proof. A base-machine
    // extension cannot borrow the Poseidon2 component registry.
    var mode = try decodeHonest(allocator, encoded);
    mode.extension.profile = .rv32im_zkvm_v1;
    try consumeAndExpectError(allocator, &mode, error.ProfileMismatch);

    // The explicit envelope identity is independently authenticated rather
    // than trusted merely because the extension statement is canonical.
    var identity = try decodeHonest(allocator, encoded);
    identity.artifact.semantic_digest[0] ^= 1;
    try consumeAndExpectError(
        allocator,
        &identity,
        error.SemanticDigestMismatch,
    );

    // Active-count authority is redundant by design: all three observed count
    // channels must agree before either component construction is considered.
    var active_count = try decodeHonest(allocator, encoded);
    active_count.extension.counts.n_guest += 1;
    try consumeAndExpectError(
        allocator,
        &active_count,
        error.CallCountMismatch,
    );

    // Padding geometry is canonical for the active count; the prover cannot
    // choose a larger domain and reinterpret the inactive suffix.
    var padding = try decodeHonest(allocator, encoded);
    padding.extension.components[0].log_size += 1;
    try consumeAndExpectError(
        allocator,
        &padding,
        error.ComponentLogSizeMismatch,
    );

    // The core descriptor count participates in the independently recomputed
    // extension admission certificate. Removing one active family cannot be
    // hidden behind the unchanged total-step claim.
    var descriptor_count = try decodeHonest(allocator, encoded);
    try std.testing.expect(descriptor_count.statement.n_components > 0);
    descriptor_count.statement.n_components -= 1;
    try consumeAndExpectError(
        allocator,
        &descriptor_count,
        error.CallCountMismatch,
    );

    // Caller and provider multiplicities are compared with the construction
    // authorities, not accepted from the detailed claim itself.
    var caller_multiplicity = try decodeHonest(allocator, encoded);
    caller_multiplicity.interaction_claim.caller.descriptor.n_rows += 1;
    try consumeAndExpectError(
        allocator,
        &caller_multiplicity,
        error.ClaimDescriptorMismatch,
    );

    var provider_multiplicity = try decodeHonest(allocator, encoded);
    provider_multiplicity.interaction_claim.provider.descriptor.n_rows += 1;
    try consumeAndExpectError(
        allocator,
        &provider_multiplicity,
        error.ClaimDescriptorMismatch,
    );

    // This compensating mutation preserves the caller aggregate, the global
    // caller/provider cancellation sum, and every structural claim invariant.
    // It therefore reaches the proof verifier and demonstrates that v2 binds
    // all physical batch claims rather than only their aggregate.
    var detailed_claim = try decodeHonest(allocator, encoded);
    const delta = QM31.fromU32Unchecked(7, 11, 13, 17);
    detailed_claim.interaction_claim.caller.batch_sums[0] =
        detailed_claim.interaction_claim.caller.batch_sums[0].add(delta);
    detailed_claim.interaction_claim.caller.batch_sums[1] =
        detailed_claim.interaction_claim.caller.batch_sums[1].add(delta.neg());
    try expectOodsRejection(allocator, &detailed_claim);

    // Corrupt one Tree 1 OODS opening, then reserialize and decode it. Postcard
    // shape/config preflight must accept the resulting artifact; only the AIR
    // composition identity may reject the canonical field value.
    var proof_source = try decodeHonest(allocator, encoded);
    var proof_source_owned = true;
    defer if (proof_source_owned) proof_source.deinit(allocator);
    try mutateTreeOneSampledValue(&proof_source.proof);
    const corrupt_proof_artifact = try artifact_wire.encodeAllocWithLimits(
        allocator,
        .{
            .pcs_config = proof_source.pcs_config,
            .statement = &proof_source.statement,
            .extension = &proof_source.extension,
            .artifact = proof_source.artifact,
            .interaction_claim = proof_source.interaction_claim,
            .proof = &proof_source.proof,
        },
        test_limits,
    );
    proof_source.deinit(allocator);
    proof_source_owned = false;
    defer allocator.free(corrupt_proof_artifact);

    var corrupt_proof = try decodeHonest(allocator, corrupt_proof_artifact);
    try expectOodsRejection(allocator, &corrupt_proof);
}

fn produceHonestArtifact(allocator: std.mem.Allocator) ![]u8 {
    const elf = test_elf.build(true, .self_loop);
    var run = try runner.runPoseidon2Extension(allocator, &elf, 16);
    defer run.deinit();
    try std.testing.expectEqual(.self_loop, run.base.completion_reason);
    try std.testing.expectEqual(@as(usize, 1), run.calls.len());
    try std.testing.expectEqual(run.calls.len(), run.execution_rows.rows().len);

    const input_words = try public_data.packInputWords(allocator, run.base.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(
        public_data.OutputWord,
        run.base.output_words.len,
    );
    defer allocator.free(output_words);
    for (output_words, run.base.output_words) |*destination, source| {
        destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
    }
    const bound_public_data = public_data.PublicData{
        .initial_pc = run.base.initial_pc,
        .final_pc = run.base.final_pc,
        .clock = @intCast(run.base.step_count),
        .initial_regs = run.base.initial_regs,
        .final_regs = run.base.final_regs,
        .reg_last_clock = run.base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data.completionFromRun(run.base),
        .io_entries = .{
            .input_start = run.base.input_start,
            .input_len = @intCast(run.base.input.len),
            .input_words = input_words,
            .output_len = run.base.output_len,
            .output_len_addr = run.base.output_len_addr,
            .output_data_addr = run.base.output_data_addr,
            .output_words = output_words,
        },
    };

    var output = try riscv_cpu.provePoseidon2WithPublicData(
        allocator,
        test_config,
        &run.base.execution_trace,
        &run.calls,
        &run.execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        null,
        bound_public_data,
    );
    defer output.deinit(allocator);
    return artifact_wire.encodeAllocWithLimits(
        allocator,
        .{
            .pcs_config = test_config,
            .statement = &output.statement,
            .extension = &output.extension,
            .artifact = output.artifact,
            .interaction_claim = output.interaction_claim,
            .proof = &output.proof,
        },
        test_limits,
    );
}

fn decodeHonest(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !artifact_wire.Decoded {
    return artifact_wire.decodeAllocForConfig(
        allocator,
        encoded,
        test_config,
        test_limits,
    );
}

/// The verifier consumes `decoded.proof` before returning. Metadata remains the
/// caller's owner and is released exactly once afterwards.
fn consumeAndExpectSuccess(
    allocator: std.mem.Allocator,
    decoded: *artifact_wire.Decoded,
) !void {
    const result = riscv_cpu.verifyPoseidon2(
        allocator,
        test_config,
        decoded.statement,
        decoded.extension,
        decoded.artifact,
        decoded.proof,
        decoded.interaction_claim,
    );
    decoded.deinitAfterProofMoved(allocator);
    return result;
}

fn consumeAndExpectError(
    allocator: std.mem.Allocator,
    decoded: *artifact_wire.Decoded,
    expected: anyerror,
) !void {
    const result = riscv_cpu.verifyPoseidon2(
        allocator,
        test_config,
        decoded.statement,
        decoded.extension,
        decoded.artifact,
        decoded.proof,
        decoded.interaction_claim,
    );
    decoded.deinitAfterProofMoved(allocator);
    try std.testing.expectError(expected, result);
}

/// Establish that structural admission accepts the mutation before requiring
/// the cryptographic layer to reject it. This prevents a later validation
/// change from silently weakening a proof-level mutation into a parser test.
fn expectOodsRejection(
    allocator: std.mem.Allocator,
    decoded: *artifact_wire.Decoded,
) !void {
    var proof_owned = true;
    errdefer if (proof_owned) decoded.deinit(allocator);
    try proof_admission.validate(
        &decoded.statement,
        &decoded.extension,
        decoded.artifact,
        .proof,
    );
    try decoded.interaction_claim.validate(
        &decoded.statement,
        &decoded.extension,
    );
    proof_owned = false;
    const result = riscv_cpu.verifyPoseidon2(
        allocator,
        test_config,
        decoded.statement,
        decoded.extension,
        decoded.artifact,
        decoded.proof,
        decoded.interaction_claim,
    );
    decoded.deinitAfterProofMoved(allocator);
    try std.testing.expectError(error.OodsNotMatching, result);
}

fn mutateTreeOneSampledValue(proof: *prover_types.Proof) !void {
    const trees = proof.commitment_scheme_proof.sampled_values.items;
    if (trees.len <= 1) return error.MissingSampledTree;
    for (trees[1]) |column| {
        if (column.len == 0) continue;
        column[0] = column[0].add(QM31.one());
        return;
    }
    return error.MissingSampledValue;
}

comptime {
    if (profile_types.caller_batch_count < 2)
        @compileError("C-012 compensating mutation requires two caller batches");
}
