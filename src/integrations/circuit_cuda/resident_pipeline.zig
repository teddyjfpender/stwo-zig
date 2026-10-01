//! One proof-owned CUDA schedule for circuit recursion. The four commitment
//! trees, transcript, composition, OODS, quotient, four-fold FRI, PoW and
//! openings run on the same resident session; only the terminal SWPC bundle
//! leaves the GPU. Shape-specific buffer allocation is separate from this
//! ordering contract.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const shared = @import("stwo_native_cuda_integration").common;
const prefix_module = @import("transcript_prefix.zig");
const transcript_module = @import("resident_transcript.zig");
const witness_module = @import("resident_witness.zig");
const commit_module = @import("resident_commit.zig");
const interaction_module = @import("resident_interaction.zig");
const composition_module = @import("resident_composition_controller.zig");
const oods_module = @import("resident_oods.zig");
const quotient_module = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
const fri_module = @import("resident_fri.zig");
const decommit_module = @import("resident_decommit.zig");
const terminal_capture = @import("resident_terminal_capture.zig");

pub const Bound = struct {
    transaction: *cuda.runtime.proof_transaction.ResidentProofTransaction,
    sink: *transcript_module.NativeSink,
    witness: *const witness_module.Plan,
    interaction: *interaction_module.Bound,
    composition: *composition_module.Bound,
    oods: *const oods_module.Bound,
    quotient: *const quotient_module.Prepared,
    fri_plan: *const fri_module.Plan,
    decommit_plan: *const decommit_module.Plan,
    commitments: *[4]commit_module.Bound,
    preprocessed_columns: []const common.Words,
    base_columns: []const common.Words,
    interaction_columns: []const common.Words,
    values: common.Words,
    output_values: common.SecureFields,
    circuit_hash: common.Words,
    error_flag: common.Words,
    oods_view: shared.resident_views.Oods,
    quotient_challenge: common.SecureFields,
    fri_view: shared.resident_views.Fri,
    decommit_view: shared.resident_views.Decommit,
    decommit_assembly: common.Words,
    proof: shared.resident_views.Proof,
    twiddles_inverse: common.Words,

    pub fn validate(self: *const Bound) !void {
        if (self.values.len == 0 or self.values.len % 4 != 0 or
            self.output_values.len == 0 or self.circuit_hash.len != 8 or
            self.error_flag.len != 1 or self.quotient_challenge.len != 1 or
            self.preprocessed_columns.len != self.commitments[0].plan.column_logs.len or
            self.base_columns.len != witness_module.base_column_count or
            self.interaction_columns.len != interaction_module.interaction_column_count or
            self.proof.trace_commitments.len != 4 * 8 + circuit.common.component_list.N_COMPONENTS * 4)
            return error.InvalidResidentCircuitPipeline;
        const first_output = circuit.witness.trace.U_VAR_IDX + 1;
        if (self.values.len / 4 < first_output + self.output_values.len or
            self.output_values.address != self.values.address + first_output * 4 * @sizeOf(u32) or
            self.output_values.owner != self.values.owner or
            self.output_values.generation != self.values.generation or
            self.interaction.buffers.claimed_sums.len != circuit.common.component_list.N_COMPONENTS or
            self.interaction.buffers.error_flag.address != self.error_flag.address or
            self.composition.buffers.composition_coefficients.address != self.commitments[3].buffers.coefficients.address)
            return error.InvalidResidentCircuitPipeline;
        const first = self.fri_view.layers[0].coordinates;
        const quotient = self.quotient.views.result_coordinates;
        const row_words = first.column_stride_words;
        if (first.storage.len != 4 * row_words or quotient.c0.address != first.storage.address or
            quotient.c1.address != first.storage.address + row_words * 4 or
            quotient.c2.address != first.storage.address + row_words * 8 or
            quotient.c3.address != first.storage.address + row_words * 12)
            return error.InvalidResidentCircuitPipeline;
    }

    /// All plans, host constants and AOT handles must have been primed during
    /// ingress. This function owns the entire proof-stage order and captures
    /// each transcript-dependent section at its producer, before its buffer
    /// can be reused. No host synchronization or proof read is permitted here.
    pub fn execute(self: *Bound, allocator: std.mem.Allocator, config: @import("stwo_core").pcs.config_v2.PcsConfigV2) !void {
        try self.validate();
        const tx = self.transaction;
        const session = tx.proofSession();
        const sink = self.sink;
        var prefix = prefix_module.Prefix(transcript_module.NativeSink){ .sink = sink };

        try tx.beginStage(.trace_generation);
        try self.witness.execute(session, self.values, self.preprocessed_columns, self.base_columns, self.error_flag);
        try tx.endStage(.trace_generation);

        try tx.beginStage(.trace_commit);
        try sink.initialize();
        try prefix.mixSalt(0);
        try prefix.mixFriConfig(config);
        try self.commitments[0].executeEvaluations(session, self.preprocessed_columns);
        const preprocessed_root = try self.commitments[0].root();
        try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = self.proof }, 0, preprocessed_root);
        try prefix.commitPreprocessed(preprocessed_root);
        try prefix.mixCircuitHash(self.circuit_hash);
        try prefix.mixClaim(try self.output_values.cast(u32));
        try self.commitments[1].executeEvaluations(session, self.base_columns);
        const base_root = try self.commitments[1].root();
        try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = self.proof }, 1, base_root);
        try prefix.commitBase(base_root);
        try prefix.absorbInteractionNonce({});
        try terminal_capture.captureInteractionNonce(session, self.proof, sink.bindings.pow_nonce_words);
        _ = try prefix.drawLookupElements();
        try self.interaction.execute(allocator, session);
        try prefix.mixInteractionClaim(try self.interaction.claims());
        try terminal_capture.captureClaims(session, self.proof, self.interaction.buffers.claimed_sums);
        try self.commitments[2].executeEvaluations(session, self.interaction_columns);
        const interaction_root = try self.commitments[2].root();
        try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = self.proof }, 2, interaction_root);
        try prefix.commitInteraction(interaction_root);
        try prefix.admitComposition();
        try tx.endStage(.trace_commit);

        try tx.beginStage(.constraint_evaluation);
        try sink.drawCompositionAlpha(self.composition.buffers.alpha);
        try self.composition.execute(session);
        try self.commitments[3].execute(session);
        const composition_root = try self.commitments[3].root();
        try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = self.proof }, 3, composition_root);
        try sink.mixCompositionRoot(composition_root);
        try tx.endStage(.constraint_evaluation);

        try tx.beginStage(.oods);
        try sink.drawOodsParameter(self.oods_view.parameter);
        try self.oods.execute(session, self.oods_view);
        try shared.proof_assembly.captureSampledValues(session, .{ .proof = self.proof, .oods = self.oods_view });
        try sink.mixSampledValues(self.oods_view.sampled_values);
        try sink.drawQuotientAlpha(self.quotient_challenge);
        try tx.endStage(.oods);

        try tx.beginStage(.quotient);
        try self.quotient.execute(session);
        try tx.endStage(.quotient);

        try tx.beginStage(.fri_commit);
        try self.fri_plan.execute(session, sink, self.fri_view, self.twiddles_inverse, self.proof);
        try terminal_capture.sealVerdict(session, self.proof, self.fri_view.last_degree_error, self.error_flag);
        try tx.endStage(.fri_commit);

        try tx.beginStage(.pow);
        try sink.absorbQueryPow();
        try terminal_capture.captureQueryNonce(session, self.proof, sink.bindings.pow_nonce_words);
        try tx.endStage(.pow);

        try tx.beginStage(.decommit);
        var buffers: [4]commit_module.Buffers = undefined;
        for (self.commitments, &buffers) |commitment, *buffer| buffer.* = commitment.buffers;
        try self.decommit_plan.execute(session, sink, buffers, self.fri_view, self.decommit_view, self.decommit_assembly, self.proof);
        try tx.endStage(.decommit);
    }
};

test "resident circuit pipeline typechecks one full native CUDA stage schedule" {
    const entry: *const fn (*Bound, std.mem.Allocator, @import("stwo_core").pcs.config_v2.PcsConfigV2) anyerror!void = &Bound.execute;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
