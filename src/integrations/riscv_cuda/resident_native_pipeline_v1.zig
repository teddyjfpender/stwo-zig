//! Finite original native stage sequence. All witness and numerical PCS work
//! stays in one device transaction; this controller is not yet GPU-qualified.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const shared = @import("stwo_native_cuda_integration").common;
const Numerical = @import("resident_parent_pcs_v1.zig");
const Quotient = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
const Pack = @import("resident_native_claim_pack_v1.zig");
pub fn ForCommitments(comptime N: usize) type {
    const Program = @import("resident_native_program_v1.zig").ForCommitments(N);
    const PCS = @import("resident_native_pcs_v1.zig").ForCommitments(N);
    const Memory = @import("resident_native_memory_v1.zig").ForCommitments(N);
    const Producer = @import("resident_native_producer_v1.zig").ForCommitments(N);
    const Composition = @import("resident_native_composition_v1.zig").ForCommitments(N);
    const Transcript = @import("resident_native_transcript_v1.zig").ForCommitments(N);
    return struct {
        transaction: *cuda.runtime.proof_transaction.ResidentProofTransaction,
        program: *const Program.Owned,
        plans: *const PCS.Plans,
        views: *const Memory.Views,
        producer: *Producer.Bound,
        composition: *Composition.Bound,
        sink: *Transcript.NativeSink,
        claim_pack: *Pack.Bound,
        oods: *const Numerical.Oods.Bound,
        quotient: *const Quotient.Prepared,
        commitments: *[N]Numerical.Commit.Bound,
        pub fn validate(self: *const @This()) !void {
            const p = self.program.view();
            const v = self.views;
            if (v.claims.len != p.physical_claim_count or v.relations.len != 106 or v.proof.trace_commitments.len != N * 8 + p.profile.projections.len * 4 + p.profile.slots.len * 38 or v.error_flag.len != 1 or v.nonce.len != 1 or self.claim_pack.views.counts.len != 2 * p.profile.slots.len) return error.InvalidResidentNativePipeline;
            for (v.sources, p.trees[0 .. N - 1], 0..) |sources, tree, i| {
                if (sources.len != tree.base_logs.len or self.commitments[i].buffers.coefficients.address != v.commits[i].coefficients.address) return error.InvalidResidentNativePipeline;
                for (sources, tree.base_logs) |source, log| if (source.len != (@as(usize, 1) << @intCast(log))) return error.InvalidResidentNativePipeline;
            }
            const output = v.fri.layers[0].coordinates;
            const q = self.quotient.views.result_coordinates;
            if (q.c0.address != output.storage.address or q.c1.address != q.c0.address + output.column_stride_words * 4 or q.c2.address != q.c1.address + output.column_stride_words * 4 or q.c3.address != q.c2.address + output.column_stride_words * 4) return error.InvalidResidentNativePipeline;
        }
        pub fn execute(self: *@This()) !void {
            try self.validate();
            const tx = self.transaction;
            const session = tx.proofSession();
            const v = self.views;
            const p = self.program.view();
            var phase: []const u8 = "witness";
            errdefer std.debug.print("RESIDENT_NATIVE_PIPELINE_FAILURE phase={s}\n", .{phase});
            try tx.beginStage(.trace_generation);
            var producer_views = try v.producer();
            try self.producer.witness(session, &producer_views);
            try tx.endStage(.trace_generation);
            phase = "first_commitments";
            try tx.beginStage(.trace_commit);
            for (0..N - 2) |tree| {
                try Numerical.commitEvaluations(&self.commitments[tree], session, v.sources[tree]);
                const first_root = try self.commitments[tree].root();
                try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = v.proof }, tree, first_root);
                try self.sink.checkFirstRoot(tree, first_root);
            }
            // Original Epoch already binds all first roots; no additional root frames
            // may be inserted before its106 challenge outputs.
            phase = "epoch";
            try self.sink.initialize();
            phase = "interactions";
            try self.producer.interactions(session, &producer_views);
            phase = "claim_pack";
            try self.claim_pack.execute(session, v.claims);
            try self.sink.mixClaims();
            const raw = try v.claims.cast(u32);
            const first = p.profile.projections.len * 4;
            if (first != 0) try session.context.copyDeviceSlice(u32, try v.proof.trace_commitments.sub(N * 8, first), try raw.sub(0, first));
            for (0..p.profile.slots.len) |i| {
                const from = first + 40 * i;
                const to = N * 8 + first + 38 * i;
                try session.context.copyDeviceSlice(u32, try v.proof.trace_commitments.sub(to, 8), try raw.sub(from, 8));
                try session.context.copyDeviceSlice(u32, try v.proof.trace_commitments.sub(to + 8, 28), try raw.sub(from + 12, 28));
                try session.context.copyDeviceSlice(u32, try v.proof.trace_commitments.sub(to + 36, 2), try self.claim_pack.views.counts.sub(i * 2, 2));
            }
            phase = "interaction_commit";
            try Numerical.commitEvaluations(&self.commitments[N - 2], session, v.sources[N - 2]);
            const interaction_root = try self.commitments[N - 2].root();
            try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = v.proof }, N - 2, interaction_root);
            try self.sink.mixTraceRoot(N - 2, interaction_root);
            try tx.endStage(.trace_commit);
            phase = "composition";
            try tx.beginStage(.constraint_evaluation);
            try self.sink.drawCompositionAlpha(v.composition_alpha);
            var composition_views = try v.composition();
            try self.composition.compose(session, &composition_views);
            try Numerical.commit(&self.commitments[N - 1], session);
            const composition_root = try self.commitments[N - 1].root();
            try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = v.proof }, N - 1, composition_root);
            try self.sink.mixTraceRoot(N - 1, composition_root);
            try tx.endStage(.constraint_evaluation);
            phase = "oods";
            try tx.beginStage(.oods);
            try self.sink.drawOodsParameter(v.oods.parameter);
            try self.oods.execute(session, v.oods);
            try shared.proof_assembly.captureSampledValues(session, .{ .proof = v.proof, .oods = v.oods });
            try self.sink.mixSamples(v.oods.sampled_values, self.plans.oods.offsets.len);
            try tx.endStage(.oods);
            phase = "deep";
            try tx.beginStage(.quotient);
            try self.sink.drawQuotientAlpha(v.quotient.challenge);
            try @import("resident_native_quotient_v1.zig").execute(self.quotient, session);
            try tx.endStage(.quotient);
            phase = "fri";
            try tx.beginStage(.fri_commit);
            try self.plans.fri.executeWith(Numerical.Blake3Commitment, session, self.sink, v.fri, v.twiddles_inverse, v.proof);
            try cuda.runtime.stages.fri.Native.circuitDegreeVerdict(session, v.fri.last_degree_error, v.error_flag, v.proof.degree_verdict);
            try tx.endStage(.fri_commit);
            phase = "pow";
            try tx.beginStage(.pow);
            try self.sink.absorbQueryPow(v.nonce);
            try session.context.copyDeviceSlice(u32, v.proof.pow_nonce, try v.nonce.cast(u32));
            try tx.endStage(.pow);
            phase = "decommit";
            try tx.beginStage(.decommit);
            try self.plans.decommit.execute(session, self.sink, v.commits, v.fri, v.decommit, v.proof.decommitment, v.proof);
            try self.sink.sealVerdict(v.proof.degree_verdict);
            try tx.endStage(.decommit);
        }
    };
}
