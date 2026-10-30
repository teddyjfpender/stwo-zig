//! Full original-parent numerical stage schedule in one resident transaction.
//! Producers are device-bound witness/interaction/composition implementations;
//! this schedule is not an admission API and never certifies arbitrary callbacks.
//! A concrete producer plus fresh original verification qualifies an entrypoint.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const shared = @import("stwo_native_cuda_integration").common;
const PCS = @import("resident_parent_pcs_v1.zig");
const Memory = @import("resident_parent_memory_v1.zig");
const Program = @import("resident_parent_program_v1.zig");
const Transcript = @import("resident_parent_transcript_v1.zig");
const Quotient = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
pub fn Bound(comptime DeviceProducer: type) type {
    return struct {
        const Self = @This();
        transaction: *cuda.runtime.proof_transaction.ResidentProofTransaction,
        program: *const Program.Owned,
        plans: *const PCS.Plans,
        views: *const Memory.Views,
        producer: *DeviceProducer,
        sink: *Transcript.NativeSink,
        oods: *const PCS.Oods.Bound,
        quotient: *const Quotient.Prepared,
        commitments: *[4]PCS.Commit.Bound,

        pub fn validate(self: *const Self) !void {
            const p = self.program.view();
            const v = self.views;
            if (v.claims.len != Program.COMPONENT_COUNT or v.relations.len != @import("../../frontends/riscv/recursion/air/universal_challenges.zig").DRAW_COUNT or v.proof.trace_commitments.len != 32 + 4 * Program.COMPONENT_COUNT or v.error_flag.len != 1 or v.nonce.len != 1) return error.InvalidResidentParentPipeline;
            for (v.sources, p.trees[0..3], 0..) |sources, tree, i| {
                if (sources.len != tree.column_logs.len or self.commitments[i].buffers.coefficients.address != v.commits[i].coefficients.address) return error.InvalidResidentParentPipeline;
                for (sources, tree.column_logs) |source, log| if (source.len != @as(usize, 1) << @intCast(log)) return error.InvalidResidentParentPipeline;
            }
            const output = v.fri.layers[0].coordinates;
            const q = self.quotient.views.result_coordinates;
            if (q.c0.address != output.storage.address or q.c1.address != q.c0.address + output.column_stride_words * 4 or q.c2.address != q.c1.address + output.column_stride_words * 4 or q.c3.address != q.c2.address + output.column_stride_words * 4) return error.InvalidResidentParentPipeline;
        }
        pub fn execute(self: *Self) !void {
            var phase: []const u8 = "validate";
            errdefer std.debug.print("RESIDENT_PARENT_PIPELINE_FAILURE phase={s}\n", .{phase});
            try self.validate();
            const tx = self.transaction;
            const session = tx.proofSession();
            const v = self.views;
            phase = "witness";
            try tx.beginStage(.trace_generation);
            // The concrete producer must consume raw bytes/device DAG values;
            // CPU-prepared MAIN columns are not accepted by the entrypoint.
            try self.producer.witness(session, v);
            try tx.endStage(.trace_generation);

            phase = "trace_commit_start";
            try tx.beginStage(.trace_commit);
            phase = "transcript_init";
            try self.sink.initialize();
            for (0..2) |tree| {
                phase = "fixed_main_commit";
                try PCS.commitEvaluations(&self.commitments[tree], session, v.sources[tree]);
                const root = try self.commitments[tree].root();
                phase = "fixed_main_capture";
                try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = v.proof }, tree, root);
                phase = "fixed_main_mix";
                try self.sink.mixTraceRoot(@intCast(tree), root);
            }
            phase = "relation_draw";
            try self.sink.drawRelations(v.relations);
            phase = "interactions";
            try self.producer.interactions(session, v);
            phase = "claims_mix";
            try self.sink.mixClaims(v.claims);
            try session.context.copyDeviceSlice(u32, try v.proof.trace_commitments.sub(32, 4 * Program.COMPONENT_COUNT), try v.claims.cast(u32));
            phase = "interaction_commit";
            try PCS.commitEvaluations(&self.commitments[2], session, v.sources[2]);
            const interaction_root = try self.commitments[2].root();
            try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = v.proof }, 2, interaction_root);
            try self.sink.mixTraceRoot(2, interaction_root);
            try tx.endStage(.trace_commit);

            try tx.beginStage(.constraint_evaluation);
            phase = "composition_alpha";
            try self.sink.drawCompositionAlpha(v.composition_alpha);
            phase = "composition_evaluation";
            try self.producer.composition(session, v);
            phase = "composition_commit";
            try PCS.commit(&self.commitments[3], session);
            const composition_root = try self.commitments[3].root();
            try shared.proof_assembly.captureStaticTraceRoot(session, .{ .proof = v.proof }, 3, composition_root);
            try self.sink.mixTraceRoot(3, composition_root);
            try tx.endStage(.constraint_evaluation);

            try tx.beginStage(.oods);
            phase = "oods_draw";
            try self.sink.drawOodsParameter(v.oods.parameter);
            phase = "oods_evaluate";
            try self.oods.execute(session, v.oods);
            try shared.proof_assembly.captureSampledValues(session, .{ .proof = v.proof, .oods = v.oods });
            phase = "oods_mix";
            try self.sink.mixSamples(v.oods.sampled_values, self.plans.oods.offsets.len);
            try tx.endStage(.oods);

            try tx.beginStage(.quotient);
            phase = "deep_draw";
            try self.sink.drawQuotientAlpha(v.quotient.challenge);
            phase = "deep_execute";
            try self.quotient.execute(session);
            try tx.endStage(.quotient);

            try tx.beginStage(.fri_commit);
            phase = "fri_execute";
            try self.plans.fri.executeWith(PCS.Blake3Commitment, session, self.sink, v.fri, v.twiddles_inverse, v.proof);
            try cuda.runtime.stages.fri.Native.circuitDegreeVerdict(session, v.fri.last_degree_error, v.error_flag, v.proof.degree_verdict);
            try tx.endStage(.fri_commit);

            try tx.beginStage(.pow);
            phase = "pow";
            try self.sink.absorbQueryPow(v.nonce);
            try session.context.copyDeviceSlice(u32, v.proof.pow_nonce, try v.nonce.cast(u32));
            try tx.endStage(.pow);

            try tx.beginStage(.decommit);
            phase = "decommit";
            try self.plans.decommit.execute(session, self.sink, v.commits, v.fri, v.decommit, v.proof.decommitment, v.proof);
            // Include late draw/rejection/PoW exhaustion before the sole read.
            phase = "seal_verdict";
            try self.sink.sealVerdict(v.proof.degree_verdict);
            try tx.endStage(.decommit);
        }
    };
}
