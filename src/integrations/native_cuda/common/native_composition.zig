//! Shared resident constraint evaluation and composition commitment.

const commit_tree = @import("commit_tree.zig");
const proof_assembly = @import("proof_assembly.zig");
const stages = @import("stwo_cuda_backend").runtime.stages;
const transcript = @import("transcript_executor.zig");

const NativeOps = struct {
    const Split = stages.composition_split.Native;
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
    const Transcript = stages.transcript.Native;
};

const NoPrelude = struct {
    pub fn run(
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {}
};

pub fn ExecutorFor(
    comptime plan_mod: type,
    comptime constraint: type,
    comptime slots: type,
) type {
    return ExecutorForWithPrelude(
        plan_mod,
        constraint,
        slots,
        NoPrelude,
    );
}

pub fn ExecutorForWithPrelude(
    comptime plan_mod: type,
    comptime constraint: type,
    comptime slots: type,
    comptime Prelude: type,
) type {
    return struct {
        pub fn run(
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
            views: anytype,
        ) !void {
            return runWith(NativeOps, transaction, prepared, views);
        }

        fn runWith(
            comptime Ops: type,
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
            views: anytype,
        ) !void {
            const geometry = prepared.logical.geometry;
            const session = transaction.proofSession();
            const composition = try views.trees.require(.composition);
            const challenge = try views
                .constraint_buffers
                .challenge_parameters
                .cast(@import("stwo_cuda_backend").abi.field.SecureField);

            try Prelude.run(session, prepared, views);
            try transcript.drawSecure(
                Ops.Transcript,
                session,
                .constraint_evaluation,
                prepared.transcript,
                views.transcript,
                4,
                .draw_composition_alpha,
                1,
                64,
                challenge,
            );
            try transaction.zeroResidentSlice(
                u32,
                .constraint_evaluation,
                slots.composition_coordinates,
                0,
                views.constraint_buffers.composition_coordinates.storage.len,
            );
            try constraint.evaluate(
                session,
                views.constraint_buffers,
                geometry,
            );
            try Ops.Split.interpolateAndSplit(
                session,
                views.constraint_buffers.composition_coordinates,
                composition.coefficients,
                geometry.commitment_log_rows,
                views.twiddles_inverse,
            );
            try Ops.Transform.extend(
                session,
                .constraint_evaluation,
                composition.coefficients,
                composition.column_log_sizes,
                composition.evaluations,
                geometry.commitment_log_rows,
                views.twiddles_forward,
                false,
            );

            const opening = try traceOpening(prepared, .composition);
            const layers = prepared.decommit.retained_layers[opening.retained_layer_offset..][0..opening.retained_layer_count];
            const Builder = commit_tree.BuilderFor(Ops.Commitment);
            const root = try Builder.baseField(
                session,
                .constraint_evaluation,
                @intCast(geometry.commitment_rows),
                composition.evaluations,
                composition.merkle_hashes,
                layers,
            );
            try proof_assembly.captureTraceRoot(
                session,
                views,
                2,
                root,
            );
            try transcript.mixWords(
                Ops.Transcript,
                session,
                .constraint_evaluation,
                prepared.transcript,
                views.transcript,
                5,
                .mix_composition_root,
                try root.cast(u32),
                false,
            );
        }

        fn traceOpening(
            prepared: *const plan_mod.PreparedPlan,
            role: @import("uniform_layout.zig").TraceRole,
        ) !@TypeOf(prepared.decommit.trace_trees[0]) {
            for (prepared.decommit.trace_trees) |opening| {
                if (opening.role == role) return opening;
            }
            return error.InvalidKernelDescriptor;
        }
    };
}
