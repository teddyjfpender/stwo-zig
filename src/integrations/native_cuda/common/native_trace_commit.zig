//! Shared resident trace generation, commitment, and transcript prefix.

const commit_tree = @import("commit_tree.zig");
const proof_assembly = @import("proof_assembly.zig");
const stages = @import("stwo_cuda_backend").runtime.stages;
const transcript = @import("transcript_executor.zig");

const NativeOps = struct {
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
    const Transcript = stages.transcript.Native;
};

fn DefaultStatementFor(comptime geometry_mod: type) type {
    return struct {
        pub fn mix(
            comptime Ops: type,
            session: anytype,
            prepared: anytype,
            views: anytype,
        ) !void {
            if (@hasDecl(geometry_mod, "statement_first_segment_words")) {
                const first_count =
                    geometry_mod.statement_first_segment_words;
                if (first_count == 0 or
                    first_count >= views.statement_words.len)
                {
                    return error.InvalidKernelDescriptor;
                }
                try transcript.mixWordsPair(
                    Ops.Transcript,
                    session,
                    .trace_commit,
                    prepared.transcript,
                    views.transcript,
                    3,
                    .mix_statement,
                    try views.statement_words.sub(0, first_count),
                    try views.statement_words.sub(
                        first_count,
                        views.statement_words.len - first_count,
                    ),
                    false,
                );
            } else {
                try transcript.mixWords(
                    Ops.Transcript,
                    session,
                    .trace_commit,
                    prepared.transcript,
                    views.transcript,
                    3,
                    .mix_statement,
                    views.statement_words,
                    false,
                );
            }
        }
    };
}

pub fn ExecutorFor(
    comptime geometry_mod: type,
    comptime plan_mod: type,
    comptime device_trace: type,
) type {
    return ExecutorForWithStatement(
        plan_mod,
        device_trace,
        DefaultStatementFor(geometry_mod),
    );
}

pub fn ExecutorForWithStatement(
    comptime plan_mod: type,
    comptime device_trace: type,
    comptime Statement: type,
) type {
    return struct {
        pub fn generate(
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
            views: anytype,
        ) !void {
            const preprocessed = try views.trees.require(.preprocessed);
            const main = try views.trees.require(.main);
            try device_trace.generate(
                transaction.proofSession(),
                .{
                    .preprocessed = preprocessed.coefficients,
                    .main = main.coefficients,
                },
                prepared.logical.geometry,
            );
        }

        pub fn commit(
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
            views: anytype,
        ) !void {
            return commitWith(NativeOps, transaction, prepared, views);
        }

        fn commitWith(
            comptime Ops: type,
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
            views: anytype,
        ) !void {
            const session = transaction.proofSession();
            try Ops.Transcript.initialize(
                session,
                .trace_commit,
                views.transcript.state,
                null,
                null,
                prepared.transcript.initialChain(),
            );
            try transcript.mixWords(
                Ops.Transcript,
                session,
                .trace_commit,
                prepared.transcript,
                views.transcript,
                0,
                .mix_pcs_config,
                views.protocol_words,
                true,
            );
            try commitRole(
                Ops,
                session,
                prepared,
                views,
                .preprocessed,
                0,
                1,
                .mix_preprocessed_root,
            );
            try commitRole(
                Ops,
                session,
                prepared,
                views,
                .main,
                1,
                2,
                .mix_main_root,
            );
            try Statement.mix(Ops, session, prepared, views);
        }

        fn commitRole(
            comptime Ops: type,
            session: anytype,
            prepared: *const plan_mod.PreparedPlan,
            views: anytype,
            role: @import("uniform_layout.zig").TraceRole,
            commitment_index: usize,
            transcript_step: u32,
            operation: @import("transcript_schedule.zig").Operation,
        ) !void {
            const geometry = prepared.logical.geometry;
            const tree = try views.trees.require(role);
            try Ops.Transform.inverseCompact(
                session,
                .trace_commit,
                tree.coefficients,
                tree.coefficients,
                geometry.traceLogSize(),
                views.twiddles_inverse,
            );
            try Ops.Transform.extend(
                session,
                .trace_commit,
                tree.coefficients,
                tree.column_log_sizes,
                tree.evaluations,
                geometry.commitment_log_rows,
                views.twiddles_forward,
                false,
            );
            const opening = try traceOpening(prepared, role);
            const layers = retainedLayers(
                prepared,
                opening.retained_layer_offset,
                opening.retained_layer_count,
            );
            const Builder = commit_tree.BuilderFor(Ops.Commitment);
            const root = try Builder.baseField(
                session,
                .trace_commit,
                @intCast(geometry.commitment_rows),
                tree.evaluations,
                tree.merkle_hashes,
                layers,
            );
            try proof_assembly.captureTraceRoot(
                session,
                views,
                commitment_index,
                root,
            );
            try transcript.mixWords(
                Ops.Transcript,
                session,
                .trace_commit,
                prepared.transcript,
                views.transcript,
                transcript_step,
                operation,
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

        fn retainedLayers(
            prepared: *const plan_mod.PreparedPlan,
            first: usize,
            count: usize,
        ) []const @import("stwo_cuda_backend").abi.field.MerkleLayerDescriptor {
            return prepared.decommit.retained_layers[first..][0..count];
        }
    };
}
