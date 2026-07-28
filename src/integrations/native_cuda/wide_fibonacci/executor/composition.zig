//! Resident wide-Fibonacci composition evaluation and commitment.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const constraints =
    @import("stwo_cuda_backend").runtime.constraints;
const runtime_error = @import("stwo_cuda_backend").runtime.runtime_error;
const stages = @import("stwo_cuda_backend").runtime.stages;
const commit_tree = @import("../commit_tree.zig");
const plan_mod = @import("../plan.zig");
const bindings = @import("../resident_bindings/mod.zig");
const slots = @import("../slots.zig");
const proof_assembly = @import("proof_assembly.zig");

const NativeOps = struct {
    const Transcript = stages.transcript.Native;
    const Power = stages.constraint_power.Native;
    const Constraint = constraints.wide_fibonacci;
    const Split = stages.composition_split.Native;
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
};

pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    return runWith(NativeOps, transaction, prepared, views);
}

fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    const geometry = prepared.logical.geometry;
    const session = transaction.proofSession();
    const trace_log = geometry.statement.log_n_rows;
    const commitment_log = geometry.queryLogSize();

    try requireOperation(prepared, 4, .draw_alpha);
    const draw_boundary = try prepared.transcript.boundary(4);
    const output_snapshot_words = try views.transcript.output_snapshot.sub(0, 4);
    const output_snapshot = try output_snapshot_words.cast(field.SecureField);
    try Ops.Transcript.drawSecure(
        session,
        .constraint_evaluation,
        views.transcript.state,
        .{
            .expected_step = draw_boundary.expected_step,
            .expected_chain = draw_boundary.expected_chain,
            .next_chain = draw_boundary.next_chain,
            .snapshot = views.transcript.boundary_snapshot,
        },
        1,
        64,
        views.constraint.composition_challenge,
        output_snapshot,
    );
    try Ops.Power.expand(
        session,
        views.constraint.composition_challenge,
        views.constraint.random_powers,
    );

    try transaction.zeroResidentSlice(
        u32,
        .constraint_evaluation,
        slots.composition_coordinates,
        0,
        views.constraint.composition_coordinates.storage.len,
    );
    var launch = try Ops.Constraint.prepare(
        session,
        .{
            .trace_evaluations = views.trace.main_evaluations,
            .random_coefficient_powers = views.constraint.random_powers,
            .denominator_inverses = views.constraint.denominator_inverses,
            .composition_coordinates = views.constraint.composition_coordinates,
        },
        trace_log,
        try count(geometry.main_columns),
        0,
    );
    try launch.launch(session);

    try Ops.Split.interpolateAndSplit(
        session,
        views.constraint.composition_coordinates,
        views.trace.composition_coefficients,
        commitment_log,
        views.trace.twiddles_inverse,
    );
    const composition_logs = try views.trace.coefficient_log_sizes.sub(
        geometry.main_columns,
        @import("../request.zig").composition_column_count,
    );
    try Ops.Transform.extend(
        session,
        .constraint_evaluation,
        views.trace.composition_coefficients,
        composition_logs,
        views.trace.composition_evaluations,
        commitment_log,
        views.trace.twiddles_forward,
        false,
    );

    const opening = prepared.decommit.trace_trees[1];
    const layers = prepared.decommit.retained_layers[opening.retained_layer_offset..][0..opening.retained_layer_count];
    const Builder = commit_tree.BuilderFor(Ops.Commitment);
    const composition_root = try Builder.baseField(
        session,
        .constraint_evaluation,
        try count(geometry.commitment_rows),
        views.trace.composition_evaluations,
        views.trace.composition_merkle_hashes,
        layers,
    );
    if (composition_root.len != 1)
        return error.InvalidKernelDescriptor;
    try proof_assembly.captureTraceRoot(
        session,
        views,
        2,
        composition_root,
    );

    try requireOperation(prepared, 5, .mix_root);
    const mix_boundary = try prepared.transcript.boundary(5);
    const root_words = try composition_root.cast(u32);
    try Ops.Transcript.mixWords(
        session,
        .constraint_evaluation,
        views.transcript.state,
        .{
            .expected_step = mix_boundary.expected_step,
            .expected_chain = mix_boundary.expected_chain,
            .next_chain = mix_boundary.next_chain,
            .snapshot = views.transcript.boundary_snapshot,
        },
        root_words,
        false,
        try views.transcript.input_snapshot.sub(0, root_words.len),
    );
}

const ExpectedOperation = enum {
    draw_alpha,
    mix_root,
};

fn requireOperation(
    prepared: *const plan_mod.PreparedPlan,
    step: u32,
    expected: ExpectedOperation,
) !void {
    const operation = try prepared.transcript.operation(step);
    switch (expected) {
        .draw_alpha => switch (operation) {
            .draw_composition_alpha => {},
            else => return error.InvalidKernelDescriptor,
        },
        .mix_root => switch (operation) {
            .mix_composition_root => {},
            else => return error.InvalidKernelDescriptor,
        },
    }
}

fn count(value: usize) runtime_error.Error!u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

test "composition executor keeps the complete AOT path resident" {
    const support = @import("trace/test_support.zig");

    const Calls = struct {
        var draw: usize = 0;
        var mix: usize = 0;
        var powers: usize = 0;
        var zero: usize = 0;
        var prepare: usize = 0;
        var launch: usize = 0;
        var split: usize = 0;
        var extend: usize = 0;
        var contiguous_leaves: usize = 0;
        var merkle_layers: usize = 0;
        var copies: usize = 0;

        fn reset() void {
            draw = 0;
            mix = 0;
            powers = 0;
            zero = 0;
            prepare = 0;
            launch = 0;
            split = 0;
            extend = 0;
            contiguous_leaves = 0;
            merkle_layers = 0;
            copies = 0;
        }
    };
    const FakeOps = struct {
        const Transcript = struct {
            pub fn drawSecure(
                _: anytype,
                stage: anytype,
                _: anytype,
                _: anytype,
                felt_count: u32,
                rejection_rounds: u32,
                output: anytype,
                snapshot: anytype,
            ) !void {
                try std.testing.expectEqual(
                    .constraint_evaluation,
                    stage,
                );
                try std.testing.expectEqual(@as(u32, 1), felt_count);
                try std.testing.expectEqual(@as(u32, 64), rejection_rounds);
                try std.testing.expectEqual(@as(usize, 1), output.len);
                try std.testing.expectEqual(@as(usize, 1), snapshot.len);
                Calls.draw += 1;
            }

            pub fn mixWords(
                _: anytype,
                stage: anytype,
                _: anytype,
                _: anytype,
                source: anytype,
                validate_m31: bool,
                snapshot: anytype,
            ) !void {
                try std.testing.expectEqual(
                    .constraint_evaluation,
                    stage,
                );
                try std.testing.expect(!validate_m31);
                try std.testing.expectEqual(@as(usize, 8), source.len);
                try std.testing.expectEqual(source.len, snapshot.len);
                Calls.mix += 1;
            }
        };
        const Power = struct {
            pub fn expand(
                _: anytype,
                challenge: anytype,
                output: anytype,
            ) !void {
                try std.testing.expectEqual(@as(usize, 1), challenge.len);
                try std.testing.expect(output.len > 0);
                Calls.powers += 1;
            }
        };
        const Constraint = struct {
            const Launch = struct {
                pub fn launch(_: *@This(), _: anytype) !void {
                    Calls.launch += 1;
                }
            };

            pub fn prepare(
                _: anytype,
                buffers: anytype,
                _: u32,
                sequence_len: u32,
                random_base: u32,
            ) !Launch {
                try std.testing.expectEqual(
                    @as(usize, sequence_len),
                    buffers.trace_evaluations.storage.len /
                        buffers.trace_evaluations.column_stride_words,
                );
                try std.testing.expectEqual(@as(u32, 0), random_base);
                Calls.prepare += 1;
                return .{};
            }
        };
        const Split = struct {
            pub fn interpolateAndSplit(
                _: anytype,
                coordinates: anytype,
                coefficients: anytype,
                _: u32,
                _: anytype,
            ) !void {
                try std.testing.expectEqual(
                    @as(usize, 4),
                    coordinates.storage.len /
                        coordinates.column_stride_words,
                );
                try std.testing.expectEqual(
                    @as(usize, 8),
                    coefficients.storage.len /
                        coefficients.column_stride_words,
                );
                Calls.split += 1;
            }
        };
        const Transform = struct {
            pub fn extend(
                _: anytype,
                stage: anytype,
                coefficients: anytype,
                logs: anytype,
                evaluations: anytype,
                _: u32,
                _: anytype,
                before_final_circle: bool,
            ) !void {
                try std.testing.expectEqual(
                    .constraint_evaluation,
                    stage,
                );
                try std.testing.expect(!before_final_circle);
                try std.testing.expectEqual(@as(usize, 8), logs.len);
                try std.testing.expectEqual(
                    logs.len,
                    coefficients.storage.len /
                        coefficients.column_stride_words,
                );
                try std.testing.expectEqual(
                    logs.len,
                    evaluations.storage.len /
                        evaluations.column_stride_words,
                );
                Calls.extend += 1;
            }
        };
        const Commitment = struct {
            pub fn contiguousLeaves(
                _: anytype,
                _: anytype,
                _: u32,
                _: anytype,
                _: anytype,
            ) !void {
                Calls.contiguous_leaves += 1;
            }
            pub fn layer(
                _: anytype,
                _: anytype,
                previous: anytype,
                output: anytype,
                four_levels: bool,
            ) runtime_error.Error!void {
                if (four_levels or previous.len / 2 != output.len)
                    return error.InvalidKernelDescriptor;
                Calls.merkle_layers += 1;
            }
            pub fn contiguousTail(
                _: anytype,
                _: anytype,
                previous: anytype,
                outputs: anytype,
                level_count: u32,
            ) runtime_error.Error!void {
                if (level_count == 0 or outputs.len != previous.len - 1)
                    return error.InvalidKernelDescriptor;
                Calls.merkle_layers += level_count;
            }
        };
    };
    const FakeContext = struct {
        pub fn copyDeviceSlice(
            _: *@This(),
            comptime F: type,
            destination: anytype,
            source: anytype,
        ) runtime_error.Error!void {
            if (F != u32 or destination.len != source.len)
                return error.InvalidKernelDescriptor;
            Calls.copies += 1;
        }
    };
    const FakeTransaction = struct {
        session: struct { context: FakeContext = .{} } = .{},

        pub fn proofSession(self: *@This()) *@TypeOf(self.session) {
            return &self.session;
        }

        pub fn zeroResidentSlice(
            _: *@This(),
            comptime F: type,
            stage: anytype,
            id: anytype,
            first: usize,
            words: usize,
        ) !void {
            try std.testing.expectEqual(u32, F);
            try std.testing.expectEqual(.constraint_evaluation, stage);
            try std.testing.expectEqual(slots.composition_coordinates, id);
            try std.testing.expectEqual(@as(usize, 0), first);
            try std.testing.expect(words > 0);
            Calls.zero += 1;
        }
    };

    const allocator = std.testing.allocator;
    const geometry = try support.geometry(5, 8);
    var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = support.Provider{ .prepared = &prepared };
    const views = try bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{};
    Calls.reset();

    try runWith(FakeOps, &transaction, &prepared, &views);

    try std.testing.expectEqual(@as(usize, 1), Calls.draw);
    try std.testing.expectEqual(@as(usize, 1), Calls.mix);
    try std.testing.expectEqual(@as(usize, 1), Calls.powers);
    try std.testing.expectEqual(@as(usize, 1), Calls.zero);
    try std.testing.expectEqual(@as(usize, 1), Calls.prepare);
    try std.testing.expectEqual(@as(usize, 1), Calls.launch);
    try std.testing.expectEqual(@as(usize, 1), Calls.split);
    try std.testing.expectEqual(@as(usize, 1), Calls.extend);
    try std.testing.expectEqual(@as(usize, 1), Calls.contiguous_leaves);
    try std.testing.expectEqual(
        @as(usize, geometry.queryLogSize()),
        Calls.merkle_layers,
    );
    try std.testing.expectEqual(@as(usize, 1), Calls.copies);
}
