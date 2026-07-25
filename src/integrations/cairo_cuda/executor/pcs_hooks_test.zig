const std = @import("std");
const column = @import(
    "../../../backends/cuda/runtime/column.zig",
);
const resident_plan = @import("resident_plan.zig");
const subject = @import("pcs_hooks.zig");

const Words = column.DeviceSlice(u32);

const TestPlan = struct {
    slots: []const resident_plan.Slot,

    pub fn slot(
        self: @This(),
        kind: resident_plan.SlotKind,
        ordinal: u32,
    ) ?resident_plan.Slot {
        for (self.slots) |candidate| {
            if (candidate.kind == kind and candidate.ordinal == ordinal)
                return candidate;
        }
        return null;
    }
};

const Provider = struct {
    plan: TestPlan,
    shortened_id: ?u32 = null,

    pub fn slot(self: @This(), id: u32) !Words {
        for (self.plan.slots) |candidate| {
            if (candidate.id != id) continue;
            return .{
                .address = 0x1000 + @as(usize, id) * 0x10000,
                .len = candidate.words -
                    @intFromBool(self.shortened_id == id),
                .owner = 9,
                .generation = 17,
            };
        }
        return error.InvalidKernelDescriptor;
    }
};

test "Cairo OODS bindings preserve exact typed extents" {
    const sample_count: usize = 3;
    const max_log: u32 = 5;
    const slots = [_]resident_plan.Slot{
        slot(1, .oods_parameter, 4),
        slot(2, .oods_offset_points, sample_count * 2),
        slot(3, .oods_fold_counts, sample_count),
        slot(4, .oods_output_indices, sample_count),
        slot(5, .oods_sample_points, sample_count * 8),
        slot(6, .oods_evaluation_points, sample_count * 8),
        slot(7, .oods_folding_factors, sample_count * max_log * 4),
        slot(8, .oods_reduce_a, sample_count * 4),
        slot(9, .oods_reduce_b, sample_count * 8),
        slot(10, .oods_sampled_values, sample_count * 4),
    };
    const plan = TestPlan{ .slots = &slots };
    const provider = Provider{ .plan = plan };
    const bound = try subject.bindOods(
        provider,
        plan,
        sample_count,
        max_log,
    );

    try std.testing.expectEqual(sample_count, bound.offset_points.len);
    try std.testing.expectEqual(sample_count, bound.sample_points.len);
    try std.testing.expectEqual(sample_count, bound.sampled_values.len);
    try std.testing.expectEqual(
        sample_count * max_log,
        bound.folding_factors.len,
    );
    try std.testing.expectEqual(
        @as(usize, sample_count),
        bound.reduce_a.len,
    );
    try std.testing.expectEqual(
        @as(usize, sample_count * 2),
        bound.reduce_b.len,
    );
}

test "Cairo PCS binding rejects a provider extent mutation" {
    const sample_count: usize = 2;
    const max_log: u32 = 4;
    const slots = [_]resident_plan.Slot{
        slot(1, .oods_parameter, 4),
        slot(2, .oods_offset_points, sample_count * 2),
        slot(3, .oods_fold_counts, sample_count),
        slot(4, .oods_output_indices, sample_count),
        slot(5, .oods_sample_points, sample_count * 8),
        slot(6, .oods_evaluation_points, sample_count * 8),
        slot(7, .oods_folding_factors, sample_count * max_log * 4),
        slot(8, .oods_reduce_a, sample_count * 2),
        slot(9, .oods_reduce_b, sample_count * 4),
        slot(10, .oods_sampled_values, sample_count * 4),
    };
    const plan = TestPlan{ .slots = &slots };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        subject.bindOods(
            Provider{ .plan = plan, .shortened_id = 5 },
            plan,
            sample_count,
            max_log,
        ),
    );
}

test "Cairo PCS stages fail closed until semantic schedules exist" {
    inline for (std.meta.fields(subject.Stage)) |field| {
        const stage: subject.Stage = @enumFromInt(field.value);
        try std.testing.expectEqual(
            subject.Readiness.buffers_bound,
            subject.readiness(stage),
        );
        try std.testing.expectError(
            switch (stage) {
                .composition_commit => subject.Gap.MissingCompositionCoordinateLayout,
                .oods => subject.Gap.MissingMixedHeightOodsSchedule,
                .quotient => subject.Gap.MissingCompactQuotientSources,
                .fri => subject.Gap.MissingFriTerminalGeometry,
                .pow => subject.Gap.MissingCairoTranscriptSchedule,
                .decommit => subject.Gap.MissingMixedHeightDecommitTopology,
                .terminal_assembly => subject.Gap.MissingTerminalCompaction,
            },
            subject.requireExecutable(stage),
        );
    }
    try std.testing.expect(!subject.production_ready);
}

test "complete Cairo PCS binder remains type-checked" {
    const proof_ir = @import("stwo_backend_contracts").proof_program;
    const compact = @import(
        "../../../frontends/cairo/compact_verifier_interchange.zig",
    );
    const CompileProvider = struct {
        pub fn slot(_: @This(), _: u32) !Words {
            return error.InvalidKernelDescriptor;
        }
    };
    var execute = false;
    std.mem.doNotOptimizeAway(&execute);
    if (execute) {
        const plan: *const resident_plan.Plan = undefined;
        const program: proof_ir.ProofProgram = undefined;
        const protocol: compact.CompactProtocolV1 = undefined;
        _ = subject.bind(
            CompileProvider{},
            plan,
            program,
            protocol,
        ) catch {};
    }
}

fn slot(
    id: u32,
    kind: resident_plan.SlotKind,
    words: usize,
) resident_plan.Slot {
    return .{
        .id = id,
        .kind = kind,
        .ordinal = 0,
        .words = words,
        .alignment_words = 1,
        .live_from = .oods,
        .live_through = .oods,
        .storage = .request_local,
        .immutable = false,
        .identity = [_]u8{1} ** 32,
    };
}
