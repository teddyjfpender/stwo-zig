const std = @import("std");
const stwo = @import("stwo_under_test");
const exact = stwo.integrations.native_cuda.poseidon;
const RuntimeError =
    stwo.backends.cuda.runtime.runtime_error.Error;

test {
    std.testing.refAllDecls(exact);
}

test "exact Poseidon arena binds three non-empty trees and one relation" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        .{ .log_n_instances = 11 },
        stwo.core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    const views = try exact.resident_bindings.bind(&provider, &prepared);

    try std.testing.expectEqual(
        @as(usize, 3),
        views.trace.trees.active().len,
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        (try views.trace.trees.require(.interaction)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1296),
        views.constraint.source_evaluations.storage.len /
            views.constraint.source_evaluations.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, 4) * try geometry.traceRowCount(),
        views.constraint.source_evaluations.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, 256) * try geometry.traceRowCount(),
        views.relation.source_values.storage.len,
    );
    try std.testing.expect(
        views.relation.source_values.storage.address !=
            views.trace.main_coefficients.storage.address,
    );

    const relation_plan = try exact.relation.Plan.init(geometry.log_n_rows);
    const instance = views.relation.instance();
    const runtime_relation =
        stwo.backends.cuda.runtime.stages.relation;
    const prepared_relation = try runtime_relation.prepare(
        allocator,
        .{
            .topology = relation_plan.topology(),
            .buffers = views.relation.buffers,
            .instances = &.{instance},
        },
    );
    runtime_relation.deinit(allocator, prepared_relation);
}

test "Poseidon exact AIR domain is independent from commitment blowup" {
    const geometry = try exact.geometry.admit(
        .{ .log_n_instances = 13 },
        stwo.core.pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(
        2 * try geometry.traceRowCount(),
        geometry.commitment_rows,
    );
    try std.testing.expectEqual(
        4 * try geometry.traceRowCount(),
        geometry.composition_rows,
    );
    const descriptor =
        try stwo.backends.cuda.runtime.constraints.poseidon.descriptor(
            geometry.log_n_rows,
        );
    try std.testing.expectEqual(
        stwo.backends.cuda.abi.schema.KernelSchema
            .native_poseidon_constraint_v1,
        descriptor.abi_schema,
    );
}

test "exact Poseidon composition executes the four-tree transcript" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        .{ .log_n_instances = 11 },
        stwo.core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(
        allocator,
        geometry,
    );
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    var views = try exact.resident_bindings.bind(
        &provider,
        &prepared,
    );
    var transaction = FakeTransaction{
        .allocator = allocator,
        .rows = try geometry.traceRowCount(),
    };
    Calls.reset();

    try exact.executor.composition.runWith(
        FakeOps,
        &transaction,
        &prepared,
        &views,
    );

    try std.testing.expectEqualSlices(
        u32,
        &.{ 3, 4, 5, 6 },
        Calls.transcript_steps[0..Calls.transcript_count],
    );
    try std.testing.expectEqual(@as(usize, 1), Calls.relations);
    try std.testing.expectEqual(
        @as(usize, 1),
        Calls.inverse_transforms,
    );
    try std.testing.expectEqual(@as(usize, 4), Calls.extensions);
    try std.testing.expectEqual(
        @as(usize, 1),
        Calls.power_expansions,
    );
    try std.testing.expectEqual(@as(usize, 1), Calls.constraints);
    try std.testing.expectEqual(@as(usize, 1), Calls.splits);
    try std.testing.expectEqual(@as(usize, 2), Calls.leaf_hashes);
    try std.testing.expectEqual(@as(usize, 2), Calls.tail_hashes);
    try std.testing.expectEqual(@as(usize, 3), Calls.capture_copies);
    try std.testing.expectEqual(@as(usize, 1), Calls.zeroes);
}

const Provider = struct {
    prepared: *const exact.plan.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: exact.slots.SlotId,
    ) !stwo.backends.cuda.runtime.column.DeviceSlice(u32) {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        return .{
            .address = 0x1_0000_0000 +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 7,
            .generation = 11,
        };
    }
};

const Calls = struct {
    var transcript_steps: [4]u32 = undefined;
    var transcript_count: usize = 0;
    var relations: usize = 0;
    var inverse_transforms: usize = 0;
    var extensions: usize = 0;
    var power_expansions: usize = 0;
    var constraints: usize = 0;
    var splits: usize = 0;
    var leaf_hashes: usize = 0;
    var tail_hashes: usize = 0;
    var capture_copies: usize = 0;
    var zeroes: usize = 0;

    fn reset() void {
        transcript_count = 0;
        relations = 0;
        inverse_transforms = 0;
        extensions = 0;
        power_expansions = 0;
        constraints = 0;
        splits = 0;
        leaf_hashes = 0;
        tail_hashes = 0;
        capture_copies = 0;
        zeroes = 0;
    }

    fn transcript(step: u32) !void {
        if (transcript_count == transcript_steps.len)
            return error.InvalidKernelDescriptor;
        transcript_steps[transcript_count] = step;
        transcript_count += 1;
    }
};

const FakeOps = struct {
    pub const Transcript = struct {
        pub fn drawSecure(
            _: anytype,
            stage: anytype,
            _: anytype,
            boundary: anytype,
            felt_count: u32,
            rejection_rounds: u32,
            output: anytype,
            snapshot: anytype,
        ) !void {
            try std.testing.expectEqual(
                stwo.backends.cuda.runtime.telemetry.Stage
                    .constraint_evaluation,
                stage,
            );
            try std.testing.expectEqual(
                @as(usize, felt_count),
                output.len,
            );
            try std.testing.expectEqual(
                @as(usize, felt_count),
                snapshot.len,
            );
            try std.testing.expectEqual(
                @as(u32, 64),
                rejection_rounds,
            );
            try Calls.transcript(boundary.expected_step);
        }

        pub fn mixWords(
            _: anytype,
            stage: anytype,
            _: anytype,
            boundary: anytype,
            source: anytype,
            validate_m31: bool,
            snapshot: anytype,
        ) !void {
            try std.testing.expectEqual(
                stwo.backends.cuda.runtime.telemetry.Stage
                    .constraint_evaluation,
                stage,
            );
            try std.testing.expect(!validate_m31);
            try std.testing.expectEqual(source.len, snapshot.len);
            try Calls.transcript(boundary.expected_step);
        }
    };

    pub const Relation = struct {
        pub fn execute(_: anytype, _: anytype) !void {
            Calls.relations += 1;
        }
    };

    pub const Transform = struct {
        pub fn inverseCompact(
            _: anytype,
            _: anytype,
            inputs: anytype,
            outputs: anytype,
            log_rows: u32,
            _: anytype,
        ) !void {
            try std.testing.expectEqual(
                inputs.storage.address,
                outputs.storage.address,
            );
            try std.testing.expect(
                outputs.column_stride_words >=
                    @as(usize, 1) << @intCast(log_rows),
            );
            Calls.inverse_transforms += 1;
        }

        pub fn extend(
            _: anytype,
            _: anytype,
            coefficients: anytype,
            logs: anytype,
            evaluations: anytype,
            _: u32,
            _: anytype,
            before_final_circle: bool,
        ) !void {
            try std.testing.expect(!before_final_circle);
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
            Calls.extensions += 1;
        }
    };

    pub const Power = struct {
        pub fn expand(
            _: anytype,
            challenge: anytype,
            powers: anytype,
        ) !void {
            try std.testing.expectEqual(@as(usize, 1), challenge.len);
            try std.testing.expectEqual(@as(usize, 1144), powers.len);
            Calls.power_expansions += 1;
        }
    };

    pub const Constraint = struct {
        pub fn evaluate(
            _: anytype,
            buffers: anytype,
            _: anytype,
        ) !void {
            try std.testing.expectEqual(
                @as(usize, 1296),
                buffers.source_evaluations.storage.len /
                    buffers.source_evaluations.column_stride_words,
            );
            try std.testing.expectEqual(
                @as(usize, 1144),
                buffers.random_coefficient_powers.len,
            );
            try std.testing.expectEqual(
                @as(usize, 2),
                buffers.lookup_elements.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                buffers.claimed_sum.len,
            );
            Calls.constraints += 1;
        }
    };

    pub const Split = struct {
        pub fn interpolateAndSplitDepthTwo(
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
                @as(usize, 16),
                coefficients.storage.len /
                    coefficients.column_stride_words,
            );
            Calls.splits += 1;
        }
    };

    pub const Commitment = struct {
        pub fn contiguousLeaves(
            _: anytype,
            _: anytype,
            size: u32,
            columns: anytype,
            leaves: anytype,
        ) RuntimeError!void {
            if (columns.column_stride_words != size or
                leaves.len != size)
            {
                return error.InvalidKernelDescriptor;
            }
            Calls.leaf_hashes += 1;
        }

        pub fn contiguousTail(
            _: anytype,
            _: anytype,
            previous: anytype,
            outputs: anytype,
            levels: u32,
        ) RuntimeError!void {
            if (levels == 0 or outputs.len >= previous.len)
                return error.InvalidKernelDescriptor;
            Calls.tail_hashes += 1;
        }

        pub fn layer(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: bool,
        ) RuntimeError!void {
            return error.InvalidKernelDescriptor;
        }
    };
};

const FakeContext = struct {
    pub fn copyDeviceSlice(
        _: *FakeContext,
        comptime F: type,
        destination: anytype,
        source: anytype,
    ) RuntimeError!void {
        if (F != u32 or destination.len != source.len)
            return error.InvalidKernelDescriptor;
        Calls.capture_copies += 1;
    }
};

const FakeTransaction = struct {
    allocator: std.mem.Allocator,
    rows: usize,
    session: struct { context: FakeContext = .{} } = .{},

    pub fn proofSession(self: *FakeTransaction) *@TypeOf(self.session) {
        return &self.session;
    }

    pub fn zeroResidentSlice(
        _: *FakeTransaction,
        comptime F: type,
        stage: anytype,
        id: exact.slots.SlotId,
        first: usize,
        count: usize,
    ) !void {
        if (F != u32 or
            stage != stwo.backends.cuda.runtime.telemetry.Stage
                .constraint_evaluation or
            id != exact.slots.composition_coordinates or
            first != 0 or count == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        Calls.zeroes += 1;
    }
};
