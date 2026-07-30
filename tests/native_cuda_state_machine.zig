const std = @import("std");
const exact = @import("stwo_under_test")
    .integrations
    .native_cuda
    .state_machine;
const RuntimeError = @import("stwo_under_test")
    .backends.cuda.runtime.runtime_error.Error;
const terminal_tests = @import("native_cuda_state_machine_terminal.zig");
test {
    std.testing.refAllDecls(exact);
    _ = terminal_tests;
}

fn stateRequest(
    log_n_rows: u32,
) @FieldType(exact.geometry.Request, "statement") {
    const M31 = @import("stwo_under_test").core.fields.m31.M31;
    return .{
        .log_n_rows = log_n_rows,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    };
}

test "exact CUDA State Machine v2 resident binding is a four-tree relation graph" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        stateRequest(8),
        @import("stwo_under_test").core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    const bound = try exact.resident_bindings.bind(&provider, &prepared);
    try std.testing.expectEqual(
        @as(usize, 31),
        prepared.proof_program.transcript.len,
    );
    try std.testing.expectEqual(
        @as(u32, 10),
        prepared.proof_program.native_air_contract.?
            .statement.public_input_words,
    );

    try std.testing.expectEqual(
        @as(usize, 3),
        bound.base.trees.active().len,
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        (try bound.base.trees.require(.interaction)).column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(usize, 12),
        bound.constraint_buffers.source_evaluations.storage.len /
            bound.constraint_buffers.source_evaluations.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, exact.geometry.relation_source_columns),
        bound.relation.source_values.storage.len /
            bound.relation.source_values.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, 1 << 8),
        bound.relation.source_values.column_stride_words,
    );
    try std.testing.expect(
        bound.relation.source_values.storage.address !=
            (try bound.base.trees.require(.main))
                .coefficients.storage.address,
    );
    try std.testing.expectEqual(
        exact.geometry.terminal_statement_words,
        bound.base.proof.statement.len,
    );
    try std.testing.expectEqual(
        bound.base.proof.terminal.len,
        bound.base.proof.statement.len + bound.base.proof.bundle.len,
    );
    try std.testing.expectEqual(
        bound.base.proof.terminal.address +
            exact.geometry.terminal_statement_words * @sizeOf(u32),
        bound.base.proof.bundle.address,
    );
    const relation_plan = try exact.relation.Plan.init(
        geometry.statement.log_n_rows,
    );
    const relation_instances = bound.relation.bindings();
    const runtime_relation = @import("stwo_under_test")
        .backends.cuda.runtime.stages.relation;
    const prepared_relation = try runtime_relation.prepare(
        allocator,
        .{
            .topology = relation_plan.topology(),
            .buffers = bound.relation.buffers,
            .instances = &relation_instances,
        },
    );
    runtime_relation.deinit(allocator, prepared_relation);
}

test "exact interaction and composition execute in transcript order" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        stateRequest(8),
        @import("stwo_under_test").core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    var bound = try exact.resident_bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{ .allocator = allocator };
    Calls.reset();

    try exact.executor.composition.runWith(
        FakeOps,
        &transaction,
        &prepared,
        &bound,
    );

    try std.testing.expectEqualSlices(
        u32,
        &.{ 4, 5, 6, 7, 8 },
        Calls.transcript_steps[0..Calls.transcript_count],
    );
    try std.testing.expectEqual(@as(usize, 1), Calls.relations);
    try std.testing.expectEqual(@as(usize, 2), Calls.inverse_transforms);
    try std.testing.expectEqual(@as(usize, 2), Calls.extensions);
    try std.testing.expectEqual(@as(usize, 1), Calls.power_expansions);
    try std.testing.expectEqual(@as(usize, 1), Calls.constraints);
    try std.testing.expectEqual(@as(usize, 1), Calls.splits);
    try std.testing.expectEqual(@as(usize, 2), Calls.leaf_hashes);
    try std.testing.expectEqual(@as(usize, 2), Calls.tail_hashes);
    try std.testing.expectEqual(@as(usize, 3), Calls.device_copies);
    try std.testing.expectEqual(@as(usize, 1), Calls.zeroes);
}

test "exact trace prefix commits empty root then mixed-height main" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        stateRequest(8),
        @import("stwo_under_test").core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    var bound = try exact.resident_bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{ .allocator = allocator };
    Calls.reset();

    try exact.executor.trace_commit.commitWith(
        TraceOps,
        &transaction,
        &prepared,
        &bound,
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0, 1, 2, 3 },
        Calls.transcript_steps[0..Calls.transcript_count],
    );
    try std.testing.expectEqual(@as(usize, 2), Calls.inverse_transforms);
    try std.testing.expectEqual(@as(usize, 1), Calls.extensions);
    try std.testing.expectEqual(@as(usize, 1), Calls.leaf_hashes);
    try std.testing.expectEqual(@as(usize, 1), Calls.tail_hashes);
    try std.testing.expectEqual(@as(usize, 2), Calls.device_copies);

    try std.testing.expectError(
        error.StateMachineV2AotUnavailable,
        exact.executor.trace_commit.generate(
            &transaction,
            &prepared,
            &bound,
        ),
    );
}

test "exact ingress uploads the sealed relation graph" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        stateRequest(8),
        @import("stwo_under_test").core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    var pack = try exact.canonical_ingress.Pack.init(
        allocator,
        geometry,
    );
    defer pack.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    var bound = try exact.resident_bindings.bind(&provider, &prepared);
    var transaction = IngressTransaction{ .prepared = &prepared };

    try exact.executor.ingress.run(
        &transaction,
        &prepared,
        &pack,
        &bound,
    );

    inline for (.{
        exact.slots.relation_source_pointer_table,
        exact.slots.relation_descriptors,
        exact.slots.relation_output_pointer_table,
        exact.slots.relation_geometry,
        exact.slots.relation_source_tables,
        exact.slots.relation_descriptor_tables,
        exact.slots.relation_output_tables,
        exact.slots.relation_denominator_tables,
        exact.slots.relation_claimed_sum_tables,
        exact.slots.constraint_denominator_inverses,
        exact.slots.empty_preprocessed_root,
        exact.slots.transcript_statement_words,
    }) |id| {
        try std.testing.expect(transaction.wasUploaded(id));
    }
}

const Provider = struct {
    prepared: *const exact.plan.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: exact.slots.SlotId,
    ) !@import("stwo_under_test")
        .backends.cuda.runtime.column.DeviceSlice(u32) {
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
    var transcript_steps: [5]u32 = undefined;
    var transcript_count: usize = 0;
    var relations: usize = 0;
    var inverse_transforms: usize = 0;
    var extensions: usize = 0;
    var power_expansions: usize = 0;
    var constraints: usize = 0;
    var splits: usize = 0;
    var leaf_hashes: usize = 0;
    var tail_hashes: usize = 0;
    var device_copies: usize = 0;
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
        device_copies = 0;
        zeroes = 0;
    }

    fn transcript(step: u32) !void {
        if (transcript_count == transcript_steps.len)
            return error.InvalidKernelDescriptor;
        transcript_steps[transcript_count] = step;
        transcript_count += 1;
    }
};

const TraceOps = struct {
    pub const Transform = FakeOps.Transform;
    pub const Commitment = FakeOps.Commitment;
    pub const Transcript = struct {
        pub fn initialize(
            _: anytype,
            stage: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: u64,
        ) !void {
            try std.testing.expectEqual(
                @import("stwo_under_test").backends.cuda.runtime
                    .telemetry.Stage.trace_commit,
                stage,
            );
        }

        pub fn mixWords(
            _: anytype,
            stage: anytype,
            _: anytype,
            boundary: anytype,
            source: anytype,
            _: bool,
            snapshot: anytype,
        ) !void {
            try std.testing.expectEqual(
                @import("stwo_under_test").backends.cuda.runtime
                    .telemetry.Stage.trace_commit,
                stage,
            );
            try std.testing.expectEqual(source.len, snapshot.len);
            try Calls.transcript(boundary.expected_step);
        }

        pub fn mixWordsPair(
            _: anytype,
            stage: anytype,
            _: anytype,
            boundary: anytype,
            first: anytype,
            second: anytype,
            _: bool,
            snapshot: anytype,
        ) !void {
            try std.testing.expectEqual(
                @import("stwo_under_test").backends.cuda.runtime
                    .telemetry.Stage.trace_commit,
                stage,
            );
            try std.testing.expectEqual(@as(usize, 2), first.len);
            try std.testing.expectEqual(@as(usize, 2), second.len);
            try std.testing.expectEqual(
                first.len + second.len,
                snapshot.len,
            );
            try Calls.transcript(boundary.expected_step);
        }
    };
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
                @import("stwo_under_test").backends.cuda.runtime
                    .telemetry.Stage.constraint_evaluation,
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
            try std.testing.expectEqual(@as(u32, 64), rejection_rounds);
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
                @import("stwo_under_test").backends.cuda.runtime
                    .telemetry.Stage.constraint_evaluation,
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
            const compact_words =
                @as(usize, 1) << @intCast(log_rows);
            try std.testing.expect(
                outputs.column_stride_words >= compact_words,
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
            try std.testing.expectEqual(@as(usize, 2), powers.len);
            Calls.power_expansions += 1;
        }
    };

    pub const Constraint = struct {
        pub fn evaluate(
            _: anytype,
            buffers: anytype,
            geometry: anytype,
        ) !void {
            try std.testing.expectEqual(
                @as(usize, 12),
                buffers.source_evaluations.storage.len /
                    buffers.source_evaluations.column_stride_words,
            );
            try std.testing.expectEqual(
                @as(usize, 2),
                buffers.random_coefficient_powers.len,
            );
            try std.testing.expectEqual(
                @as(usize, 2),
                buffers.claimed_sums.len,
            );
            try std.testing.expectEqual(
                @as(u32, 12),
                geometry.traceColumnCount(),
            );
            Calls.constraints += 1;
        }
    };

    pub const Split = struct {
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
        Calls.device_copies += 1;
    }
};

const FakeTransaction = struct {
    allocator: std.mem.Allocator,
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
        try std.testing.expectEqual(u32, F);
        try std.testing.expectEqual(
            @import("stwo_under_test").backends.cuda.runtime
                .telemetry.Stage.constraint_evaluation,
            stage,
        );
        try std.testing.expectEqual(
            exact.slots.composition_coordinates,
            id,
        );
        try std.testing.expectEqual(@as(usize, 0), first);
        try std.testing.expect(count > 0);
        Calls.zeroes += 1;
    }
};

const IngressTransaction = struct {
    prepared: *const exact.plan.PreparedPlan,
    uploaded: [128]exact.slots.SlotId = undefined,
    uploaded_count: usize = 0,

    pub fn upload(
        self: *IngressTransaction,
        comptime F: type,
        id: exact.slots.SlotId,
        values: []const F,
    ) !void {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        const words = values.len * (@sizeOf(F) / @sizeOf(u32));
        if (placement.requirement.words != words)
            return error.InvalidKernelDescriptor;
        try self.record(id);
    }

    pub fn uploadResidentSlice(
        self: *IngressTransaction,
        comptime F: type,
        id: exact.slots.SlotId,
        first: usize,
        values: []const F,
    ) !void {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        const words = values.len * (@sizeOf(F) / @sizeOf(u32));
        if (first + words > placement.requirement.words or
            (id == exact.slots.proof_bundle and
                first != exact.geometry.terminal_statement_words) or
            (id != exact.slots.proof_bundle and first != 0))
        {
            return error.InvalidKernelDescriptor;
        }
        try self.record(id);
    }

    pub fn zeroResidentSlice(
        self: *IngressTransaction,
        comptime F: type,
        stage: anytype,
        id: exact.slots.SlotId,
        first: usize,
        count: usize,
    ) !void {
        if (F != u32 or
            stage != @import("stwo_under_test").backends.cuda.runtime
                .telemetry.Stage.ingress or
            id != exact.slots.proof_bundle or first != 0 or count == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        try self.record(id);
    }

    pub fn wasUploaded(
        self: *const IngressTransaction,
        id: exact.slots.SlotId,
    ) bool {
        for (self.uploaded[0..self.uploaded_count]) |candidate| {
            if (candidate == id) return true;
        }
        return false;
    }

    fn record(
        self: *IngressTransaction,
        id: exact.slots.SlotId,
    ) !void {
        if (self.uploaded_count == self.uploaded.len)
            return error.InvalidKernelDescriptor;
        self.uploaded[self.uploaded_count] = id;
        self.uploaded_count += 1;
    }
};
