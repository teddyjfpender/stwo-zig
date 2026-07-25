const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const composition = @import(
    "../../../frontends/cairo/witness/composition_bundle.zig",
);
const fixed_table = @import(
    "../../../frontends/cairo/witness/fixed_table_bundle.zig",
);
const semantic_authority = @import(
    "../../../frontends/cairo/proof_plan/semantic_authority.zig",
);
const resident_plan = @import("resident_plan.zig");
const resident_test = @import("resident_plan_test_support.zig");
const resident_fixture = @import("resident_plan_test.zig");
const trace_schedule = @import("trace_schedule.zig");
const subject = @import("trace_commit.zig");

test "SN2 trace commitment compiles all 58 writer spans into compact mixed cohorts" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var fixed = try fixed_table.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    const preprocessed_logs = try semantic_authority.preprocessedLogs(
        allocator,
        fixed,
    );
    defer allocator.free(preprocessed_logs);
    const protocol = try resident_fixture.sn2Protocol(
        bundle,
        preprocessed_logs.len,
    );
    var program = try resident_fixture.sn2Program(
        allocator,
        bundle,
        protocol,
        preprocessed_logs,
    );
    defer program.deinit(allocator);
    var plan = try resident_plan.Plan.init(
        allocator,
        program,
        protocol,
        bundle,
        try resident_test.geometry(program, bundle),
    );
    defer plan.deinit(allocator);

    const entries = try allocator.alloc(
        trace_schedule.Entry,
        trace_schedule.expected_entry_count,
    );
    defer allocator.free(entries);
    const launch_order = try allocator.alloc(
        u32,
        trace_schedule.expected_launch_count,
    );
    defer allocator.free(launch_order);
    for (entries, 0..) |*entry, index| {
        entry.* = .{
            .component_index = @intCast(index),
            .canonical_ordinal = @intCast(index),
            .name = "authenticated-sn2-component",
            .instance = 0,
            .writer = .recorded_aot,
            .prepare_api = .recorded_witness_prepare,
            .execution = .standalone,
            .launch_owner = @intCast(index),
            .buffers = .{
                .trace_outputs = @intCast(index),
                .lookup_outputs = @intCast(index),
                .subword_outputs = @intCast(index),
                .multiplicity_outputs = @intCast(index),
                .native_partial_workspace = null,
                .native_partial_inputs = null,
            },
            .catalog_identity = [_]u8{1} ** 32,
            .dependencies = &.{},
        };
        if (index < launch_order.len) launch_order[index] = @intCast(index);
    }
    const schedule = trace_schedule.Schedule{
        .allocator = allocator,
        .entries = entries,
        .dependency_storage = &.{},
        .launch_order = launch_order,
        .writer_counts = [_]u32{0} **
            std.meta.fields(@TypeOf(entries[0].writer)).len,
        .identity = [_]u8{7} ** 32,
    };
    var prepared = try subject.Prepared.initMain(
        allocator,
        program,
        plan,
        schedule,
    );
    defer prepared.deinit();
    try prepared.validateMainAuthority(
        program,
        plan,
        schedule,
    );

    try std.testing.expectEqual(@as(usize, 58), prepared.writer_spans.len);
    try std.testing.expect(prepared.cohorts.len > 1);
    try std.testing.expect(prepared.tree_size > 0);
    try std.testing.expect(!std.mem.allEqual(u8, &prepared.identity, 0));
    var covered_columns: usize = 0;
    for (prepared.writer_spans) |span| {
        try std.testing.expect(span.column_count > 0);
        covered_columns += span.column_count;
    }
    try std.testing.expectEqual(
        @as(usize, protocol.trace_columns[1]),
        covered_columns,
    );

    inline for (.{ .preprocessed, .interaction, .composition }) |role| {
        var produced = try subject.Prepared.initProduced(
            allocator,
            program,
            plan,
            role,
        );
        defer produced.deinit();
        try produced.validateProducedAuthority(
            program,
            plan,
            role,
        );
        try std.testing.expectEqual(@as(usize, 0), produced.writer_spans.len);
        try std.testing.expect(produced.cohorts.len > 0);
        try std.testing.expect(!std.mem.allEqual(
            u8,
            &produced.identity,
            0,
        ));
        try std.testing.expectEqual(
            if (role == .interaction)
                subject.InputForm.evaluations
            else
                subject.InputForm.coefficients,
            produced.input_form,
        );
        try std.testing.expectEqual(
            if (role == .composition)
                telemetry.Stage.constraint_evaluation
            else
                telemetry.Stage.trace_commit,
            produced.stage,
        );
    }
    prepared.slots.root +%= 1;
    try std.testing.expectError(
        error.InvalidTraceCommitAuthority,
        prepared.validateMainAuthority(
            program,
            plan,
            schedule,
        ),
    );
}

test "mixed trace commitment transforms packed cohorts and copies only on device" {
    const cohorts = [_]subject.Cohort{
        .{
            .first_column = 0,
            .column_count = 1,
            .trace_log_rows = 2,
            .evaluation_log_rows = 3,
            .coefficient_offset_words = 0,
            .coefficient_words = 4,
            .evaluation_offset_words = 0,
            .evaluation_words = 8,
        },
        .{
            .first_column = 1,
            .column_count = 1,
            .trace_log_rows = 3,
            .evaluation_log_rows = 4,
            .coefficient_offset_words = 4,
            .coefficient_words = 8,
            .evaluation_offset_words = 8,
            .evaluation_words = 16,
        },
    };
    const writers = [_]subject.WriterSpan{
        .{
            .schedule_ordinal = 0,
            .component_index = 0,
            .first_column = 0,
            .column_count = 1,
            .trace_log_rows = 2,
            .coefficient_offset_words = 0,
            .coefficient_words = 4,
        },
        .{
            .schedule_ordinal = 1,
            .component_index = 1,
            .first_column = 1,
            .column_count = 1,
            .trace_log_rows = 3,
            .coefficient_offset_words = 4,
            .coefficient_words = 8,
        },
    };
    const logs = [_]u32{ 2, 3 };
    const offsets = [_]u32{ 0, 4, 12 };
    const layers = [_]field.MerkleLayerDescriptor{
        .{ .offset_hashes = 0, .hash_count = 16 },
        .{ .offset_hashes = 16, .hash_count = 8 },
        .{ .offset_hashes = 24, .hash_count = 4 },
        .{ .offset_hashes = 28, .hash_count = 2 },
        .{ .offset_hashes = 30, .hash_count = 1 },
    };
    const prepared = subject.Prepared{
        .allocator = std.testing.allocator,
        .tree_ordinal = 1,
        .tree_size = 16,
        .input_form = .evaluations,
        .stage = .trace_commit,
        .cohorts = @constCast(&cohorts),
        .writer_spans = @constCast(&writers),
        .column_logs = @constCast(&logs),
        .column_offsets = @constCast(&offsets),
        .layers = @constCast(&layers),
        .slots = .{
            .coefficients = 1,
            .evaluations = 2,
            .column_logs = 3,
            .column_offsets = 4,
            .merkle_hashes = 5,
            .merkle_layers = 6,
            .progressive_states = 7,
            .root = 8,
            .twiddles_forward = 9,
            .twiddles_inverse = 10,
        },
        .identity = [_]u8{9} ** 32,
    };
    const Provider = struct {
        pub fn slot(_: @This(), id: u32) !common.Words {
            return switch (id) {
                1 => words(0x1000, 12),
                2 => words(0x2000, 24),
                3 => words(0x3000, 2),
                4 => words(0x4000, 3),
                5 => words(0x5000, 31 * 8),
                6 => words(0x6000, 5 * 4),
                7 => words(0x7000, 16 * 24),
                8 => words(0x8000, 8),
                9 => words(0x9000, 32),
                10 => words(0xa000, 32),
                else => error.ArenaSlotMissing,
            };
        }
    };
    var bound = try subject.Bound.init(
        std.testing.allocator,
        &prepared,
        Provider{},
    );
    defer bound.deinit();

    const first_writer = try bound.writerOutput(0);
    const second_writer = try bound.writerOutput(1);
    try std.testing.expectEqual(@as(usize, 4), first_writer.storage.len);
    try std.testing.expectEqual(@as(usize, 8), second_writer.storage.len);
    try std.testing.expectEqual(@as(usize, 0x1010), second_writer.storage.address);
    try std.testing.expectError(error.UnknownTraceWriter, bound.writerOutput(2));

    var session = FakeSession{};
    FakeTransform.reset();
    FakeCommitment.reset();
    try bound.executeWith(
        struct {
            pub const Transform = FakeTransform;
            pub const Commitment = FakeCommitment;
        },
        &session,
    );
    try std.testing.expectEqual(@as(usize, 2), FakeTransform.inverse_calls);
    try std.testing.expectEqual(@as(usize, 2), FakeTransform.extend_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeCommitment.init_calls);
    try std.testing.expectEqual(@as(usize, 2), FakeCommitment.absorb_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeCommitment.finalize_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeCommitment.tail_calls);
    try std.testing.expectEqual(@as(usize, 1), session.context.copy_count);
    try std.testing.expectEqual(@as(usize, 0x8000), session.context.destination);
    try std.testing.expectEqual(@as(usize, 0x53c0), session.context.source);
}

fn words(address: usize, len: usize) common.Words {
    return .{ .address = address, .len = len, .owner = 1, .generation = 1 };
}

const FakeSession = struct {
    context: struct {
        copy_count: usize = 0,
        destination: usize = 0,
        source: usize = 0,

        pub fn copyDeviceSlice(
            self: *@This(),
            comptime F: type,
            destination: anytype,
            source: anytype,
        ) !void {
            try std.testing.expectEqual(u32, F);
            try std.testing.expectEqual(destination.len, source.len);
            self.copy_count += 1;
            self.destination = destination.address;
            self.source = source.address;
        }
    } = .{},
};

const FakeTransform = struct {
    var inverse_calls: usize = 0;
    var extend_calls: usize = 0;

    fn reset() void {
        inverse_calls = 0;
        extend_calls = 0;
    }

    pub fn inverseCompact(
        _: anytype,
        stage: telemetry.Stage,
        input: common.WordMatrix,
        output: common.WordMatrix,
        log_rows: u32,
        _: common.Words,
    ) !void {
        try std.testing.expectEqual(telemetry.Stage.trace_commit, stage);
        try std.testing.expectEqual(input.storage.address, output.storage.address);
        try std.testing.expectEqual(
            @as(usize, 1) << @intCast(log_rows),
            input.column_stride_words,
        );
        inverse_calls += 1;
    }

    pub fn extend(
        _: anytype,
        stage: telemetry.Stage,
        coefficients: common.WordMatrix,
        logs: common.Words,
        evaluations: common.WordMatrix,
        log_rows: u32,
        _: common.Words,
        before_circle: bool,
    ) !void {
        try std.testing.expectEqual(telemetry.Stage.trace_commit, stage);
        try std.testing.expect(!before_circle);
        try std.testing.expectEqual(@as(usize, 1), logs.len);
        try std.testing.expectEqual(
            @as(usize, 1) << @intCast(log_rows),
            evaluations.column_stride_words,
        );
        try std.testing.expectEqual(
            coefficients.storage.len * 2,
            evaluations.storage.len,
        );
        extend_calls += 1;
    }
};

const FakeCommitment = struct {
    var init_calls: usize = 0;
    var absorb_calls: usize = 0;
    var finalize_calls: usize = 0;
    var tail_calls: usize = 0;

    fn reset() void {
        init_calls = 0;
        absorb_calls = 0;
        finalize_calls = 0;
        tail_calls = 0;
    }

    pub fn progressiveInit(
        _: anytype,
        stage: telemetry.Stage,
        states: common.ProgressiveStates,
    ) runtime_error.Error!void {
        if (stage != .trace_commit or states.len != 16)
            return error.InvalidKernelDescriptor;
        init_calls += 1;
    }

    pub fn progressiveAbsorbLifted(
        _: anytype,
        _: telemetry.Stage,
        size: u32,
        source_size: u32,
        absorbed: u32,
        columns: common.WordMatrix,
        _: common.ProgressiveStates,
    ) runtime_error.Error!void {
        if (size != 16 or
            !((source_size == 8 and absorbed == 0 and
                columns.storage.len == 8) or
                (source_size == 16 and absorbed == 1 and
                    columns.storage.len == 16)))
        {
            return error.InvalidKernelDescriptor;
        }
        absorb_calls += 1;
    }

    pub fn progressiveFinalize(
        _: anytype,
        _: telemetry.Stage,
        absorbed: u32,
        _: common.ProgressiveStates,
        leaves: common.Hashes,
    ) runtime_error.Error!void {
        if (absorbed != 2 or leaves.len != 16)
            return error.InvalidKernelDescriptor;
        finalize_calls += 1;
    }

    pub fn contiguousTail(
        _: anytype,
        _: telemetry.Stage,
        previous: common.Hashes,
        outputs: common.Hashes,
        levels: u32,
    ) runtime_error.Error!void {
        if (previous.len != 16 or outputs.len != 15 or levels != 4)
            return error.InvalidKernelDescriptor;
        tail_calls += 1;
    }

    pub fn layer(
        _: anytype,
        _: telemetry.Stage,
        previous: common.Hashes,
        output: common.Hashes,
        four_levels: bool,
    ) runtime_error.Error!void {
        if (four_levels or previous.len != output.len * 2)
            return error.InvalidKernelDescriptor;
        return error.InvalidKernelDescriptor;
    }
};
