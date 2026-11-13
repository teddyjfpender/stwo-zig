//! Private, std-only fixtures for consumer-selected provider laws.
//! Provider namespaces and field types always come from each consumer's imports.
const std = @import("std");

pub fn field(comptime F: type) !void {
    const one = F.one();
    const two = one.add(one);
    try std.testing.expect(two.mul(try two.inv()).eql(one));
    try std.testing.expect(two.sub(one).eql(one));
    try std.testing.expectError(error.DivisionByZero, F.zero().inv());
}

pub fn column(comptime api: type) !void {
    const F = std.meta.Child(@FieldType(api.ColumnEvaluation, "values"));
    const values = [_]F{ F.zero(), F.one(), F.one().add(F.one()), F.one().neg() };
    const input = api.ColumnEvaluation{ .log_size = 2, .values = &values };
    for (0..16) |position| try std.testing.expectEqual(values[((position >> 3) << 1) + (position & 1)], try input.valueAtLiftingPosition(4, position));
    try std.testing.expectError(error.ShapeMismatch, input.valueAtLiftingPosition(4, 16));
    const invalid = api.ColumnEvaluation{ .log_size = 2, .values = values[0..3] };
    try std.testing.expectError(error.InvalidColumnLength, invalid.validate());
}

pub fn diagnostic(comptime api: type) !void {
    var output: ?api.ProveDiagnostic = null;
    api.ProveDiagnostic.recordFirst(&output, .tree1, error.OutOfMemory);
    api.ProveDiagnostic.recordFirst(&output, .finalize, error.ShapeMismatch);
    try std.testing.expectEqual(error.OutOfMemory, output.?.cause);
    try std.testing.expectEqual(api.ProvePhase.tree1, output.?.phase);
}

pub fn logicalWork(comptime api: type) !void {
    const Counters = api.work_profile.Counters;
    const before = Counters{ .field_additions = std.math.maxInt(u64) };
    try std.testing.expectError(error.CounterOverflow, before.add(.{ .field_additions = 1 }));
    try std.testing.expectEqual(std.math.maxInt(u64), before.field_additions);
    const sum = try (Counters{ .fft_butterflies = 2 }).add(.{ .fft_butterflies = 3 });
    try std.testing.expectEqual(@as(u64, 5), sum.fft_butterflies);
    try std.testing.expectError(error.InvalidCounterGroup, (api.work_profile.SourceMask{ .bits = 0xff }).validate());
}

fn stages(comptime api: type, allocator: std.mem.Allocator) !void {
    var recorder = api.stage_profile.Recorder.init(allocator, "cdc", "consumer");
    defer recorder.deinit();
    var scope = try api.stage_profile.StageScope.begin(&recorder, "owned", "consumer");
    scope.end();
    scope.end();
    var snapshot = try recorder.snapshot(allocator);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), snapshot.stages.len);
    try std.testing.expectEqualStrings("owned", snapshot.stages[0].id);
}

pub fn stageOwnership(comptime api: type) !void {
    try stages(api, std.testing.allocator);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            try stages(api, allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Runner.run, .{});
}

pub fn taskOrdering(comptime api: type) !void {
    const Key = api.task_profile.TaskKey;
    const first = Key{ .epoch = 1, .component_registry_index = 9 };
    const second = Key{ .epoch = 2, .component_registry_index = 0 };
    try std.testing.expect(first.lessThan(second));
    try std.testing.expect(!second.lessThan(first));
    try std.testing.expect(first.eql(first));
    try std.testing.expect(!first.eql(second));
    var recorder = api.task_profile.Recorder.init(std.testing.allocator, "cdc", "task-owner");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraphShape(.{ .event_count = 0, .contribution_count = 0, .component_work_count = 0 });
    defer pending.deinit();
    try std.testing.expectError(error.TaskGraphReservationActive, recorder.snapshot(std.testing.allocator));
    try pending.abort();
    try std.testing.expectError(error.TaskGraphReservationStale, pending.abort());
}

pub fn nativeGeometry(comptime backend: type) !void {
    var geometry = backend.proof_program.NativeTraceGeometry{ .component = 0, .log_rows = 5, .preprocessed_columns = 1, .main_columns = 2, .interaction_columns = 3 };
    try std.testing.expectEqual(@as(u64, 192), try geometry.elementCount());
    geometry.log_rows = 63;
    try std.testing.expectError(error.InvalidGeometry, geometry.elementCount());
    geometry.log_rows = 62;
    try std.testing.expectError(error.GeometryOverflow, geometry.elementCount());
}

pub fn arena(comptime backend: type) !void {
    const A = backend.arena_plan;
    const buffers = [_]A.LogicalBuffer{.{ .id = 7, .size_bytes = 64, .alignment = 16, .live_ranges = &.{.{ .first = 0, .last = 1 }} }};
    var plan = try A.build(std.testing.allocator, &buffers, 16 * 1024);
    defer plan.deinit();
    try std.testing.expectEqual(@as(u64, 64), (try plan.binding(7)).size_bytes);
    try std.testing.expectError(error.UnknownBinding, plan.binding(8));
    try std.testing.expectError(error.BudgetExceeded, A.build(std.testing.allocator, &buffers, 16 * 1024 - 1));
    try std.testing.expectError(error.EmptySchedule, A.build(std.testing.allocator, &.{}, 64));
}

pub fn line(comptime backend: type, comptime core: type) !void {
    const domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(2));
    const values = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.one()} ** 3;
    try std.testing.expectError(error.InvalidLength, backend.line_evaluation.LineEvaluation.initBorrowed(domain, &values));
}

pub fn framing(comptime W: type) !void {
    var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinary(allocator.allocator(), ""));
    try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytesBinary(allocator.allocator(), "NOTSTWO!"));
    try std.testing.expectEqual(@as(usize, 0), allocator.allocations);
    try std.testing.expectEqual(@as(usize, 0), allocator.allocated_bytes);
}

pub fn recursionDecode(comptime wire: type) !void {
    const codec = wire.circuit_serialize;
    const config: codec.ProofConfig = .{
        .n_preprocessed_columns = 1,
        .component_shapes = &.{.{ .trace_columns = 1, .interaction_columns = 4 }},
        .log_trace_size = 3,
        .fri = .{ .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 1, .n_queries = 1, .fold_step = 2 },
    };
    try std.testing.expectError(error.NotEnoughData, codec.deserializeProof(std.testing.allocator, "", config));
    var invalid = config;
    invalid.fri.fold_step = 0;
    try std.testing.expectError(error.InvalidProofShape, codec.deserializeProof(std.testing.allocator, "", invalid));
}

pub fn postcardDecode(comptime postcard: type, comptime wire: type) !void {
    var input = std.io.fixedBufferStream(@as([]const u8, ""));
    var counted = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const Result = @typeInfo(@TypeOf(postcard.deserializeProof(wire.Hasher, counted.allocator(), input.reader()))).error_union.payload;
    try std.testing.expect(Result == wire.Proof);
    try std.testing.expectError(error.EndOfStream, postcard.deserializeProof(wire.Hasher, counted.allocator(), input.reader()));
    try std.testing.expectEqual(@as(usize, 0), counted.allocations);
}
