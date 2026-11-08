const std = @import("std");
const core = @import("stwo_core");
const component_prover = @import("component_prover.zig");
const device_composition = @import("device_composition.zig");
const composition_execution = @import("composition_execution.zig");
const secure_column = @import("../secure_column.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;

const QM31 = core.fields.qm31.QM31;
const TreeVec = core.pcs.TreeVec;
const ComponentProvers = component_prover.ComponentProvers;
const Poly = component_prover.Poly;
const SecureColumn = secure_column.SecureColumnByCoords;
const Trace = component_prover.Trace;

test "OM31 CpuBackend whole-stage callback runs before unsupported wide CPU scheduling" {
    const O = core.fields.om31.OM31;
    const C = component_prover.ForField(O);
    const Column = secure_column.SecureColumnByCoordsFor(O);
    const Callback = struct {
        fn evaluate(ctx: *anyopaque, allocator: std.mem.Allocator, alpha: O, _: u32, _: usize, _: *const anyopaque, result: *anyopaque) anyerror!bool {
            const count: *usize = @ptrCast(@alignCast(ctx));
            count.* += 1;
            const output: *Column = @ptrCast(@alignCast(result));
            output.* = try Column.zeros(allocator, 1);
            for (output.columns, alpha.toM31Array()) |column, value| column[0] = value;
            return true;
        }
    };
    var calls: usize = 0;
    const provers = C.ComponentProvers{ .components = &.{}, .n_preprocessed_columns = 0, .composition_stage = .{ .context = &calls, .evaluate = Callback.evaluate }, .cpu_composition_execution = .{ .worker_count = 0, .host_byte_budget = 0 } };
    var trace = C.Trace{ .polys = TreeVec([]const C.Poly).initOwned(try std.testing.allocator.alloc([]const C.Poly, 0)) };
    defer trace.polys.deinit(std.testing.allocator);
    const Backend = struct {};
    const alpha = O.fromBase(core.fields.m31.M31.fromCanonical(17));
    var output = try provers.computeCompositionEvaluationForBackend(Backend, std.testing.allocator, alpha, &trace, &.{}, null);
    defer output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expect(output.at(0).eql(alpha));
}

fn emptyTrace(allocator: std.mem.Allocator) !Trace {
    return .{
        .polys = TreeVec([]const Poly).initOwned(try allocator.alloc([]const Poly, 0)),
    };
}

test "CPU execution resolution happens only after the device stage declines" {
    const Backend = struct {
        var calls: usize = 0;

        pub fn computeCompositionEvaluationWithExecution(
            _: std.mem.Allocator,
            _: anytype,
            _: QM31,
            _: anytype,
            _: anytype,
            _: anytype,
            _: composition_execution.Execution,
        ) !?SecureColumn {
            calls += 1;
            return null;
        }
    };
    const Device = struct {
        fn evaluate(
            _: *anyopaque,
            allocator: std.mem.Allocator,
            _: QM31,
            _: u32,
            _: usize,
            _: *const anyopaque,
            result: *anyopaque,
        ) anyerror!bool {
            const output: *SecureColumn = @ptrCast(@alignCast(result));
            output.* = try SecureColumn.uninitialized(allocator, 1);
            return true;
        }
    };

    var context: u8 = 0;
    const provers = ComponentProvers{
        .components = &.{},
        .n_preprocessed_columns = 0,
        .composition_stage = device_composition.Stage{
            .context = &context,
            .evaluate = Device.evaluate,
        },
        // Invalid on purpose: reaching CPU resolution would fail this test.
        .cpu_composition_execution = .{
            .worker_count = 0,
            .host_byte_budget = 0,
        },
    };
    var trace = try emptyTrace(std.testing.allocator);
    defer trace.polys.deinit(std.testing.allocator);
    var output = try provers.computeCompositionEvaluationForBackend(
        Backend,
        std.testing.allocator,
        QM31.zero(),
        &trace,
        &.{},
        null,
    );
    defer output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), Backend.calls);
}

test "execution-aware backend receives the exact public request" {
    const Backend = struct {
        var workers: usize = 0;
        var bytes: usize = 0;
        var strict: bool = false;
        var received_recorder: bool = false;

        pub fn computeCompositionEvaluationWithExecution(
            allocator: std.mem.Allocator,
            _: anytype,
            _: QM31,
            _: anytype,
            _: anytype,
            _: anytype,
            execution: composition_execution.Execution,
        ) !?SecureColumn {
            workers = execution.worker_budget.count;
            bytes = execution.host_byte_budget;
            strict = execution.isStrict();
            received_recorder = execution.task_recorder != null;
            return try SecureColumn.uninitialized(allocator, 1);
        }
    };

    var recorder = stage_profile.Recorder.init(std.testing.allocator, "Debug", "dispatch");
    defer recorder.deinit();
    const provers = ComponentProvers{
        .components = &.{},
        .n_preprocessed_columns = 0,
        .cpu_composition_execution = .{
            .worker_count = 4,
            .host_byte_budget = 12345,
            .contention_policy = .strict,
        },
        .task_recorder = &recorder,
    };
    var trace = try emptyTrace(std.testing.allocator);
    defer trace.polys.deinit(std.testing.allocator);
    var output = try provers.computeCompositionEvaluationForBackend(
        Backend,
        std.testing.allocator,
        QM31.zero(),
        &trace,
        &.{},
        null,
    );
    defer output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), Backend.workers);
    try std.testing.expectEqual(@as(usize, 12345), Backend.bytes);
    try std.testing.expect(Backend.strict);
    try std.testing.expect(Backend.received_recorder);
    var tasks = try recorder.taskSnapshot(std.testing.allocator);
    defer tasks.deinit(std.testing.allocator);
    // A backend that returns directly did not execute a bounded graph. Passing
    // the recorder must not invent an event for it.
    try std.testing.expectEqual(@as(usize, 0), tasks.graphs.len);
}

test "legacy backend composition hook remains source compatible" {
    const Backend = struct {
        var calls: usize = 0;

        pub fn computeCompositionEvaluation(
            allocator: std.mem.Allocator,
            _: anytype,
            _: QM31,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !?SecureColumn {
            calls += 1;
            return try SecureColumn.uninitialized(allocator, 1);
        }
    };

    const provers = ComponentProvers{
        .components = &.{},
        .n_preprocessed_columns = 0,
        // A device backend that succeeds must not resolve this CPU-only value.
        .cpu_composition_execution = .{
            .worker_count = 0,
            .host_byte_budget = 0,
        },
    };
    var trace = try emptyTrace(std.testing.allocator);
    defer trace.polys.deinit(std.testing.allocator);
    var output = try provers.computeCompositionEvaluationForBackend(
        Backend,
        std.testing.allocator,
        QM31.zero(),
        &trace,
        &.{},
        null,
    );
    defer output.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), Backend.calls);
}
