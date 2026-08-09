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
