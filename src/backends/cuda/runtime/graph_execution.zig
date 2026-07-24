//! Fail-closed CUDA graph lifecycle over one proof session stream.

const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub fn begin(comptime Api: type, context: anytype) runtime_error.Error!void {
    _ = context.active_stage orelse return error.StageNotActive;
    if (context.capture_active) return error.InvalidState;
    const handle = context.handle orelse return error.ContextClosed;
    try runtime_error.check(Api.stwo_graph_capture_begin(handle));
    context.capture_active = true;
}

pub fn finish(
    comptime Api: type,
    context: anytype,
    expected_kernel_nodes: u64,
) runtime_error.Error!*anyopaque {
    if (!context.capture_active) return error.InvalidState;
    const handle = context.handle orelse return error.ContextClosed;
    var raw_exec: ?*anyopaque = null;
    var kernel_nodes: u64 = 0;
    runtime_error.check(Api.stwo_graph_capture_end(
        handle,
        &raw_exec,
        &kernel_nodes,
    )) catch |err| {
        context.capture_active = false;
        return err;
    };
    context.capture_active = false;
    const exec = raw_exec orelse return error.InvalidState;
    if (kernel_nodes != expected_kernel_nodes or kernel_nodes == 0) {
        _ = Api.stwo_graph_destroy(exec);
        return error.InvalidState;
    }
    return exec;
}

pub fn abort(comptime Api: type, context: anytype) runtime_error.Error!void {
    if (!context.capture_active) return error.InvalidState;
    defer context.capture_active = false;
    const handle = context.handle orelse return error.ContextClosed;
    try runtime_error.check(Api.stwo_graph_capture_abort(handle));
}

pub fn launchReplay(
    comptime Api: type,
    context: anytype,
    graph: *anyopaque,
    replayed: telemetry.StageCounters,
) runtime_error.Error!void {
    const stage = context.active_stage orelse return error.StageNotActive;
    try launch(Api, context, graph);
    context.counters.replay(stage, replayed);
    context.counters.graphs(stage, 1);
    context.counters.graphCache(stage, true);
}

pub fn launchCaptured(
    comptime Api: type,
    context: anytype,
    graph: *anyopaque,
) runtime_error.Error!void {
    const stage = context.active_stage orelse return error.StageNotActive;
    try launch(Api, context, graph);
    context.counters.graphs(stage, 1);
    context.counters.graphCache(stage, false);
}

pub fn destroy(
    comptime Api: type,
    context: anytype,
    graph: *anyopaque,
) runtime_error.Error!void {
    if (context.active_stage != null or context.capture_active or
        !context.synchronized)
    {
        return error.InvalidState;
    }
    try runtime_error.check(Api.stwo_graph_destroy(graph));
}

fn launch(
    comptime Api: type,
    context: anytype,
    graph: *anyopaque,
) runtime_error.Error!void {
    if (context.capture_active) return error.InvalidState;
    const handle = context.handle orelse return error.ContextClosed;
    try runtime_error.check(Api.stwo_graph_launch(graph, handle));
    context.synchronized = false;
}
