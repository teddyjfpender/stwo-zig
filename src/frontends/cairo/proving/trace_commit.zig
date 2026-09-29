//! Ownership transfer for a trace already written into its commitment arena.
const std = @import("std");
const prover = @import("stwo_prover_engine");
const trace_arena = @import("trace_arena.zig");

pub const Marker = struct { id: []const u8, label: []const u8 };

/// Admission and all local fallible work precede taking the trace's columns.
/// The engine owns every transferred buffer on both success and failure.
pub fn commit(
    comptime Engine: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    trace: anytype,
    arena: *?trace_arena.Arena,
    recorder: ?*prover.stage_profile.Recorder,
    channel: anytype,
    marker: Marker,
) !void {
    if (arena.*) |*ready| {
        if (!trace_arena.columnsMatchPlan(ready, trace.columns))
            return error.ArenaPlanMismatch;
        var bound = try prover.stage_profile.StageScope.begin(recorder, marker.id, marker.label);
        bound.end();
        const backing = try ready.backing(allocator);
        const columns = trace.takeColumns();
        ready.layout.deinit();
        arena.* = null;
        trace.arena_backed = false;
        try Engine.commitWithBacking(scheme, allocator, columns, backing, recorder, channel);
    } else {
        try Engine.commit(scheme, allocator, trace.takeColumns(), recorder, channel);
    }
}
