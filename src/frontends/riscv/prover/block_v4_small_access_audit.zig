//! Bounded development census for a small block-v4 batch. The proved global
//! relation remains the authority; this check catches witness disagreement
//! before spending time on PCS/FRI proofs.
const std = @import("std");
const event = @import("../air/block/memory_event.zig");
const access = @import("../runner/state_chain.zig").Access;
const bus = @import("block_memory_relation_v2.zig");

pub fn check(a: std.mem.Allocator, frame: event.Frame, accesses: []const access, opcode_traces: anytype, extension_traces: anytype) !void {
    if (accesses.len > 10_000) return;
    var runner: std.ArrayList(event.Event) = .empty;
    defer runner.deinit(a);
    var typed: std.ArrayList(event.Event) = .empty;
    defer typed.deinit(a);
    for (accesses) |item| try runner.append(a, try frame.project(item));
    for (opcode_traces) |*trace| try appendTrace(a, &typed, trace);
    for (extension_traces) |*trace| try appendTrace(a, &typed, trace);
    std.mem.sort(event.Event, runner.items, {}, event.Event.lessThan);
    std.mem.sort(event.Event, typed.items, {}, event.Event.lessThan);
    if (runner.items.len != typed.items.len) return error.SmallBlockTypedAccessCountMismatch;
    var mismatches: usize = 0;
    var runner_index: usize = 0;
    var typed_index: usize = 0;
    while (runner_index < runner.items.len and typed_index < typed.items.len) {
        const expected = runner.items[runner_index];
        const actual = typed.items[typed_index];
        if (std.meta.eql(expected, actual)) {
            runner_index += 1;
            typed_index += 1;
            continue;
        }
        if (mismatches < 16) std.debug.print("BLOCK_V4_ACCESS_DIFF runner[{d}]={} typed[{d}]={}\n", .{ runner_index, expected, typed_index, actual });
        mismatches += 1;
        if (event.Event.lessThan({}, expected, actual)) {
            runner_index += 1;
        } else if (event.Event.lessThan({}, actual, expected)) {
            typed_index += 1;
        } else {
            runner_index += 1;
            typed_index += 1;
        }
    }
    if (mismatches != 0 or runner_index != runner.items.len or typed_index != typed.items.len) {
        var runner_memory: usize = 0;
        for (runner.items) |item| runner_memory += @intFromBool(item.space == 1);
        var typed_memory: usize = 0;
        for (typed.items) |item| typed_memory += @intFromBool(item.space == 1);
        std.debug.print("BLOCK_V4_ACCESS_CENSUS runner_total={d} typed_total={d} runner_memory={d} typed_memory={d}\n", .{ runner.items.len, typed.items.len, runner_memory, typed_memory });
        return error.SmallBlockTypedAccessTupleMismatch;
    }
}

fn appendTrace(a: std.mem.Allocator, result: *std.ArrayList(event.Event), trace: anytype) !void {
    for (0..trace.domainSize()) |logical| {
        const row = try trace.row(logical);
        if (!row.active) continue;
        const tuple = try bus.decodeTransitionTuple(row.tuple);
        try result.append(a, .{ .space = tuple.space, .address = tuple.address, .clock = tuple.clock, .value = tuple.after });
    }
}
