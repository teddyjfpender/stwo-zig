//! Backend-neutral execution boundary for Cairo interaction traces.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const interaction_trace = @import("interaction_trace.zig");

pub const MaterializedTrace = struct {
    allocator: std.mem.Allocator,
    values: []QM31,
    row_count: usize,
    column_count: usize,
    claimed_sum: QM31,

    pub fn deinit(self: *MaterializedTrace) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn column(self: MaterializedTrace, index: usize) []const QM31 {
        std.debug.assert(index < self.column_count);
        return self.values[index * self.row_count ..][0..self.row_count];
    }
};

pub const Request = struct {
    descriptors: []const u32,
    source: interaction_trace.SourceView,
    z: QM31,
    alpha_powers: []const QM31,
};

/// Backend implementations must either return the exact canonical trace or
/// fail the proof. Callers never fall back after selecting an executor.
pub const Executor = struct {
    context: ?*anyopaque = null,
    execute_fn: *const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        request: Request,
    ) anyerror!MaterializedTrace,

    pub fn execute(
        self: Executor,
        allocator: std.mem.Allocator,
        request: Request,
    ) !MaterializedTrace {
        return self.execute_fn(self.context, allocator, request);
    }
};
