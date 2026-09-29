//! Backend-neutral execution boundary for Cairo interaction traces.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const M31 = @import("stwo_core").fields.m31.M31;
const interaction_trace = @import("interaction_trace.zig");
const residency = @import("interaction_residency.zig");

pub const LookupAllocation = residency.LookupAllocation;
pub const LookupAllocationRequest = residency.LookupAllocationRequest;

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
    allocate_lookup_fn: ?*const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        request: LookupAllocationRequest,
    ) anyerror!?LookupAllocation = null,
    execute_fn: *const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        request: Request,
    ) anyerror!MaterializedTrace,
    /// Write canonical coordinate planes directly. Backends with planar
    /// outputs avoid a secure-field allocation and two full transposes.
    execute_coordinates_fn: ?*const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        request: Request,
        planes: []const []M31,
    ) anyerror!QM31 = null,

    pub fn materializeCoordinates(
        self: Executor,
        allocator: std.mem.Allocator,
        request: Request,
        planes: []const []M31,
    ) !QM31 {
        if (request.descriptors.len == 0 or
            request.descriptors.len % interaction_trace.descriptor_words != 0 or
            planes.len != request.descriptors.len / interaction_trace.descriptor_words * 4)
            return error.InvalidInteractionGeometry;
        for (planes) |plane| if (plane.len != request.source.rows())
            return error.InvalidInteractionGeometry;
        if (self.execute_coordinates_fn) |execute_coordinates|
            return execute_coordinates(self.context, allocator, request, planes);
        var materialized = try self.execute(allocator, request);
        defer materialized.deinit();
        if (materialized.row_count != request.source.rows() or
            materialized.column_count * 4 != planes.len)
            return error.InvalidInteractionGeometry;
        for (0..materialized.column_count) |column_index|
            interaction_trace.lowerLastColumn(
                planes[column_index * 4 ..][0..4],
                materialized.column(column_index),
            );
        return materialized.claimed_sum;
    }

    pub fn execute(
        self: Executor,
        allocator: std.mem.Allocator,
        request: Request,
    ) !MaterializedTrace {
        return self.execute_fn(self.context, allocator, request);
    }

    pub fn allocateLookup(
        self: Executor,
        allocator: std.mem.Allocator,
        request: LookupAllocationRequest,
    ) !?LookupAllocation {
        const allocate = self.allocate_lookup_fn orelse return null;
        return allocate(self.context, allocator, request);
    }
};

test {
    _ = @import("interaction_executor_test.zig");
}
