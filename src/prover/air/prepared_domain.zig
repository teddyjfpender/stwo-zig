//! Type-erased ownership boundary for allocation-free domain evaluation.
//!
//! A frontend prepares one of these values on the coordinator. The task graph
//! may then call `run` exactly once while all owned scratch remains stable, and
//! the coordinator calls `deinit` only after the graph has drained.

const task_graph = @import("../task_graph.zig");

/// Reviewed stack requirement for allocation-free AIR row evaluators.
///
/// This is an admission requirement, not a stack allocation request. The
/// generic prover pool may retain a larger configured stack for other kernel
/// classes. Every component opting into `PreparedDomainEvaluation` must keep
/// fixed locals below this bound and execute its production row loop on a
/// helper configured with exactly this stack in its focused tests.
pub const ROW_EVALUATOR_STACK_BYTES: usize = 128 * 1024;

pub const Error = error{
    CoordinatorPreparedDomainRejected,
    InvalidPreparedDomainResources,
};

pub const VTable = struct {
    run: *const fn (
        context: *anyopaque,
        task_context: *task_graph.TaskContext,
    ) anyerror!void,
    deinit: *const fn (context: *anyopaque) void,
};

/// Owned, type-erased prepared evaluation.
///
/// `context` must remain valid through `run`. `deinit` is deliberately
/// allocator-free at this layer: the concrete owner retains the allocator
/// identity used by its coordinator-side preparation.
pub const PreparedDomainEvaluation = struct {
    context: *anyopaque,
    vtable: *const VTable,
    task_class: task_graph.TaskClass = .leaf,
    resources: task_graph.ResourceReservation = .{},

    pub fn validate(self: PreparedDomainEvaluation) Error!void {
        if (self.task_class == .coordinator) {
            return error.CoordinatorPreparedDomainRejected;
        }
        _ = self.resources.residentBytes() catch
            return error.InvalidPreparedDomainResources;
    }

    pub fn run(
        self: *PreparedDomainEvaluation,
        task_context: *task_graph.TaskContext,
    ) anyerror!void {
        try self.vtable.run(self.context, task_context);
    }

    pub fn deinit(self: *PreparedDomainEvaluation) void {
        self.vtable.deinit(self.context);
        self.* = undefined;
    }
};

test "prepared domain: coordinator class is rejected" {
    const std = @import("std");
    const Noop = struct {
        fn run(_: *anyopaque, _: *task_graph.TaskContext) !void {}
        fn deinit(_: *anyopaque) void {}
    };
    var byte: u8 = 0;
    const prepared = PreparedDomainEvaluation{
        .context = &byte,
        .vtable = &.{ .run = Noop.run, .deinit = Noop.deinit },
        .task_class = .coordinator,
    };
    try std.testing.expectError(
        error.CoordinatorPreparedDomainRejected,
        prepared.validate(),
    );
}

test "prepared domain: resident resource overflow is rejected" {
    const std = @import("std");
    const Noop = struct {
        fn run(_: *anyopaque, _: *task_graph.TaskContext) !void {}
        fn deinit(_: *anyopaque) void {}
    };
    var byte: u8 = 0;
    const prepared = PreparedDomainEvaluation{
        .context = &byte,
        .vtable = &.{ .run = Noop.run, .deinit = Noop.deinit },
        .resources = .{
            .final_output_bytes = std.math.maxInt(usize),
            .shared_resident_bytes = 1,
        },
    };
    try std.testing.expectError(
        error.InvalidPreparedDomainResources,
        prepared.validate(),
    );
}
