//! Structural dispatch for a complete resident STARK proof schedule.

const execution_plan = @import("stwo_cuda_backend").runtime.execution_plan;
const proof_ir = @import("stwo_backend_contracts").proof_program;

/// The adapter supplies AIR-owned operations. Dispatch is deliberately keyed
/// only by the backend-neutral proof-program operation kind.
pub fn ExecutorFor(comptime Adapter: type) type {
    comptime assertAdapter(Adapter);
    return struct {
        pub fn executeNode(
            transaction: anytype,
            prepared: *Adapter.PreparedPlan,
            geometry: Adapter.Geometry,
            scheduled: execution_plan.ScheduledNode,
        ) !void {
            const program = Adapter.program(prepared);
            if (scheduled.node_id >= program.nodes.len)
                return error.InvalidKernelDescriptor;
            const expected = program.nodes[scheduled.node_id];
            if (expected.id != scheduled.node_id or
                expected.kind != scheduled.kind or
                @intFromEnum(expected.stage) != @intFromEnum(scheduled.stage))
            {
                return error.InvalidKernelDescriptor;
            }
            switch (scheduled.kind) {
                .trace_generation => try Adapter.traceGeneration(
                    transaction,
                    prepared,
                    geometry,
                ),
                .commitment => try Adapter.traceCommit(
                    transaction,
                    prepared,
                    geometry,
                ),
                .constraint_evaluation => try Adapter.constraintEvaluation(
                    transaction,
                    prepared,
                    geometry,
                ),
                .oods => try Adapter.oods(
                    transaction,
                    prepared,
                    geometry,
                ),
                .quotient => try Adapter.quotient(
                    transaction,
                    prepared,
                    geometry,
                ),
                .fri_commit => try Adapter.friCommit(
                    transaction,
                    prepared,
                    geometry,
                ),
                .pow => try Adapter.pow(
                    transaction,
                    prepared,
                    geometry,
                ),
                .decommit => try Adapter.decommit(
                    transaction,
                    prepared,
                    geometry,
                ),
            }
        }
    };
}

fn assertAdapter(comptime Adapter: type) void {
    inline for (&.{
        "PreparedPlan",
        "Geometry",
        "program",
        "traceGeneration",
        "traceCommit",
        "constraintEvaluation",
        "oods",
        "quotient",
        "friCommit",
        "pow",
        "decommit",
    }) |name| {
        if (!@hasDecl(Adapter, name))
            @compileError("Native CUDA scheduled adapter is missing " ++ name);
    }
}

test "structural dispatcher covers every proof operation and rejects drift" {
    const std = @import("std");
    const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
    const stages = [_]telemetry.Stage{
        .trace_generation,
        .trace_commit,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    const kinds = [_]proof_ir.OperationKind{
        .trace_generation,
        .commitment,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    const Plan = struct {
        nodes: [kinds.len]proof_ir.Node,
    };
    const Adapter = struct {
        pub const PreparedPlan = Plan;
        pub const Geometry = struct {};
        var calls: usize = 0;

        pub fn program(prepared: *const PreparedPlan) *const PreparedPlan {
            return prepared;
        }

        fn mark() !void {
            calls += 1;
        }

        pub fn traceGeneration(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn traceCommit(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn constraintEvaluation(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn oods(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn quotient(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn friCommit(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn pow(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
        pub fn decommit(_: anytype, _: anytype, _: Geometry) !void {
            try mark();
        }
    };
    var prepared: Plan = undefined;
    for (&prepared.nodes, 0..) |*node, index| {
        node.* = .{
            .id = @intCast(index),
            .kind = kinds[index],
            .stage = @enumFromInt(@intFromEnum(stages[index])),
            .dependencies = .{ .first = 0, .count = 0 },
            .parallelism = .coordination,
            .graph_candidate = false,
            .work = .{
                .bytes_read = 0,
                .bytes_written = 0,
                .field_operations = 0,
                .hash_compressions = 0,
                .minimum_launches = 1,
            },
        };
    }
    const Executor = ExecutorFor(Adapter);
    var transaction: u8 = 0;
    Adapter.calls = 0;
    for (kinds, 0..) |kind, index| {
        try Executor.executeNode(
            &transaction,
            &prepared,
            .{},
            .{
                .node_id = @intCast(index),
                .kind = kind,
                .stage = stages[index],
                .stream_index = 0,
                .graph_region = 0,
                .graph_candidate = false,
                .dependency_count = 0,
            },
        );
    }
    try std.testing.expectEqual(kinds.len, Adapter.calls);

    const calls_before = Adapter.calls;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Executor.executeNode(
            &transaction,
            &prepared,
            .{},
            .{
                .node_id = 0,
                .kind = .pow,
                .stage = .trace_generation,
                .stream_index = 0,
                .graph_region = 0,
                .graph_candidate = false,
                .dependency_count = 0,
            },
        ),
    );
    try std.testing.expectEqual(calls_before, Adapter.calls);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Executor.executeNode(
            &transaction,
            &prepared,
            .{},
            .{
                .node_id = @intCast(kinds.len),
                .kind = .decommit,
                .stage = .decommit,
                .stream_index = 0,
                .graph_region = 0,
                .graph_candidate = false,
                .dependency_count = 0,
            },
        ),
    );
    try std.testing.expectEqual(calls_before, Adapter.calls);
}
