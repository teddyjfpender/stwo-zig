//! Fixed-position assignment records for a validated zero-CSR witness plan.
//! The original plan/order and all device ABI bytes are preserved. Callers own
//! allocation; helpers write disjoint records and join before returning errors.
const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = Circuit.builder.witness_plan;
const Rows = @import("stwo_prover_engine").lookups.row_work;
pub const Task = extern struct { kind: u32, out: u32, args: [6]u32 = @splat(0) };
pub const Error = error{ InvalidWitnessOrigin, UnexpectedPermutationTask, TaskPackLengthMismatch };

fn record(ctx: *const Circuit.builder.Context(Q), task: Schedule.Task) Error!Task {
    if (task.kind == .permutation) return error.UnexpectedPermutationTask;
    var ibuf: [6]u32 = undefined;
    var obuf: [4]u32 = undefined;
    const input = Schedule.inputs(ctx, task, &ibuf);
    const outputs = Schedule.outputs(ctx, task, &obuf);
    var out: Task = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
    @memcpy(out.args[0..input.len], input);
    if (task.kind == .hint) {
        const hint = ctx.witness_metadata.?.origins.items[task.index];
        out.kind = switch (hint.kind) {
            .seed => return error.InvalidWitnessOrigin,
            .inverse => 8,
            .divide => 9,
            .pointwise_inverse_or_zero => 10,
            .pointwise_lsb => 11,
            .byte => 12,
            .byte_complement => 13,
            .is_nonzero => 14,
            .zero => 15,
        };
        if (hint.kind == .byte or hint.kind == .byte_complement) out.args[1] = hint.b;
    }
    return out;
}

/// Does not allocate or acquire another pool. A missing/fully leased scoped
/// pool follows the same serial record path. Capability errors remain deferred
/// until every packing error is checked, matching the original two-pass order.
pub fn fill(ctx: *const Circuit.builder.Context(Q), source: []const Schedule.Task, tasks: []Task, capabilities: u32) !usize {
    if (source.len != tasks.len) return error.TaskPackLengthMismatch;
    const Context = struct {
        ctx: *const Circuit.builder.Context(Q),
        source: []const Schedule.Task,
        tasks: []Task,
        capabilities: u32,
        errors: [Rows.MAX_SHARDS]?Error = @splat(null),
        unsupported: [Rows.MAX_SHARDS]bool = @splat(false),
        pub fn runRange(self: *@This(), shard: usize, begin: usize, end: usize) void {
            for (self.source[begin..end], self.tasks[begin..end]) |input, *out| {
                out.* = record(self.ctx, input) catch |err| {
                    self.errors[shard] = err;
                    return;
                };
                if (self.capabilities & (@as(u32, 1) << @intCast(out.kind)) == 0) self.unsupported[shard] = true;
            }
        }
    };
    var context = Context{ .ctx = ctx, .source = source, .tasks = tasks, .capabilities = capabilities };
    const shards = Rows.forEachRange(source.len, &context, .{ .min_rows_per_shard = 16384 });
    for (context.errors[0..shards]) |err| if (err) |failure| return failure;
    for (context.unsupported[0..shards]) |unsupported| if (unsupported) return error.UnsupportedCircuitAssignmentHint;
    return shards;
}

test {
    _ = @import("tests/outer_assignment_pack_test.zig");
}
