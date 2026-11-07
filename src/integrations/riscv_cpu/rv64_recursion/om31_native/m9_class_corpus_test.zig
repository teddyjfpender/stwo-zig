//! M9 L1a corpus capture (measurement only, off unless
//! STWO_RV64_M9_CORPUS_DIR is set). Builds the ACTUAL CPU leaf verifier graph
//! of the D2 profile fixture (both native bundles independently accepted),
//! pads it exactly as outer_wrap.wrapGraph does, and dumps the two class
//! statics the GPU path packs per class:
//!   fixed_<i>.u32 : PreprocessedCircuit column i (M31 words, channels 1)
//!   tasks.u32     : assignment records {kind, out, args[6]} (channels 8),
//!                   same record mapping as riscv_cuda outer_assignment_pack.
//! tools/rv64-m9-packed-ingress/corpus.zig packs these with cache_pack and the
//! CUDA bench checks device decode == host unpack on them.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const Fixture = @import("../../word16_global_execution/services/gkr_local/d2_profile_test.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const Graph = @import("leaf_graph.zig");
const Wrap = @import("outer_wrap.zig");
const C = @import("common.zig");
const Schedule = circuit.builder.witness_plan;
const PP = circuit.common.preprocessed.PreprocessedCircuit;

const Record = extern struct { kind: u32, out: u32, args: [6]u32 = @splat(0) };

fn record(ctx: *const C.Context, task: Schedule.Task) !Record {
    if (task.kind == .permutation) return error.UnexpectedPermutationTask;
    var ibuf: [6]u32 = undefined;
    var obuf: [4]u32 = undefined;
    const input = Schedule.inputs(ctx, task, &ibuf);
    const outputs = Schedule.outputs(ctx, task, &obuf);
    var out: Record = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
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

fn dump(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(name, .{});
    defer file.close();
    try file.writeAll(bytes);
}

const Capture = struct {
    var done = false;
    pub fn run(a: std.mem.Allocator, setups: anytype, bundle: anytype, expected: anytype, config: anytype, authority: anytype) !void {
        const path = std.posix.getenv("STWO_RV64_M9_CORPUS_DIR") orelse return;
        var inventory = try Execution.Inventory.initWithAuthority(a, setups, &.{}, bundle.requests, expected, config, authority);
        defer inventory.deinit();
        var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
        defer stages.deinit();
        var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
        defer manifest.deinit(a);
        var graph = try Graph.cpuTraceOnly(a, .{ .setup = setups[0], .request = bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &manifest, .index = 0, .stage = &stages.stages[0], .config = config, .encoded = &bundle.cpus[0], .fixed = authority.at(0) });
        defer graph.deinit();
        const ctx = graph.ctx;
        try circuit.common.finalize.padToTargets(C.Q, ctx, try Wrap.paddingTargets(ctx));
        var dir = try std.fs.cwd().makeOpenPath(path, .{});
        defer dir.close();
        var pp = try PP.fromBuilderCircuit(a, &ctx.circuit);
        defer pp.deinit(a);
        var fixed_bytes: usize = 0;
        for (pp.columns, 0..) |column, i| {
            var name: [32]u8 = undefined;
            try dump(dir, try std.fmt.bufPrint(&name, "fixed_{d:0>3}.u32", .{i}), std.mem.sliceAsBytes(column.values));
            fixed_bytes += column.values.len * 4;
        }
        var plan = try Schedule.build(a, ctx);
        defer plan.deinit();
        const records = try a.alloc(Record, plan.tasks.len);
        defer a.free(records);
        for (plan.tasks, records) |task, *out| out.* = try record(ctx, task);
        try dump(dir, "tasks.u32", std.mem.sliceAsBytes(records));
        std.debug.print("M9_CLASS_CORPUS dir={s} fixed_columns={} fixed_bytes={} tasks={} task_bytes={} n_vars={} trace_only={}\n", .{ path, pp.columns.len, fixed_bytes, records.len, records.len * @sizeOf(Record), ctx.circuit.n_vars, ctx.trace_only });
        done = true;
    }
};

test "M9 L1a capture actual CPU leaf class statics for packed-ingress parity" {
    if (std.posix.getenv("STWO_RV64_M9_CORPUS_DIR") == null) return error.SkipZigTest;
    // The D2 profile fits the fixture's 4 GiB schedule cap on a laptop; the
    // default b2/q108 profile OOMs there (stage_one, kind=cpu) [M].
    try Fixture.exercise(.d2_native_b4_q54_p20_fold4, Capture);
    try std.testing.expect(Capture.done);
}
