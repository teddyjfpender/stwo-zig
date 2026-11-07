//! M9 witness-rowpar prep (STWO_RV64_M9_WITNESS_ROWPAR, measurement only):
//! records REAL recursion-node assignment plans on the CPU, with no GPU.
//!
//! Nodes:
//! - `leaf-d2`: the actual CPU recursive verifier graph (leaf_graph.cpuTraceOnly)
//!   of the D2 native CPU mini fixture (profile d2_native_b4_q54_p20_fold4,
//!   both native proofs freshly accepted first), padded with the production
//!   `outer_wrap.paddingTargets`.
//! - `fold-m3-a<k>`: the production fold builder (om31_outer.buildFoldTraceOnly)
//!   over k OM31 children proved under the production outer profile
//!   m3_b4_q51_p26_fold4, padded the same way.
//!
//! For each node the plan is exactly what `outer_assignment.initFull` uploads:
//! witness_plan.buildProfiled, the 32-byte device records of
//! outer_assignment_pack.record (mirrored below; that file lives in the CUDA
//! integration module), the level ends, the seeds, and the CPU reference
//! values of witness_plan.evaluate (the qualification oracle).
//!
//! File `<dir>/<name>.m9rp` (little-endian u32):
//!   header[8] = { 0x5052394d "M9RP", 1, n_vars, n_tasks, n_indices, n_levels, n_seeds, 0 }
//!   ends[n_levels], records[n_tasks * 8], indices[n_indices],
//!   seeds[n_seeds * 5] (out, limbs[4]), reference[n_vars * 4].
//! Env: STWO_M9_ROWPAR_DUMP_DIR (required; the test is a no-op without it),
//! STWO_M9_ROWPAR_CHILD_BLOCKS (fold children's chained Blake blocks, default 64),
//! STWO_M9_ROWPAR_NODES (comma list of leaf,fold2,fold4; default leaf,fold4).
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Bridge = @import("rv64_recursion/om31_outer.zig");
const Wrap = @import("rv64_recursion/om31_native/outer_wrap.zig");
const Candidate = @import("word16_execution/om31_security_candidate.zig");
const Fixture = @import("word16_global_execution/services/gkr_local/d2_profile_test.zig");
const Execution = @import("word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("word16_global_execution/services/gkr_local/manifest_wire.zig");
const Graph = @import("rv64_recursion/om31_native/leaf_graph.zig");
const Q = Outer.protocol.Q;
const B = circuit.builder;
const Schedule = B.witness_plan;
const Word = B.wrappers.U32Wrapper(B.Var);

const Task = extern struct { kind: u32, out: u32, args: [6]u32 = @splat(0) };

fn dumpDir() ?[]const u8 {
    return std.posix.getenv("STWO_M9_ROWPAR_DUMP_DIR");
}
fn wanted(name: []const u8) bool {
    const list = std.posix.getenv("STWO_M9_ROWPAR_NODES") orelse "leaf,fold4";
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| if (std.mem.eql(u8, item, name)) return true;
    return false;
}

/// Mirror of outer_assignment.initFull's record packing (both branches).
fn pack(a: std.mem.Allocator, ctx: *const B.Context(Q), plan: Schedule.Plan, indices: *std.ArrayList(u32)) ![]Task {
    const tasks = try a.alloc(Task, plan.tasks.len);
    errdefer a.free(tasks);
    for (plan.tasks, tasks) |task, *out| {
        var ibuf: [6]u32 = undefined;
        var obuf: [4]u32 = undefined;
        const in = Schedule.inputs(ctx, task, &ibuf);
        const outputs = Schedule.outputs(ctx, task, &obuf);
        out.* = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
        if (task.kind == .permutation) {
            out.args[0] = @intCast(indices.items.len);
            out.args[1] = @intCast(in.len);
            try indices.appendSlice(a, in);
            try indices.appendSlice(a, outputs);
            continue;
        }
        @memcpy(out.args[0..in.len], in);
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
    }
    return tasks;
}

fn dump(a: std.mem.Allocator, ctx: *B.Context(Q), name: []const u8) !void {
    const dir_path = dumpDir() orelse return;
    try circuit.common.finalize.padToTargets(Q, ctx, try Wrap.paddingTargets(ctx));
    var timer = try std.time.Timer.start();
    var plan = try Schedule.build(a, ctx);
    defer plan.deinit();
    const plan_ns = timer.lap();
    var indices: std.ArrayList(u32) = .empty;
    defer indices.deinit(a);
    const tasks = try pack(a, ctx, plan, &indices);
    defer a.free(tasks);
    const reference = try Schedule.evaluate(a, ctx, plan);
    defer a.free(reference);
    const eval_ns = timer.lap();
    var kinds = [_]u64{0} ** 16;
    for (tasks) |t| kinds[@min(t.kind, 15)] += 1;
    var dir = try std.fs.cwd().makeOpenPath(dir_path, .{});
    defer dir.close();
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}.m9rp", .{name});
    var file = try dir.createFile(path, .{});
    defer file.close();
    var buffer: [1 << 16]u8 = undefined;
    var w = file.writer(&buffer);
    const io = &w.interface;
    const header = [8]u32{ 0x5052394d, 1, @intCast(ctx.circuit.n_vars), @intCast(tasks.len), @intCast(indices.items.len), @intCast(plan.level_ends.len), @intCast(plan.seeds.len), 0 };
    try io.writeAll(std.mem.sliceAsBytes(&header));
    for (plan.level_ends) |end| try io.writeInt(u32, @intCast(end), .little);
    try io.writeAll(std.mem.sliceAsBytes(tasks));
    try io.writeAll(std.mem.sliceAsBytes(indices.items));
    for (plan.seeds) |seed| {
        const limbs = B.ivalue.limbs(seed.value);
        try io.writeAll(std.mem.sliceAsBytes(&[5]u32{ seed.variable, limbs[0], limbs[1], limbs[2], limbs[3] }));
    }
    for (reference) |value| try io.writeAll(std.mem.sliceAsBytes(&B.ivalue.limbs(value)));
    try io.flush();
    std.debug.print("M9_ROWPAR_DUMP name={s} vars={} tasks={} levels={} seeds={} indices={} plan_ns={} eval_ns={} kinds={any}\n", .{ name, ctx.circuit.n_vars, tasks.len, plan.level_ends.len, plan.seeds.len, indices.items.len, plan_ns, eval_ns, kinds });
}

const LeafHook = struct {
    pub fn run(a: std.mem.Allocator, setups: anytype, bundle: anytype, expected: anytype, config: anytype, authority: anytype) !void {
        var inventory = try Execution.Inventory.initWithAuthority(a, setups, &.{}, bundle.requests, expected, config, authority);
        defer inventory.deinit();
        var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
        defer stages.deinit();
        var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
        defer manifest.deinit(a);
        var graph = try Graph.cpuTraceOnly(a, .{ .setup = setups[0], .request = bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &manifest, .index = 0, .stage = &stages.stages[0], .config = config, .encoded = &bundle.cpus[0], .fixed = authority.at(0) });
        defer graph.deinit();
        try dump(std.heap.smp_allocator, graph.ctx, "leaf-d2");
    }
};

test "M9 witness rowpar: record the actual D2 CPU leaf assignment plan" {
    if (dumpDir() == null or !wanted("leaf")) return;
    try Fixture.exercise(.d2_native_b4_q54_p20_fold4, LeafHook);
}

const Child = struct {
    ctx: B.Context(Q),
    pp: circuit.common.preprocessed.PreprocessedCircuit,
    authority: Outer.prove.Authority,
    produced: Outer.prove.Produced,
    capture: Outer.prove.Capture,
    fn deinit(self: *Child, a: std.mem.Allocator) void {
        self.capture.deinit(a);
        self.produced.deinit();
        self.authority.deinit();
        self.pp.deinit(a);
        self.ctx.deinit();
    }
};

/// The m3 fold census child (rv64_om31_m3_fold_test_root.makeChild): `blocks`
/// chained Blake2s compressions and 8 public digest outputs.
fn makeChild(a: std.mem.Allocator, blocks: usize, seed: u32) !*Child {
    const self = try a.create(Child);
    errdefer a.destroy(self);
    self.ctx = try B.Context(Q).init(a, 8);
    var state: [8]Word = undefined;
    for (&state, 0..) |*w, i| w.* = .newUnsafe(try self.ctx.guess(B.wrappers.u32Value(Q, seed +% @as(u32, @intCast(i)) *% 0x9e3779b9).get()));
    for (0..blocks) |b| {
        var message: [16]Word = undefined;
        @memcpy(message[0..8], &state);
        for (message[8..], 0..) |*w, i| w.* = .newUnsafe(try self.ctx.guess(B.wrappers.u32Value(Q, @as(u32, @intCast(b * 8 + i)) ^ seed).get()));
        state = (try B.blake.blake2sU32s(Q, &self.ctx, &message, 64)).words;
    }
    var outputs: [8]B.Var = undefined;
    for (&outputs, state) |*out, w| out.* = w.get();
    try self.ctx.setOutputs(&outputs);
    try self.ctx.finalize(true);
    try circuit.common.finalize.padToTargets(Q, &self.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&self.ctx.circuit)));
    self.pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &self.ctx.circuit);
    self.authority = try Outer.prove.Authority.init(a, &self.pp);
    self.produced = try Outer.prove.prove(a, &self.authority, self.ctx.values());
    self.capture = try Outer.prove.verify(a, &self.authority, self.produced.outputs, self.produced.claims, &self.produced.proof.proof);
    self.authority.retireProverData();
    return self;
}

test "M9 witness rowpar: record actual m3 fold assignment plans" {
    if (dumpDir() == null) return;
    const a = std.heap.smp_allocator;
    const before = Outer.protocol.active();
    defer Outer.protocol.selectForTesting(before);
    Outer.protocol.selectForTesting(.m3_b4_q51_p26_fold4);
    const blocks = blk: {
        const text = std.posix.getenv("STWO_M9_ROWPAR_CHILD_BLOCKS") orelse break :blk @as(usize, 64);
        break :blk try std.fmt.parseInt(usize, text, 10);
    };
    for ([_]usize{ 2, 4 }) |arity| {
        var name_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&name_buf, "fold{}", .{arity});
        if (!wanted(key)) continue;
        var kids: [4]*Child = undefined;
        var made: usize = 0;
        defer for (kids[0..made]) |k| {
            k.deinit(a);
            a.destroy(k);
        };
        for (kids[0..arity], 0..) |*k, i| {
            k.* = try makeChild(a, blocks, 0x1000 * @as(u32, @intCast(i + 1)));
            made += 1;
        }
        var views: [4]Bridge.Child = undefined;
        for (views[0..arity], kids[0..arity]) |*v, k| v.* = .{ .authority = &k.authority, .produced = &k.produced, .capture = &k.capture };
        var graph = try Bridge.buildFoldTraceOnly(a, views[0..arity]);
        defer graph.deinit();
        var file_buf: [64]u8 = undefined;
        try dump(a, &graph.ctx, try std.fmt.bufPrint(&file_buf, "fold-m3-a{}-b{}", .{ arity, blocks }));
    }
}
