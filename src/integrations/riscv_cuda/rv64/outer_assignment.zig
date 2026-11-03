//! Device assignments from the original topology and explicit input origins.
//! Production trace-only builders retain compact seeds without CPU assignment
//! storage. Optional reference reconstruction is restricted to qualification;
//! graph construction and schedule preparation remain host work.
const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = Circuit.builder.witness_plan;
const SC = @import("session_context.zig");
const N = @import("pcs_native_abi.zig");
const Events = @import("cuda_events.zig");
const Span = enum { seed, levels };
const Recorder = Events.RecorderFor(Span);
pub const Task = extern struct { kind: u32, out: u32, args: [6]u32 = @splat(0) };
pub const Seed = extern struct { out: u32, value: [4]u32 };
pub const Job = extern struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32, record_count: u32, index_count: u32, first: u32, count: u32, reserved: u32 = 0 };
pub const Launch = *const fn (*anyopaque, u32, *const Job) callconv(.c) c_int;
pub fn requireProductionMask(mask: u32) !void {
    if (mask & 0xffff != 0xffff) return error.UnsupportedCircuitAssignmentHint;
}
pub fn requireProductionCapabilities(library: *std.DynLib) !void {
    _ = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
    _ = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
    const query = library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities") orelse return error.MissingCircuitAssignmentKernel;
    try requireProductionMask(query());
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    reference: ?[*]const Q,
    count: usize,
    plan: Schedule.Plan,
    tasks: []Task,
    indices: []u32,
    seeds: []Seed,
    identity: [32]u8,
    check_reference: bool = false,
    seed: Launch,
    level: Launch,
    timing_api: Events.Api,
    pub fn init(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib) !Prepared {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        var timer = try std.time.Timer.start();
        var metrics: Schedule.BuildMetrics = .{};
        var plan = try Schedule.buildProfiled(a, ctx, &metrics);
        errdefer plan.deinit();
        const plan_ns = timer.lap();
        const tasks = try a.alloc(Task, plan.tasks.len);
        errdefer a.free(tasks);
        var indices: std.ArrayList(u32) = .empty;
        defer indices.deinit(a);
        var permutation_count: usize = 0;
        var max_permutation_inputs: usize = 0;
        var permutation_pair_work: u64 = 0;
        for (plan.tasks, tasks) |task, *out| {
            var ibuf: [6]u32 = undefined;
            var obuf: [4]u32 = undefined;
            const in = Schedule.inputs(ctx, task, &ibuf);
            const outputs = Schedule.outputs(ctx, task, &obuf);
            out.* = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
            if (task.kind == .permutation) {
                permutation_count += 1;
                max_permutation_inputs = @max(max_permutation_inputs, in.len);
                const count: u64 = @intCast(in.len);
                permutation_pair_work = permutation_pair_work +| count *| count;
                out.args[0] = std.math.cast(u32, indices.items.len) orelse return error.WitnessPlanTooLarge;
                out.args[1] = std.math.cast(u32, in.len) orelse return error.WitnessPlanTooLarge;
                try indices.appendSlice(a, in);
                try indices.appendSlice(a, outputs);
            } else {
                @memcpy(out.args[0..in.len], in);
                if (task.kind == .hint) out.kind = switch (ctx.witness_metadata.?.origins.items[task.index].kind) {
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
                if (task.kind == .hint) {
                    const hint = ctx.witness_metadata.?.origins.items[task.index];
                    if (hint.kind == .byte or hint.kind == .byte_complement) out.args[1] = hint.b;
                }
            }
        }
        const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
        for (tasks) |task| if (capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
        const task_pack_ns = timer.lap();
        const seeds = try a.alloc(Seed, plan.seeds.len);
        errdefer a.free(seeds);
        for (plan.seeds, seeds) |input, *out| out.* = .{ .out = input.variable, .value = Circuit.builder.ivalue.limbs(input.value) };
        const seed_pack_ns = timer.lap();
        // This cache identity binds every generation byte. Chunking changes
        // only the private immutable-cache key, never the proof transcript.
        const identity = try @import("schedule_identity.zig").digest(a, .{ std.mem.sliceAsBytes(tasks), std.mem.sliceAsBytes(indices.items), std.mem.sliceAsBytes(plan.level_ends) });
        const hash_ns = timer.lap();
        std.debug.print("GPU_OUTER_ASSIGNMENT_PLAN plan_ns={} producer_alloc_zero_ns={} seeds_ns={} tasks_ns={} level_alloc_zero_ns={} dependency_walk_ns={} ready_tasks={} dfs_roots={} ordering_ns={} task_pack_ns={} seed_pack_ns={} hash_ns={} task_bytes={} index_bytes={} levels={} permutation_count={} max_permutation_inputs={} permutation_pair_work={}\n", .{ plan_ns, metrics.producer_init_ns, metrics.seeds_ns, metrics.tasks_ns, metrics.level_init_ns, metrics.walk_ns, metrics.ready_tasks, metrics.dfs_roots, metrics.ordering_ns, task_pack_ns, seed_pack_ns, hash_ns, tasks.len * @sizeOf(Task), indices.items.len * 4, plan.level_ends.len, permutation_count, max_permutation_inputs, permutation_pair_work });
        return .{ .allocator = a, .reference = if (ctx.trace_only) null else ctx.values().ptr, .count = ctx.circuit.n_vars, .plan = plan, .tasks = tasks, .indices = try indices.toOwnedSlice(a), .seeds = seeds, .identity = identity, .seed = seed, .level = level, .timing_api = try Events.Api.load(library) };
    }
    pub fn deinit(self: *Prepared) void {
        self.plan.deinit();
        self.allocator.free(self.tasks);
        self.allocator.free(self.indices);
        self.allocator.free(self.seeds);
        self.* = undefined;
    }
    fn key(self: *const Prepared, fixed: [32]u8, kind: u32) [8]u32 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&fixed);
        hash.update(&self.identity);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, kind, .little);
        hash.update(&bytes);
        const digest = hash.finalResult();
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        return words;
    }
    pub fn generate(self: *const Prepared, owner: anytype, ctx: *SC.Context) !N.Lease {
        const service = owner.backend.service;
        var total_timer = try std.time.Timer.start();
        var timer = try std.time.Timer.start();
        var recorder = try Recorder.init(&self.timing_api);
        defer recorder.deinit();
        var stream: ?*anyopaque = null;
        if (owner.backend.api.lane_stream(ctx.native_context, 1, &stream) != 0 or stream == null) return error.InvalidLane;
        const lane = stream.?;
        var values = try ctx.allocate(self.count * 4, 0);
        errdefer ctx.release(&values) catch {};
        var status = try ctx.allocate(1, 0);
        defer ctx.release(&status) catch {};
        var seed_lease = try ctx.allocate(self.seeds.len * 5, 0);
        defer ctx.release(&seed_lease) catch {};
        const alloc_ns = timer.lap();
        try ctx.upload(try ctx.borrow(seed_lease), @as([*]const u32, @ptrCast(self.seeds.ptr))[0 .. self.seeds.len * 5]);
        try ctx.upload(try ctx.borrow(status), &.{0});
        var job: Job = .{ .values = values.words.?, .records = seed_lease.words.?, .indices = null, .status = @ptrCast(status.words.?), .value_count = @intCast(self.count), .record_count = @intCast(self.seeds.len), .index_count = 0, .first = 0, .count = @intCast(self.seeds.len) };
        try ctx.join();
        const seed_upload_ns = timer.lap();
        try recorder.mark(.seed, false, lane);
        if (self.seed(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
        try recorder.mark(.seed, true, lane);
        const seed_enqueue_ns = timer.lap();
        const task_words = @as([*]const u32, @ptrCast(self.tasks.ptr))[0 .. self.tasks.len * 8];
        const tasks = try service.immutableWords(ctx.native_context, ctx.scope, self.key(owner.initial_scope.fixed, 0), task_words);
        const indices: ?N.Lease = if (self.indices.len == 0) null else try service.immutableWords(ctx.native_context, ctx.scope, self.key(owner.initial_scope.fixed, 1), self.indices);
        job.records = tasks.words.?;
        job.record_count = @intCast(self.tasks.len);
        if (indices) |lease| {
            job.indices = lease.words.?;
            job.index_count = @intCast(self.indices.len);
        }
        try ctx.join();
        const static_ingress_ns = timer.lap();
        try recorder.mark(.levels, false, lane);
        var launches: usize = 1;
        var begin: usize = 0;
        for (self.plan.level_ends) |end| {
            if (end != begin) {
                job.first = @intCast(begin);
                job.count = @intCast(end - begin);
                if (self.level(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
                launches += 1;
            }
            begin = end;
        }
        try recorder.mark(.levels, true, lane);
        const levels_enqueue_ns = timer.lap();
        // Numeric kernels use lane1 while the copy API uses stream0. A join
        // must precede status D2H; joining after enqueue alone can read old0.
        try ctx.join();
        const levels_join_ns = timer.lap();
        var flag: [1]u32 = undefined;
        try ctx.download(try ctx.borrow(status), &flag);
        try ctx.join();
        if (flag[0] != 0) return error.InvalidCircuitDeviceAssignment;
        const status_ns = timer.lap();
        if (self.check_reference) {
            const observed = try self.allocator.alloc(u32, self.count * 4);
            defer self.allocator.free(observed);
            try ctx.download(try ctx.borrow(values), observed);
            try ctx.join();
            const expected = @as([*]const u32, @ptrCast(self.reference orelse return error.CircuitAssignmentReferenceUnavailable))[0 .. self.count * 4];
            if (!std.mem.eql(u32, observed, expected)) return error.CircuitDeviceAssignmentMismatch;
        }
        const reference_readback_ns = timer.lap();
        // Event spans include enqueue starvation; they are not sums of
        // individual kernel durations. Nsight supplies the latter.
        std.debug.print("GPU_OUTER_ASSIGNMENT_TIMING total_ns={} alloc_ns={} seed_upload_ns={} seed_enqueue_ns={} static_ingress_ns={} levels_enqueue_ns={} levels_join_ns={} status_ns={} reference_readback_ns={} seed_stream_ms={d:.3} levels_stream_ms={d:.3} launches={} native_level_calls={}\n", .{ total_timer.read(), alloc_ns, seed_upload_ns, seed_enqueue_ns, static_ingress_ns, levels_enqueue_ns, levels_join_ns, status_ns, reference_readback_ns, try recorder.milliseconds(.seed), try recorder.milliseconds(.levels), launches, launches - 1 });
        std.debug.print("GPU_OUTER_ASSIGNMENT variables={} seed_words={} static_words={} levels={} full_assignment_upload_words=0\n", .{ self.count, self.seeds.len * 5, task_words.len + self.indices.len, self.plan.level_ends.len });
        return values;
    }
};

test "production trace factory refuses partial generation capability masks" {
    for ([_]u32{ 0, 0xfff, 0x7fff, 0xfffe }) |mask| try std.testing.expectError(error.UnsupportedCircuitAssignmentHint, requireProductionMask(mask));
    try requireProductionMask(0xffff);
    try requireProductionMask(0x1ffff);
}
