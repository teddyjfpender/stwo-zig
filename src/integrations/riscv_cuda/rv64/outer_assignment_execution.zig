//! Execution-phase owner: borrowed assignment plan, device leases, launch ordering and checked readback.
const Schema = @import("outer_assignment.zig");
const std = @import("std");
const SC = @import("session_context.zig");
const N = @import("pcs_native_abi.zig");
const Recorder = Events.RecorderFor(Span);
const Events = @import("cuda_events.zig");
const Span = enum { seed, levels };

pub const Execution = struct {
    prepared: *const Schema.Prepared,
    fn key(self: *const Execution, fixed: [32]u8, kind: u32) [8]u32 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&fixed);
        hash.update(&self.prepared.identity);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, kind, .little);
        hash.update(&bytes);
        const digest = hash.finalResult();
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        return words;
    }
    fn prefillSample(self: *const Execution, owner: anytype, ctx: *SC.Context, values: N.Lease, status: N.Lease) !void {
        const outputs = self.prepared.blake_sample_outputs orelse return;
        const inputs = self.prepared.blake_sample_inputs orelse return error.MissingBlakeSampleInputs;
        if (outputs.len != inputs.len or outputs.len == 0) return error.BlakeSampleInputCountMismatch;
        const Fn = *const fn (*anyopaque, u32, [*]u32, u32, [*]const u32, [*]const u32, u32, [*]u32) callconv(.c) c_int;
        const kernel = owner.backend.service.library.lookup(Fn, "stwo_circuit_blake_sample_prefill_on") orelse return error.MissingBlakeSamplePrefillKernel;
        var tape = try ctx.allocate(inputs.len * 26, 0);
        defer ctx.release(&tape) catch {};
        var map = try ctx.allocate(outputs.len, 0);
        defer ctx.release(&map) catch {};
        try ctx.upload(try ctx.borrow(tape), @as([*]const u32, @ptrCast(inputs.ptr))[0 .. inputs.len * 26]);
        try ctx.upload(try ctx.borrow(map), outputs);
        // Seed kernel is lane1; uploads are lane0. Join before cross-lane use.
        try ctx.join();
        if (kernel(ctx.native_context, 1, values.words.?, @intCast(self.prepared.count), tape.words.?, map.words.?, @intCast(inputs.len), status.words.?) != 0) return error.CudaBlakeSamplePrefillFailed;
        // Keep both request leases live until this numerical kernel completes.
        try ctx.join();
        std.debug.print("BLAKE_SAMPLE_PREFILL records={} gg_rows={} original_air=true\n", .{ inputs.len, inputs.len * 80 });
    }
    pub fn generate(self: *const Execution, owner: anytype, ctx: *SC.Context) !N.Lease {
        const graph_enabled = try @import("assignment_graphs.zig").enabled();
        const service = owner.backend.service;
        var total_timer = try std.time.Timer.start();
        var timer = try std.time.Timer.start();
        var recorder = try Recorder.init(&self.prepared.timing_api);
        defer recorder.deinit();
        var stream: ?*anyopaque = null;
        if (owner.backend.api.lane_stream(ctx.native_context, 1, &stream) != 0 or stream == null) return error.InvalidLane;
        const lane = stream.?;
        var values = try ctx.allocate(self.prepared.count * 4, 0);
        errdefer ctx.release(&values) catch {};
        var status = try ctx.allocate(1, 0);
        defer ctx.release(&status) catch {};
        var seed_lease = try ctx.allocate(self.prepared.seeds.len * 5, 0);
        defer ctx.release(&seed_lease) catch {};
        const alloc_ns = timer.lap();
        try ctx.upload(try ctx.borrow(seed_lease), @as([*]const u32, @ptrCast(self.prepared.seeds.ptr))[0 .. self.prepared.seeds.len * 5]);
        try ctx.upload(try ctx.borrow(status), &.{0});
        var job: Schema.Job = .{ .values = values.words.?, .records = seed_lease.words.?, .indices = null, .status = @ptrCast(status.words.?), .value_count = @intCast(self.prepared.count), .record_count = @intCast(self.prepared.seeds.len), .index_count = 0, .first = 0, .count = @intCast(self.prepared.seeds.len) };
        try ctx.join();
        const seed_upload_ns = timer.lap();
        try recorder.mark(.seed, false, lane);
        if (self.prepared.seed(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
        try recorder.mark(.seed, true, lane);
        const seed_enqueue_ns = timer.lap();
        try self.prefillSample(owner, ctx, values, status);
        const task_words = @as([*]const u32, @ptrCast(self.prepared.tasks.ptr))[0 .. self.prepared.tasks.len * 8];
        var one_shot: [3]?N.Lease = .{ null, null, null };
        defer for (&one_shot) |*lease| if (lease.*) |*l| ctx.release(l) catch {};
        const Static = struct {
            fn words(prepared: *const Schema.Prepared, c: *SC.Context, svc: anytype, slot: *?N.Lease, fixed: [32]u8, kind: u32, data: []const u32) !N.Lease {
                if (prepared.reusable) return svc.immutableWords(c.native_context, c.scope, prepared.key(fixed, kind), data);
                slot.* = try c.allocate(data.len, 0);
                try c.upload(try c.borrow(slot.*.?), data);
                return slot.*.?;
            }
        };
        const tasks = try Static.words(self, ctx, service, &one_shot[0], owner.initial_scope.fixed, 0, task_words);
        const indices: ?N.Lease = if (self.prepared.indices.len == 0) null else try Static.words(self, ctx, service, &one_shot[1], owner.initial_scope.fixed, 1, self.prepared.indices);
        job.records = tasks.words.?;
        job.record_count = @intCast(self.prepared.tasks.len);
        if (indices) |lease| {
            job.indices = lease.words.?;
            job.index_count = @intCast(self.prepared.indices.len);
        }
        // Chain runs read the plan's absolute level ends from the device.
        var chain_ends: ?N.Lease = null;
        if (self.prepared.narrow_plan) |plan| {
            var need_ends = graph_enabled;
            for (plan.runs) |run| if (run.kind == .chain) {
                need_ends = true;
                break;
            };
            if (need_ends) chain_ends = try Static.words(self, ctx, service, &one_shot[2], owner.initial_scope.fixed, 2, plan.ends);
        }
        try ctx.join();
        const static_ingress_ns = timer.lap();
        try recorder.mark(.levels, false, lane);
        var launches: usize = 1;
        var ordinary_level_calls: usize = 0;
        var narrow_run_calls: usize = 0;
        var chain_run_calls: usize = 0;
        if (graph_enabled) {
            const plan = self.prepared.narrow_plan orelse return error.AssignmentGraphRequiresChainPlan;
            if (self.prepared.wide_level == null or self.prepared.chain_run == null) return error.AssignmentGraphRequiresChainPlan;
            const Graphs = @import("assignment_graphs.zig");
            const sequence = try Graphs.steps(self.prepared.allocator, &plan);
            defer self.prepared.allocator.free(sequence);
            job.first = 0;
            job.count = job.record_count;
            const hit = try owner.backend.assignment_graphs.run(owner.backend.allocator, &service.library, ctx, self.prepared.identity, sequence, &job, .{ .values = values, .tasks = tasks, .indices = indices, .status = status, .ends = chain_ends.? }, plan.ends.len);
            std.debug.print("GPU_OUTER_ASSIGNMENT_GRAPH hit={} nodes={} launches=1 fresh_pointers=true\n", .{ hit, sequence.len });
            launches += 1;
        } else if (self.prepared.narrow_plan) |plan| {
            for (plan.runs) |run| {
                job.first = run.first_task;
                job.count = run.task_count;
                const status_code = switch (run.kind) {
                    .narrow => blk: {
                        const function = self.prepared.narrow_run orelse return error.MissingCircuitAssignmentNarrowRunKernel;
                        narrow_run_calls += 1;
                        break :blk function(ctx.native_context, 1, &job, plan.ends[run.first_level..].ptr, run.level_count);
                    },
                    .chain => blk: {
                        const function = self.prepared.chain_run orelse return error.MissingCircuitAssignmentChainKernel;
                        const ends = chain_ends orelse return error.MissingCircuitAssignmentChainKernel;
                        chain_run_calls += 1;
                        break :blk function(ctx.native_context, 1, &job, ends.words.?, run.first_level, run.level_count);
                    },
                    .ordinary => blk: {
                        ordinary_level_calls += 1;
                        break :blk (self.prepared.wide_level orelse self.prepared.level)(ctx.native_context, 1, &job);
                    },
                };
                if (status_code != 0) return error.CudaCircuitAssignmentFailed;
                launches += 1;
            }
        } else {
            var begin: usize = 0;
            for (self.prepared.plan.level_ends) |end| {
                if (end != begin) {
                    job.first = @intCast(begin);
                    job.count = @intCast(end - begin);
                    if (self.prepared.level(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
                    launches += 1;
                    ordinary_level_calls += 1;
                }
                begin = end;
            }
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
        if (self.prepared.check_reference) {
            const observed = try self.prepared.allocator.alloc(u32, self.prepared.count * 4);
            defer self.prepared.allocator.free(observed);
            try ctx.download(try ctx.borrow(values), observed);
            try ctx.join();
            const expected = @as([*]const u32, @ptrCast(self.prepared.reference orelse return error.CircuitAssignmentReferenceUnavailable))[0 .. self.prepared.count * 4];
            if (!std.mem.eql(u32, observed, expected)) return error.CircuitDeviceAssignmentMismatch;
        }
        const reference_readback_ns = timer.lap();
        // Event spans include enqueue starvation; they are not sums of
        // individual kernel durations. Nsight supplies the latter.
        std.debug.print("GPU_OUTER_ASSIGNMENT_TIMING total_ns={} alloc_ns={} seed_upload_ns={} seed_enqueue_ns={} static_ingress_ns={} levels_enqueue_ns={} levels_join_ns={} status_ns={} reference_readback_ns={} seed_stream_ms={d:.3} levels_stream_ms={d:.3} launches={} native_level_calls={} ordinary_level_calls={} narrow_run_calls={} chain_run_calls={}\n", .{ total_timer.read(), alloc_ns, seed_upload_ns, seed_enqueue_ns, static_ingress_ns, levels_enqueue_ns, levels_join_ns, status_ns, reference_readback_ns, try recorder.milliseconds(.seed), try recorder.milliseconds(.levels), launches, launches - 1, ordinary_level_calls, narrow_run_calls, chain_run_calls });
        std.debug.print("GPU_OUTER_ASSIGNMENT variables={} seed_words={} static_words={} levels={} full_assignment_upload_words=0\n", .{ self.prepared.count, self.prepared.seeds.len * 5, task_words.len + self.prepared.indices.len, self.prepared.plan.level_ends.len });
        return values;
    }
};
