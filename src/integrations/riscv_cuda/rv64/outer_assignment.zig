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
const Pack = @import("outer_assignment_pack.zig");
const Runs = @import("assignment_runs.zig");
pub const Task = Pack.Task;
pub const Seed = extern struct { out: u32, value: [4]u32 };
pub const Job = extern struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32, record_count: u32, index_count: u32, first: u32, count: u32, reserved: u32 = 0 };
pub const Launch = *const fn (*anyopaque, u32, *const Job) callconv(.c) c_int;
pub const LaunchRun = *const fn (*anyopaque, u32, *const Job, [*]const u32, u32) callconv(.c) c_int;
pub fn requireProductionMask(mask: u32) !void {
    if (mask & 0xffff != 0xffff) return error.UnsupportedCircuitAssignmentHint;
}
pub fn requireProductionCapabilities(library: *std.DynLib) !void {
    _ = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
    _ = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
    const query = library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities") orelse return error.MissingCircuitAssignmentKernel;
    try requireProductionMask(query());
}
/// Producer-only, in-process fold-class assignment templates. A v2 fold's
/// topology is a function of its class (om31_outer.classKey), so tasks,
/// permutation indices, level ends and the seed-variable layout are reused;
/// only seed VALUES are re-read from the new graph. Proof-neutral: an equal
/// plan yields the equal assignment. A wrong reuse cannot be accepted (the
/// receiver checks every proof under its own authority) and the seed-layout
/// check below rejects any graph whose constants/guesses differ in layout.
/// STWO_RV64_OUTER_PLAN_CLASS_CACHE=0 off, =check rebuild+compare, default on.
pub const ClassCache = struct {
    pub const Mode = enum { off, on, check };
    const Template = struct { key: [32]u8, n_vars: u32, n_constants: usize, n_origins: usize, seed_vars: []u32, tasks: []Task, indices: []u32, level_ends: []usize, identity: [32]u8, bytes: usize };
    const gpa = std.heap.smp_allocator;
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayListUnmanaged(*Template) = .empty;
    var held_bytes: usize = 0;
    pub var hits: usize = 0;
    pub var misses: usize = 0;
    pub var checked: usize = 0;
    pub fn mode() Mode {
        const value = std.posix.getenv("STWO_RV64_OUTER_PLAN_CLASS_CACHE") orelse return .on;
        if (std.mem.eql(u8, value, "0")) return .off;
        if (std.mem.eql(u8, value, "check")) return .check;
        return .on;
    }
    fn limit() usize {
        const value = std.posix.getenv("STWO_RV64_OUTER_PLAN_CLASS_CACHE_BYTES") orelse return 6 << 30;
        return std.fmt.parseUnsigned(usize, value, 10) catch 6 << 30;
    }
    fn find(key: [32]u8) ?*Template {
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |t| if (std.mem.eql(u8, &t.key, &key)) return t;
        return null;
    }
    fn originCount(ctx: *const Circuit.builder.Context(Q)) usize {
        return if (ctx.witness_metadata) |m| m.origins.items.len else 0;
    }
    /// Same order as witness_plan.buildImpl: constants, then seed origins.
    fn seedsFor(a: std.mem.Allocator, t: *const Template, ctx: *const Circuit.builder.Context(Q)) ![]Seed {
        if (ctx.circuit.n_vars != t.n_vars or ctx.constants.count() != t.n_constants or originCount(ctx) != t.n_origins) return error.PlanClassShapeMismatch;
        const seeds = try a.alloc(Seed, t.seed_vars.len);
        errdefer a.free(seeds);
        var i: usize = 0;
        for (ctx.constants.keys(), ctx.constants.values()) |key, variable| {
            if (i >= seeds.len or t.seed_vars[i] != variable.idx) return error.PlanClassSeedLayout;
            seeds[i] = .{ .out = variable.idx, .value = Circuit.builder.ivalue.limbs(Circuit.builder.context.constantFromKey(key)) };
            i += 1;
        }
        for (ctx.witness_metadata.?.origins.items) |origin| if (origin.kind == .seed) {
            if (i >= seeds.len or t.seed_vars[i] != origin.out) return error.PlanClassSeedLayout;
            seeds[i] = .{ .out = origin.out, .value = Circuit.builder.ivalue.limbs(origin.value) };
            i += 1;
        };
        if (i != seeds.len) return error.PlanClassSeedLayout;
        return seeds;
    }
    fn insert(key: [32]u8, p: *const Prepared, ctx: *const Circuit.builder.Context(Q)) void {
        insertImpl(key, p, ctx) catch |err| std.debug.print("GPU_OUTER_PLAN_CLASS insert_error={s}\n", .{@errorName(err)});
    }
    fn insertImpl(key: [32]u8, p: *const Prepared, ctx: *const Circuit.builder.Context(Q)) !void {
        const bytes = p.tasks.len * @sizeOf(Task) + p.indices.len * 4 + p.plan.level_ends.len * @sizeOf(usize) + p.seeds.len * 4;
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |t| if (std.mem.eql(u8, &t.key, &key)) return;
        if (held_bytes + bytes > limit()) return;
        const t = try gpa.create(Template);
        errdefer gpa.destroy(t);
        const seed_vars = try gpa.alloc(u32, p.seeds.len);
        errdefer gpa.free(seed_vars);
        for (seed_vars, p.seeds) |*out, seed| out.* = seed.out;
        const tasks = try gpa.dupe(Task, p.tasks);
        errdefer gpa.free(tasks);
        const indices = try gpa.dupe(u32, p.indices);
        errdefer gpa.free(indices);
        const level_ends = try gpa.dupe(usize, p.plan.level_ends);
        errdefer gpa.free(level_ends);
        t.* = .{ .key = key, .n_vars = ctx.circuit.n_vars, .n_constants = ctx.constants.count(), .n_origins = originCount(ctx), .seed_vars = seed_vars, .tasks = tasks, .indices = indices, .level_ends = level_ends, .identity = p.identity, .bytes = bytes };
        try entries.append(gpa, t);
        held_bytes += bytes;
    }
};
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
    narrow_plan: ?Runs.Plan = null,
    narrow_run: ?LaunchRun = null,
    /// tasks/indices/plan.level_ends are owned by a ClassCache template.
    borrowed: bool = false,
    pub fn init(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib) !Prepared {
        const cache_mode = ClassCache.mode();
        const hint = if (cache_mode == .off) null else @import("stwo_circuit_cpu_integration").om31.device_prove.class_hint;
        const template = if (hint) |class_key| ClassCache.find(class_key) else null;
        if (template) |t| if (cache_mode == .on) return initFromTemplate(a, ctx, library, t);
        var fresh = try initFull(a, ctx, library);
        errdefer fresh.deinit();
        if (template) |t| {
            // check mode: the template must equal the freshly built plan.
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(t.tasks), std.mem.sliceAsBytes(fresh.tasks)) or !std.mem.eql(u32, t.indices, fresh.indices) or !std.mem.eql(usize, t.level_ends, fresh.plan.level_ends) or !std.mem.eql(u8, &t.identity, &fresh.identity)) return error.PlanClassMismatch;
            const seeds = try ClassCache.seedsFor(a, t, ctx);
            defer a.free(seeds);
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(seeds), std.mem.sliceAsBytes(fresh.seeds))) return error.PlanClassMismatch;
            ClassCache.mutex.lock();
            ClassCache.checked += 1;
            ClassCache.mutex.unlock();
            std.debug.print("GPU_OUTER_PLAN_CLASS check_ok class={x}\n", .{t.key[0..8]});
        } else if (hint) |class_key| {
            ClassCache.insert(class_key, &fresh, ctx);
            ClassCache.mutex.lock();
            ClassCache.misses += 1;
            ClassCache.mutex.unlock();
        }
        return fresh;
    }
    fn initFromTemplate(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib, t: *const ClassCache.Template) !Prepared {
        var timer = try std.time.Timer.start();
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        const option = std.process.getEnvVarOwned(a, "STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (option) |value| a.free(value);
        const enabled = try Runs.parseOptIn(option);
        const narrow_run = library.lookup(LaunchRun, "stwo_circuit_assignment_narrow_run_on");
        if (enabled and narrow_run == null) return error.MissingCircuitAssignmentNarrowRunKernel;
        const seeds = try ClassCache.seedsFor(a, t, ctx);
        errdefer a.free(seeds);
        var narrow_plan: ?Runs.Plan = if (enabled) try Runs.Plan.init(a, t.level_ends, t.tasks.len) else null;
        errdefer if (narrow_plan) |*value| value.deinit();
        ClassCache.mutex.lock();
        ClassCache.hits += 1;
        ClassCache.mutex.unlock();
        std.debug.print("GPU_OUTER_ASSIGNMENT_PLAN class_cache_hit=true class={x} seeds_ns={} task_bytes={} levels={}\n", .{ t.key[0..8], timer.read(), t.tasks.len * @sizeOf(Task), t.level_ends.len });
        return .{ .allocator = a, .reference = if (ctx.trace_only) null else ctx.values().ptr, .count = ctx.circuit.n_vars, .plan = .{ .allocator = a, .tasks = &.{}, .seeds = &.{}, .level_ends = t.level_ends }, .tasks = t.tasks, .indices = t.indices, .seeds = seeds, .identity = t.identity, .seed = seed, .level = level, .timing_api = try Events.Api.load(library), .narrow_plan = narrow_plan, .narrow_run = narrow_run, .borrowed = true };
    }
    fn initFull(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib) !Prepared {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        const option = std.process.getEnvVarOwned(a, "STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (option) |value| a.free(value);
        const enabled = try Runs.parseOptIn(option);
        const narrow_run = library.lookup(LaunchRun, "stwo_circuit_assignment_narrow_run_on");
        if (enabled and narrow_run == null) return error.MissingCircuitAssignmentNarrowRunKernel;
        var timer = try std.time.Timer.start();
        var metrics: Schedule.BuildMetrics = .{};
        var plan = try Schedule.buildProfiled(a, ctx, &metrics);
        errdefer plan.deinit();
        const plan_ns = timer.lap();
        var narrow_plan: ?Runs.Plan = if (enabled) try Runs.Plan.init(a, plan.level_ends, plan.tasks.len) else null;
        errdefer if (narrow_plan) |*value| value.deinit();
        const level_stats = if (narrow_plan) |value| value.stats else try Runs.inspect(plan.level_ends, plan.tasks.len);
        const run_plan_ns = timer.lap();
        std.debug.print("GPU_OUTER_ASSIGNMENT_LEVELS enabled={} cta_threads={} max_run_levels={} levels={} nonempty={} empty={} width_1_32={} width_33_64={} width_65_128={} width_129_256={} width_gt256={} max_width={} selected_narrow_runs={} selected_narrow_levels={} run_plan_ns={}\n", .{ enabled, Runs.threads, Runs.max_levels, level_stats.levels, level_stats.nonempty, level_stats.empty, level_stats.width_1_32, level_stats.width_33_64, level_stats.width_65_128, level_stats.width_129_256, level_stats.width_gt256, level_stats.max_width, if (narrow_plan) |value| value.narrow_runs else 0, if (narrow_plan) |value| value.narrow_levels else 0, run_plan_ns });

        const tasks = try a.alloc(Task, plan.tasks.len);
        errdefer a.free(tasks);
        var indices: std.ArrayList(u32) = .empty;
        defer indices.deinit(a);
        var permutation_count: usize = 0;
        var max_permutation_inputs: usize = 0;
        var permutation_pair_work: u64 = 0;
        const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
        if (ctx.circuit.permutation.ends.items.len == 0) {
            // Production graphs have no CSR permutation records. Keep every
            // output at its original plan ordinal without a second task copy.
            _ = try Pack.fill(ctx, plan.tasks, tasks, capabilities);
        } else {
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
            for (tasks) |task| if (capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
        }
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
        return .{ .allocator = a, .reference = if (ctx.trace_only) null else ctx.values().ptr, .count = ctx.circuit.n_vars, .plan = plan, .tasks = tasks, .indices = try indices.toOwnedSlice(a), .seeds = seeds, .identity = identity, .seed = seed, .level = level, .timing_api = try Events.Api.load(library), .narrow_plan = narrow_plan, .narrow_run = narrow_run };
    }
    /// Re-resolve kernel entry points against the adopting device's library.
    /// Plan/pack/seed/identity bytes are library independent. The same mapped
    /// image (identical entry points) needs no capability re-check.
    pub fn rebind(self: *Prepared, library: *std.DynLib) !void {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        if (seed == self.seed and level == self.level) return;
        const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
        for (self.tasks) |task| if (capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
        const narrow_run = library.lookup(LaunchRun, "stwo_circuit_assignment_narrow_run_on");
        if (self.narrow_plan != null and narrow_run == null) return error.MissingCircuitAssignmentNarrowRunKernel;
        self.timing_api = try Events.Api.load(library);
        self.seed = seed;
        self.level = level;
        self.narrow_run = narrow_run;
    }
    pub fn deinit(self: *Prepared) void {
        if (self.narrow_plan) |*value| value.deinit();
        if (self.borrowed) {
            self.allocator.free(self.seeds);
            self.* = undefined;
            return;
        }
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
        var ordinary_level_calls: usize = 0;
        var narrow_run_calls: usize = 0;
        if (self.narrow_plan) |plan| {
            for (plan.runs) |run| {
                job.first = run.first_task;
                job.count = run.task_count;
                const status_code = if (run.kind == .narrow) blk: {
                    const function = self.narrow_run orelse return error.MissingCircuitAssignmentNarrowRunKernel;
                    narrow_run_calls += 1;
                    break :blk function(ctx.native_context, 1, &job, plan.ends[run.first_level..].ptr, run.level_count);
                } else blk: {
                    ordinary_level_calls += 1;
                    break :blk self.level(ctx.native_context, 1, &job);
                };
                if (status_code != 0) return error.CudaCircuitAssignmentFailed;
                launches += 1;
            }
        } else {
            var begin: usize = 0;
            for (self.plan.level_ends) |end| {
                if (end != begin) {
                    job.first = @intCast(begin);
                    job.count = @intCast(end - begin);
                    if (self.level(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
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
        std.debug.print("GPU_OUTER_ASSIGNMENT_TIMING total_ns={} alloc_ns={} seed_upload_ns={} seed_enqueue_ns={} static_ingress_ns={} levels_enqueue_ns={} levels_join_ns={} status_ns={} reference_readback_ns={} seed_stream_ms={d:.3} levels_stream_ms={d:.3} launches={} native_level_calls={} ordinary_level_calls={} narrow_run_calls={}\n", .{ total_timer.read(), alloc_ns, seed_upload_ns, seed_enqueue_ns, static_ingress_ns, levels_enqueue_ns, levels_join_ns, status_ns, reference_readback_ns, try recorder.milliseconds(.seed), try recorder.milliseconds(.levels), launches, launches - 1, ordinary_level_calls, narrow_run_calls });
        std.debug.print("GPU_OUTER_ASSIGNMENT variables={} seed_words={} static_words={} levels={} full_assignment_upload_words=0\n", .{ self.count, self.seeds.len * 5, task_words.len + self.indices.len, self.plan.level_ends.len });
        return values;
    }
};

test "production trace factory refuses partial generation capability masks" {
    for ([_]u32{ 0, 0xfff, 0x7fff, 0xfffe }) |mask| try std.testing.expectError(error.UnsupportedCircuitAssignmentHint, requireProductionMask(mask));
    try requireProductionMask(0xffff);
    try requireProductionMask(0x1ffff);
}
