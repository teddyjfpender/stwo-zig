//! Bounded two-stage producer for the explicitly selected OM services profile.
//! This initial retained-owner coordinator rejects block-size inventories until
//! parking is wired. Schedule policy is operational; the manifest barrier is not.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const Pipeline = @import("../pipeline.zig");
const Advice = @import("../collector.zig").Advice;
const Schedule = @import("../schedule.zig");
const Native = @import("../../../word16_execution/prepared.zig").Prepared;
const CPU = @import("cpu_worker.zig");
const Truth = @import("truth_worker.zig");
const W = @import("worker_protocol.zig");
const Manifest = @import("manifest.zig");
const ManifestWire = @import("manifest_wire.zig");
const Execution = @import("execution.zig");
const Retention = @import("retention_plan.zig");
const TruthRetention = @import("truth_retention.zig");
pub const Store = @import("../../retained_main_store.zig").Store;
pub const WorkerTiming = struct {
    source_ns: u64 = 0,
    seal_native_and_gkr_ns: u64 = 0,
    main_commit_ns: u64 = 0,
    gkr_ns: u64 = 0,
    metadata_retire_ns: u64 = 0,
    spill_ns: u64 = 0,
    restore_ns: u64 = 0,
    native_complete_ns: u64 = 0,
    stage1_ns: u64 = 0,
    stage2_ns: u64 = 0,
    actual_main_merkle_bytes: usize = 0,
    stage1_completed: bool = false,
    stage2_completed: bool = false,
};
pub const Options = struct {
    max_workers: usize = 8,
    /// Frontend MAIN/backing+binding admission, excluding independently owned setup
    /// and proof-engine scratch. This is not a total-RSS or device-memory claim.
    max_retained_frontend_bytes: usize = 512 << 20,
    gkr_budget: usize = 512 << 20,
    global_budget: usize = 1 << 30,
    retained_store: ?*Store = null,
    worker_timings: ?[]WorkerTiming = null,
    schedule: Schedule.Policy = .{ .lanes = 1, .workers_per_lane = 2 },
    pub fn validate(self: Options, count: usize) !void {
        if (self.max_workers == 0 or self.max_workers > Manifest.MAX_WORKERS or count > self.max_workers or self.max_retained_frontend_bytes == 0 or self.gkr_budget == 0 or self.global_budget == 0) return error.BoundedWideCoordinatorLimit;
        if (self.worker_timings) |timings| if (timings.len != count) return error.InvalidWideCoordinatorTimings;
        try self.schedule.validate();
        if (self.retained_store) |store| {
            if (!store.stats().parking_enabled or self.schedule.memory_cap_bytes == 0) return error.WideCoordinatorRequiresParkingAdmission;
        } else if (self.max_workers > 8) return error.BoundedWideCoordinatorLimit;
    }
};
pub const Bundle = struct {
    requests: []P.Request,
    stage_one_bytes: []u8,
    cpus: []CPU.CpuEncoded,
    truths: []Truth.TruthEncoded,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.cpus) |*v| v.deinit(a);
        for (self.truths) |*v| v.deinit(a);
        a.free(self.cpus);
        a.free(self.truths);
        a.free(self.stage_one_bytes);
        freeRequests(a, self.requests);
        self.* = undefined;
    }
    pub fn verify(self: *const Bundle, a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, config: W.PcsConfig) !Execution.Verified {
        return Execution.verify(a, setups, truths, self.requests, expected, config, self.stage_one_bytes, self.cpus, self.truths);
    }
};
fn freeRequests(a: std.mem.Allocator, requests: []P.Request) void {
    for (requests) |r| {
        a.free(r.base.memory.initial);
        a.free(r.base.memory.terminal);
    }
    a.free(requests);
}
fn requestsFrom(a: std.mem.Allocator, native: []const *Native, advice: *const Advice) ![]P.Request {
    const requests = try a.alloc(P.Request, native.len);
    errdefer a.free(requests);
    var done: usize = 0;
    errdefer for (requests[0..done]) |r| {
        a.free(r.base.memory.initial);
        a.free(r.base.memory.terminal);
    };
    for (native, requests, 0..) |n, *r, i| {
        const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
        const initial = try a.dupe(A.memory.closed_ram.types.Cell, if (i == 0) advice.initial else &.{});
        errdefer a.free(initial);
        const terminal = try a.dupe(A.memory.closed_ram.types.Cell, if (i + 1 == native.len) advice.terminal else &.{});
        r.* = .{ .calls = .{ @intCast(advice.keccak[i].len), @intCast(advice.secp[i][0].len), @intCast(advice.secp[i][1].len) }, .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = initial, .terminal = terminal, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[i].len) } } };
        done += 1;
    }
    return requests;
}
const Worker = union(enum) {
    cpu: CPU.CpuWorker,
    truth: Truth.TruthWorker,
    fn deinit(self: *Worker, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*v| v.deinit(a),
        }
    }
};
const Result = union(enum) {
    cpu: CPU.CpuEncoded,
    truth: Truth.TruthEncoded,
    fn deinit(self: *Result, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*v| v.deinit(a),
        }
    }
};
const Run = struct {
    a: std.mem.Allocator,
    setups: []const *const R.CpuSetup,
    truths: []const R.Truth,
    native: []const *Native,
    advice: *const Advice,
    requests: []const P.Request,
    inventory: *const Execution.Inventory,
    config: W.PcsConfig,
    options: Options,
    workers: []?Worker,
    stages: []Manifest.StageOne,
    results: []?Result,
    pending: ?*const Manifest.PendingManifest = null,
    fn stageOne(self: *Run, index: usize) !void {
        const timing = if (self.options.worker_timings) |values| &values[index] else null;
        var timer: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
        var total_timer = timer;
        defer if (total_timer) |*clock| {
            timing.?.stage1_ns = clock.read();
        };
        if (index < self.setups.len) {
            var source = try Pipeline.buildCpuSource(self.a, self.setups[index], self.requests[index], self.native[index], self.advice, index, self.inventory.first_ids[index], false, null);
            if (timer) |*clock| timing.?.source_ns = clock.lap();
            var owned = true;
            errdefer if (owned) source.deinit();
            const worker = try CPU.CpuWorker.init(self.a, self.setups[index], self.requests[index], source, self.inventory.workers[index], self.config, self.inventory.first_ids[index], self.options.gkr_budget);
            owned = false;
            self.workers[index] = .{ .cpu = worker };
            var cpu_timing = CPU.SealTiming{};
            self.workers[index].?.cpu.seal_timing = if (timing != null) &cpu_timing else null;
            defer self.workers[index].?.cpu.seal_timing = null;
            self.stages[index] = try self.workers[index].?.cpu.seal(self.a);
            if (timer) |*clock| {
                timing.?.seal_native_and_gkr_ns = clock.lap();
                timing.?.main_commit_ns = cpu_timing.main_commit_ns;
                timing.?.gkr_ns = cpu_timing.gkr_ns;
                timing.?.actual_main_merkle_bytes = try mainNodes(&self.workers[index].?.cpu.scheme);
            }
            try self.workers[index].?.cpu.retireLocalMetadata();
            if (timer) |*clock| timing.?.metadata_retire_ns = clock.lap();
            if (self.options.retained_store) |store| _ = try self.workers[index].?.cpu.spillMain(store);
        } else {
            const truth = self.truths[index - self.setups.len];
            var source = try R.TruthSource.init(self.a, truth, self.advice);
            if (timer) |*clock| timing.?.source_ns = clock.lap();
            var owned = true;
            errdefer if (owned) source.deinit();
            const worker = try Truth.TruthWorker.init(self.a, truth, source, self.inventory.workers[index], self.config, self.options.global_budget);
            owned = false;
            self.workers[index] = .{ .truth = worker };
            self.stages[index] = try self.workers[index].?.truth.seal(self.a);
            if (timer) |*clock| {
                timing.?.seal_native_and_gkr_ns = clock.lap();
                timing.?.main_commit_ns = timing.?.seal_native_and_gkr_ns;
                timing.?.actual_main_merkle_bytes = try mainNodes(&self.workers[index].?.truth.scheme);
            }
            if (self.options.retained_store) |store| _ = try self.workers[index].?.truth.spillMain(store);
        }
        if (timer) |*clock| {
            timing.?.spill_ns = clock.lap();
            timing.?.stage1_completed = true;
        }
    }
    fn stageTwo(self: *Run, index: usize) !void {
        const timing = if (self.options.worker_timings) |values| &values[index] else null;
        var timer: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
        var total_timer = timer;
        defer if (total_timer) |*clock| {
            timing.?.stage2_ns = clock.read();
        };
        const worker = if (self.workers[index]) |*v| v else return error.MissingWideCoordinatorWorker;
        const pending = self.pending orelse return error.MissingWideCoordinatorManifest;
        if (self.options.retained_store) |store| switch (worker.*) {
            .cpu => |*v| {
                _ = try v.restoreMain(store);
            },
            .truth => |*v| {
                _ = try v.restoreMain(store);
            },
        };
        if (timer) |*clock| timing.?.restore_ns = clock.lap();
        self.results[index] = switch (worker.*) {
            .cpu => |*v| .{ .cpu = try v.complete(self.a, pending, index, self.options.global_budget) },
            .truth => |*v| .{ .truth = try v.complete(self.a, pending, index, self.options.global_budget) },
        };
        if (timer) |*clock| {
            timing.?.native_complete_ns = clock.lap();
            timing.?.stage2_completed = true;
        }
    }
};
fn mainNodes(scheme: *const W.Scheme) !usize {
    var bytes: usize = 0;
    for (scheme.trees.items[1].commitment.layers) |layer| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, layer.len, @sizeOf(W.H.Hash)));
    return bytes;
}
/// Consume prepared CPU traces only through successful original source building;
/// advice and setup remain borrowed. Returned request cell lists are independent.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options) !Bundle {
    const count = try std.math.add(usize, setups.len, truths.len);
    try options.validate(count);
    if (options.worker_timings) |timings| @memset(timings, .{});
    if (setups.len == 0 or setups.len != native.len or native.len != advice.events.len or native.len != advice.keccak.len or native.len != advice.secp.len) return error.InvalidCombinedInventory;
    const requests = try requestsFrom(a, native, advice);
    errdefer freeRequests(a, requests);
    var inventory = try Execution.Inventory.init(a, setups, truths, requests, expected, config);
    defer inventory.deinit();
    const estimates = try admit(a, setups, truths, requests, &inventory, config, options);
    defer a.free(estimates);
    const workers = try a.alloc(?Worker, count);
    defer a.free(workers);
    @memset(workers, null);
    defer for (workers) |*slot| if (slot.*) |*v| v.deinit(a);
    const stages = try a.alloc(Manifest.StageOne, count);
    defer a.free(stages);
    const results = try a.alloc(?Result, count);
    defer a.free(results);
    @memset(results, null);
    defer for (results) |*slot| if (slot.*) |*v| v.deinit(a);
    var run = Run{ .a = a, .setups = setups, .truths = truths, .native = native, .advice = advice, .requests = requests, .inventory = &inventory, .config = config, .options = options, .workers = workers, .stages = stages, .results = results };
    const run_options = Schedule.RunOptions{ .estimates = if (options.schedule.memory_cap_bytes != 0) estimates else &.{} };
    try Schedule.runWithOptions(Run, a, &run, count, options.schedule, run_options, Run.stageOne);
    // The complete ordered set of sealed MAINs and local children is joined once.
    var pending = try Manifest.verifyAndSeal(a, inventory.execution_identity, inventory.workers, stages);
    defer pending.deinit(a);
    const stage_bytes = try ManifestWire.encode(a, inventory.execution_identity, inventory.workers, stages);
    errdefer a.free(stage_bytes);
    run.pending = &pending;
    try Schedule.runWithOptions(Run, a, &run, count, options.schedule, run_options, Run.stageTwo);
    const cpus = try a.alloc(CPU.CpuEncoded, setups.len);
    errdefer a.free(cpus);
    const encoded_truths = try a.alloc(Truth.TruthEncoded, truths.len);
    errdefer a.free(encoded_truths);
    for (results) |result| if (result == null) return error.MissingWideCoordinatorResult;
    for (cpus, results[0..setups.len]) |*out, result| out.* = result.?.cpu;
    for (encoded_truths, results[setups.len..]) |*out, result| out.* = result.?.truth;
    @memset(results, null);
    return .{ .requests = requests, .stage_one_bytes = stage_bytes, .cpus = cpus, .truths = encoded_truths };
}
fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, inventory: *const Execution.Inventory, config: W.PcsConfig, options: Options) ![]u64 {
    const estimates = try a.alloc(u64, inventory.workers.len);
    errdefer a.free(estimates);
    // Requests are coordinator-owned copies, separate from worker source lists.
    var retained: usize = ManifestWire.MAX_BYTES;
    retained = try std.math.add(usize, retained, try std.math.mul(usize, requests.len, @sizeOf(P.Request)));
    for (requests) |request| retained = try std.math.add(usize, retained, try std.math.mul(usize, request.base.memory.initial.len + request.base.memory.terminal.len, @sizeOf(A.memory.closed_ram.types.Cell)));
    const full_nodes = if (options.retained_store) |store| store.stats().merkle_parking_enabled else false;
    var disk: usize = 0;
    for (estimates, 0..) |*estimate, i| {
        const plan = if (i < setups.len) try Retention.forCpu(a, setups[i], requests[i], config, options.gkr_budget, options.global_budget) else try TruthRetention.forTruth(a, truths[i - setups.len], config, options.global_budget);
        // Preserve the previous conservative task admission, which also reserves
        // the explicit witness cap; partial counters must never tighten it.
        const legacy = try std.math.add(usize, try std.math.mul(usize, plan.coefficient_bytes, 2), @max(plan.gkr_peak_bytes, options.global_budget));
        estimate.* = @intCast(@max(legacy, @max(plan.stage1_task_bytes, plan.stage2_task_bytes)));
        retained = try std.math.add(usize, retained, if (options.retained_store != null) plan.parked_retained_bytes - (if (full_nodes) plan.main_merkle_node_bytes else 0) else @max(plan.resident_retained_bytes, try std.math.add(usize, try std.math.mul(usize, plan.coefficient_bytes, 2), plan.binding_bytes)));
        disk = try std.math.add(usize, disk, try @import("stwo_prover_engine").file_backed_allocator.ReservedFile.roundedLength(try std.math.add(usize, plan.coefficient_bytes, if (full_nodes) try std.math.add(usize, plan.main_merkle_node_bytes, Store.MERKLE_HEADER_BYTES) else 0)));
    }
    if (retained > options.max_retained_frontend_bytes) return error.BoundedWideCoordinatorRetainedLimit;
    if (options.retained_store) |store| {
        const stats = store.stats();
        if (disk > stats.limit_bytes - stats.live_bytes) return error.RetainedMainBudgetExceeded;
    }
    return estimates;
}
