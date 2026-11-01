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
const Resource = @import("resource.zig");
pub const Options = struct {
    max_workers: usize = 8,
    /// Frontend MAIN/backing+binding admission, excluding independently owned setup
    /// and proof-engine scratch. This is not a total-RSS or device-memory claim.
    max_retained_frontend_bytes: usize = 512 << 20,
    gkr_budget: usize = 512 << 20,
    global_budget: usize = 1 << 30,
    schedule: Schedule.Policy = .{ .lanes = 1, .workers_per_lane = 2 },
    fn validate(self: Options, count: usize) !void {
        if (self.max_workers == 0 or self.max_workers > 8 or count > self.max_workers or self.max_retained_frontend_bytes == 0 or self.gkr_budget == 0 or self.global_budget == 0) return error.BoundedWideCoordinatorLimit;
        try self.schedule.validate();
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
        if (index < self.setups.len) {
            var source = try Pipeline.buildCpuSource(self.a, self.setups[index], self.requests[index], self.native[index], self.advice, index, self.inventory.first_ids[index], false, null);
            var owned = true;
            errdefer if (owned) source.deinit();
            const worker = try CPU.CpuWorker.init(self.a, self.setups[index], self.requests[index], source, self.inventory.workers[index], self.config, self.inventory.first_ids[index], self.options.gkr_budget);
            owned = false;
            self.workers[index] = .{ .cpu = worker };
            self.stages[index] = try self.workers[index].?.cpu.seal(self.a);
            try self.workers[index].?.cpu.retireLocalMetadata();
        } else {
            const truth = self.truths[index - self.setups.len];
            var source = try R.TruthSource.init(self.a, truth, self.advice);
            var owned = true;
            errdefer if (owned) source.deinit();
            const worker = try Truth.TruthWorker.init(self.a, truth, source, self.inventory.workers[index], self.config, self.options.global_budget);
            owned = false;
            self.workers[index] = .{ .truth = worker };
            self.stages[index] = try self.workers[index].?.truth.seal(self.a);
        }
    }
    fn stageTwo(self: *Run, index: usize) !void {
        const worker = if (self.workers[index]) |*v| v else return error.MissingWideCoordinatorWorker;
        const pending = self.pending orelse return error.MissingWideCoordinatorManifest;
        self.results[index] = switch (worker.*) {
            .cpu => |*v| .{ .cpu = try v.complete(self.a, pending, index, self.options.global_budget) },
            .truth => |*v| .{ .truth = try v.complete(self.a, pending, index, self.options.global_budget) },
        };
    }
};
/// Consume prepared CPU traces only through successful original source building;
/// advice and setup remain borrowed. Returned request cell lists are independent.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options) !Bundle {
    const count = try std.math.add(usize, setups.len, truths.len);
    try options.validate(count);
    if (setups.len == 0 or setups.len != native.len or native.len != advice.events.len or native.len != advice.keccak.len or native.len != advice.secp.len) return error.InvalidCombinedInventory;
    const requests = try requestsFrom(a, native, advice);
    errdefer freeRequests(a, requests);
    var inventory = try Execution.Inventory.init(a, setups, truths, requests, expected, config);
    defer inventory.deinit();
    const estimates = try admit(a, setups, truths, &inventory, options);
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
fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, inventory: *const Execution.Inventory, options: Options) ![]u64 {
    const estimates = try a.alloc(u64, inventory.workers.len);
    errdefer a.free(estimates);
    var retained: usize = 0;
    for (estimates, 0..) |*estimate, i| {
        const logs = if (i < setups.len) try setups[i].logs(a, 1) else try truths[i - setups.len].logs(a, 1);
        defer a.free(logs);
        var main: usize = 0;
        for (logs) |log| {
            if (log > 26) return error.BoundedWideCoordinatorLimit;
            main = try std.math.add(usize, main, try std.math.mul(usize, @as(usize, 1) << @intCast(log), 8));
        }
        var binding: usize = 0;
        var peak: usize = 0;
        if (i < setups.len) {
            const plan = try Resource.Plan.forInstances(inventory.instances[i], options.gkr_budget);
            binding = plan.binding_bytes;
            peak = plan.peak_bytes;
        }
        retained = try std.math.add(usize, retained, try std.math.add(usize, main, binding));
        estimate.* = try std.math.add(u64, @intCast(main), @intCast(@max(peak, options.global_budget)));
    }
    if (retained > options.max_retained_frontend_bytes) return error.BoundedWideCoordinatorRetainedLimit;
    return estimates;
}
