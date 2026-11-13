//! Bounded two-stage producer for the explicitly selected OM services profile.
//! Large inventories require explicit parking and retained/disk/task admission.
//! Those partial bounds exclude setup/capture/PCS scratch; they are not total RSS.
//! Schedule policy is operational; the manifest barrier is not.
const std = @import("std");
const State = @import("coordinator_state.zig");
const Operations = @import("coordinator_operations.zig");
pub const ForEarlySources = Operations.ForEarlySources;
const Operational = ForEarlySources(void, void);

const A = @import("stwo_riscv_frontend").rv64_air;
const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const Advice = @import("../collector.zig").Advice;
const Schedule = @import("../schedule.zig");
const Native = @import("../../../word16_execution/prepared.zig").Prepared;
const CPU = @import("cpu_worker.zig");
const Truth = @import("truth_worker.zig");
const W = @import("worker_protocol.zig");
const Execution = @import("execution.zig");
pub const Options = Operational.Options;
/// Consume prepared CPU traces only through successful original source building;
/// advice and setup remain borrowed. Returned request cell lists are independent.
pub const produce = Operational.produce;
pub const produceWithAuthority = Operational.produceWithAuthority;
/// Borrowed request metadata for pre-key admission. Public cell arrays remain
/// owned by advice; callers must not pass these views to freeRequests.
pub const requestView = State.requestView;
/// The authority is independently derived from trusted setup, never parsed from
/// operational resource JSON or a producer bundle. It stays live through return.
/// Diagnostic only (block_to_inputs harness): runs exactly the stage-one
/// source construction of every worker, in ordinal order, with the same
/// requests/inventory as produce, records source timestamps and drops each
/// source. No proof, manifest or acceptance is produced.
pub const buildInputsOnly = State.buildInputsOnly;
/// Shared declaration routing for producer preflight and actual source building.
pub const routeDword = State.routeDword;
pub const assignSpongeIds = State.assignSpongeIds;
const mainNodes = State.mainNodes;
const admit = Operational.planAdmission;
const produceFrozen = Operational.produceWithPolicy;
pub const Store = @import("../../retained_main_store.zig").Store;
pub const WorkerTiming = State.WorkerTiming;
/// Producer scheduling hook (sched M6 streaming handoff; default null = M5).
/// No proof, manifest or identity byte depends on it. `sealed` runs once on
/// the produce caller thread after the stage-one barrier; `cpu_done` /
/// `truth_done` run on the stage-two worker thread right after that
/// ordinal's encoded result is final (its address is valid only for the call;
/// the heap it references is moved into the returned Bundle). `abort` runs on
/// every error return after `sealed`, before requests or results are freed,
/// and returns only when the consumer no longer reads any of them.
pub const Stream = State.Stream;
/// M8 native-hybrid seam (retired with rv64/native_hybrid.zig; default null = the
/// legacy path, byte for byte). After the global-chi barrier, a CPU ordinal's
/// whole stage two (the replay restore and `CpuWorker.complete`) is replaced
/// by `stage_two`, which proves the segment from the worker's sealed state
/// and the manifest (job runtime; rv64/native_hybrid.zig) and returns exactly
/// the bytes and claims `complete` would. Truth ordinals stay legacy.
pub const NativeStageTwo = State.NativeStageTwo;

pub const Bundle = State.Bundle;
const freeRequests = State.freeRequests;

test "MAIN host accounting accepts a device slot without a dummy host tree" {
    var scheme: W.Scheme = undefined;
    scheme.trees = .empty;
    scheme.device_om31_trace_trees = @splat(null);
    try std.testing.expectError(error.MissingPhysicalMainCommitment, mainNodes(&scheme));
    scheme.device_om31_trace_trees[1] = .{ .root = @splat(0), .columns = &.{} };
    try std.testing.expectEqual(@as(usize, 0), try mainNodes(&scheme));
}

test "device truth barrier contract reduces retained admission without reducing transient tasks" {
    const a = std.testing.allocator;
    const F = @import("coordinator_fixture.zig");
    const Original = @import("../fixture.zig");
    const DS = @import("truth_device_source.zig");
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const pointers = [_]*Native{ &captured.native[0], &captured.native[1] };
    const requests = [_]P.Request{ try requestView(&pointers, &captured.advice, 0), try requestView(&pointers, &captured.advice, 1) };
    const config = try F.config();
    const all_truths = keys.truths();
    var inventory = try Execution.Inventory.initWithAuthority(a, &keys.pointers(), &all_truths, &requests, Original.expectedFor(captured.program.identity), config, null);
    defer inventory.deinit();
    // This admission-only view selects the first real Keccak provider; no
    // incomplete inventory is ever passed to execution or a receiver.
    var view = inventory;
    view.workers = inventory.workers[0..3];
    const truth = all_truths[0..1];
    const policy = @import("child.zig").TreePolicy{ .stream_bottom = true, .tight_admission = true };
    var options = Options{ .gkr_budget = 2 << 30, .global_budget = 1 << 30, .max_retained_frontend_bytes = 4 << 30 };
    var legacy = try admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null);
    defer legacy.deinit(a);
    const Fake = struct {
        fn unused(_: *anyopaque, _: std.mem.Allocator, _: DS.Prepare) !DS.Owner {
            return error.UnusedTestPrepare;
        }
        fn retained(_: *anyopaque, request: DS.RetentionRequest) !DS.Retained {
            return .{ .compact_input_bytes = try DS.compactInputBytes(request.truth), .narrow_metadata_bytes = 4096, .kept_device_bytes = 0, .main_replayed = true };
        }
    };
    var marker: u8 = 0;
    options.truth_device_source_stage = .{ .context = &marker, .prepare = Fake.unused, .retained_upper_bound = Fake.retained };
    var replay = try admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null);
    defer replay.deinit(a);
    try std.testing.expect(replay.retained_bytes < legacy.retained_bytes);
    try std.testing.expectEqualSlices(u64, legacy.stage1, replay.stage1);
    try std.testing.expectEqualSlices(u64, legacy.stage2, replay.stage2);
    options.max_retained_frontend_bytes = legacy.retained_bytes - 1;
    var bounded = try admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null);
    bounded.deinit(a);
    options.truth_device_source_stage = null;
    try std.testing.expectError(error.BoundedWideCoordinatorRetainedLimit, admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null));
}

test "hybrid per-CPU policies preserve complete physical proofs fresh verification and admission OOM ownership" {
    const a = std.testing.allocator;
    const F = @import("coordinator_fixture.zig");
    const Original = @import("../fixture.zig");
    const Child = @import("child.zig");
    var control = try F.Case.init(a);
    defer control.deinit();
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const pointers = [_]*Native{ &captured.native[0], &captured.native[1] };
    const requests = [_]P.Request{ try requestView(&pointers, &captured.advice, 0), try requestView(&pointers, &captured.advice, 1) };
    const config = try F.config();
    const base = Child.TreePolicy{ .stream_bottom = true, .tight_admission = true };
    const p0 = try @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, 2 << 30, 1 << 30, base, 0);
    const p1 = try @import("tree_selection.zig").forCpu(a, keys.cpus[1], requests[1], config, 2 << 30, 1 << 30, base, 0);
    try std.testing.expect(p0.plan.gkr_peak_bytes != p1.plan.gkr_peak_bytes);
    const threshold = @min(p0.plan.gkr_peak_bytes, p1.plan.gkr_peak_bytes);
    var timings: [5]WorkerTiming = undefined;
    var observed: Child.TreePolicy = undefined;
    const options = Options{ .gkr_budget = 2 << 30, .checkpoint_above_gkr_bytes = threshold, .worker_timings = &timings, .observed_tree_policy = &observed, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } };
    const expected = Original.expectedFor(captured.program.identity);
    var inventory = try Execution.Inventory.initWithAuthority(a, &keys.pointers(), &keys.truths(), &requests, expected, config, null);
    defer inventory.deinit();
    const AdmissionContext = struct {
        setups: []const *const R.CpuSetup,
        truths: []const R.Truth,
        requests: []const P.Request,
        inventory: *const Execution.Inventory,
        config: W.PcsConfig,
        options: Options,
        policy: Child.TreePolicy,
        fn run(allocator: std.mem.Allocator, context: @This()) !void {
            const value = try admit(allocator, context.setups, context.truths, context.requests, context.inventory, context.config, context.options, context.policy, &.{}, null);
            defer value.deinit(allocator);
        }
    };
    const setup_pointers = keys.pointers();
    const truths = keys.truths();
    try std.testing.checkAllAllocationFailures(a, AdmissionContext.run, .{AdmissionContext{ .setups = &setup_pointers, .truths = &truths, .requests = &requests, .inventory = &inventory, .config = config, .options = options, .policy = base }});
    // A selected non-checkpoint CPU may not silently switch after its budget
    // fails, even when checkpointing would have fit.
    try std.testing.expectError(error.LocalGkrBudgetExceeded, @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, p0.plan.gkr_peak_bytes - 1, 1 << 30, base, std.math.maxInt(usize)));
    const checkpoint_plan = try @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, 2 << 30, 1 << 30, base, 1);
    try std.testing.expect(checkpoint_plan.plan.gkr_peak_bytes < p0.plan.gkr_peak_bytes);
    const between = checkpoint_plan.plan.gkr_peak_bytes + (p0.plan.gkr_peak_bytes - checkpoint_plan.plan.gkr_peak_bytes) / 2;
    const admitted_below_dense = try @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, between, 1 << 30, base, 1);
    try std.testing.expect(admitted_below_dense.policy.checkpointed and admitted_below_dense.plan.gkr_peak_bytes <= between);
    var conflicting = base;
    conflicting.checkpointed = true;
    try std.testing.expectError(error.InvalidHybridGkrTreePolicy, produceFrozen(a, &setup_pointers, &truths, &pointers, &captured.advice, expected, config, options, null, conflicting));
    try std.testing.expect(captured.native[0].cpu != null and captured.native[1].cpu != null);
    var bundle = try produceFrozen(a, &setup_pointers, &truths, &pointers, &captured.advice, expected, config, options, null, base);
    defer bundle.deinit(a);
    try std.testing.expectEqualDeep(base, observed);
    for (timings, 0..) |timing, i| {
        if (i < 2) {
            const peak = if (i == 0) p0.plan.gkr_peak_bytes else p1.plan.gkr_peak_bytes;
            const selected = try @import("tree_selection.zig").resolve(base, threshold, peak);
            try std.testing.expectEqualDeep(selected, timing.resolved_tree_policy.?);
            const selected_plan = try @import("tree_selection.zig").forCpu(a, keys.cpus[i], requests[i], config, options.gkr_budget, options.global_budget, base, threshold);
            try std.testing.expectEqual(selected_plan.plan.gkr_peak_bytes, timing.admitted_gkr_peak_bytes);
            try std.testing.expect(timing.including_binding_requested_peak_bytes <= timing.admitted_gkr_peak_bytes);
            try std.testing.expect(timing.gkr_allocator_limit_bytes <= options.gkr_budget);
        } else try std.testing.expect(timing.resolved_tree_policy == null);
    }
    try std.testing.expect(timings[0].resolved_tree_policy.?.checkpointed != timings[1].resolved_tree_policy.?.checkpointed);
    try std.testing.expectEqualSlices(u8, control.bundle.stage_one_bytes, bundle.stage_one_bytes);
    for (control.bundle.cpus, bundle.cpus) |before, after| {
        try std.testing.expectEqualSlices(u8, before.bytes, after.bytes);
        try std.testing.expectEqualDeep(before.claims, after.claims);
    }
    for (control.bundle.truths, bundle.truths) |before, after| try std.testing.expectEqualSlices(u8, before.bytes, after.bytes);
    var fresh = try F.Keys.init(a);
    defer fresh.deinit();
    const result = try bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, config);
    try std.testing.expect(result.completed);
    // Fail the next allocation only after CPU0 has a complete owned child and
    // physical MAIN. The serial outer lane then fails CPU1, exercising teardown
    // of live workers, frozen policy storage and every pending owner together.
    var failure_timings: [5]WorkerTiming = @splat(.{});
    var failing = HybridFailureAllocator{ .child = a, .first = &failure_timings[0] };
    var failed_capture = try Original.Captured.init(failing.allocator());
    defer failed_capture.deinit();
    var failure_options = options;
    failure_options.worker_timings = &failure_timings;
    failure_options.schedule = .{ .lanes = 1, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 };
    try std.testing.expectError(error.OutOfMemory, produceFrozen(failing.allocator(), &setup_pointers, &truths, &.{ &failed_capture.native[0], &failed_capture.native[1] }, &failed_capture.advice, expected, config, failure_options, null, base));
    try std.testing.expect(failure_timings[0].stage1_completed and !failure_timings[1].stage1_completed);
}

const HybridFailureAllocator = struct {
    child: std.mem.Allocator,
    first: *const WorkerTiming,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return if (self.first.stage1_completed) null else self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return !self.first.stage1_completed and self.child.rawResize(memory, alignment, len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return if (self.first.stage1_completed) null else self.child.rawRemap(memory, alignment, len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};
