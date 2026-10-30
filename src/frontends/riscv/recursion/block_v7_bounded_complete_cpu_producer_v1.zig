//! Budget-admitted direct windows -> one exact bounded reduction root.
//! Only one direct window retains wide verifier rows/PCS state at a time.
//! The result remains a candidate until the detached complete receiver verifies.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Original = @import("../prover/block_v7_execution_receiver_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Bus = @import("block_v7_mixed_public_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Collection = @import("block_v7_mixed_collection_v1.zig");
const Protocol = @import("block_v7_mixed_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Reduction = @import("block_v7_mixed_batch_producer_v1.zig");
const Receiver = @import("block_v7_mixed_batch_receiver_v1.zig");
const Model = @import("block_v7_parent_resource_model_v1.zig");
const NativeCompilers = @import("block_v7_native_compiler_set_v1.zig");
pub const Options = struct {
    quotient_executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor = null,
    composition_executor: ?*const @import("blake3_parent_composition_executor_v1.zig").Executor = null,
    interaction_executor: ?*const @import("blake3_parent_interaction_executor_v1.zig").Executor = null,
    reuse_native_compiler: bool = false,
    max_native_compiler_bytes: usize = 2 << 30,
    parallel_families: u32 = 1,
    parallel_preparation: usize = 1,
    family_max_bytes: ?usize = null,
    profile: @import("blake3_execution_parent_protocol.zig").Profile,
    capacity: u32 = 2,
    max_originals: usize = 2048,
    max_direct_children: usize = 4,
    max_batches: usize = 32,
    max_metadata_bytes: usize = 1 << 30,
    max_staging_bytes: usize = 512 << 20,
    direct: Model.Limits = .{},
    reduction: Reduction.Limits = .{},
};
pub const WindowStats = struct {
    first: u32,
    count: u32,
    cold_setup_ns: u64,
    capture_prepare_ns: u64,
    key_plan_ns: u64,
    proof_ns: u64,
    encoding_ns: u64,
    resource_retries: usize,
    retained_bytes: usize,
    planned_peak_bytes: usize,
    /// Peak requested bytes charged to this window, not process RSS. Shared
    /// pool/submission owners, metadata and staging may belong to the parent.
    charged_peak_bytes: usize,
    parent_budget_live_before_bytes: ?usize = null,
    parent_budget_live_after_bytes: ?usize = null,
    /// Lifetime cumulative parent peak, not a window-only high-water mark.
    parent_budget_cumulative_peak_bytes: ?usize = null,
    parent_budget_limit_bytes: ?usize = null,
};
pub const Stats = struct { metadata_ns: u64, direct_ns: u64, reduction_ns: u64, whole_ns: u64, staged_peak_bytes: usize };
pub const Output = struct {
    allocator: std.mem.Allocator,
    metadata_budget: *Budget,
    staging_budget: *Budget,
    metadata: *Metadata.Owned,
    counts: []u32,
    pins: []Receiver.DirectPin,
    windows: []WindowStats,
    root: Reduction.Artifact,
    stats: Stats,
    pub fn deinit(self: *Output) void {
        self.root.deinit();
        const stage = self.staging_budget.allocator();
        for (self.pins) |pin| stage.free(pin.wires);
        stage.free(self.pins);
        stage.free(self.counts);
        stage.free(self.windows);
        self.metadata.deinit();
        self.metadata_budget.destroy();
        self.staging_budget.destroy();
        self.* = undefined;
    }
};
const Direct = struct {
    bytes: []u8,
    key: Protocol.Key,
    wires: []Bus.Wire,
    stats: WindowStats,
    fn deinit(self: *Direct, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.wires);
        self.* = undefined;
    }
};
pub fn produce(a: std.mem.Allocator, trusted: Original.Trusted, originals: Original.Input, options: Options) !Output {
    if (options.capacity == 0 or options.max_originals == 0 or options.max_originals > 2048 or options.max_batches == 0 or options.max_batches > 32 or options.max_direct_children == 0 or options.max_direct_children > Bus.MAX_CHILDREN or options.max_metadata_bytes == 0 or options.max_staging_bytes == 0) return error.InvalidBoundedRootOptions;
    try @import("block_v7_receiver_security_v1.zig").require(options.profile.config(), trusted.config, originals.epoch.config);
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const metadata_budget = try Budget.createRetainingParent(a, options.max_metadata_bytes);
    errdefer metadata_budget.destroy();
    const metadata = try Metadata.Owned.initWhole(metadata_budget.allocator(), trusted, originals, options.max_originals);
    errdefer metadata.deinit();
    const input = metadata.input();
    const total = try input.count();
    if (try std.math.divCeil(usize, total, options.max_direct_children) > options.max_batches) return error.BoundedReductionDepthRequired;
    const metadata_ns = phase.lap();
    const staging_budget = try Budget.createRetainingParent(a, options.max_staging_bytes);
    errdefer staging_budget.destroy();
    const stage = staging_budget.allocator();
    var batches: std.ArrayList(Direct) = .empty;
    defer {
        for (batches.items) |*batch| batch.deinit(stage);
        batches.deinit(stage);
    }
    var first: usize = 0;
    while (first < total) {
        if (batches.items.len == options.max_batches) return error.BoundedReductionDepthRequired;
        var batch = try proveWindow(a, stage, originals, input, first, @min(options.max_direct_children, total - first), options);
        errdefer batch.deinit(stage);
        try batches.append(stage, batch);
        first += batch.stats.count;
    }
    const direct_ns = phase.lap();
    const counts = try stage.alloc(u32, batches.items.len);
    errdefer stage.free(counts);
    const pins = try stage.alloc(Receiver.DirectPin, batches.items.len);
    var done: usize = 0;
    errdefer {
        for (pins[0..done]) |pin| stage.free(pin.wires);
        stage.free(pins);
    }
    const windows = try stage.alloc(WindowStats, batches.items.len);
    errdefer stage.free(windows);
    var proofs: [32][]const u8 = undefined;
    for (batches.items, counts, pins, windows, 0..) |batch, *count, *pin, *window, i| {
        count.* = batch.stats.count;
        pin.* = .{ .key = batch.key, .wires = try stage.dupe(Bus.Wire, batch.wires) };
        done += 1;
        window.* = batch.stats;
        proofs[i] = batch.bytes;
    }
    var reduction_limits = options.reduction;
    reduction_limits.quotient_executor = options.quotient_executor;
    reduction_limits.composition_executor = options.composition_executor;
    reduction_limits.interaction_executor = options.interaction_executor;
    reduction_limits.metadata.global.max_entries = options.max_originals;
    // Mandatory cold PCS planning on the final reduction, not merely row caps.
    reduction_limits.resources = .{ .max_row_log = options.direct.max_row_log, .max_retained_bytes = options.direct.max_retained_bytes, .max_planned_bytes = options.reduction.max_bytes, .scratch_headroom_bytes = options.direct.scratch_headroom_bytes };
    var root = try Reduction.prove(a, input, counts, pins, proofs[0..batches.items.len], reduction_limits);
    errdefer root.deinit();
    const reduction_ns = phase.lap();
    const stats = Stats{ .metadata_ns = metadata_ns, .direct_ns = direct_ns, .reduction_ns = reduction_ns, .whole_ns = whole.read(), .staged_peak_bytes = staging_budget.snapshot().peak_live_bytes };
    return .{ .allocator = a, .metadata_budget = metadata_budget, .staging_budget = staging_budget, .metadata = metadata, .counts = counts, .pins = pins, .windows = windows, .root = root, .stats = stats };
}
fn proveWindow(backing: std.mem.Allocator, stage: std.mem.Allocator, originals: Original.Input, input: Inputs.Input, first: usize, initial_count: usize, options: Options) !Direct {
    const parent = Budget.fromAllocator(backing);
    const parent_before = if (parent) |owner| owner.snapshot() else null;
    Budget.reportStage(backing, "v7.window.begin.parent");
    const budget = try Budget.createRetainingParent(backing, options.direct.max_planned_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var phase = try std.time.Timer.start();
    var selected = try selectWindowImpl(a, input, first, initial_count, options);
    defer if (selected.native_compilers) |*set| set.deinit();
    const count = selected.count;
    var cold = selected.cold;
    const estimate = selected.estimate;
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    const cold_ns = phase.lap();
    var live = try Collection.prepareWindow(a, originals, input, first, count, .{ .parallel_preparation = options.parallel_preparation, .native_compilers = if (selected.native_compilers) |*set| set.slots else null, .family_max_bytes = options.family_max_bytes, .max_entries = options.max_originals, .capacity = options.capacity, .join = .{ .max_row_log = options.direct.max_row_log, .max_join_bytes = options.direct.max_planned_bytes } });
    defer live.deinit();
    if (selected.native_compilers) |*set| set.clear();
    try cold.validateLive(&live);
    const retained = try live.recursive.rows.retainedBytes();
    if (retained > options.direct.max_retained_bytes) return error.ParentWindowResourceLimit;
    const preparation_ns = phase.lap();
    const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
    var committed = try Fixed.deriveCommitted(a, cold.fixed, cold.context, options.profile);
    var committed_live = true;
    defer if (committed_live) committed.deinit();
    const key = try Protocol.Key.fromGeometry(committed.key, live.wires, live.expected);
    cold.deinit();
    cold_live = false;
    const admission = try Protocol.Admission.init(key, try key.identity(), live.wires, live.values(), live.expected);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.initFromFixedCommitment(a, &live.recursive.rows, admission, &committed);
    defer plan.deinit();
    plan.setQuotientExecutor(options.quotient_executor);
    plan.setCompositionExecutor(options.composition_executor);
    plan.setInteractionExecutor(options.interaction_executor);
    committed.deinit();
    committed_live = false;
    const key_plan_ns = phase.lap();
    var proof = try plan.proveConsuming(a, &live.recursive.rows);
    defer proof.deinit();
    const proof_ns = phase.lap();
    const bytes = try Parent.codec.encode(stage, &proof, &admission);
    errdefer stage.free(bytes);
    const wires = try stage.dupe(Bus.Wire, live.wires);
    const encoding_ns = phase.lap();
    const parent_after = if (parent) |owner| owner.snapshot() else null;
    Budget.reportStage(a, "v7.window.finished.child");
    Budget.reportStage(backing, "v7.window.finished.parent");
    return .{ .bytes = bytes, .key = key, .wires = wires, .stats = .{ .first = @intCast(first), .count = @intCast(count), .cold_setup_ns = cold_ns, .capture_prepare_ns = preparation_ns, .key_plan_ns = key_plan_ns, .proof_ns = proof_ns, .encoding_ns = encoding_ns, .resource_retries = selected.resource_retries, .retained_bytes = retained, .planned_peak_bytes = estimate.planned_peak_bytes, .charged_peak_bytes = budget.snapshot().peak_live_bytes, .parent_budget_live_before_bytes = if (parent_before) |snapshot| snapshot.live_bytes else null, .parent_budget_live_after_bytes = if (parent_after) |snapshot| snapshot.live_bytes else null, .parent_budget_cumulative_peak_bytes = if (parent_after) |snapshot| snapshot.peak_live_bytes else null, .parent_budget_limit_bytes = if (parent_after) |snapshot| snapshot.limit else null } };
}

/// Independently compile/admit a bounded next window without any live witness.
/// The caller owns the returned cold roster. Resource failures never alter
/// source admission: all non-resource errors propagate unchanged.
pub const SelectedWindow = struct { native_compilers: ?NativeCompilers.Owned = null, cold: Cold.Owned, count: usize, estimate: Model.Estimate, resource_retries: usize };
pub fn selectWindow(a: std.mem.Allocator, input: Inputs.Input, first: usize, initial_count: usize, options: Options) !SelectedWindow {
    // A cold-only geometry probe has no later live consumer and retains no cache.
    var probe = options;
    probe.reuse_native_compiler = false;
    return selectWindowImpl(a, input, first, initial_count, probe);
}
fn selectWindowImpl(a: std.mem.Allocator, input: Inputs.Input, first: usize, initial_count: usize, options: Options) !SelectedWindow {
    if (initial_count == 0 or initial_count > Bus.MAX_CHILDREN or options.capacity == 0) return error.InvalidBoundedRootOptions;
    var count = initial_count;
    var retries: usize = 0;
    while (true) {
        var compilers = if (options.reuse_native_compiler) NativeCompilers.Owned.initWindow(a, input, first, count, options.max_originals, .{ .max_bytes = options.max_native_compiler_bytes, .parallel_families = options.parallel_families }) catch |err| {
            if (err != error.OutOfMemory) return err;
            if (count == 1) return error.OriginalVerifierExceedsWindowBudget;
            count = @max(@as(usize, 1), count / 2);
            retries += 1;
            continue;
        } else null;
        var transferred = false;
        defer if (!transferred) {
            if (compilers) |*set| set.deinit();
        };
        var cold = Cold.Owned.deriveWindow(a, input, first, count, options.max_originals, options.capacity, .{ .native_compilers = if (compilers) |*set| set.slots else null, .parallel_families = options.parallel_families, .family_max_bytes = options.family_max_bytes, .max_bytes = options.direct.max_planned_bytes, .max_row_log = options.direct.max_row_log }) catch |err| {
            if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) std.debug.print("V7_WINDOW_RESOURCE phase=cold first={d} count={d} error={s} max_row_log={d} max_retained_bytes={d} max_planned_bytes={d}\n", .{ first, count, @errorName(err), options.direct.max_row_log, options.direct.max_retained_bytes, options.direct.max_planned_bytes });
            switch (err) {
                error.OutOfMemory, error.MixedDirectResourceLimit => {
                    if (count == 1) return error.OriginalVerifierExceedsWindowBudget;
                    count = @max(@as(usize, 1), count / 2);
                    retries += 1;
                    continue;
                },
                else => return err,
            }
        };
        const estimate = Model.estimate(cold.fixed, options.profile.config(), options.direct) catch |err| {
            cold.deinit();
            return err;
        };
        if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) std.debug.print("V7_WINDOW_ESTIMATE first={d} count={d} row_log={d} fixed_bytes={d} retained_bytes={d} cells={d} planned_bytes={d} max_row_log={d} max_retained_bytes={d} max_planned_bytes={d}\n", .{ first, count, estimate.largest_row_log, estimate.fixed_bytes, estimate.retained_rows_bytes, estimate.committed_cells, estimate.planned_peak_bytes, options.direct.max_row_log, options.direct.max_retained_bytes, options.direct.max_planned_bytes });
        estimate.require(options.direct) catch |err| {
            cold.deinit();
            if (err != error.ParentWindowResourceLimit) return err;
            if (count == 1) return error.OriginalVerifierExceedsWindowBudget;
            count = @max(@as(usize, 1), count / 2);
            retries += 1;
            continue;
        };
        transferred = true;
        return .{ .native_compilers = compilers, .cold = cold, .count = count, .estimate = estimate, .resource_retries = retries };
    }
}
