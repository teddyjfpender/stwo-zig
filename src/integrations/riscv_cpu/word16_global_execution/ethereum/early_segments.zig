//! Per-segment MAIN construction before inventory. Device coefficients are
//! allocated in their final scope; inventory authorizes adoption and the
//! existing coordinator retains the ordered global root/challenge barrier.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Pipeline = @import("../services/pipeline.zig");
const Worker = @import("../services/gkr_local/cpu_worker.zig");
const W = @import("../services/gkr_local/worker_protocol.zig");
const D = @import("stwo_prover_api").device_pcs;
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const SegmentStages = struct {
    source: Pipeline.DeviceSourceStage,
    projection: @import("../../word16_execution/cpu_source.zig").ProjectionStage,
    trace_commit: *const D.TraceCommitStage,
    pcs: *const D.Stage,
    numerical: *const @import("../services/gkr_local/child.zig").NumericalStage,
    composition: *const Worker.ResidentCompositionStage,
};
pub const StageProvider = struct {
    context: *anyopaque,
    lanes: usize,
    laneForOrdinal: *const fn (*anyopaque, usize) anyerror!usize,
    stages: *const fn (*anyopaque, usize) anyerror!SegmentStages,
    configure: *const fn (*anyopaque, usize) anyerror!void,
    abort: *const fn (*anyopaque) void,
    host_budget: ?*Budget = null,
};
const Capture = @import("capture.zig");
const Collector = @import("../services/collector.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Replay = @import("../../word16_execution/replay_capture.zig");
const CpuSource = @import("../../word16_execution/cpu_source.zig");
const Plan = @import("plan.zig");
const Keys = @import("keys.zig").Owner;
const Fixed = @import("../services/gkr_local/fixed_authority.zig");
const Coordinator = @import("../services/gkr_local/coordinator.zig");
const Execution = @import("../services/gkr_local/execution.zig");
const Manifest = @import("../services/gkr_local/manifest.zig");
const P = @import("../services/protocol.zig");
const T = @import("../services/types.zig");
const Cell = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell;
const heads = .{ "events", "keccak", "secp", "sha256", "arith256_mod", "curves", "bulk", "sponge" };
const max_segments = 256;
pub const Options = struct {
    allocator: std.mem.Allocator,
    image: *const @import("../../word16_execution/expected_image.zig").Owner,
    config: @import("../../rv64_ethereum_request.zig").Config,
    pcs: W.PcsConfig,
    layout: Plan.CpuLayout,
    strict_roster: bool,
    canonical_rungs: bool,
    caches: @import("../../word16_execution/setup.zig").ImmutableCaches,
    setup_cache: *@import("setup_cache.zig").Cache,
    fixed_cache: *const Fixed.Fixed.Cache,
    provider: StageProvider,
    memory: @import("early_cpu0.zig").MemoryAdmission,
    gkr_budget: usize,
};
pub const Slot = struct {
    native: ?*const Native = null,
    shard: ?Collector.Shard = null,
    first_ids: [T.FAMILIES]u32 = @splat(0),
    sponge_before: u64 = 0,
    seal: ?CpuSource.CaptureSeal = null,
    declaration: ?@import("../services/wire.zig").CpuDeclaration = null,
    overlay: ?Replay.Capture = null,
    advice: ?Collector.Advice = null,
    keys: ?Keys = null,
    binding: ?Fixed.Binding = null,
    ticket: ?@import("early_cpu0.zig").Ticket = null,
    worker: ?Worker.CpuWorker = null,
    done: bool = false,
    transferred: bool = false,
    building: bool = false,
    ready_utc_ns: u64 = 0,
    setup_wait_begin_utc_ns: u64 = 0,
    setup_begin_utc_ns: u64 = 0,
    setup_end_utc_ns: u64 = 0,
    source_begin_utc_ns: u64 = 0,
    source_end_utc_ns: u64 = 0,
};
pub const Owner = struct {
    options: Options,
    mutex: std.Thread.Mutex = .{},
    setup_mutex: std.Thread.Mutex = .{},
    parallel_setup: bool = false,
    changed: std.Thread.Condition = .{},
    slots: [max_segments]Slot = @splat(.{}),
    threads: [4]?std.Thread = @splat(null),
    stacks: Budget.ExternalReservation = .{},
    count: usize = 0,
    published: usize = 0,
    next_ids: [T.FAMILIES]u64 = @splat(1),
    next_sponge: u64 = 0,
    global_info: ?Capture.GlobalRamInfo = null,
    initial: []Cell = &.{},
    initial_allocator: ?std.mem.Allocator = null,
    terminal: []const Cell = &.{},
    terminal_ready: bool = false,
    advice: ?Collector.Advice = null,
    natives: []*Native = &.{},
    cancelled: bool = false,
    failure: ?anyerror = null,
    pub fn create(options: Options) !*Owner {
        if (options.provider.lanes == 0 or options.provider.lanes > 4 or options.provider.host_budget == null or options.memory.host_budget == null or options.provider.host_budget.? != options.memory.host_budget.?) return error.EarlySegmentsHostBudgetRequired;
        const self = try options.allocator.create(Owner);
        self.* = .{ .options = options, .parallel_setup = false };
        return self;
    }
    pub fn hook(self: *Owner) Capture.Ready {
        return .{ .context = self, .call = ready, .cancel = cancel, .seal_native = true, .native_segment = nativeReady, .take_global_ram = takeGlobalRam, .terminal_ready = terminalReady, .ram_stack_budget = self.options.provider.host_budget, .require_ram_stack_budget = true };
    }
    fn ready(_: *anyopaque, _: usize, _: *const Native, _: []const @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event, _: u64) void {}
    fn nativeReady(raw: *anyopaque, ordinal: usize, native: *const Native, shard: Collector.Shard, _: u64) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.publish(ordinal, native, shard) catch |err| self.fail(err);
    }
    fn publish(self: *Owner, ordinal: usize, native: *const Native, shard: Collector.Shard) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cancelled) return;
        if (ordinal >= max_segments or ordinal != self.published or (self.count != 0 and ordinal >= self.count)) return error.EarlySegmentsCaptureOrder;
        const slot = &self.slots[ordinal];
        if (slot.native != null) return error.EarlySegmentsDuplicateCapture;
        const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
        slot.seal = cpu.capture_seal orelse return error.UnsealedEarlySegmentCapture;
        // Capture publishes the immutable owner before any later canonical
        // proof-layout normalization. Keep this small private header now;
        // the 224 MB metadata plane remains shared and reference owned.
        slot.overlay = try Replay.Capture.borrowSealed(self.options.allocator, native, slot.seal.?);
        var view = Collector.OneShardView.init(shard);
        var local_advice = view.advice(self.options.allocator, &.{}, &.{});
        const request = try Coordinator.requestView(&.{@constCast(native)}, &local_advice, 0);
        for (self.next_ids, &slot.first_ids, request.calls, &self.next_ids) |first, *out, calls, *next| {
            out.* = std.math.cast(u32, first) orelse return error.CombinedLookupMassExceeded;
            next.* = try std.math.add(u64, first, calls);
        }
        slot.sponge_before = self.next_sponge;
        self.next_sponge = try std.math.add(u64, self.next_sponge, request.sponge.perms);
        slot.native = native;
        slot.shard = shard;
        slot.ready_utc_ns = now();
        self.published += 1;
        if (self.advice) |*advice| self.bindHeads(advice, ordinal, shard);
        self.changed.broadcast();
    }
    fn bindHeads(self: *Owner, advice: *Collector.Advice, ordinal: usize, shard: Collector.Shard) void {
        const view = Collector.OneShardView.init(shard);
        inline for (heads) |name| @field(advice, name)[ordinal] = @field(view, name)[0];
        self.natives[ordinal] = @constCast(self.slots[ordinal].native.?);
    }
    fn takeGlobalRam(raw: *anyopaque, allocator: std.mem.Allocator, cells: []Cell, info: Capture.GlobalRamInfo) bool {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        if (self.initial_allocator != null or self.cancelled) {
            self.mutex.unlock();
            self.fail(error.EarlySegmentsRamOwnership);
            return false;
        }
        self.initial = cells;
        self.initial_allocator = allocator;
        self.global_info = info;
        self.mutex.unlock();
        self.start(info) catch |err| self.fail(err);
        return true;
    }
    fn start(self: *Owner, info: Capture.GlobalRamInfo) !void {
        const n = try std.math.divCeil(u64, info.total_steps, self.options.config.batch_steps);
        if (n == 0 or n > max_segments or info.final_pc != self.options.image.terminal_pc) return error.InvalidEarlySegmentsRoster;
        try self.options.provider.configure(self.options.provider.context, @intCast(n));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cancelled or self.failure != null) return;
        self.count = @intCast(n);
        const a = self.options.allocator;
        var advice: Collector.Advice = undefined;
        advice.allocator = a;
        var made: usize = 0;
        var owns_heads = true;
        errdefer inline for (heads, 0..) |name, i| {
            if (owns_heads and i < made) a.free(@field(advice, name));
        };
        inline for (heads) |name| {
            @field(advice, name) = try a.alloc(@typeInfo(@FieldType(Collector.Advice, name)).pointer.child, self.count);
            made += 1;
        }
        self.natives = try a.alloc(*Native, self.count);
        advice.initial = self.initial;
        advice.terminal = @constCast(self.terminal);
        self.advice = advice;
        owns_heads = false;
        for (0..self.published) |ordinal| self.bindHeads(&self.advice.?, ordinal, self.slots[ordinal].shard.?);
        self.stacks = try self.options.provider.host_budget.?.reserveExternal(self.options.provider.lanes * (2 << 20));
        for (self.threads[0..self.options.provider.lanes], 0..) |*thread, lane| thread.* = try std.Thread.spawn(.{ .stack_size = 2 << 20 }, runLane, .{ self, lane });
        self.changed.broadcast();
    }
    fn terminalReady(raw: *anyopaque, cells: []const Cell) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.terminal = cells;
        self.terminal_ready = true;
        self.changed.broadcast();
    }
    fn runLane(self: *Owner, lane: usize) void {
        self.runLaneFallible(lane) catch |err| self.fail(err);
    }
    fn runLaneFallible(self: *Owner, lane: usize) !void {
        for (0..self.count) |ordinal| {
            if (try self.options.provider.laneForOrdinal(self.options.provider.context, ordinal) != lane) continue;
            self.mutex.lock();
            while (!self.cancelled and self.failure == null and (self.slots[ordinal].native == null or (ordinal + 1 == self.count and !self.terminal_ready))) self.changed.wait(&self.mutex);
            const stop = self.cancelled or self.failure != null;
            if (!stop) self.slots[ordinal].building = true;
            self.mutex.unlock();
            if (stop) return;
            try self.build(ordinal);
            self.mutex.lock();
            self.slots[ordinal].done = true;
            self.slots[ordinal].building = false;
            self.changed.broadcast();
            self.mutex.unlock();
        }
    }
    fn build(self: *Owner, ordinal: usize) !void {
        const o = self.options;
        const a = o.allocator;
        const slot = &self.slots[ordinal];
        const stages = try o.provider.stages(o.provider.context, ordinal);
        var local_native = slot.overlay.?.value;
        var declaration = try Plan.cpuForShard(&local_native, slot.shard.?, ordinal, self.count, self.initial.len, o.layout);
        if (o.strict_roster or o.canonical_rungs) _ = try Plan.canonicalCpuForSegment(&local_native, slot.shard.?.events, o.layout, &declaration, ordinal, self.count, @import("canon_native_rungs.zig"), o.strict_roster);
        slot.declaration = declaration;
        slot.setup_wait_begin_utc_ns = now();
        var setup_timer = try std.time.Timer.start();
        var setup_wait_ns: u64 = 0;
        slot.keys = blk: {
            // Cache.obtain serializes equal keys; independent setup builds,
            // cache leases and the thread-local key seal seam are independent.
            // Keep the previous outer serialization unless explicitly enabled.
            if (!self.parallel_setup) self.setup_mutex.lock();
            defer if (!self.parallel_setup) self.setup_mutex.unlock();
            slot.setup_begin_utc_ns = now();
            setup_wait_ns = setup_timer.lap();
            break :blk try Keys.initResident(a, o.image, &.{declaration}, &.{}, true, @import("../../word16_execution/pcs_suite.zig").Suite.experimentalFold4(), o.caches, o.setup_cache);
        };
        const setup_build_ns = setup_timer.read();
        slot.setup_end_utc_ns = now();
        std.debug.print("EARLY_NATIVE_SEGMENT event=setup_ready ordinal={} utc_ns={} wait_ns={} build_ns={} parallel_setup={} capture_ready_utc_ns={}\n", .{ ordinal, slot.setup_end_utc_ns, setup_wait_ns, setup_build_ns, self.parallel_setup, slot.ready_utc_ns });
        const setup = slot.keys.?.cpus[0];
        slot.binding = try Fixed.Binding.acquire(o.fixed_cache, &setup.key, o.pcs);
        slot.advice = self.advice.?;
        slot.advice.?.terminal = if (ordinal + 1 == self.count) @constCast(self.terminal) else &.{};
        var request = try Coordinator.requestView(self.natives, &slot.advice.?, ordinal);
        try Coordinator.routeDword(&request, setup.bridges, slot.shard.?.events);
        if (request.sponge.any()) request.sponge.first_id = std.math.cast(u32, try std.math.add(u64, try std.math.add(u64, self.global_info.?.counters.keccak, slot.sponge_before), 1)) orelse return error.CombinedLookupMassExceeded;
        const expected = try Execution.localCpuExpected(a, setup, request, @intCast(ordinal), slot.first_ids, o.pcs, &slot.binding.?);
        defer a.free(expected.local_instances.?);
        const scope = D.Scope{ .statement = expected.statement, .fixed = expected.fixed, .main = @splat(0), .ordinal = @intCast(ordinal) };
        slot.overlay.?.value.cpu.?.log_size = setup.materials.geometry.cpu_log;
        slot.overlay.?.value.jalr.?.log_size = setup.materials.geometry.jalr_log;
        slot.overlay.?.value.device_cpu_projection = stages.projection;
        slot.overlay.?.value.device_cpu_scope = scope;
        const source_request = Pipeline.DeviceSourceStage.Request{ .setup = setup, .request = request, .native = &slot.overlay.?.value, .advice = &slot.advice.?, .ordinal = ordinal, .first_ids = slot.first_ids, .scope = scope, .pcs_config = o.pcs };
        slot.ticket = try o.memory.reserve(o.memory.context, a, source_request, o.pcs, o.memory.host_budget.?);
        slot.source_begin_utc_ns = now();
        std.debug.print("EARLY_NATIVE_SEGMENT event=source_begin ordinal={} utc_ns={} capture_ready_utc_ns={} seal={x}\n", .{ ordinal, slot.source_begin_utc_ns, slot.ready_utc_ns, slot.seal.?.digest });
        var source = try stages.source.invoke(a, source_request);
        var owns_source = true;
        errdefer if (owns_source) source.deinit();
        slot.source_end_utc_ns = now();
        slot.worker = try Worker.CpuWorker.initWithAuthority(a, setup, request, source, expected, o.pcs, slot.first_ids, o.gkr_budget, &slot.binding.?);
        owns_source = false;
        const worker = &slot.worker.?;
        worker.device_trace_commit_stage = stages.trace_commit.*;
        worker.scheme.device_om31_pcs_stage = stages.pcs;
        worker.numerical_gkr_stage = stages.numerical.*;
        worker.resident_composition_stage = stages.composition.*;
        const root = try worker.prepareMain(a);
        try slot.ticket.?.finish_joined(slot.ticket.?.context);
        std.debug.print("EARLY_NATIVE_SEGMENT event=main_committed ordinal={} utc_ns={} commit_begin_utc_ns={} source_begin_utc_ns={} root={x}\n", .{ ordinal, worker.main_commit_end_utc_ns, worker.main_commit_begin_utc_ns, slot.source_begin_utc_ns, root });
    }
    pub fn take(self: *Owner, ordinal: usize, setup: anytype, request: P.Request, expected: Manifest.ExpectedWorker, config: W.PcsConfig, first_ids: [T.FAMILIES]u32) !Worker.CpuWorker {
        _ = request; // The globally admitted statement binds all public cells.
        self.mutex.lock();
        defer self.mutex.unlock();
        if (ordinal >= self.count) return error.EarlySegmentsInventoryMismatch;
        while (!self.slots[ordinal].done and !self.cancelled and self.failure == null) self.changed.wait(&self.mutex);
        if (self.failure) |err| return err;
        const slot = &self.slots[ordinal];
        if (self.cancelled or slot.transferred or slot.worker == null or !std.meta.eql(config, self.options.pcs) or !std.meta.eql(first_ids, slot.first_ids)) return error.EarlySegmentsInventoryMismatch;
        if (!std.meta.eql(slot.declaration.?, @import("../services/wire.zig").CpuDeclaration{ .geometry = setup.materials.geometry, .bridges = setup.bridges }) or !std.meta.eql(slot.native.?.cpu.?.capture_seal.?, slot.seal.?)) return error.EarlySegmentsInventoryMismatch;
        try Execution.requireSameCpuExpected(slot.worker.?.expected, expected);
        var worker = slot.worker.?;
        worker.expected.chain = expected.chain;
        slot.worker = null;
        slot.transferred = true;
        std.debug.print("EARLY_NATIVE_SEGMENT event=inventory_adopted ordinal={} utc_ns={} root={x}\n", .{ ordinal, now(), try worker.preparedMainRoot() });
        return worker;
    }
    fn fail(self: *Owner, err: anyerror) void {
        self.mutex.lock();
        const first_failure = self.failure == null;
        if (self.failure == null) self.failure = err;
        self.changed.broadcast();
        self.mutex.unlock();
        if (first_failure) self.options.provider.abort(self.options.provider.context);
    }
    pub fn cancel(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        var active = false;
        for (&self.slots) |*slot| active = active or slot.building;
        const must_abort = !self.cancelled and active;
        self.cancelled = true;
        self.changed.broadcast();
        self.mutex.unlock();
        // An active producer may be asleep on physical admission, whose
        // condition is independent of this owner's readiness condition.
        if (must_abort) self.options.provider.abort(self.options.provider.context);
        for (&self.threads) |*thread| if (thread.*) |running| {
            running.join();
            thread.* = null;
        };
        self.stacks.deinit();
    }
    pub fn deinit(self: *Owner) void {
        cancel(self);
        const a = self.options.allocator;
        for (&self.slots) |*slot| {
            if (slot.worker) |*worker| worker.deinit(a);
            if (slot.ticket) |ticket| ticket.release_destroyed(ticket.context);
            if (slot.overlay) |*overlay| overlay.deinit();
            if (slot.binding) |*binding| binding.deinit();
            if (slot.keys) |*keys| keys.deinit();
        }
        if (self.advice) |advice| inline for (heads) |name| a.free(@field(advice, name));
        a.free(self.natives);
        if (self.initial_allocator) |allocator| allocator.free(self.initial);
        a.destroy(self);
    }
};
fn now() u64 {
    return @intCast(std.time.nanoTimestamp());
}
