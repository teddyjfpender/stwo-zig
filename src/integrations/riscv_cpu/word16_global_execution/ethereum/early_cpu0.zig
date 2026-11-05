//! Default-OFF CPU0 MAIN before global inventory. Local static admission is
//! mandatory, separately from whole-request/global-planner qualification.
const std = @import("std");
const Pipeline = @import("../services/pipeline.zig");
const W = @import("../services/gkr_local/worker_protocol.zig");
const engine = @import("stwo_prover_engine");
pub const FLAG = "STWO_RV64_EARLY_NATIVE_MAIN";
pub const STACK_BYTES: usize = 2 << 20;
/// One private source+MAIN-commit admission. Raw copies do not retain ownership.
/// finish_joined follows Source.releaseMain and TC completion on success, or
/// joined unpublished-owner destruction on failure. The physical phase gate
/// may then open, but retained-tree admission survives until actual final
/// worker/PCS destruction (including global-inventory rejection/abort).
pub const Ticket = struct {
    context: *anyopaque,
    finish_joined: *const fn (*anyopaque) anyerror!void,
    release_destroyed: *const fn (*anyopaque) void,
};
pub const MemoryAdmission = struct {
    context: *anyopaque,
    /// Null is unavailable, never implicitly unbudgeted for an early GPU job.
    /// The RAM/CPU0 helper reserves its explicit 2MiB stack before spawn and
    /// retains that reservation until join, using this exact budget owner.
    host_budget: ?*engine.host_budget_allocator.SharedHostBudget = null,
    /// Borrowed request header/slices are valid for this call only. Derive/copy
    /// the pinned class/cost plan now; do not retain a pointer to this frame.
    /// Reserve BEFORE CPU/JALR clone, MAIN allocation or GPU source launch.
    reserve: *const fn (*anyopaque, std.mem.Allocator, Pipeline.DeviceSourceStage.Request, W.PcsConfig, *engine.host_budget_allocator.SharedHostBudget) anyerror!Ticket,
};

const Collector = @import("../services/collector.zig");
const Capture = @import("capture.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Replay = @import("../../word16_execution/replay_capture.zig").Capture;
const Plan = @import("plan.zig");
const Keys = @import("keys.zig").Owner;
const SetupCache = @import("setup_cache.zig");
const Fixed = @import("../services/gkr_local/fixed_authority.zig");
const Worker = @import("../services/gkr_local/cpu_worker.zig");
const Execution = @import("../services/gkr_local/execution.zig");
const Coordinator = @import("../services/gkr_local/coordinator.zig");
const Manifest = @import("../services/gkr_local/manifest.zig");
const P = @import("../services/protocol.zig");
const T = @import("../services/types.zig");
const D = @import("stwo_prover_api").device_pcs;
const Cell = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell;
pub const Options = struct {
    allocator: std.mem.Allocator,
    image: *const @import("../../word16_execution/expected_image.zig").Owner,
    config: @import("../../rv64_ethereum_request.zig").Config,
    pcs: W.PcsConfig,
    layout: Plan.CpuLayout,
    strict_roster: bool,
    canonical_rungs: bool,
    caches: @import("../../word16_execution/setup.zig").ImmutableCaches,
    setup_cache: *SetupCache.Cache,
    fixed_cache: *const Fixed.Fixed.Cache,
    memory: MemoryAdmission,
    source: Pipeline.DeviceSourceStage,
    projection: @import("../../word16_execution/cpu_source.zig").ProjectionStage,
    trace_commit: *const D.TraceCommitStage,
    pcs_stage: *const D.Stage,
    numerical: *const @import("../services/gkr_local/child.zig").NumericalStage,
    composition: *const Worker.ResidentCompositionStage,
    gkr_budget: usize,
};
/// Bounded first landing: one CPU0, one private device owner, no stage two.
/// The existing RAM helper executes build/commit, with its explicit admitted
/// stack. Other native GPU jobs cannot start until capture/helper joins and
/// the full Inventory has admitted the exact final class/public statement.
pub const Owner = struct {
    options: Options,
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    cancelled: bool = false,
    callback_active: bool = false,
    failure: ?anyerror = null,
    native: ?*const Native = null,
    shard: ?Collector.Shard = null,
    view: Collector.OneShardView = undefined,
    advice: Collector.Advice = undefined,
    initial: []Cell = &.{},
    overlay: ?Replay = null,
    keys: ?Keys = null,
    binding: ?Fixed.Binding = null,
    ticket: ?Ticket = null,
    ticket_finished: bool = false,
    worker: ?Worker.CpuWorker = null,
    expected: ?Manifest.ExpectedWorker = null,
    declaration: ?@import("../services/wire.zig").CpuDeclaration = null,
    transferred: bool = false,
    ready_utc_ns: u64 = 0,
    admit_utc_ns: u64 = 0,
    source_begin_utc_ns: u64 = 0,
    source_end_utc_ns: u64 = 0,
    pub fn create(options: Options) !*Owner {
        if (options.memory.host_budget == null) return error.EarlyMainHostBudgetRequired;
        const self = try options.allocator.create(Owner);
        self.* = .{ .options = options };
        return self;
    }
    pub fn hook(self: *Owner) Capture.Ready {
        return .{ .context = self, .call = ready, .cancel = cancel, .native_segment = nativeReady, .global_ram = globalReady, .ram_stack_budget = self.options.memory.host_budget, .require_ram_stack_budget = true };
    }
    fn ready(raw: *anyopaque, index: usize, _: *const Native, _: []const @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event, _: u64) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (index == 0) self.ready_utc_ns = now();
    }
    fn nativeReady(raw: *anyopaque, index: usize, native: *const Native, shard: Collector.Shard, _: u64) void {
        if (index != 0) return;
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cancelled) return;
        if (self.native != null) {
            self.failure = error.EarlyMainDuplicateNative;
            self.changed.broadcast();
            return;
        }
        self.native = native;
        self.shard = shard;
        self.changed.broadcast();
    }
    fn globalReady(raw: *anyopaque, cells: []const Cell, info: Capture.GlobalRamInfo) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        if (self.cancelled) {
            self.mutex.unlock();
            return;
        }
        self.callback_active = true;
        while (self.native == null and !self.cancelled and self.failure == null) self.changed.wait(&self.mutex);
        const skip = self.cancelled or self.failure != null;
        self.mutex.unlock();
        defer {
            self.mutex.lock();
            self.callback_active = false;
            self.changed.broadcast();
            self.mutex.unlock();
        }
        if (skip) return;
        self.build(cells, info) catch |err| {
            self.mutex.lock();
            if (self.failure == null) self.failure = err;
            self.mutex.unlock();
        };
    }
    fn build(self: *Owner, cells: []const Cell, info: Capture.GlobalRamInfo) !void {
        const o = self.options;
        const a = o.allocator;
        const segments = std.math.divCeil(u64, info.total_steps, o.config.batch_steps) catch return error.InvalidEarlyMainRoster;
        // CPU0-single also owns TERMINAL. This initial bounded landing does not
        // guess its clocked final cells; the normal pipeline remains available
        // when this opt-in is absent. No silent fallback when requested.
        if (segments < 2 or segments > 256 or info.final_pc != o.image.terminal_pc) return error.EarlyMainRequiresFirstOfMultipleSegments;
        var local_native = self.native.?.*;
        self.view = Collector.OneShardView.init(self.shard.?);
        self.advice = self.view.advice(a, @constCast(cells), &.{});
        var declaration = try Plan.cpuForSegment(&local_native, &self.advice, 0, @intCast(segments), cells.len, o.layout);
        if (o.strict_roster or o.canonical_rungs) _ = try Plan.canonicalCpuForSegment(&local_native, self.advice.events[0], o.layout, &declaration, 0, @intCast(segments), @import("canon_native_rungs.zig"), o.strict_roster);
        self.declaration = declaration;
        self.keys = try Keys.initResident(a, o.image, &.{declaration}, &.{}, true, @import("../../word16_execution/pcs_suite.zig").Suite.experimentalFold4(), o.caches, o.setup_cache);
        const setup = self.keys.?.cpus[0];
        self.binding = try Fixed.Binding.acquire(o.fixed_cache, &setup.key, o.pcs);
        var request = try Coordinator.requestView(&.{&local_native}, &self.advice, 0);
        try Coordinator.routeDword(&request, setup.bridges, self.advice.events[0]);
        if (request.sponge.any()) request.sponge.first_id = std.math.cast(u32, try std.math.add(u64, info.counters.keccak, 1)) orelse return error.CombinedLookupMassExceeded;
        const first_ids: [T.FAMILIES]u32 = @splat(1);
        const expected = try Execution.localCpuExpected(a, setup, request, 0, first_ids, o.pcs, &self.binding.?);
        defer a.free(expected.local_instances.?);
        const scope = D.Scope{ .statement = expected.statement, .fixed = expected.fixed, .main = @splat(0), .ordinal = 0 };
        var source_request = Pipeline.DeviceSourceStage.Request{ .setup = setup, .request = request, .native = &local_native, .advice = &self.advice, .ordinal = 0, .first_ids = first_ids, .scope = scope };
        self.ticket = try o.memory.reserve(o.memory.context, a, source_request, o.pcs, o.memory.host_budget.?);
        self.admit_utc_ns = now();
        // All unpublished source owners must be destroyed before the ticket's
        // joined finish runs on an error. Root's ticket poisons failed custody.
        errdefer {
            if (self.worker) |*worker| {
                worker.deinit(a);
                self.worker = null;
            }
            self.finishTicket() catch |err| {
                self.fail(err);
            };
        }
        self.initial = try a.dupe(Cell, cells);
        self.advice.initial = self.initial;
        request.base.memory.initial = self.initial;
        self.overlay = try Replay.init(a, &local_native);
        self.overlay.?.value.device_cpu_projection = o.projection;
        self.overlay.?.value.device_cpu_scope = scope;
        source_request.request = request;
        source_request.native = &self.overlay.?.value;
        self.source_begin_utc_ns = now();
        std.debug.print("EARLY_NATIVE_MAIN event=source_begin ordinal=0 utc_ns={} capture_ready_utc_ns={} admitted_utc_ns={} initial_words={}\n", .{ self.source_begin_utc_ns, self.ready_utc_ns, self.admit_utc_ns, cells.len });
        var source = try o.source.invoke(a, source_request);
        var owns_source = true;
        errdefer if (owns_source) source.deinit();
        self.source_end_utc_ns = now();
        self.worker = try Worker.CpuWorker.initWithAuthority(a, setup, request, source, expected, o.pcs, first_ids, o.gkr_budget, &self.binding.?);
        owns_source = false;
        const worker = &self.worker.?;
        worker.device_trace_commit_stage = o.trace_commit.*;
        worker.scheme.device_om31_pcs_stage = o.pcs_stage;
        worker.numerical_gkr_stage = o.numerical.*;
        worker.resident_composition_stage = o.composition.*;
        const root = try worker.prepareMain(a);
        try self.finishTicket();
        std.debug.print("EARLY_NATIVE_MAIN event=main_committed ordinal=0 utc_ns={} source_end_utc_ns={} commit_begin_utc_ns={} root={x}\n", .{ worker.main_commit_end_utc_ns, self.source_end_utc_ns, worker.main_commit_begin_utc_ns, root });
    }
    fn fail(self: *Owner, err: anyerror) void {
        self.mutex.lock();
        if (self.failure == null) self.failure = err;
        self.changed.broadcast();
        self.mutex.unlock();
    }
    fn finishTicket(self: *Owner) !void {
        if (self.ticket) |ticket| if (!self.ticket_finished) {
            try ticket.finish_joined(ticket.context);
            self.ticket_finished = true;
        };
    }
    pub fn requireReady(self: *Owner) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.callback_active) return error.EarlyMainReaderNotJoined;
        if (self.failure) |err| return err;
        if (self.cancelled or self.worker == null or !self.worker.?.main_committed or !self.ticket_finished) return error.EarlyMainNotReady;
    }
    /// Called only AFTER full global Inventory has admitted requests/roles.
    /// This moves the very same scheme/channel/coefficient owner; no rebind,
    /// recomputation or producer class selection can enter the late pipeline.
    pub fn take(self: *Owner, setup: anytype, request: P.Request, expected: Manifest.ExpectedWorker, config: W.PcsConfig, first_ids: [T.FAMILIES]u32) !Worker.CpuWorker {
        try self.requireReady();
        if (self.transferred or !std.meta.eql(config, self.options.pcs) or !std.meta.eql(first_ids, @as([T.FAMILIES]u32, @splat(1)))) return error.EarlyCpuInventoryMismatch;
        if (!std.meta.eql(self.declaration.?, @import("../services/wire.zig").CpuDeclaration{ .geometry = setup.materials.geometry, .bridges = setup.bridges })) return error.EarlyCpuInventoryMismatch;
        const local = try Execution.localCpuExpected(self.options.allocator, setup, request, 0, first_ids, config, &self.binding.?);
        defer self.options.allocator.free(local.local_instances.?);
        try Execution.requireSameCpuExpected(self.worker.?.expected, local);
        try Execution.requireSameCpuExpected(local, expected);
        var worker = self.worker.?;
        worker.expected.chain = expected.chain;
        self.worker = null;
        self.transferred = true;
        std.debug.print("EARLY_NATIVE_MAIN event=inventory_adopted ordinal=0 utc_ns={} root={x}\n", .{ now(), try worker.preparedMainRoot() });
        return worker;
    }
    pub fn cancel(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        self.cancelled = true;
        self.changed.broadcast();
        while (self.callback_active) self.changed.wait(&self.mutex);
        self.mutex.unlock();
        // Must run before captured advice/facts are freed, including errors.
        self.destroyPrivate();
    }
    fn destroyPrivate(self: *Owner) void {
        if (self.worker) |*worker| {
            worker.deinit(self.options.allocator);
            self.worker = null;
        }
        if (self.ticket) |ticket| {
            if (!self.ticket_finished) self.finishTicket() catch {};
            ticket.release_destroyed(ticket.context);
            self.ticket = null;
        }
    }
    pub fn deinit(self: *Owner) void {
        cancel(self);
        if (self.overlay) |*overlay| overlay.deinit();
        if (self.binding) |*binding| binding.deinit();
        if (self.keys) |*keys| keys.deinit();
        self.options.allocator.free(self.initial);
        const a = self.options.allocator;
        a.destroy(self);
    }
};
fn now() u64 {
    return @intCast(std.time.nanoTimestamp());
}
