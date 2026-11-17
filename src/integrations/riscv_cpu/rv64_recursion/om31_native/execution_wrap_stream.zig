//! Native-to-recursion streaming handoff, cancellation and lifetime ownership.
const std = @import("std");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Root = @import("services_root.zig");
const CpuLeaf = @import("cpu_leaf.zig");
const TruthLeaf = @import("truth_leaf.zig");
const KeccakLeaf = @import("keccak_leaf.zig");
const Outer = @import("outer_wrap.zig");
const SharedBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Dag = @import("ready_dag.zig");
const ownership_owner = @import("execution_wrap_ownership.zig");
const copyMarginals = ownership_owner.copyMarginals;
const freeMarginals = ownership_owner.freeMarginals;
const context_owner = @import("execution_wrap_context.zig");
const Pipe = context_owner.Pipe;
const runPreparedParallel = context_owner.runPreparedParallel;
const pipeline_owner = @import("execution_wrap_pipeline.zig");
const Pipelined = pipeline_owner.Pipelined;
const main_owner = @import("execution_wrap.zig");
const ParallelOptions = main_owner.ParallelOptions;
const Report = main_owner.Report;
const StackReservations = main_owner.StackReservations;
const foldArity = main_owner.foldArity;
const validateLanes = main_owner.validateLanes;

pub const Streaming = struct {
    const Cpu = std.meta.Child(@FieldType(Coordinator.Bundle, "cpus"));
    const TruthEnc = std.meta.Child(@FieldType(Coordinator.Bundle, "truths"));
    allocator: std.mem.Allocator,
    setups: []const *const R.CpuSetup,
    truths: []const R.Truth,
    expected: P.Expected,
    config: W.PcsConfig,
    fixed: ?*const FixedSet,
    dir: std.fs.Dir,
    options: ParallelOptions,
    /// View only: requests/stage bytes alias the producer's; cpus/truths are
    /// shallow copies of results the returned Bundle owns. Never deinit.
    bundle: Coordinator.Bundle = undefined,
    cpus: []Cpu,
    truth_slots: []TruthEnc,
    inventory: ?Execution.Inventory = null,
    stages: ?MW.Owned = null,
    manifest: ?@import("../../word16_global_execution/services/gkr_local/manifest.zig").PendingManifest = null,
    words: [][]const u32,
    cpu_frames: []Root.CpuFrame,
    timer: std.time.Timer,
    ready: [Dag.max_leaves]std.atomic.Value(bool) = @splat(.init(false)),
    ready_ns: [Dag.max_leaves]u64 = @splat(0),
    native_done: std.atomic.Value(bool) = .init(false),
    native_done_ns: u64 = 0,
    stopped: std.atomic.Value(bool) = .init(false),
    /// Guards fatal, attached and thread; never taken while holding the
    /// pipeline mutex (lock order: stream -> pipeline).
    mutex: std.Thread.Mutex = .{},
    fatal: ?anyerror = null,
    attached: ?*Pipelined = null,
    thread: ?std.Thread = null,
    result: ?(anyerror!Report) = null,
    /// Host workers allowed to prep leaves while native still owns the GPUs.
    prep_during_native: usize,

    pub fn enabled() bool {
        // Streaming exists only on the pipelined executor. With
        // STWO_RV64_RECURSION_PIPELINE=0 (the M5 lane path) keep the M5
        // handoff instead of failing the request after native production
        return true;
    }
    pub fn create(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir, options: ParallelOptions) !*Streaming {
        const n = setups.len + truths.len;
        if (n == 0 or n > Dag.max_leaves) return error.ServicesRootRoster;
        try validateLanes(options);
        const prep_text = "4";
        const prep = std.fmt.parseUnsigned(usize, prep_text, 10) catch return error.InvalidRecursionPipelineOption;
        if (prep == 0) return error.InvalidRecursionPipelineOption;
        const self = try a.create(Streaming);
        errdefer a.destroy(self);
        const cpus = try a.alloc(Cpu, setups.len);
        errdefer a.free(cpus);
        const truth_slots = try a.alloc(TruthEnc, truths.len);
        errdefer a.free(truth_slots);
        const words = try a.alloc([]const u32, n);
        errdefer a.free(words);
        @memset(words, &.{});
        const frames = try a.alloc(Root.CpuFrame, setups.len);
        @memset(frames, .{ .words = &.{}, .physical_claims = &.{}, .terminal_marginals = &.{} });
        self.* = .{ .allocator = a, .setups = setups, .truths = truths, .expected = expected, .config = config, .fixed = fixed, .dir = dir, .options = options, .cpus = cpus, .truth_slots = truth_slots, .words = words, .cpu_frames = frames, .timer = try std.time.Timer.start(), .prep_during_native = prep };
        return self;
    }
    pub fn hook(self: *Streaming) Coordinator.Stream {
        return .{ .context = self, .sealed = sealedHook, .cpu_done = cpuHook, .truth_done = truthHook, .abort = abortHook };
    }
    pub fn of(raw: *anyopaque) *Streaming {
        return @ptrCast(@alignCast(raw));
    }
    pub fn fail(self: *Streaming, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal == null) self.fatal = err;
        self.stopped.store(true, .release);
        self.notifyLocked();
    }
    /// Caller holds self.mutex. Wakes the pipeline's waiters.
    pub fn notifyLocked(self: *Streaming) void {
        if (self.attached) |pipeline| {
            pipeline.mutex.lock();
            pipeline.changed.broadcast();
            pipeline.mutex.unlock();
        }
    }
    pub fn notify(self: *Streaming) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.notifyLocked();
    }
    pub fn sealedHook(raw: *anyopaque, requests: []const P.Request, stage_one_bytes: []const u8) void {
        const self = of(raw);
        self.sealed(requests, stage_one_bytes) catch |err| self.fail(err);
    }
    pub fn sealed(self: *Streaming, requests: []const P.Request, stage_one_bytes: []const u8) !void {
        const a = self.allocator;
        self.timer.reset();
        self.bundle = .{ .requests = @constCast(requests), .stage_one_bytes = @constCast(stage_one_bytes), .cpus = self.cpus, .truths = self.truth_slots };
        self.inventory = try Execution.Inventory.initWithAuthority(a, self.setups, self.truths, requests, self.expected, self.config, self.fixed);
        const inventory = &self.inventory.?;
        if (inventory.workers.len != self.words.len) return error.ServicesRootRoster;
        self.stages = try MW.decode(a, inventory.execution_identity, inventory.workers, stage_one_bytes);
        self.manifest = try self.stages.?.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fatal != null) return;
        self.thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, threadMain, .{self});
    }
    pub fn cpuHook(raw: *anyopaque, ordinal: usize, encoded: *const Cpu) void {
        const self = of(raw);
        self.cpuDone(ordinal, encoded) catch |err| self.fail(err);
    }
    /// Exactly the frame derivation of runImpl for one CPU ordinal.
    pub fn cpuDone(self: *Streaming, i: usize, encoded: *const Cpu) !void {
        const a = self.allocator;
        if (self.manifest == null or i >= self.setups.len) return error.StreamingHandoffOrder;
        self.cpus[i] = encoded.*;
        const manifest = &self.manifest.?;
        const inventory = &self.inventory.?;
        const local = manifest.entries[i].local orelse return error.WideCpuLocalRequired;
        self.words[i] = try CpuLeaf.expectedWords(a, self.setups[i], self.bundle.requests[i], inventory.first_ids[i], inventory.workers[i], manifest.digest, self.stages.?.stages[i].main, local.digest, self.cpus[i].claims);
        self.cpu_frames[i] = .{ .words = self.words[i], .physical_claims = self.cpus[i].claims, .terminal_marginals = try copyMarginals(a, local.artifact.claims_to_verify_by_instance) };
        self.open(i);
    }
    pub fn truthHook(raw: *anyopaque, ordinal: usize, encoded: *const TruthEnc) void {
        const self = of(raw);
        self.truthDone(ordinal, encoded) catch |err| self.fail(err);
    }
    /// Exactly the truth frame derivation of runImpl for one ordinal.
    pub fn truthDone(self: *Streaming, ordinal: usize, encoded: *const TruthEnc) !void {
        const a = self.allocator;
        if (self.manifest == null or ordinal < self.setups.len or ordinal >= self.words.len) return error.StreamingHandoffOrder;
        const i = ordinal - self.setups.len;
        self.truth_slots[i] = encoded.*;
        const truth = self.truths[i];
        const worker = self.inventory.?.workers[ordinal];
        const claims = self.truth_slots[i].claims;
        const digest = self.manifest.?.digest;
        const main = self.stages.?.stages[ordinal].main;
        if (truth == .keccak) {
            if (claims.len != 5) return error.InvalidWideTruthClaims;
            const public = KeccakLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = digest, .claims = claims[0..5].* };
            self.words[ordinal] = try a.dupe(u32, &KeccakLeaf.statementWords(truth, public, main));
        } else {
            if (claims.len != 1) return error.InvalidWideTruthClaims;
            const public = TruthLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = digest, .claim = claims[0] };
            self.words[ordinal] = try a.dupe(u32, &TruthLeaf.statementWords(truth, public, main));
        }
        self.open(ordinal);
    }
    pub fn open(self: *Streaming, ordinal: usize) void {
        self.ready_ns[ordinal] = self.timer.read();
        self.ready[ordinal].store(true, .release);
        self.notify();
    }
    pub fn abortHook(raw: *anyopaque) void {
        of(raw).stop(error.NativeProductionFailed);
    }
    /// Native production, the terminal check and native publication are done.
    pub fn nativeDone(self: *Streaming) void {
        self.native_done_ns = self.timer.read();
        self.native_done.store(true, .release);
        self.notify();
    }
    /// Final verifier reads the complete native bundle. Its barrier stays
    /// separate from per-leaf GPU dispatch when bounded admission is active.
    pub fn nativeComplete(self: *const Streaming) bool {
        return self.native_done.load(.acquire);
    }
    pub fn admissionActive(self: *const Streaming) bool {
        // Optional capability is supplied only by a runtime enforcing GLOBAL
        // physical-GPU allocation envelopes. An environment flag cannot open it.
        if (comptime @hasField(Outer.Device.Factory, "memory_admission_enabled")) {
            for (self.options.lanes) |lane| {
                if (comptime @hasField(Outer.Device.Factory, "requires_native_complete")) {
                    if (lane.factory.requires_native_complete) return false;
                }
                const admission_enabled = lane.factory.memory_admission_enabled orelse return false;
                if (!admission_enabled(lane.factory.context)) return false;
            }
            return self.options.lanes.len != 0;
        } else return false;
    }
    pub fn deviceOpen(self: *const Streaming) bool {
        // The prepared queue contains only acquire-published native-ready
        // leaves and folds whose children have completed. Consumers can make
        // progress before native producers exhaust the static retention arena.
        return self.nativeComplete() or self.admissionActive();
    }
    /// Stops dispatch (if still running) and joins the recursion thread.
    /// After return nothing reads producer-owned native data any more.
    pub fn stop(self: *Streaming, err: anyerror) void {
        self.mutex.lock();
        if (self.result == null and self.fatal == null and self.thread != null) self.fatal = err;
        if (self.fatal != null) self.stopped.store(true, .release);
        self.notifyLocked();
        const thread = self.thread;
        self.thread = null;
        self.mutex.unlock();
        if (thread) |t| t.join();
    }
    pub fn join(self: *Streaming) !Report {
        self.mutex.lock();
        const thread = self.thread;
        self.thread = null;
        self.mutex.unlock();
        if (thread) |t| t.join();
        if (self.fatal) |err| return err;
        return self.result orelse error.StreamingRecursionNotStarted;
    }
    pub fn destroy(self: *Streaming) void {
        self.stop(error.StreamingRecursionCancelled);
        const a = self.allocator;
        for (self.cpu_frames) |frame| freeMarginals(a, frame.terminal_marginals);
        a.free(self.cpu_frames);
        for (self.words) |value| a.free(value);
        a.free(self.words);
        if (self.manifest) |*m| m.deinit(a);
        if (self.stages) |*st| st.deinit();
        if (self.inventory) |*inv| inv.deinit();
        a.free(self.truth_slots);
        a.free(self.cpus);
        a.destroy(self);
    }
    pub fn threadMain(self: *Streaming) void {
        const outcome = self.runInner();
        self.mutex.lock();
        defer self.mutex.unlock();
        self.result = outcome;
        if (outcome) |_| {} else |err| if (self.fatal == null) {
            self.fatal = err;
        }
    }
    pub fn runInner(self: *Streaming) !Report {
        const a = self.allocator;
        const budget = try @import("../../rv64_recursion_budget.zig").require(SharedBudget, a);
        _ = budget.retain();
        defer budget.destroy();
        var stacks = try StackReservations.init(a, self.options);
        defer stacks.deinit();
        const pipe = (try Pipe.Options.fromEnv(a, self.options)) orelse return error.StreamingRequiresPipelinedRecursion;
        const frames = Root.Frames{ .cpus = self.cpu_frames, .truths = self.words[self.setups.len..] };
        return runPreparedParallel(.{ .allocator = a, .setups = self.setups, .truths = self.truths, .bundle = &self.bundle, .expected = self.expected, .config = self.config, .fixed = self.fixed, .dir = self.dir, .allow_resume = false, .inventory = &self.inventory.?, .stages = &self.stages.?, .manifest = &self.manifest.?, .words = self.words, .frames = frames, .timer = &self.timer, .stream = self }, self.options, pipe, try foldArity());
    }
};
