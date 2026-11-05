//! Parallel native batches: one fast first pass (fast_execution.Engine, no
//! tracing) runs the guest to the end on the request's memory and publishes a
//! checkpoint at every batch boundary; up to `workers` segment walks then
//! re-execute batches from their checkpoints concurrently with the exact
//! serial capture code (`Walk.next`), each on its own copy of the image.
//!
//! Batches are returned strictly in index order and are the serial walk's
//! batches: every segment's end state (CPU, service counters, allocated page
//! set, set of written pages and their bytes) must equal the next checkpoint,
//! or the run fails with `EthereumSegmentContinuity`. A batch the serial walk
//! would fail fails here with the same error, surfaced in the same order.
//! Producer scheduling only: nothing here enters a statement or identity.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const Walk = @import("rv64_ethereum_native_prepare.zig").Walk;
const Native = @import("rv64_ethereum_batch.zig");
pub const MAX_WORKERS = 32;

/// M6 traced fast engine for segment walks (`STWO_RV64_TRACED_ENGINE`,
/// default on; `0` restores the M5 reference loop). Scheduling only: the
/// batches are byte-identical either way. Tests may force it.
pub var traced_engine_override: ?bool = null;
pub fn tracedEngineEnabled() bool {
    if (traced_engine_override) |value| return value;
    const text = std.posix.getenv("STWO_RV64_TRACED_ENGINE") orelse return true;
    return !std.mem.eql(u8, text, "0");
}

/// Bounded CPU0 producer prototype. Existing traced capture remains the
/// acceptance/ordered-ledger source and compares every minimal record.
/// No GPU projection or proof consumer trusts this transport yet.
pub fn minimalFirstPassEnabled() bool {
    const text = std.posix.getenv("STWO_RV64_FIRST_PASS_CPU0_RECORDS") orelse return false;
    return std.mem.eql(u8, text, "1");
}

pub fn ramFirstPassEnabled() bool {
    const text = std.posix.getenv("STWO_RV64_FIRST_PASS_RAM") orelse return false;
    return std.mem.eql(u8, text, "1");
}

pub const Stats = struct {
    segments: u32 = 0,
    workers: u8 = 0,
    first_pass_ns: u64 = 0,
    first_pass_retired: u64 = 0,
    minimal_cpu0_records: u64 = 0,
    minimal_cpu0_bytes: u64 = 0,
    minimal_cpu0_ready_utc_ns: u64 = 0,
    minimal_cpu0_checked: bool = false,
    first_pass_ram_words: u64 = 0,
    first_pass_ram_ready_utc_ns: u64 = 0,
    fast_retired: u64 = 0,
    pages_copied: u64 = 0,
    peak_live_pages: u64 = 0,
    /// Consumer time spent waiting for the next segment in order.
    wait_ns: u64 = 0,
    /// Traced segment walks (checkpoint materialise + `Walk.nextTaking` +
    /// continuity check), summed and worst, with their retired steps:
    /// report-only emulator throughput baseline (M7).
    walk_ns_total: u64 = 0,
    walk_ns_max: u64 = 0,
    walk_retired: u64 = 0,
    /// Split of `walk_ns_total`: traced execution and `batch.finish`.
    walk_traced_ns: u64 = 0,
    walk_finish_ns: u64 = 0,
    /// M6 traced fast engine: on, program build time, and the steps it
    /// retired (the rest went through the reference `captureNext`).
    traced_engine: bool = false,
    traced_program_ns: u64 = 0,
    walk_fast_retired: u64 = 0,
    /// Split of `walk_traced_ns`: traced fast runs, and reference steps.
    walk_fast_ns: u64 = 0,
    walk_reference_ns: u64 = 0,
    walk_reference_steps: u64 = 0,
};

const FirstPass = struct {
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    /// Checkpoint k is the state before batch k (and after batch k-1).
    checkpoints: std.ArrayList(*rv.checkpoint.Checkpoint) = .empty,
    /// First index not yet released by the consumer (back-pressure).
    consumed: u32 = 0,
    /// Exclusive bound on batch indices, set when the pass ends: after the
    /// completing batch, after the batch whose guest error stopped it (so
    /// that batch is re-executed and reports the error), or max_batches.
    bound: u32 = std.math.maxInt(u32),
    done: bool = false,
    cancel: bool = false,
    /// Recording failure (not a guest error: those surface from segments).
    err: ?anyerror = null,
};

const Worker = struct {
    owner: *Segments,
    index: u32,
    thread: ?std.Thread = null,
    taken: ?Walk.Taken = null,
    completed: bool = false,
    err: ?anyerror = null,
    walk_ns: u64 = 0,
    retired: u64 = 0,
    traced_ns: u64 = 0,
    finish_ns: u64 = 0,
    fast_retired: u64 = 0,
    fast_ns: u64 = 0,
    reference_ns: u64 = 0,
    reference_steps: u64 = 0,
    fn run(self: *Worker) void {
        var timer = std.time.Timer.start() catch null;
        self.work() catch |err| {
            self.err = err;
        };
        if (timer) |*t| self.walk_ns = t.read();
    }
    fn work(self: *Worker) !void {
        const owner = self.owner;
        const a = owner.allocator;
        const cp = owner.checkpointAt(self.index) orelse return error.EthereumSegmentContinuity;
        var walk = try Walk.createSegment(a, owner.main, cp, self.index);
        defer walk.destroy();
        var dirty = rv.checkpoint.Dirty{ .bits = try a.alloc(u64, owner.engine.dirty.bits.len) };
        defer a.free(dirty.bits);
        @memset(dirty.bits, 0);
        walk.memory.backing.dirty = &dirty;
        defer walk.memory.backing.dirty = null;
        var taken = (try walk.nextTaking()) orelse return error.EthereumSegmentContinuity;
        errdefer taken.deinit();
        // Continuity: this segment ends exactly where the first pass's next
        // checkpoint (or its end state) begins.
        const next = owner.checkpointAt(self.index + 1) orelse return error.EthereumSegmentContinuity;
        if (!rv.checkpoint.matches(&walk.session, &dirty, next)) return error.EthereumSegmentContinuity;
        if (self.index == 0) if (owner.minimal_cpu0) |trace| {
            // checkpointAt(1) acquires the first pass publication mutex after
            // CPU0 is sealed; later batches never write this record span.
            if (trace.len != taken.tape.len) return error.EthereumMinimalCpuMismatch;
            var pc = taken.tape.initial_pc;
            for (trace.records[0..trace.len], taken.tape.steps()) |record, step| {
                if (pc < owner.engine.code_lo or pc >= owner.engine.code_hi or pc & 3 != 0) return error.EthereumMinimalCpuMismatch;
                const op = (try owner.main.request.authority.instructionAt(pc)).instruction.opcode;
                const branch = switch (op) {
                    .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => true,
                    else => false,
                };
                if (record.pc != pc or record.next_pc != step.next_pc or record.result != (if (branch) step.flags & 1 else step.result)) return error.EthereumMinimalCpuMismatch;
                pc = step.next_pc;
            }
        };
        self.completed = walk.completed;
        self.retired = taken.tape.len;
        self.traced_ns = walk.traced_ns;
        self.finish_ns = walk.finish_ns;
        self.fast_retired = walk.fast_retired;
        self.fast_ns = walk.fast_ns;
        self.reference_ns = walk.reference_ns;
        self.reference_steps = walk.reference_steps;
        self.taken = taken;
    }
};

pub const Segments = struct {
    allocator: std.mem.Allocator,
    main: *Walk,
    workers: u8,
    engine: rv.fast_execution.Engine,
    /// Traced program for segment walks (a restricted copy of `engine`'s).
    program: ?rv.fast_execution.Engine = null,
    recorder: rv.checkpoint.Recorder,
    pass: FirstPass = .{},
    /// Owned by the Segments lifetime. Written only by firstPass for batch0,
    /// sealed before checkpoint1 publication, borrowed read-only by worker0.
    minimal_cpu0: ?rv.fast_execution.MinimalTrace = null,
    ram_words: ?rv.ram_word_set.Set = null,
    pass_thread: ?std.Thread = null,
    ring: [MAX_WORKERS]?*Worker = @splat(null),
    next_index: u32 = 0,
    launched: u32 = 0,
    finished: bool = false,
    stats: Stats = .{},

    /// `main` is a fresh walk (no batch taken); the first pass drives its
    /// session and memory to the end. `a` must be thread-safe.
    pub fn create(a: std.mem.Allocator, main: *Walk, workers: u8) !*Segments {
        if (workers == 0 or workers > MAX_WORKERS) return error.InvalidEthereumSegmentWorkers;
        if (main.batches != 0 or main.pending or main.tape.len != 0) return error.InvalidEthereumBatchSeed;
        const self = try a.create(Segments);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .main = main, .workers = workers, .engine = undefined, .recorder = undefined };
        if (minimalFirstPassEnabled()) self.minimal_cpu0 = .{ .records = try a.alloc(rv.fast_execution.MinimalRecord, main.config.batch_steps) };
        errdefer if (self.minimal_cpu0) |trace| a.free(trace.records);
        if (self.minimal_cpu0) |*trace| trace.seeds = try a.alloc(rv.fast_execution.MinimalSeed, std.math.divCeil(usize, trace.records.len, rv.fast_execution.MINIMAL_CHUNK_ROWS) catch unreachable);
        errdefer if (self.minimal_cpu0) |trace| a.free(trace.seeds);
        if (ramFirstPassEnabled()) self.ram_words = try rv.ram_word_set.Set.init(a, 1 << 24);
        errdefer if (self.ram_words) |*words| words.deinit();
        self.engine = try rv.fast_execution.Engine.init(a, main.memory, .{ .stop_pcs = &.{main.config.terminal_pc}, .isa = main.session.keccak.base.decoder.isa });
        errdefer self.engine.deinit();
        self.engine.attach();
        if (tracedEngineEnabled()) {
            var timer = std.time.Timer.start() catch null;
            self.program = try rv.fast_execution.Engine.cloneProgram(a, &self.engine);
            self.program.?.restrict(@as(*const @TypeOf(main.request.authority), &main.request.authority), Native.admitsFast);
            main.fast_program = &self.program.?;
            if (timer) |*t| self.stats.traced_program_ns = t.read();
            self.stats.traced_engine = true;
        }
        errdefer if (self.program) |*p| {
            main.fast_program = null;
            p.deinit();
        };
        self.recorder = try rv.checkpoint.Recorder.init(a, &self.engine);
        errdefer self.recorder.deinit();
        self.stats.workers = workers;
        self.pass_thread = try std.Thread.spawn(.{}, firstPass, .{self});
        return self;
    }

    pub fn destroy(self: *Segments) void {
        const a = self.allocator;
        self.joinPass();
        for (&self.ring) |*slot| if (slot.*) |w| {
            if (w.thread) |t| t.join();
            if (w.taken) |*t| t.deinit();
            a.destroy(w);
            slot.* = null;
        };
        for (self.pass.checkpoints.items[self.pass.consumed..]) |cp| {
            self.recorder.release(cp);
            a.destroy(cp);
        }
        self.pass.checkpoints.deinit(a);
        self.recorder.deinit();
        if (self.program) |*p| {
            if (self.main.fast_program == p) self.main.fast_program = null;
            p.deinit();
        }
        self.engine.deinit();
        if (self.ram_words) |*words| words.deinit();
        if (self.minimal_cpu0) |trace| {
            a.free(trace.records);
            a.free(trace.seeds);
        }
        a.destroy(self);
    }

    fn checkpointAt(self: *Segments, index: u32) ?*const rv.checkpoint.Checkpoint {
        self.pass.mutex.lock();
        defer self.pass.mutex.unlock();
        while (index >= self.pass.checkpoints.items.len and !self.pass.done) self.pass.changed.wait(&self.pass.mutex);
        if (index < self.pass.checkpoints.items.len) return self.pass.checkpoints.items[index];
        return null;
    }

    fn publish(self: *Segments, cp: rv.checkpoint.Checkpoint) !void {
        const owned = try self.allocator.create(rv.checkpoint.Checkpoint);
        owned.* = cp;
        self.pass.mutex.lock();
        defer self.pass.mutex.unlock();
        self.pass.checkpoints.append(self.allocator, owned) catch |err| {
            self.recorder.release(owned);
            self.allocator.destroy(owned);
            return err;
        };
        self.pass.changed.broadcast();
    }

    fn firstPass(self: *Segments) void {
        var timer = std.time.Timer.start() catch null;
        self.runFirstPass() catch |err| {
            self.pass.mutex.lock();
            self.pass.err = err;
            self.pass.mutex.unlock();
        };
        if (timer) |*t| self.stats.first_pass_ns = t.read();
        self.stats.first_pass_retired = self.main.cpuState().retired;
        self.stats.fast_retired = self.engine.fast_retired;
        if (self.ram_words) |words| {
            self.stats.first_pass_ram_words = words.count;
            self.stats.first_pass_ram_ready_utc_ns = @intCast(std.time.nanoTimestamp());
        }
        self.engine.detach();
        self.pass.mutex.lock();
        self.pass.done = true;
        self.pass.changed.broadcast();
        self.pass.mutex.unlock();
    }

    /// Executes like `Walk.next` batch by batch, without tracing. A guest
    /// error ends the pass silently: the segment re-executing that batch
    /// hits the same error and reports it in order.
    fn runFirstPass(self: *Segments) !void {
        const config = self.main.config;
        const session = &self.main.session;
        const cpu = &session.keccak.base.cpu;
        const ahead: u32 = 2 * @as(u32, self.workers) + 2;
        var index: u32 = 0;
        while (true) : (index += 1) {
            {
                self.pass.mutex.lock();
                defer self.pass.mutex.unlock();
                while (index >= self.pass.consumed + ahead and !self.pass.cancel) self.pass.changed.wait(&self.pass.mutex);
                if (self.pass.cancel) return;
            }
            try self.publish(try self.recorder.take(session));
            if (config.max_batches != 0 and index >= config.max_batches) return self.end(index);
            const limit = cpu.retired +| config.batch_steps;
            var event: rv.ethereum_services.Event = undefined;
            while (true) {
                if (index == 0 and self.minimal_cpu0 != null) {
                    if (self.ram_words) |*words| {
                        _ = try self.engine.runMinimalRam(cpu, @min(limit, config.max_steps), &self.minimal_cpu0.?, words);
                    } else _ = try self.engine.runMinimal(cpu, @min(limit, config.max_steps), &self.minimal_cpu0.?);
                } else if (self.ram_words) |*words| {
                    _ = try self.engine.runRam(cpu, @min(limit, config.max_steps), words);
                } else _ = self.engine.run(cpu, @min(limit, config.max_steps));
                if (cpu.pc == config.terminal_pc) break;
                if (cpu.retired == limit) break;
                if (index == 0) if (self.minimal_cpu0) |*trace| trace.prepareReference(&cpu.regs);
                const row = session.step(&event) catch return self.end(index + 1);
                if (index == 0) if (self.minimal_cpu0) |*trace| try trace.appendRetirement(row orelse event.retirement());
                if (self.ram_words) |*words| {
                    if (row) |retirement| try words.observeRetirement(retirement) else try words.observeEvent(event);
                }
                if (cpu.pc == config.terminal_pc or cpu.retired == limit) break;
            }
            if (index == 0) if (self.minimal_cpu0) |trace| {
                self.stats.minimal_cpu0_records = trace.len;
                self.stats.minimal_cpu0_bytes = trace.len * @sizeOf(rv.fast_execution.MinimalRecord) + (std.math.divCeil(usize, trace.len, rv.fast_execution.MINIMAL_CHUNK_ROWS) catch unreachable) * @sizeOf(rv.fast_execution.MinimalSeed);
                self.stats.minimal_cpu0_ready_utc_ns = @intCast(std.time.nanoTimestamp());
                std.debug.print("GPU_CPU_MINIMAL event=first_pass_ready ordinal=0 records={} bytes={} utc_ns={}\n", .{ trace.len, self.stats.minimal_cpu0_bytes, self.stats.minimal_cpu0_ready_utc_ns });
            };
            if (cpu.pc == config.terminal_pc) {
                // End state of the final batch, for its continuity check.
                try self.publish(try self.recorder.take(session));
                return self.end(index + 1);
            }
        }
    }

    fn end(self: *Segments, bound: u32) void {
        self.pass.mutex.lock();
        defer self.pass.mutex.unlock();
        self.pass.bound = bound;
    }

    /// Keep up to `workers` segments in flight from `next_index`. Blocks only
    /// for the checkpoint of `next_index` itself.
    fn launch(self: *Segments) !void {
        while (self.launched < self.next_index + self.workers) {
            const j = self.launched;
            {
                self.pass.mutex.lock();
                defer self.pass.mutex.unlock();
                while (j >= self.pass.checkpoints.items.len and !self.pass.done) {
                    if (j != self.next_index) return;
                    self.pass.changed.wait(&self.pass.mutex);
                }
                if (j >= self.pass.checkpoints.items.len or j >= self.pass.bound) return;
            }
            const w = try self.allocator.create(Worker);
            w.* = .{ .owner = self, .index = j };
            self.ring[j % MAX_WORKERS] = w;
            self.launched += 1;
            w.thread = std.Thread.spawn(.{}, Worker.run, .{w}) catch blk: {
                w.run();
                break :blk null;
            };
        }
    }

    pub const GlobalRam = struct { words: *const rv.ram_word_set.Set, counters: rv.checkpoint.Counters };
    /// Waits for the WHOLE fast pass, not the parallel traced capture. It never
    /// returns a partial key set on a recording/resource failure.
    pub fn globalRam(self: *Segments) !GlobalRam {
        self.pass.mutex.lock();
        defer self.pass.mutex.unlock();
        while (!self.pass.done) self.pass.changed.wait(&self.pass.mutex);
        if (self.pass.err) |err| return err;
        if (self.main.cpuState().pc != self.main.config.terminal_pc) return error.FirstPassRamIncomplete;
        const words = if (self.ram_words) |*value| value else return error.FirstPassRamUnavailable;
        if (words.failure) |err| return err;
        return .{ .words = words, .counters = rv.checkpoint.Counters.of(&self.main.session) };
    }

    pub const MinimalCpu = struct {
        trace: *const rv.fast_execution.MinimalTrace,
        initial: rv.machine.Cpu,
        final: rv.machine.Cpu,
    };
    /// CPU0 only, before consuming any traced batch. Publication of checkpoint1
    /// seals records/seeds; ownership remains Segments until destroy. A stage
    /// must finish/copy its borrow before returning to the capture caller.
    pub fn firstMinimalCpu(self: *Segments) !MinimalCpu {
        if (self.next_index != 0) return error.MinimalCpuAlreadyConsumed;
        const first = self.checkpointAt(0) orelse return error.MinimalCpuUnavailable;
        const following = self.checkpointAt(1) orelse return error.MinimalCpuUnavailable;
        const trace = if (self.minimal_cpu0) |*value| value else return error.MinimalCpuUnavailable;
        if (trace.len == 0 or following.cpu.retired - first.cpu.retired != trace.len) return error.MinimalCpuUnavailable;
        return .{ .trace = trace, .initial = first.cpu, .final = following.cpu };
    }

    /// The next batch in index order (caller owns it), or null when the
    /// serial walk would have stopped. Mirrors `Walk.nextTaking`.
    pub fn next(self: *Segments) !?Walk.Taken {
        const result = self.nextUnjoined();
        // Once no batch follows, the pass has stopped touching the request's
        // memory (its final image, e.g. for the terminal proof): join it.
        if (self.finished) self.joinPass();
        return result;
    }
    fn joinPass(self: *Segments) void {
        {
            self.pass.mutex.lock();
            defer self.pass.mutex.unlock();
            self.pass.cancel = true;
            self.pass.changed.broadcast();
        }
        if (self.pass_thread) |t| t.join();
        self.pass_thread = null;
        self.stats.pages_copied = self.recorder.pages_copied;
        self.stats.peak_live_pages = self.recorder.peak_live_pages;
    }
    fn nextUnjoined(self: *Segments) !?Walk.Taken {
        if (self.finished) return null;
        const config = self.main.config;
        if (config.max_batches != 0 and self.next_index >= config.max_batches) {
            self.finished = true;
            return null;
        }
        try self.launch();
        const slot = &self.ring[self.next_index % MAX_WORKERS];
        const w = slot.* orelse {
            // No worker: the pass ended without a checkpoint for this batch
            // (a recording failure; guest stops always launch their batch).
            self.finished = true;
            self.pass.mutex.lock();
            defer self.pass.mutex.unlock();
            return self.pass.err orelse error.EthereumSegmentContinuity;
        };
        var timer = try std.time.Timer.start();
        if (w.thread) |t| t.join();
        w.thread = null;
        self.stats.wait_ns += timer.read();
        slot.* = null;
        defer self.allocator.destroy(w);
        if (w.err) |err| {
            self.finished = true;
            return err;
        }
        // Batch k and the checkpoint before it are no longer needed.
        {
            self.pass.mutex.lock();
            defer self.pass.mutex.unlock();
            const cp = self.pass.checkpoints.items[self.next_index];
            self.recorder.release(cp);
            self.allocator.destroy(cp);
            self.pass.consumed = self.next_index + 1;
            self.pass.changed.broadcast();
        }
        self.next_index += 1;
        if (self.next_index == 1 and self.minimal_cpu0 != null) self.stats.minimal_cpu0_checked = true;
        self.stats.segments += 1;
        self.stats.walk_ns_total += w.walk_ns;
        self.stats.walk_ns_max = @max(self.stats.walk_ns_max, w.walk_ns);
        self.stats.walk_retired += w.retired;
        self.stats.walk_traced_ns += w.traced_ns;
        self.stats.walk_finish_ns += w.finish_ns;
        self.stats.walk_fast_retired += w.fast_retired;
        self.stats.walk_fast_ns += w.fast_ns;
        self.stats.walk_reference_ns += w.reference_ns;
        self.stats.walk_reference_steps += w.reference_steps;
        self.main.batches = self.next_index;
        if (w.completed) {
            self.main.completed = true;
            self.finished = true;
        }
        return w.taken.?;
    }
};

/// Serial walk or parallel segments behind one batch source.
pub const Source = struct {
    walk: *Walk,
    segments: ?*Segments = null,
    pub fn init(a: std.mem.Allocator, walk: *Walk, workers: u8) !Source {
        return .{ .walk = walk, .segments = if (workers == 0) null else try Segments.create(a, walk, workers) };
    }
    pub fn deinit(self: *Source) void {
        if (self.segments) |s| s.destroy();
        self.* = undefined;
    }
    pub fn cancelFirstPass(self: *Source) void {
        if (self.segments) |segments| segments.joinPass();
    }
    pub fn globalRam(self: *Source) !Segments.GlobalRam {
        return (self.segments orelse return error.FirstPassRamRequiresSegments).globalRam();
    }
    pub fn firstMinimalCpu(self: *Source) !Segments.MinimalCpu {
        return (self.segments orelse return error.MinimalCpuRequiresSegments).firstMinimalCpu();
    }
    pub fn next(self: *Source) !?Walk.Taken {
        return if (self.segments) |s| s.next() else self.walk.nextTaking();
    }
    /// Launch the first segment walks now (scheduling only; `next` would
    /// launch them on its first call). No-op for the serial walk.
    pub fn prime(self: *Source) !void {
        if (self.segments) |s| if (!s.finished) try s.launch();
    }
};
