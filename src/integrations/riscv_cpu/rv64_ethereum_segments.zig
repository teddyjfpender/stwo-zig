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
pub const MAX_WORKERS = 32;

pub const Stats = struct {
    segments: u32 = 0,
    workers: u8 = 0,
    first_pass_ns: u64 = 0,
    first_pass_retired: u64 = 0,
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
        self.completed = walk.completed;
        self.retired = taken.tape.len;
        self.taken = taken;
    }
};

pub const Segments = struct {
    allocator: std.mem.Allocator,
    main: *Walk,
    workers: u8,
    engine: rv.fast_execution.Engine,
    recorder: rv.checkpoint.Recorder,
    pass: FirstPass = .{},
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
        self.engine = try rv.fast_execution.Engine.init(a, main.memory, .{ .stop_pcs = &.{main.config.terminal_pc}, .isa = main.session.keccak.base.decoder.isa });
        errdefer self.engine.deinit();
        self.engine.attach();
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
        self.engine.deinit();
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
                _ = self.engine.run(cpu, @min(limit, config.max_steps));
                if (cpu.pc == config.terminal_pc) break;
                if (cpu.retired == limit) break;
                _ = session.step(&event) catch return self.end(index + 1);
                if (cpu.pc == config.terminal_pc or cpu.retired == limit) break;
            }
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
        self.stats.segments += 1;
        self.stats.walk_ns_total += w.walk_ns;
        self.stats.walk_ns_max = @max(self.stats.walk_ns_max, w.walk_ns);
        self.stats.walk_retired += w.retired;
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
    pub fn next(self: *Source) !?Walk.Taken {
        return if (self.segments) |s| s.next() else self.walk.nextTaking();
    }
    /// Launch the first segment walks now (scheduling only; `next` would
    /// launch them on its first call). No-op for the serial walk.
    pub fn prime(self: *Source) !void {
        if (self.segments) |s| if (!s.finished) try s.launch();
    }
};
