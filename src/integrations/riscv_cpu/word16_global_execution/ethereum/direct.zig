//! In-process handoff: one process executes the guest and captures each batch
//! without serialising native job packets to disk. Producer-only scheduling;
//! no field here enters a proof statement or receiver identity.
//!
//! Authority is unchanged from the on-disk route: every batch passes the same
//! identity, statement-decode, ROM/PC admission and tape checks as a packet
//! read, and the same header resource limits and decoded-allocation bound
//! (`Packet.fromNative`), then the same ordered adjacency/ledger owner
//! (`Capture.Ordered`). Only packet framing, the SHA-256 transport digest and
//! the legacy Poseidon RAM frontier (which the Word16 reader skips: it carries
//! no INIT, terminal or global-memory authority there) are not produced, so the
//! limits on that frontier graph do not apply here (see `Packet.fromNative`).
//! Without the graph the sparse-cache root is never chained, so each batch's
//! `metadata.before`/`after` are `Packet.ABSENT_ROOT` (and `content_digest` is
//! zero) rather than a placeholder root; `fromNative` rejects any other value.
//!
//! Schedule: the calling thread runs only the execution walk. Each finished
//! batch is admitted (`Packet.fromNative`) and captured on its own helper
//! thread while execution continues; one consumer thread joins captures in
//! index order and feeds `Capture.Ordered` (the serial ledger). At most
//! `inflight` batches are outstanding. Acceptance order is fixed by index, so
//! the result is independent of thread timing.
const std = @import("std");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Packet = @import("../../word16_execution/packet.zig");
const Header = @import("../../rv64_work_packet_header.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const Capture = @import("capture.zig");
const Walk = @import("../../rv64_ethereum_native_prepare.zig").Walk;
const Segments = @import("../../rv64_ethereum_segments.zig");
const Collector = @import("../services/collector.zig");
/// M8 capture concurrency overrides (`STWO_RV64_M8_CAPTURE_INFLIGHT`,
/// `STWO_RV64_M8_CAPTURE_WORKERS`; unset = the caller's options). Producer
/// scheduling only. Measured A/B: see `vectors/reports/rv64-m8-20261106/
/// opt-T1-capture-parallel/README.md`.
fn envCount(name: []const u8, max: u8) ?u8 {
    const text = std.posix.getenv(name) orelse return null;
    const value = std.fmt.parseUnsigned(u8, text, 10) catch return null;
    if (value == 0 or value > max) return null;
    return value;
}
pub fn inflightOverride(inflight: u8) u8 {
    return envCount("STWO_RV64_M8_CAPTURE_INFLIGHT", MAX_INFLIGHT) orelse inflight;
}
pub fn workersOverride(workers: u8) u8 {
    if (workers == 0) return 0;
    return envCount("STWO_RV64_M8_CAPTURE_WORKERS", Segments.MAX_WORKERS) orelse workers;
}
pub const MAX_INFLIGHT = @import("capture_prefetch.zig").MAX_INFLIGHT;
pub const Stats = struct {
    batches: u32 = 0,
    max_inflight: u8 = 0,
    execution_ns: u64 = 0,
    join_wait_ns: u64 = 0,
    /// Parallel segment scheduling (segment_workers > 0 only).
    segments: ?Segments.Stats = null,
    /// Batch 0 critical path, ns from `capture` start: batch handed over by
    /// the walk, admitted (`Packet.fromNative`), captured (`captureOne`).
    first_batch_ready_ns: u64 = 0,
    first_batch_admit_ns: u64 = 0,
    first_batch_capture_ns: u64 = 0,
    /// Per-segment readiness timeline (the `Capture.Ready` instants, ns from
    /// the ordered owner's start) for the first `MAX_READY_TIMES` segments:
    /// when a streaming native stage 1 (M6) could start on each segment.
    segments_ready: u32 = 0,
    segment_ready_ns: [MAX_READY_TIMES]u64 = @splat(0),
    /// M6 async start: walk request init + segment start (on its own
    /// thread), and how long `capture` then waited for it.
    start_boot_ns: u64 = 0,
    start_join_ns: u64 = 0,
    fast_ram_words: u64 = 0,
    fast_ram_derive_ns: u64 = 0,
    fast_ram_ready_utc_ns: u64 = 0,
    fast_ram_compared: bool = false,
    fast_ram_keccak_calls: u64 = 0,
    /// M8 two-phase ledger: segments merged from a phase-1 local ledger,
    /// segments that fell back to the serial ledger, and summed phase-1 ns.
    local_ledgers: u64 = 0,
    local_fallbacks: u64 = 0,
    local_ledger_ns: u64 = 0,
    /// Summed per-job admission (`Packet.fromNative`) and capture (narrow
    /// capture, seal, event prefault, phase-1 ledger) durations.
    job_admit_ns: u64 = 0,
    job_capture_ns: u64 = 0,
};
pub const MAX_READY_TIMES = 32;
/// Records each segment's ready instant into `Stats`, then forwards to the
/// caller's hook (if any). Runs on the ordered owner's thread; report-only.
const ReadyTap = struct {
    stats: *Stats,
    inner: ?Capture.Ready,
    fn terminalReady(raw: *anyopaque, cells: []const @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell) void {
        const self: *ReadyTap = @ptrCast(@alignCast(raw));
        if (self.inner) |hook| if (hook.terminal_ready) |invoke| invoke(hook.context, cells);
    }
    fn nativeSegment(raw: *anyopaque, index: usize, native: *const Native, shard: @import("../services/collector.zig").Shard, at_ns: u64) void {
        const self: *ReadyTap = @ptrCast(@alignCast(raw));
        if (self.inner) |hook| if (hook.native_segment) |invoke| invoke(hook.context, index, native, shard, at_ns);
    }
    fn call(context: *anyopaque, index: usize, native: *const Native, events: []const @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event, at_ns: u64) void {
        const self: *ReadyTap = @ptrCast(@alignCast(context));
        if (index < MAX_READY_TIMES) self.stats.segment_ready_ns[index] = at_ns;
        self.stats.segments_ready = @intCast(index + 1);
        if (self.inner) |hook| hook.call(hook.context, index, native, events, at_ns);
    }
};
const Job = struct {
    allocator: std.mem.Allocator,
    program: *const Program,
    image: *const Image.Owner,
    config: Request.Config,
    index: usize,
    // Inputs, consumed by `run`.
    tape: ?@import("stwo_riscv_frontend").rv64.compact_tape.Tape,
    public: @import("../../rv64_keccak_cpu.zig").Public,
    metadata: Header.Metadata,
    cells: usize,
    chunks: usize,
    seal_native: bool = false,
    /// M8 two-phase ledger: this batch's starting checkpoint (released by
    /// `run`/`destroy`) and the phase-1 segment ledger built from it.
    start: ?*@import("stwo_riscv_frontend").rv64.checkpoint.Checkpoint = null,
    segments: ?*Segments.Segments = null,
    local: ?Collector.Local = null,
    local_ns: u64 = 0,
    // Outputs.
    packet: ?Packet.Packet = null,
    native: ?*Native = null,
    /// LS event array for this batch's ledger shard, allocated and
    /// prefaulted here in parallel (scheduling only; see `prepareEvents`).
    events: ?[]@import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event = null,
    err: ?anyerror = null,
    thread: ?std.Thread = null,
    /// Report-only durations of admission and capture.
    admit_ns: u64 = 0,
    capture_ns: u64 = 0,
    fn run(self: *Job) void {
        // The first batch gates the whole ordered ledger: its CPU capture
        // takes all its range helpers (M6; `STWO_RV64_CAPTURE_CRITICAL=0` off).
        if (self.index == 0 and criticalFirst()) @import("../../word16_execution/cpu_source.zig").critical_capture = true;
        defer @import("../../word16_execution/cpu_source.zig").critical_capture = false;
        lowerJobPriority();
        var timer = std.time.Timer.start() catch null;
        const tape = self.tape.?;
        self.tape = null;
        self.packet = Packet.fromNative(tape, self.public, self.metadata, self.cells, self.chunks, self.image, self.config) catch |err| {
            self.err = err;
            return;
        };
        if (timer) |*t| self.admit_ns = t.lap();
        self.native = Capture.Owner.captureOne(self.allocator, self.program, &self.packet.?, self.index) catch |err| {
            self.err = err;
            return;
        };
        // Seal alongside the parallel capture work. Ordered publication only
        // reads this cached seal, so hashing cannot serialize every segment's
        // ledger or add a second scan before early MAIN starts.
        if (self.seal_native) _ = @import("../../word16_execution/replay_capture.zig").sealCaptured(self.native.?) catch |err| {
            self.err = err;
            return;
        };
        // Best effort: on failure the ordered ledger allocates as before.
        self.events = @import("../services/collector.zig").prepareEvents(self.allocator, self.native.?) catch null;
        if (self.start) |cp| {
            // Phase 1 of the two-phase ledger; on any failure the ordered
            // owner runs the serial ledger for this segment instead.
            const local_start = std.time.Instant.now() catch null;
            self.local = Collector.prepareLocal(self.allocator, @import("../../word16_execution/memory/statement.zig").fromOwner(self.image), .{ .owner = self.image }, self.native.?, &self.packet.?.tape, self.index, &self.events, cp) catch null;
            if (local_start) |t0| if (std.time.Instant.now()) |t1| {
                self.local_ns = t1.since(t0);
            } else |_| {};
            self.releaseStart();
        }
        if (timer) |*t| self.capture_ns = t.read();
    }
    fn releaseStart(self: *Job) void {
        if (self.start) |cp| self.segments.?.releaseStart(cp);
        self.start = null;
    }
    fn join(self: *Job) void {
        if (self.thread) |t| t.join();
        self.thread = null;
    }
    fn destroy(self: *Job) void {
        self.join();
        self.releaseStart();
        if (self.local) |*l| l.deinit(self.allocator);
        if (self.tape) |*t| t.deinit();
        if (self.native) |n| {
            n.deinit();
            self.allocator.destroy(n);
        }
        if (self.events) |e| self.allocator.free(e);
        if (self.packet) |*p| p.deinit();
        self.allocator.destroy(self);
    }
};
fn criticalFirst() bool {
    const text = std.posix.getenv("STWO_RV64_CAPTURE_CRITICAL") orelse return true;
    return !std.mem.eql(u8, text, "0");
}
/// `STWO_RV64_CAPTURE_JOB_NICE=N` (1..19): run batch admission/capture (and
/// the range threads it spawns, which inherit it) at nice N, so the serial
/// ordered ledger and the segment walks win CPU under a quota. Scheduling only.
fn lowerJobPriority() void {
    if (@import("builtin").os.tag != .linux) return;
    const text = std.posix.getenv("STWO_RV64_CAPTURE_JOB_NICE") orelse return;
    const nice = std.fmt.parseInt(u5, text, 10) catch return;
    if (nice == 0 or nice > 19) return;
    // setpriority(PRIO_PROCESS, 0 = calling thread on Linux, nice).
    _ = std.os.linux.syscall3(.setpriority, 0, 0, nice);
}
/// Bounded in-order hand-over between the executing thread and the consumer.
const Queue = struct {
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    ring: [MAX_INFLIGHT]?*Job = @splat(null),
    head: usize = 0,
    live: usize = 0,
    closed: bool = false,
    /// Set by the consumer on its first error or on completion.
    stop: bool = false,
    /// Returns the outstanding count including `job`, or null if stopped.
    fn push(self: *Queue, job: *Job, limit: usize) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.live >= limit and !self.stop) self.changed.wait(&self.mutex);
        if (self.stop) return null;
        self.ring[(self.head + self.live) % MAX_INFLIGHT] = job;
        self.live += 1;
        self.changed.broadcast();
        return self.live;
    }
    /// Oldest job (still counted live until `release`), or null when closed.
    fn peek(self: *Queue) ?*Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.live == 0 and !self.closed) self.changed.wait(&self.mutex);
        if (self.live == 0) return null;
        return self.ring[self.head];
    }
    fn release(self: *Queue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ring[self.head] = null;
        self.head = (self.head + 1) % MAX_INFLIGHT;
        self.live -= 1;
        self.changed.broadcast();
    }
    fn close(self: *Queue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.changed.broadcast();
    }
    fn halt(self: *Queue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stop = true;
        self.changed.broadcast();
    }
    fn isStopped(self: *Queue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stop;
    }
};
const Consumer = struct {
    queue: *Queue,
    ordered: *Capture.Ordered,
    done: bool = false,
    err: ?anyerror = null,
    join_wait_ns: u64 = 0,
    first_admit_ns: u64 = 0,
    first_capture_ns: u64 = 0,
    local_ledgers: u64 = 0,
    local_ns: u64 = 0,
    admit_ns: u64 = 0,
    capture_ns: u64 = 0,
    fn run(self: *Consumer) void {
        while (self.runOne()) {}
    }
    /// Joins and accepts the oldest job; false once the queue is closed and empty.
    fn runOne(self: *Consumer) bool {
        const job = self.queue.peek() orelse return false;
        var timer = std.time.Timer.start() catch null;
        job.join();
        if (timer) |*t| self.join_wait_ns += t.read();
        self.admit_ns += job.admit_ns;
        self.capture_ns += job.capture_ns;
        if (job.index == 0) {
            self.first_admit_ns = job.admit_ns;
            self.first_capture_ns = job.capture_ns;
        }
        if (self.err == null and !self.done) self.accept(job) catch |err| {
            self.err = err;
            self.queue.halt();
        };
        self.queue.release();
        job.destroy();
        return true;
    }
    fn accept(self: *Consumer, job: *Job) !void {
        if (job.err) |err| {
            // A batch that failed admission was never admitted: surface the
            // ordered adjacency error first when the packet decoded at all.
            if (job.packet) |*p| try self.ordered.admit(p);
            return err;
        }
        const p = &job.packet.?;
        try self.ordered.admit(p);
        const n = job.native.?;
        job.native = null;
        const events = job.events;
        job.events = null;
        // Ownership of the phase-1 ledger moves to the ordered owner.
        var local = job.local;
        job.local = null;
        if (local != null) {
            self.local_ledgers += 1;
            self.local_ns += job.local_ns;
        }
        if (try self.ordered.acceptPrepared(p, n, events, if (local) |*l| l else null)) {
            self.done = true;
            self.queue.halt();
        }
    }
};
/// `a` must be thread-safe. `inflight` = 1 runs admission and capture of each
/// batch on the calling thread right after it executes (no overlap).
pub fn capture(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, prefix_packets: u32, inflight: u8, stats: *Stats) !Capture.Owner {
    return captureWithSegments(a, image, program, config, prefix_packets, inflight, 0, stats);
}
/// `segment_workers` > 0: batches come from a fast first pass plus that many
/// concurrent segment walks (rv64_ethereum_segments.zig), in index order and
/// byte-identical to the serial walk; 0 = the serial walk.
pub fn captureWithSegments(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, prefix_packets: u32, inflight: u8, segment_workers: u8, stats: *Stats) !Capture.Owner {
    if (prefix_packets > 256) return error.TooManyEthereumPackets;
    if (inflight == 0 or inflight > MAX_INFLIGHT) return error.InvalidEthereumCaptureOptions;
    if (Segments.ramFirstPassEnabled() and (prefix_packets != 0 or segment_workers == 0)) return error.FirstPassRamRequiresWholeSegmentedBlock;
    var started = try Started.start(a, config, prefix_packets, segment_workers);
    defer started.deinit(stats);
    return started.capture(image, program, inflight, stats);
}
/// The executing half of the handoff, started before the caller's expected
/// image/program init so execution overlaps it: the walk's own request
/// (pinned ELF/input, ROM authority, policy; no legacy Poseidon cache, see
/// `Request.Options`), the fast first pass and, with segment workers, the
/// first segment walks. Nothing here is admitted yet: every batch still goes
/// through `Packet.fromNative` against the caller's independently loaded
/// image and the ordered owner in `capture`. Heap-pinned (threads borrow it).
pub const Started = struct {
    allocator: std.mem.Allocator,
    config: Request.Config,
    walk_config: Request.Config,
    prefix_packets: u32,
    segment_workers: u8,
    authority_provider: ?Request.AuthorityProvider = null,
    /// Set by `boot` (null until joined, or after a boot failure).
    walk: ?*Walk = null,
    source: ?Segments.Source = null,
    /// M6: the walk's own request init (pinned ELF/input, ROM authority,
    /// policy) and segment start run on this thread, so they overlap the
    /// caller's expected image/program init instead of preceding it.
    /// `STWO_RV64_CAPTURE_ASYNC_START=0` boots on the caller's thread.
    boot_thread: ?std.Thread = null,
    boot_err: ?anyerror = null,
    /// Report-only: walk request init and segment start.
    boot_ns: u64 = 0,
    /// Optional per-segment readiness hook (M6), set before `capture`.
    ready: ?Capture.Ready = null,
    pub fn start(a: std.mem.Allocator, config: Request.Config, prefix_packets: u32, segment_workers: u8) !*Started {
        return startWithAuthority(a, config, prefix_packets, segment_workers, null);
    }
    pub fn startWithAuthority(a: std.mem.Allocator, config: Request.Config, prefix_packets: u32, segment_workers: u8, provider: ?Request.AuthorityProvider) !*Started {
        if (prefix_packets > 256) return error.TooManyEthereumPackets;
        var walk_config = config;
        // Never collect batches the requested prefix will not consume.
        if (prefix_packets != 0 and (walk_config.max_batches == 0 or walk_config.max_batches > prefix_packets)) walk_config.max_batches = prefix_packets;
        const self = try a.create(Started);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .config = config, .walk_config = walk_config, .prefix_packets = prefix_packets, .segment_workers = workersOverride(segment_workers), .ready = null, .authority_provider = provider };
        const async_start = if (std.posix.getenv("STWO_RV64_CAPTURE_ASYNC_START")) |v| !std.mem.eql(u8, v, "0") else true;
        if (async_start) {
            if (std.Thread.spawn(.{}, bootThread, .{self})) |t| {
                self.boot_thread = t;
                return self;
            } else |_| {}
        }
        try self.boot();
        return self;
    }
    fn bootThread(self: *Started) void {
        self.boot() catch |err| {
            self.boot_err = err;
        };
    }
    fn boot(self: *Started) !void {
        var timer = std.time.Timer.start() catch null;
        defer if (timer) |*t| {
            self.boot_ns = t.read();
        };
        const a = self.allocator;
        const walk = try Walk.createWithOptions(a, self.walk_config, .{ .poseidon_initial_cache = false, .authority_provider = self.authority_provider });
        errdefer walk.destroy();
        var source = try Segments.Source.init(a, walk, self.segment_workers);
        errdefer source.deinit();
        try source.prime();
        self.walk = walk;
        self.source = source;
    }
    /// Waits for the boot (walk init and segment start); its error, if any.
    fn joinBoot(self: *Started) !void {
        if (self.boot_thread) |t| t.join();
        self.boot_thread = null;
        if (self.boot_err) |err| return err;
    }
    /// Joins every thread and frees the walk (also after a failed `capture`).
    pub fn deinit(self: *Started, stats: *Stats) void {
        self.joinBoot() catch {};
        stats.start_boot_ns = self.boot_ns;
        if (self.source) |*source| {
            if (source.segments) |seg| stats.segments = seg.stats;
            source.deinit();
        }
        if (self.walk) |walk| walk.destroy();
        self.allocator.destroy(self);
    }
    /// Admits and captures every batch in index order. Call at most once.
    pub fn capture(self: *Started, image: *const Image.Owner, program: *const Program, inflight: u8, stats: *Stats) !Capture.Owner {
        var timer = std.time.Timer.start() catch null;
        try self.joinBoot();
        if (timer) |*t| stats.start_join_ns = t.read();
        return run(self.allocator, image, program, self.config, self.prefix_packets, inflightOverride(inflight), self.walk.?, &self.source.?, self.ready, stats);
    }
};
const RamJob = struct {
    allocator: std.mem.Allocator,
    image: *const Image.Owner,
    source: *Segments.Source,
    stats: *Stats,
    hook: ?Capture.Ready,
    cells: ?[]@import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell = null,
    // Borrow retained through capture return even when ownership transfers,
    // so final Collector equivalence remains mandatory before publication.
    comparison_cells: ?[]const @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell = null,
    failure: ?anyerror = null,
    thread: ?std.Thread = null,
    fn run(self: *RamJob) void {
        self.work() catch |err| {
            self.failure = err;
        };
    }
    fn join(self: *RamJob) void {
        if (self.thread) |thread| thread.join();
        self.thread = null;
    }
    fn work(self: *RamJob) !void {
        const ram = try self.source.globalRam();
        var timer = try std.time.Timer.start();
        const a = self.allocator;
        const keys = try ram.words.sorted(a);
        defer a.free(keys);
        const Cell = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell;
        const cells = try a.alloc(Cell, keys.len);
        self.cells = cells;
        self.comparison_cells = cells;
        var pages = @import("../collector.zig").OwnerPages{ .owner = self.image };
        const pinned = @import("../../word16_execution/memory/statement.zig").fromOwner(self.image);
        for (keys, cells) |key, *cell| cell.* = .{ .address = key, .state = pages.lookup(key) orelse .{ .value = try self.image.initialWord(key), .rights = try pinned.wordRights(key) } };
        self.stats.fast_ram_words = cells.len;
        self.stats.fast_ram_derive_ns = timer.read();
        self.stats.fast_ram_ready_utc_ns = @intCast(std.time.nanoTimestamp());
        self.stats.fast_ram_keccak_calls = ram.counters.keccak;
        std.debug.print("GPU_FAST_RAM event=initial_ready utc_ns={} words={} derive_ns={} keccak_calls={}\n", .{ self.stats.fast_ram_ready_utc_ns, cells.len, self.stats.fast_ram_derive_ns, ram.counters.keccak });
        const info = Capture.GlobalRamInfo{ .counters = ram.counters, .total_steps = ram.total_steps, .final_pc = ram.final_pc };
        if (self.hook) |hook| {
            // Old synchronous borrower finishes before ownership can transfer.
            if (hook.global_ram) |call| call(hook.context, cells, info);
            if (hook.take_global_ram) |take| if (take(hook.context, a, cells, info)) {
                self.cells = null;
            };
        }
    }
};

fn run(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, prefix_packets: u32, inflight: u8, walk: *Walk, source: *Segments.Source, ready: ?Capture.Ready, stats: *Stats) !Capture.Owner {
    if (inflight == 0 or inflight > MAX_INFLIGHT) return error.InvalidEthereumCaptureOptions;
    if (Segments.ramFirstPassEnabled() and (prefix_packets != 0 or source.segments == null)) return error.FirstPassRamRequiresWholeSegmentedBlock;
    var ordered = Capture.Ordered.init(a, image, config, prefix_packets);
    defer ordered.deinit();
    // Queue cleanup below joins all readiness publishers first. Then cancel
    // their asynchronous readers BEFORE ordered.deinit frees captured values.
    errdefer if (ready) |hook| if (hook.cancel) |cancel| cancel(hook.context);
    var tap = ReadyTap{ .stats = stats, .inner = ready };
    ordered.on_ready = .{ .context = &tap, .call = ReadyTap.call, .native_segment = ReadyTap.nativeSegment, .terminal_ready = ReadyTap.terminalReady, .seal_native = if (ready) |hook| hook.seal_native else false };
    var queue = Queue{};
    var consumer = Consumer{ .queue = &queue, .ordered = &ordered };
    const local_ledger = source.segments != null and Collector.localLedgerEnabled();
    if (source.segments) |segments| segments.retain_starts = local_ledger;
    const fallbacks_before = Collector.local_stats.fallbacks;
    const concurrent = inflight > 1;
    var consumer_thread: ?std.Thread = if (concurrent) try std.Thread.spawn(.{}, Consumer.run, .{&consumer}) else null;
    // Always close and drain the consumer before `ordered`/`walk` unwind.
    defer {
        queue.close();
        if (consumer_thread) |t| t.join();
        consumer_thread = null;
        consumer.run(); // frees any job left after an early exit
    }
    var timer = try std.time.Timer.start();
    var ram_job = RamJob{ .allocator = a, .image = image, .source = source, .stats = stats, .hook = ready };
    var stack = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.ExternalReservation.empty();
    defer stack.deinit();
    if (Segments.ramFirstPassEnabled()) {
        const stack_bytes: usize = 2 << 20;
        if (ready) |hook| {
            if (hook.ram_stack_budget) |budget| stack = try budget.reserveExternal(stack_bytes) else if (hook.require_ram_stack_budget) return error.SharedExternalBudgetRequired;
        }
        ram_job.thread = try std.Thread.spawn(.{ .stack_size = stack_bytes }, RamJob.run, .{&ram_job});
    }
    // A failed capture can leave the first pass under bounded checkpoint
    // backpressure. Cancel it before joining this waiter, while all Source
    // owners still live, so no path waits for a consumer that has stopped.
    defer {
        if (ram_job.thread != null) {
            // A global-RAM consumer may be waiting for local capture. Wake it
            // before joining; publishers and all input owners still live.
            if (ready) |hook| if (hook.cancel) |cancel| cancel(hook.context);
            source.cancelFirstPass();
        }
        ram_job.join();
        if (ram_job.cells) |cells| a.free(cells);
    }
    if (ready) |hook| if (hook.first_pass) |early| {
        const minimal = try source.firstMinimalCpu();
        const public = @import("stwo_riscv_frontend").rv64_air.word16_execution.types.Boundary{
            .steps = @intCast(minimal.trace.len),
            .initial_pc = minimal.initial.pc,
            .final_pc = minimal.final.pc,
            .initial_registers = minimal.initial.regs,
            .final_registers = minimal.final.regs,
            .register_clocks = minimal.trace.clocks,
        };
        const first = @import("../../word16_execution/cpu_source.zig").FirstPass{
            .program = program,
            .public = public,
            .epoch = 1,
            .log_size = try @import("../../word16_execution/coverage.zig").minimalCpuLog(public.steps),
            .trace = minimal.trace,
        };
        std.debug.print("GPU_CPU_MINIMAL event=before_traced_capture utc_ns={} records={}\n", .{ std.time.nanoTimestamp(), minimal.trace.len });
        early(hook.context, &first);
    };
    var failure: ?anyerror = null;
    while (!queue.isStopped()) {
        const started = timer.read();
        const maybe = source.next() catch |err| {
            failure = err;
            break;
        };
        stats.execution_ns += timer.read() - started;
        const step = maybe orelse break;
        if (step.index == 0) stats.first_batch_ready_ns = timer.read();
        var finished = step.finished;
        defer finished.deinit();
        var tape = step.tape;
        const metadata = Header.Metadata{ .identity = walk.identity, .index = step.index, .first_step = tape.initial_clock, .before = Packet.ABSENT_ROOT, .after = Packet.ABSENT_ROOT };
        const job = a.create(Job) catch |err| {
            tape.deinit();
            failure = err;
            break;
        };
        job.* = .{ .allocator = a, .program = program, .image = image, .config = config, .index = step.index, .tape = tape, .public = finished.public, .metadata = metadata, .cells = finished.cells.len, .chunks = if (finished.openings) |o| o.chunks.len else 0, .seal_native = if (ready) |hook| hook.seal_native else false };
        if (local_ledger) {
            job.segments = source.segments;
            job.start = source.segments.?.takeStart();
        }
        stats.batches += 1;
        if (!concurrent) {
            job.run();
            _ = queue.push(job, 1) orelse {
                job.destroy();
                break;
            };
            _ = consumer.runOne();
            stats.max_inflight = 1;
            continue;
        }
        job.thread = std.Thread.spawn(.{}, Job.run, .{job}) catch blk: {
            job.run();
            break :blk null;
        };
        const live = queue.push(job, inflight) orelse {
            job.destroy();
            break;
        };
        stats.max_inflight = @max(stats.max_inflight, @as(u8, @intCast(live)));
    }
    queue.close();
    if (consumer_thread) |t| t.join();
    consumer_thread = null;
    stats.join_wait_ns = consumer.join_wait_ns;
    stats.local_ledgers = consumer.local_ledgers;
    stats.job_admit_ns = consumer.admit_ns;
    stats.job_capture_ns = consumer.capture_ns;
    stats.local_ledger_ns = consumer.local_ns;
    stats.local_fallbacks = Collector.local_stats.fallbacks - fallbacks_before;
    if (stats.batches != 0) {
        stats.first_batch_admit_ns = stats.first_batch_ready_ns + consumer.first_admit_ns;
        stats.first_batch_capture_ns = stats.first_batch_admit_ns + consumer.first_capture_ns;
    }
    if (failure) |err| return err;
    if (consumer.err) |err| return err;
    stats.max_inflight = @max(1, stats.max_inflight);
    var result = try ordered.finish(.{ .max_inflight_packets = stats.max_inflight, .max_worker_shards = stats.max_inflight });
    errdefer {
        // terminal_ready may already have started an asynchronous last-segment
        // reader. Join it before freeing advice on post-finish RAM mismatch.
        if (ready) |hook| if (hook.cancel) |cancel| cancel(hook.context);
        result.deinit();
    }
    ram_job.join();
    if (ram_job.failure) |err| return err;
    if (ram_job.comparison_cells) |cells| {
        if (cells.len != result.advice.initial.len) {
            std.debug.print("GPU_FAST_RAM mismatch first_pass={} collector={}\n", .{ cells.len, result.advice.initial.len });
            return error.FirstPassRamMismatch;
        }
        for (cells, result.advice.initial) |early, final| if (!std.meta.eql(early, final)) return error.FirstPassRamMismatch;
        stats.fast_ram_compared = true;
    }
    return result;
}
