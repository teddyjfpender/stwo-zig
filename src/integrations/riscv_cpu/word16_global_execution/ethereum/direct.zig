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
};
pub const MAX_READY_TIMES = 32;
/// Records each segment's ready instant into `Stats`, then forwards to the
/// caller's hook (if any). Runs on the ordered owner's thread; report-only.
const ReadyTap = struct {
    stats: *Stats,
    inner: ?Capture.Ready,
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
        // Best effort: on failure the ordered ledger allocates as before.
        self.events = @import("../services/collector.zig").prepareEvents(self.allocator, self.native.?) catch null;
        if (timer) |*t| self.capture_ns = t.read();
    }
    fn join(self: *Job) void {
        if (self.thread) |t| t.join();
        self.thread = null;
    }
    fn destroy(self: *Job) void {
        self.join();
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
    fn run(self: *Consumer) void {
        while (self.runOne()) {}
    }
    /// Joins and accepts the oldest job; false once the queue is closed and empty.
    fn runOne(self: *Consumer) bool {
        const job = self.queue.peek() orelse return false;
        var timer = std.time.Timer.start() catch null;
        job.join();
        if (timer) |*t| self.join_wait_ns += t.read();
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
        if (try self.ordered.acceptWithEvents(p, n, events)) {
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
    prefix_packets: u32,
    walk: *Walk,
    source: Segments.Source,
    /// Optional per-segment readiness hook (M6), set before `capture`.
    ready: ?Capture.Ready = null,
    pub fn start(a: std.mem.Allocator, config: Request.Config, prefix_packets: u32, segment_workers: u8) !*Started {
        if (prefix_packets > 256) return error.TooManyEthereumPackets;
        var walk_config = config;
        // Never collect batches the requested prefix will not consume.
        if (prefix_packets != 0 and (walk_config.max_batches == 0 or walk_config.max_batches > prefix_packets)) walk_config.max_batches = prefix_packets;
        const self = try a.create(Started);
        errdefer a.destroy(self);
        const walk = try Walk.createWithOptions(a, walk_config, .{ .poseidon_initial_cache = false });
        errdefer walk.destroy();
        self.* = .{ .allocator = a, .config = config, .prefix_packets = prefix_packets, .walk = walk, .source = try Segments.Source.init(a, walk, segment_workers), .ready = null };
        errdefer self.source.deinit();
        try self.source.prime();
        return self;
    }
    /// Joins every thread and frees the walk (also after a failed `capture`).
    pub fn deinit(self: *Started, stats: *Stats) void {
        if (self.source.segments) |seg| stats.segments = seg.stats;
        self.source.deinit();
        self.walk.destroy();
        self.allocator.destroy(self);
    }
    /// Admits and captures every batch in index order. Call at most once.
    pub fn capture(self: *Started, image: *const Image.Owner, program: *const Program, inflight: u8, stats: *Stats) !Capture.Owner {
        return run(self.allocator, image, program, self.config, self.prefix_packets, inflight, self.walk, &self.source, self.ready, stats);
    }
};
fn run(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, prefix_packets: u32, inflight: u8, walk: *Walk, source: *Segments.Source, ready: ?Capture.Ready, stats: *Stats) !Capture.Owner {
    if (inflight == 0 or inflight > MAX_INFLIGHT) return error.InvalidEthereumCaptureOptions;
    var ordered = Capture.Ordered.init(a, image, config, prefix_packets);
    defer ordered.deinit();
    var tap = ReadyTap{ .stats = stats, .inner = ready };
    ordered.on_ready = .{ .context = &tap, .call = ReadyTap.call };
    var queue = Queue{};
    var consumer = Consumer{ .queue = &queue, .ordered = &ordered };
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
        job.* = .{ .allocator = a, .program = program, .image = image, .config = config, .index = step.index, .tape = tape, .public = finished.public, .metadata = metadata, .cells = finished.cells.len, .chunks = if (finished.openings) |o| o.chunks.len else 0 };
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
    if (stats.batches != 0) {
        stats.first_batch_admit_ns = stats.first_batch_ready_ns + consumer.first_admit_ns;
        stats.first_batch_capture_ns = stats.first_batch_admit_ns + consumer.first_capture_ns;
    }
    if (failure) |err| return err;
    if (consumer.err) |err| return err;
    stats.max_inflight = @max(1, stats.max_inflight);
    return ordered.finish(.{ .max_inflight_packets = stats.max_inflight, .max_worker_shards = stats.max_inflight });
}
