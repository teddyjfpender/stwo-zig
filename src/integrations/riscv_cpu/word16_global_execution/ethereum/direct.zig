//! In-process handoff: one process executes the guest and captures each batch
//! without serialising native job packets to disk. Producer-only scheduling;
//! no field here enters a proof statement or receiver identity.
//!
//! Authority is unchanged from the on-disk route: every batch passes the same
//! identity, statement-decode, ROM/PC admission and tape checks as a packet
//! read (`Packet.fromNative`), then the same ordered adjacency/ledger owner
//! (`Capture.Ordered`). Only packet framing, the SHA-256 transport digest and
//! the legacy Poseidon RAM frontier (which the Word16 reader skips: it carries
//! no INIT, terminal or global-memory authority there) are not produced.
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
pub const MAX_INFLIGHT = @import("capture_prefetch.zig").MAX_INFLIGHT;
pub const Stats = struct {
    batches: u32 = 0,
    max_inflight: u8 = 0,
    execution_ns: u64 = 0,
    join_wait_ns: u64 = 0,
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
    // Outputs.
    packet: ?Packet.Packet = null,
    native: ?*Native = null,
    err: ?anyerror = null,
    thread: ?std.Thread = null,
    fn run(self: *Job) void {
        const tape = self.tape.?;
        self.tape = null;
        self.packet = Packet.fromNative(tape, self.public, self.metadata, self.cells, self.image, self.config) catch |err| {
            self.err = err;
            return;
        };
        self.native = Capture.Owner.captureOne(self.allocator, self.program, &self.packet.?, self.index) catch |err| {
            self.err = err;
            return;
        };
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
        if (self.packet) |*p| p.deinit();
        self.allocator.destroy(self);
    }
};
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
    fn run(self: *Consumer) void {
        while (self.runOne()) {}
    }
    /// Joins and accepts the oldest job; false once the queue is closed and empty.
    fn runOne(self: *Consumer) bool {
        const job = self.queue.peek() orelse return false;
        var timer = std.time.Timer.start() catch null;
        job.join();
        if (timer) |*t| self.join_wait_ns += t.read();
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
        if (try self.ordered.accept(p, n)) {
            self.done = true;
            self.queue.halt();
        }
    }
};
/// `a` must be thread-safe. `inflight` = 1 runs admission and capture of each
/// batch on the calling thread right after it executes (no overlap).
pub fn capture(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, prefix_packets: u32, inflight: u8, stats: *Stats) !Capture.Owner {
    if (prefix_packets > 256) return error.TooManyEthereumPackets;
    if (inflight == 0 or inflight > MAX_INFLIGHT) return error.InvalidEthereumCaptureOptions;
    var walk_config = config;
    // Never collect batches the requested prefix will not consume.
    if (prefix_packets != 0 and (walk_config.max_batches == 0 or walk_config.max_batches > prefix_packets)) walk_config.max_batches = prefix_packets;
    var walk = try Walk.create(a, walk_config);
    defer walk.destroy();
    var ordered = Capture.Ordered.init(a, image, config, prefix_packets);
    defer ordered.deinit();
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
        const maybe = walk.next() catch |err| {
            failure = err;
            break;
        };
        stats.execution_ns += timer.read() - started;
        var step = maybe orelse break;
        var finished = step.finished;
        defer finished.deinit();
        const root = walk.request.initial_cache.root();
        const metadata = Header.Metadata{ .identity = walk.identity, .index = step.index, .first_step = walk.tape.initial_clock, .before = root, .after = root };
        var tape = walk.advanceTakingTape(&step.batch) catch |err| {
            failure = err;
            break;
        };
        const job = a.create(Job) catch |err| {
            tape.deinit();
            failure = err;
            break;
        };
        job.* = .{ .allocator = a, .program = program, .image = image, .config = config, .index = step.index, .tape = tape, .public = finished.public, .metadata = metadata, .cells = finished.cells.len };
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
    if (failure) |err| return err;
    if (consumer.err) |err| return err;
    stats.max_inflight = @max(1, stats.max_inflight);
    return ordered.finish(.{ .max_inflight_packets = stats.max_inflight, .max_worker_shards = stats.max_inflight });
}
