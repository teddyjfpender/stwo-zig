//! One native execution walk producing durable, independently consumable narrow
//! jobs. Collection is not execution-proof acceptance or recursive aggregation.
const std = @import("std");
const A = @import("stwo_riscv_cpu_integration").rv64_execution.legacy.authenticated;
const rv = @import("ethereum_frontend_component").rv64;
const Request = @import("rv64_ethereum_request.zig");
const Native = @import("rv64_ethereum_batch.zig");
const Packet = @import("rv64_prepared_work_packet.zig");
const Receipt = @import("stwo_riscv_cpu_integration").rv64_proof_artifact_support;
const Terminal = @import("stwo_riscv_cpu_integration").rv64_execution.runtime.terminal;
pub const Summary = struct {
    schema: []const u8 = "rv64-native-work-collection-v1",
    identity: Packet.Identity,
    collected_batches: u32,
    instructions: u64,
    completed: bool,
    global_chain_accepted: bool = false,
    recursive_aggregation: bool = false,
};
const Persist = struct {
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    name: []const u8,
    metadata: Packet.Metadata,
    finished: *const Native.Finished,
    tape: *const rv.compact_tape.Tape,
    digest: ?Packet.Digest = null,
    fn write(context: ?*anyopaque, graph: *const A.R.native_frontier.Prepared) anyerror!void {
        const self: *Persist = @ptrCast(@alignCast(context.?));
        self.metadata.after = graph.witness.after;
        self.digest = try Packet.writeAtomic(self.allocator, self.directory, self.name, .{ .metadata = self.metadata, .finished = self.finished, .native = graph, .tape = self.tape });
    }
};
/// The single native execution walk, one batch per `next`. Both the durable
/// job collector (`run`) and the in-process Word16 handoff consume it, so the
/// executed retirements, tape advice, boundary cells and statements are the
/// same code path whichever consumer is attached. Heap-pinned: the session
/// borrows the request's memory.
pub const Walk = struct {
    allocator: std.mem.Allocator,
    config: Request.Config,
    /// Shared immutable setup (authority, policy, expected output). Owned by
    /// the walk from `create`; borrowed from the parent by segment walks.
    request: *Request.Request,
    owns_request: bool,
    /// Guest memory this walk executes on: the request's own image, or an
    /// independently owned checkpoint image for a segment walk.
    memory: *rv.memory.Memory,
    owns_memory: bool,
    identity: Packet.Identity,
    session: rv.ethereum_services.Session,
    tape: rv.compact_tape.Tape,
    capture: rv.boundary_capture.Capture,
    batches: u32 = 0,
    calls: [3]u64 = @splat(0),
    sha256_calls: u64 = 0,
    arith256_calls: u64 = 0,
    curve_calls: [rv.ethereum_services.curves.COUNT]u64 = @splat(0),
    completed: bool = false,
    pending: bool = false,
    /// Report-only emulator split (M7 baseline): traced execution
    /// (`captureNext` loop) and `batch.finish`, summed over batches.
    traced_ns: u64 = 0,
    finish_ns: u64 = 0,
    /// M6 traced fast engine. `fast_program` (borrowed, immutable, restricted
    /// to this request's authority with `Native.admitsFast`) is inherited by
    /// segment walks; `fast` executes on this walk's own memory. Null: the
    /// reference `captureNext` loop. Output bytes are identical either way.
    fast_program: ?*const rv.fast_execution.Engine = null,
    fast: ?rv.fast_execution.Engine = null,
    /// Steps retired by `fast` (report-only), and the split of `traced_ns`
    /// into fast runs and reference `captureNext` steps (count, time).
    fast_retired: u64 = 0,
    fast_ns: u64 = 0,
    reference_ns: u64 = 0,
    reference_steps: u64 = 0,
    pub const Step = struct {
        index: u32,
        batch: Native.Batch,
        finished: Native.Finished,
    };
    /// A finished batch whose tape the walk has handed over (see `nextTaking`).
    pub const Taken = struct {
        index: u32,
        finished: Native.Finished,
        tape: rv.compact_tape.Tape,
        pub fn deinit(self: *Taken) void {
            self.finished.deinit();
            self.tape.deinit();
            self.* = undefined;
        }
    };
    pub fn create(a: std.mem.Allocator, config: Request.Config) !*Walk {
        return createWithOptions(a, config, .{});
    }
    /// `options.poseidon_initial_cache = false` is for consumers that never
    /// chain the legacy Poseidon frontier (the in-process Word16 handoff);
    /// `run` (durable job collection) requires the cache.
    pub fn createWithOptions(a: std.mem.Allocator, config: Request.Config, options: Request.Options) !*Walk {
        try Request.validateBudget(config);
        const request = try a.create(Request.Request);
        errdefer a.destroy(request);
        request.* = try Request.Request.initWithOptions(a, config, options);
        errdefer request.deinit();
        const cpu = rv.machine.Cpu.init(request.loaded.info.entry, config.symbols.stack_top);
        return createOn(a, config, request, true, &request.loaded.memory, false, cpu, .{}, 0);
    }
    /// A walk that executes batch `index` (and any later ones) from a fast
    /// first-pass checkpoint, on its own copy of the checkpoint image. It
    /// borrows `parent`'s request; `parent` must outlive it.
    pub fn createSegment(a: std.mem.Allocator, parent: *const Walk, cp: *const rv.checkpoint.Checkpoint, index: u32) !*Walk {
        const memory = try a.create(rv.memory.Memory);
        errdefer a.destroy(memory);
        memory.* = try rv.checkpoint.materialize(a, parent.memory, cp);
        errdefer memory.deinit();
        const self = try createOn(a, parent.config, parent.request, false, memory, true, cp.cpu, cp.counters, index);
        errdefer self.destroy();
        if (parent.fast_program) |program| try self.useFast(program);
        return self;
    }
    /// Execute ordinary instructions with the traced fast engine borrowing
    /// `program` (built on an image with this walk's mappings).
    pub fn useFast(self: *Walk, program: *const rv.fast_execution.Engine) !void {
        if (self.fast != null or self.pending or self.tape.len != 0) return error.InvalidEthereumBatchSeed;
        self.fast = try rv.fast_execution.Engine.initBorrowing(self.allocator, self.memory, program);
        self.fast_program = program;
    }
    fn createOn(a: std.mem.Allocator, config: Request.Config, request: *Request.Request, owns_request: bool, memory: *rv.memory.Memory, owns_memory: bool, cpu_state: rv.machine.Cpu, counters: rv.checkpoint.Counters, index: u32) !*Walk {
        const self = try a.create(Walk);
        errdefer a.destroy(self);
        self.allocator = a;
        self.config = config;
        self.request = request;
        self.owns_request = owns_request;
        self.memory = memory;
        self.owns_memory = owns_memory;
        self.traced_ns = 0;
        self.finish_ns = 0;
        self.fast_program = null;
        self.fast = null;
        self.fast_retired = 0;
        self.fast_ns = 0;
        self.reference_ns = 0;
        self.reference_steps = 0;
        self.identity = try Packet.identityFor(config, &self.request.authority, &self.request.policy);
        self.session = try rv.ethereum_services.Session.initWithProfile(a, cpu_state, memory, .{ .max_retirements = config.max_steps }, Request.tapeProfile(config));
        errdefer self.session.deinit();
        counters.apply(&self.session);
        const cpu = &self.session.keccak.base.cpu;
        self.tape = try rv.compact_tape.Tape.init(a, config.batch_steps, cpu.pc, cpu.retired, Request.tapeProfile(config));
        errdefer self.tape.deinit();
        self.capture = try rv.boundary_capture.Capture.init(a, cpu.retired, config.batch_steps, 1 << 24);
        self.batches = index;
        self.calls = .{ counters.keccak, counters.add, counters.double };
        self.sha256_calls = counters.sha256;
        self.arith256_calls = counters.arith256_mod;
        self.curve_calls = counters.curve;
        self.completed = false;
        self.pending = false;
        return self;
    }
    pub fn destroy(self: *Walk) void {
        const a = self.allocator;
        if (self.fast) |*engine| engine.deinit();
        self.capture.deinit();
        self.tape.deinit();
        self.session.deinit();
        if (self.owns_memory) {
            self.memory.deinit();
            a.destroy(self.memory);
        }
        if (self.owns_request) {
            self.request.deinit();
            a.destroy(self.request);
        }
        a.destroy(self);
    }
    pub fn cpuState(self: *Walk) *rv.machine.Cpu {
        return &self.session.keccak.base.cpu;
    }
    /// Executes the next batch into `self.tape`/`self.capture` and returns its
    /// finished statement (caller owns `finished`). The caller must call
    /// `advance` (or `advanceTakingTape`) before the next `next`. Null once the
    /// guest completed or `max_batches` were collected.
    pub fn next(self: *Walk) !?Step {
        if (self.pending) return error.InvalidEthereumBatchSeed;
        const config = self.config;
        if (self.completed or (config.max_batches != 0 and self.batches >= config.max_batches)) return null;
        const c = self.cpuState();
        const ids = [_]u32{ @intCast(self.calls[0] + 1), @intCast(self.calls[1] + 1), @intCast(self.calls[2] + 1) };
        var batch = try Native.Batch.init(&self.request.authority, &self.tape, &self.capture, c.regs, ids);
        batch.state_policy = config.state_policy;
        batch.sha256_first = @intCast(self.sha256_calls + 1);
        batch.arith256_first = @intCast(self.arith256_calls + 1);
        for (&batch.curve_first, self.curve_calls) |*first, total| first.* = @intCast(total + 1);
        const memory = self.memory;
        var timer = std.time.Timer.start() catch null;
        while (self.tape.len < self.tape.storage.len) {
            if (self.fast) |*engine| {
                // Fast traced run up to the next instruction it cannot
                // retire; it never executes the terminal pc (a stop pc).
                const before = self.tape.len;
                const t0 = if (timer) |*t| t.read() else 0;
                try Native.runFast(engine, &self.session, &self.tape, &self.capture, &batch, std.math.maxInt(u64));
                const t1 = if (timer) |*t| t.read() else 0;
                self.fast_ns += t1 - t0;
                self.fast_retired += self.tape.len - before;
                if (self.tape.len != before and c.pc == config.terminal_pc) {
                    try self.complete();
                    break;
                }
                if (self.tape.len == self.tape.storage.len) break;
                try Native.captureNext(&self.session, &self.tape, &self.capture, &batch);
                self.reference_ns += (if (timer) |*t| t.read() else 0) - t1;
                self.reference_steps += 1;
            } else try Native.captureNext(&self.session, &self.tape, &self.capture, &batch);
            if (c.pc == config.terminal_pc) {
                try self.complete();
                break;
            }
        }
        // A failed finish has not cleared capture. Later errors abort this
        // collection; no in-place execution retry or advice replay is hidden.
        if (timer) |*t| self.traced_ns += t.lap();
        const finished = try batch.finish(self.allocator, c, memory, &self.request.policy, .chunk512);
        if (timer) |*t| self.finish_ns += t.read();
        self.pending = true;
        return .{ .index = self.batches, .batch = batch, .finished = finished };
    }
    fn complete(self: *Walk) !void {
        const config = self.config;
        const memory = self.memory;
        if (try memory.load(config.symbols.halt_flag, 4) != 1 or try memory.load(config.symbols.output_len, 4) != 43) return error.InvalidEthereumCompletion;
        for (self.request.expected_output, 0..) |byte, i| if (try memory.load(config.symbols.output_data + i, 1) != byte) return error.EthereumOutputMismatch;
        self.completed = true;
    }
    fn account(self: *Walk, batch: *const Native.Batch) void {
        for (&self.calls, batch.calls) |*total, count| total.* += count;
        self.sha256_calls += batch.sha256_calls;
        self.arith256_calls += batch.arith256_calls;
        for (&self.curve_calls, batch.curve_calls) |*total, count| total.* += count;
        self.batches += 1;
        self.pending = false;
    }
    /// The consumer has durably used the batch: reuse tape/capture storage.
    pub fn advance(self: *Walk, batch: *const Native.Batch) !void {
        if (!self.pending) return error.InvalidEthereumBatchSeed;
        try self.capture.clearRetainingCapacity();
        self.tape.clearRetainingCapacity();
        self.account(batch);
    }
    /// Like `advance`, but moves the batch's tape to the caller (who must
    /// deinit it) and continues on a fresh tape with the same seed values
    /// `clearRetainingCapacity` would have produced.
    pub fn advanceTakingTape(self: *Walk, batch: *const Native.Batch) !rv.compact_tape.Tape {
        if (!self.pending or self.tape.len == 0) return error.InvalidEthereumBatchSeed;
        const next_pc = self.tape.storage[self.tape.len - 1].next_pc;
        const next_clock = try std.math.add(u64, self.tape.initial_clock, self.tape.len);
        var fresh = try rv.compact_tape.Tape.init(self.allocator, self.config.batch_steps, next_pc, next_clock, self.tape.execution_profile);
        errdefer fresh.deinit();
        try self.capture.clearRetainingCapacity();
        const taken = self.tape;
        self.tape = fresh;
        self.account(batch);
        return taken;
    }
    /// `next` followed by `advanceTakingTape`: the caller owns the result.
    pub fn nextTaking(self: *Walk) !?Taken {
        var step = (try self.next()) orelse return null;
        errdefer step.finished.deinit();
        const tape = try self.advanceTakingTape(&step.batch);
        return .{ .index = step.index, .finished = step.finished, .tape = tape };
    }
};
/// One batch's ordered publication: graph from the sparse cache, durable
/// packet write, cache advance, descriptor line. Owns `finished` and `tape`.
const Publish = struct {
    const Shared = struct {
        allocator: std.mem.Allocator,
        jobs: std.fs.Dir,
        descriptor: std.fs.File,
        cache: *A.R.values.Cache,
        identity: Packet.Identity,
    };
    shared: *Shared,
    index: u32,
    finished: Native.Finished,
    tape: rv.compact_tape.Tape,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    fn start(self: *Publish, concurrent: bool) void {
        if (!concurrent) return self.work();
        self.thread = std.Thread.spawn(.{}, work, .{self}) catch blk: {
            self.work();
            break :blk null;
        };
    }
    /// Joins, frees, and returns this publication's outcome.
    fn finish(self: *Publish) !void {
        if (self.thread) |t| t.join();
        const err = self.err;
        self.finished.deinit();
        self.tape.deinit();
        self.shared.allocator.destroy(self);
        if (err) |e| return e;
    }
    fn work(self: *Publish) void {
        self.publish() catch |err| {
            self.err = err;
        };
    }
    fn publish(self: *Publish) !void {
        const shared = self.shared;
        const a = shared.allocator;
        const tape = &self.tape;
        const finished = &self.finished;
        const name = try std.fmt.allocPrint(a, "job-{d:0>6}.work", .{self.index});
        defer a.free(name);
        var persist = Persist{ .allocator = a, .directory = shared.jobs, .name = name, .metadata = .{ .identity = shared.identity, .index = self.index, .first_step = tape.initial_clock, .before = shared.cache.root(), .after = shared.cache.root() }, .finished = finished, .tape = tape };
        if (finished.openings) |*openings| {
            var graph = try A.R.native_frontier.Prepared.init(a, shared.cache, openings);
            defer graph.deinit();
            // File sync/exclusive publication precedes sparse cache mutation.
            try graph.handoffAndPublish(shared.cache, .{ .context = &persist, .persist = Persist.write });
        } else persist.digest = try Packet.writeAtomic(a, shared.jobs, name, .{ .metadata = persist.metadata, .finished = finished, .native = null, .tape = tape });
        const entry = try std.json.Stringify.valueAlloc(a, .{ .index = self.index, .first_step = tape.initial_clock, .instructions = tape.len, .packet_sha256 = std.fmt.bytesToHex(persist.digest.?, .lower) }, .{});
        defer a.free(entry);
        try shared.descriptor.writeAll(entry);
        try shared.descriptor.writeAll("\n");
        try shared.descriptor.sync();
    }
};
pub const RunOptions = struct {
    /// Overlap execution with ordered publication. Requires a thread-safe
    /// allocator; output bytes are identical either way.
    pipeline: bool = true,
    /// > 0: batches from a fast first pass plus this many concurrent segment
    /// walks (rv64_ethereum_segments.zig); output bytes are identical.
    segment_workers: u8 = 0,
};
pub fn run(a: std.mem.Allocator, config: Request.Config) !Summary {
    return runWithOptions(a, config, .{});
}
pub fn runWithOptions(a: std.mem.Allocator, config: Request.Config, options: RunOptions) !Summary {
    // Request admission and identity precede any output-directory effect.
    var walk = try Walk.create(a, config);
    defer walk.destroy();
    // Create only our own output directory. Its configured parent must already
    // exist; recursively creating unsynced ancestors would weaken durability.
    std.fs.cwd().makeDir(config.output_directory) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
    var directory = try std.fs.cwd().openDir(config.output_directory, .{ .iterate = true });
    defer directory.close();
    const json = try std.json.Stringify.valueAlloc(a, config, .{ .whitespace = .indent_2 });
    defer a.free(json);
    // Existing collection is deliberately not restarted/replayed implicitly.
    try Receipt.writeExclusive(directory, "request.json", json);
    try directory.makeDir("jobs");
    var jobs = try directory.openDir("jobs", .{ .iterate = true });
    defer jobs.close();
    var descriptor = try directory.createFile("jobs.jsonl", .{ .exclusive = true });
    defer descriptor.close();
    // Sync newly created directory entries as well as packet file contents.
    // A packet in jobs/ is not crash-durable if jobs itself can disappear.
    try Receipt.syncDirectory(directory);
    var output_parent = try directory.openDir("..", .{ .iterate = true });
    defer output_parent.close();
    try Receipt.syncDirectory(output_parent);
    const request = walk.request;
    const identity = walk.identity;
    // Two-stage pipeline: this thread executes batch k+1 while a single
    // publisher builds batch k's frontier graph, writes and syncs its packet,
    // advances the sparse cache and appends its descriptor line. Publisher
    // k+1 starts only after publisher k is joined, so publication is in strict
    // index order and every packet, root and descriptor byte is the serial
    // one. The execution walk never reads the sparse cache, and finished
    // openings own their chunk values, so execution may mutate guest RAM.
    var shared = Publish.Shared{ .allocator = a, .jobs = jobs, .descriptor = descriptor, .cache = &request.initial_cache, .identity = identity };
    var pending: ?*Publish = null;
    // On any error: still join the in-flight publisher before unwinding.
    errdefer if (pending) |p| p.finish() catch {};
    var source = try @import("rv64_ethereum_segments.zig").Source.init(a, walk, options.segment_workers);
    defer source.deinit();
    while (try source.next()) |step_value| {
        var step = step_value;
        var finished_owned = true;
        errdefer if (finished_owned) step.deinit();
        // The previous batch is durable and published before this one starts.
        if (pending) |p| {
            pending = null;
            try p.finish();
        }
        const item = try a.create(Publish);
        errdefer a.destroy(item);
        // The batch's tape moves to the publisher; execution continues on a
        // fresh tape with the seed `clearRetainingCapacity` would produce.
        item.* = .{ .shared = &shared, .index = step.index, .finished = step.finished, .tape = step.tape };
        finished_owned = false;
        pending = item;
        item.start(options.pipeline);
    }
    if (pending) |p| {
        pending = null;
        try p.finish();
    }
    const completed = walk.completed;
    if (completed) {
        const public = Terminal.Statement{ .geometry = .chunk512, .root = request.initial_cache.root(), .policy = &request.policy, .halt_flag = config.symbols.halt_flag, .output = request.expected_output };
        const bytes = try Terminal.prove(a, public, &request.initial_cache, &request.loaded.memory);
        defer a.free(bytes);
        try Terminal.verify(a, public, bytes);
        try Receipt.writeExclusive(directory, "terminal.proof", bytes);
    }
    const summary = Summary{ .identity = identity, .collected_batches = walk.batches, .instructions = walk.cpuState().retired, .completed = completed };
    const result = try std.json.Stringify.valueAlloc(a, summary, .{ .whitespace = .indent_2 });
    defer a.free(result);
    try Receipt.writeExclusive(directory, "collection.json", result);
    try Receipt.syncDirectory(directory);
    // Never publish summary.json or a verified checkpoint from native data.
    return summary;
}
