//! One native execution walk producing durable, independently consumable narrow
//! jobs. Collection is not execution-proof acceptance or recursive aggregation.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const rv = A.frontend.rv64;
const Request = @import("rv64_ethereum_request.zig");
const Native = @import("rv64_ethereum_batch.zig");
const Packet = @import("rv64_prepared_work_packet.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Terminal = @import("rv64_ram_terminal.zig");
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
    request: Request.Request,
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
    pub const Step = struct {
        index: u32,
        batch: Native.Batch,
        finished: Native.Finished,
    };
    pub fn create(a: std.mem.Allocator, config: Request.Config) !*Walk {
        try Request.validateBudget(config);
        const self = try a.create(Walk);
        errdefer a.destroy(self);
        self.allocator = a;
        self.config = config;
        self.request = try Request.Request.init(a, config);
        errdefer self.request.deinit();
        self.identity = try Packet.identityFor(config, &self.request.authority, &self.request.policy);
        self.session = try rv.ethereum_services.Session.initWithProfile(a, rv.machine.Cpu.init(self.request.loaded.info.entry, config.symbols.stack_top), &self.request.loaded.memory, .{ .max_retirements = config.max_steps }, Request.tapeProfile(config));
        errdefer self.session.deinit();
        const cpu = &self.session.keccak.base.cpu;
        self.tape = try rv.compact_tape.Tape.init(a, config.batch_steps, cpu.pc, cpu.retired, Request.tapeProfile(config));
        errdefer self.tape.deinit();
        self.capture = try rv.boundary_capture.Capture.init(a, cpu.retired, config.batch_steps, 1 << 24);
        self.batches = 0;
        self.calls = @splat(0);
        self.sha256_calls = 0;
        self.arith256_calls = 0;
        self.curve_calls = @splat(0);
        self.completed = false;
        self.pending = false;
        return self;
    }
    pub fn destroy(self: *Walk) void {
        const a = self.allocator;
        self.capture.deinit();
        self.tape.deinit();
        self.session.deinit();
        self.request.deinit();
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
        const memory = &self.request.loaded.memory;
        while (self.tape.len < self.tape.storage.len) {
            try Native.captureNext(&self.session, &self.tape, &self.capture, &batch);
            if (c.pc == config.terminal_pc) {
                if (try memory.load(config.symbols.halt_flag, 4) != 1 or try memory.load(config.symbols.output_len, 4) != 43) return error.InvalidEthereumCompletion;
                for (self.request.expected_output, 0..) |byte, i| if (try memory.load(config.symbols.output_data + i, 1) != byte) return error.EthereumOutputMismatch;
                self.completed = true;
                break;
            }
        }
        // A failed finish has not cleared capture. Later errors abort this
        // collection; no in-place execution retry or advice replay is hidden.
        const finished = try batch.finish(self.allocator, c, memory, &self.request.policy, .chunk512);
        self.pending = true;
        return .{ .index = self.batches, .batch = batch, .finished = finished };
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
    var directory = try std.fs.cwd().openDir(config.output_directory, .{});
    defer directory.close();
    const json = try std.json.Stringify.valueAlloc(a, config, .{ .whitespace = .indent_2 });
    defer a.free(json);
    // Existing collection is deliberately not restarted/replayed implicitly.
    try Receipt.writeExclusive(directory, "request.json", json);
    try directory.makeDir("jobs");
    var jobs = try directory.openDir("jobs", .{});
    defer jobs.close();
    var descriptor = try directory.createFile("jobs.jsonl", .{ .exclusive = true });
    defer descriptor.close();
    // Sync newly created directory entries as well as packet file contents.
    // A packet in jobs/ is not crash-durable if jobs itself can disappear.
    try std.posix.fsync(directory.fd);
    var output_parent = try directory.openDir("..", .{});
    defer output_parent.close();
    try std.posix.fsync(output_parent.fd);
    const request = &walk.request;
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
    while (try walk.next()) |step_value| {
        var step = step_value;
        var finished_owned = true;
        errdefer if (finished_owned) step.finished.deinit();
        // The previous batch is durable and published before this one starts.
        if (pending) |p| {
            pending = null;
            try p.finish();
        }
        const item = try a.create(Publish);
        errdefer a.destroy(item);
        // The batch's tape moves to the publisher; execution continues on a
        // fresh tape with the seed `clearRetainingCapacity` would produce.
        const tape = try walk.advanceTakingTape(&step.batch);
        item.* = .{ .shared = &shared, .index = step.index, .finished = step.finished, .tape = tape };
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
    try std.posix.fsync(directory.fd);
    // Never publish summary.json or a verified checkpoint from native data.
    return summary;
}
