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
pub fn run(a: std.mem.Allocator, config: Request.Config) !Summary {
    try Request.validateBudget(config);
    var request = try Request.Request.init(a, config);
    defer request.deinit();
    const identity = try Packet.identityFor(config, &request.authority, &request.policy);
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
    var session = try rv.ethereum_services.Session.initWithProfile(a, rv.machine.Cpu.init(request.loaded.info.entry, config.symbols.stack_top), &request.loaded.memory, .{ .max_retirements = config.max_steps }, .ethereum_services_v2);
    defer session.deinit();
    const cpu = &session.keccak.base.cpu;
    var tape = try rv.compact_tape.Tape.init(a, config.batch_steps, cpu.pc, cpu.retired, .ethereum_services_v2);
    defer tape.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, cpu.retired, config.batch_steps, 1 << 24);
    defer capture.deinit();
    var batches: u32 = 0;
    var calls: [3]u64 = @splat(0);
    var completed = false;
    while (!completed and (config.max_batches == 0 or batches < config.max_batches)) {
        const ids = [_]u32{ @intCast(calls[0] + 1), @intCast(calls[1] + 1), @intCast(calls[2] + 1) };
        var batch = try Native.Batch.init(&request.authority, &tape, &capture, cpu.regs, ids);
        batch.state_policy = config.state_policy;
        while (tape.len < tape.storage.len) {
            try Native.captureNext(&session, &tape, &capture, &batch);
            if (cpu.pc == config.terminal_pc) {
                if (try request.loaded.memory.load(config.symbols.halt_flag, 4) != 1 or try request.loaded.memory.load(config.symbols.output_len, 4) != 43) return error.InvalidEthereumCompletion;
                for (request.expected_output, 0..) |byte, i| if (try request.loaded.memory.load(config.symbols.output_data + i, 1) != byte) return error.EthereumOutputMismatch;
                completed = true;
                break;
            }
        }
        // A failed finish has not cleared capture. Later errors abort this
        // collection; no in-place execution retry or advice replay is hidden.
        var finished = try batch.finish(a, cpu, &request.loaded.memory, &request.policy, .chunk512);
        defer finished.deinit();
        const name = try std.fmt.allocPrint(a, "job-{d:0>6}.work", .{batches});
        defer a.free(name);
        var persist = Persist{ .allocator = a, .directory = jobs, .name = name, .metadata = .{ .identity = identity, .index = batches, .first_step = tape.initial_clock, .before = request.initial_cache.root(), .after = request.initial_cache.root() }, .finished = &finished, .tape = &tape };
        if (finished.openings) |*openings| {
            var graph = try A.R.native_frontier.Prepared.init(a, &request.initial_cache, openings);
            defer graph.deinit();
            // File sync/exclusive publication precedes sparse cache mutation.
            try graph.handoffAndPublish(&request.initial_cache, .{ .context = &persist, .persist = Persist.write });
        } else persist.digest = try Packet.writeAtomic(a, jobs, name, .{ .metadata = persist.metadata, .finished = &finished, .native = null, .tape = &tape });
        const entry = try std.json.Stringify.valueAlloc(a, .{ .index = batches, .first_step = tape.initial_clock, .instructions = tape.len, .packet_sha256 = std.fmt.bytesToHex(persist.digest.?, .lower) }, .{});
        defer a.free(entry);
        try descriptor.writeAll(entry);
        try descriptor.writeAll("\n");
        try descriptor.sync();
        for (&calls, batch.calls) |*total, count| total.* += count;
        batches += 1;
        // Both packet and frontier publication are durable before reuse.
        try capture.clearRetainingCapacity();
        tape.clearRetainingCapacity();
    }
    if (completed) {
        const public = Terminal.Statement{ .geometry = .chunk512, .root = request.initial_cache.root(), .policy = &request.policy, .halt_flag = config.symbols.halt_flag, .output = request.expected_output };
        const bytes = try Terminal.prove(a, public, &request.initial_cache, &request.loaded.memory);
        defer a.free(bytes);
        try Terminal.verify(a, public, bytes);
        try Receipt.writeExclusive(directory, "terminal.proof", bytes);
    }
    const summary = Summary{ .identity = identity, .collected_batches = batches, .instructions = cpu.retired, .completed = completed };
    const result = try std.json.Stringify.valueAlloc(a, summary, .{ .whitespace = .indent_2 });
    defer a.free(result);
    try Receipt.writeExclusive(directory, "collection.json", result);
    try std.posix.fsync(directory.fd);
    // Never publish summary.json or a verified checkpoint from native data.
    return summary;
}
