//! The prepared worker receives owned compact advice/boundaries and expected
//! immutable material only. Native VM/memory/capture die before proof starts.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const B = @import("../rv64_ethereum_batch.zig");
const Worker = @import("../rv64_ethereum_prove_batch.zig");
const Request = @import("../rv64_ethereum_request.zig");
const Chain = @import("../rv64_ethereum_chain.zig");
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
const rv = A.frontend.rv64;
const R = A.R;
const a = std.testing.allocator;
const pc: u64 = 4096;
const ptr: u64 = 8192;
const words = [_]u32{ 0x0020b023, 0x0000b183 };
const Packet = struct {
    tape: rv.compact_tape.Tape,
    finished: B.Finished,
    frontier: R.values.Cache,
    owns_frontier: bool = true,
    fn deinit(self: *Packet) void {
        self.finished.deinit();
        self.tape.deinit();
        if (self.owns_frontier) self.frontier.deinit();
    }
};
fn collect(authority: *const A.Full.ProgramAuthority, policy: *const R.policy.Policy) !Packet {
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 8, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = ptr, .size = 512, .permissions = .{ .read = true, .write = true } });
    for (words, 0..) |raw, index| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc + 4 * index, &bytes);
    }
    var frontier = try R.values.Cache.fromMemory(a, .chunk512, &memory);
    errdefer frontier.deinit();
    var tape = try rv.compact_tape.Tape.init(a, 2, pc, 0, .ethereum_services_v2);
    errdefer tape.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, 0, 2, 1);
    defer capture.deinit();
    var cpu = rv.machine.Cpu.init(pc, 0);
    cpu.regs[1] = ptr;
    cpu.regs[2] = 17;
    var batch = try B.Batch.init(authority, &tape, &capture, cpu.regs, .{ 1, 1, 1 });
    for (words) |_| {
        const record = try cpu.step(&memory);
        try tape.append(record);
        try capture.append(record, &memory);
        try batch.observe(record);
    }
    var finished = try batch.finish(a, &cpu, &memory, policy, .chunk512);
    errdefer finished.deinit();
    // This is the serial wrapper's ownership barrier. Nothing below needs the
    // native object again; the worker packet survives their scoped destruction.
    try capture.clearRetainingCapacity();
    return .{ .tape = tape, .finished = finished, .frontier = frontier };
}
fn config() Request.Config {
    return .{ .elf = "", .input = "", .elf_sha256 = "", .input_sha256 = "", .expected_output = "", .symbols = std.mem.zeroes(rv.ethereum_contract.Symbols), .output_directory = "", .terminal_pc = pc + 8, .batch_steps = 2, .profile_stages = false };
}
fn provePrepared(authority: *const A.Full.ProgramAuthority, policy: *const R.policy.Policy, arena: bool, detached: bool) ![]u8 {
    var packet = try collect(authority, policy);
    defer packet.deinit();
    const initial_root = packet.frontier.root();
    var native: ?R.native_frontier.Prepared = if (detached) try R.native_frontier.Prepared.init(a, &packet.frontier, &packet.finished.openings.?) else null;
    defer if (native) |*value| value.deinit();
    const expected_after: ?R.values.Digest = if (native) |*value| value.witness.after else null;
    if (detached) {
        packet.frontier.deinit();
        packet.owns_frontier = false;
    }
    var cursor = Chain.Cursor{ .root = initial_root, .pc = pc, .registers = packet.finished.public.statement.initial_registers };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var options = config();
    options.shared_main_arena = arena;
    options.profile_stages = arena and detached;
    const metrics = try Worker.provePrepared(a, .{ .authority = authority, .policy = policy, .frontier = if (detached) .{ .detached = .{ .before = initial_root, .graph = &native.? } } else .{ .cache = &packet.frontier } }, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{ .native_ns = 17, .openings_ns = 23, .before_worker_ns = 29 });
    if (options.profile_stages) {
        const report = metrics.memory orelse return error.MissingBatchMemoryMetrics;
        try std.testing.expect(report.sampled_peak_rss_bytes.? >= report.baseline_rss_bytes.?);
        const stages = try temporary.dir.readFileAlloc(a, "batch-000000.stages.json", 4 * 1024 * 1024);
        defer a.free(stages);
        var parsed = try std.json.parseFromSlice(std.json.Value, a, stages, .{});
        defer parsed.deinit();
        const memory = parsed.value.object.get("memory").?.object;
        try std.testing.expectEqual(@as(i64, @intCast(report.sampled_peak_rss_bytes.?)), memory.get("sampled_peak_rss_bytes").?.integer);
    } else try std.testing.expect(metrics.memory == null);
    try std.testing.expectEqual(@as(u64, 17), metrics.native_ns);
    try std.testing.expectEqual(@as(u64, 23), metrics.openings_ns);
    try std.testing.expect(metrics.total_after_native_ns >= 29);
    try std.testing.expectEqual(@as(u32, 1), cursor.batches);
    try std.testing.expectEqual(@as(u64, 2), cursor.steps);
    try std.testing.expectEqual(pc + 8, cursor.pc);
    try std.testing.expectEqual(@as(u64, 17), cursor.registers[3]);
    try std.testing.expectEqual(@as(u32, 0), packet.tape.len);
    if (detached) {
        try std.testing.expectEqual(R.native_frontier.Phase.consumed, native.?.phase);
        try std.testing.expectEqualSlices(u32, &expected_after.?, &cursor.root);
    } else {
        try std.testing.expect(!std.mem.eql(u32, &initial_root, &packet.frontier.root()));
        try std.testing.expectEqualSlices(u32, &cursor.root, &packet.frontier.root());
    }
    const encoded = try temporary.dir.readFileAlloc(a, "batch-000000.proof", 16 * 1024 * 1024);
    errdefer a.free(encoded);
    const json = try temporary.dir.readFileAlloc(a, "batch-000000.json", 1024 * 1024);
    defer a.free(json);
    const receipt = try std.json.parseFromSlice(Receipt.Receipt, a, json, .{});
    defer receipt.deinit();
    const public = try receipt.value.bound(authority);
    var receiver = try A.Prepared.initWithAuthority(a, public, policy, authority);
    defer receiver.deinit();
    const wire = @import("stwo_proof_wire");
    try receiver.verifyOwned(a, public, receipt.value.claims, try wire.decodeProofBytesBinary(a, encoded));
    return encoded;
}
test "prepared Ethereum worker proves after native owners die with owned arena byte parity" {
    var authority = try A.Full.ProgramAuthority.init(a, .{ .base = pc, .words = &words }, .ethereum_services_v2);
    defer authority.deinit();
    var policy = try R.policy.Policy.init(a, &.{ .{ .first = pc, .last = pc + 7, .flags = 5 }, .{ .first = ptr, .last = ptr + 511, .flags = 3 } });
    defer policy.deinit();
    const owned = try provePrepared(&authority, &policy, false, false);
    defer a.free(owned);
    const arena = try provePrepared(&authority, &policy, true, false);
    defer a.free(arena);
    try std.testing.expectEqualSlices(u8, owned, arena);
    const detached = try provePrepared(&authority, &policy, false, true);
    defer a.free(detached);
    try std.testing.expectEqualSlices(u8, owned, detached);
    const detached_arena = try provePrepared(&authority, &policy, true, true);
    defer a.free(detached_arena);
    try std.testing.expectEqualSlices(u8, owned, detached_arena);
}
test "prepared worker rejects authority profile tape and adjacency before allocation" {
    var authority = try A.Full.ProgramAuthority.init(a, .{ .base = pc, .words = &words }, .ethereum_services_v2);
    defer authority.deinit();
    var policy = try R.policy.Policy.init(a, &.{ .{ .first = pc, .last = pc + 7, .flags = 5 }, .{ .first = ptr, .last = ptr + 511, .flags = 3 } });
    defer policy.deinit();
    var packet = try collect(&authority, &policy);
    defer packet.deinit();
    var cursor = Chain.Cursor{ .root = packet.frontier.root(), .pc = pc, .registers = packet.finished.public.statement.initial_registers };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const context = Worker.PreparedContext{ .authority = &authority, .policy = &policy, .frontier = .{ .cache = &packet.frontier } };
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const fail = failing.allocator();
    var options = config();
    options.control_policy = .limbs24_v2;
    try std.testing.expectError(error.InvalidEthereumPreparedProfile, Worker.provePrepared(fail, context, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    options = config();
    const initial_pc = packet.tape.initial_pc;
    packet.tape.initial_pc += 4;
    try std.testing.expectError(error.InvalidEthereumPreparedBoundary, Worker.provePrepared(fail, context, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    packet.tape.initial_pc = initial_pc;
    const original_program = packet.finished.public.statement.program;
    const other = [_]u32{0x01200093};
    packet.finished.public.statement.program = .{ .base = pc, .words = &other };
    try std.testing.expectError(error.Rv64FullSetupMismatch, Worker.provePrepared(fail, context, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    packet.finished.public.statement.program = original_program;
    cursor.pc += 4;
    try std.testing.expectError(error.InvalidEthereumBatchAdjacency, Worker.provePrepared(fail, context, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    cursor.pc = pc;
    var native = try R.native_frontier.Prepared.init(a, &packet.frontier, &packet.finished.openings.?);
    defer native.deinit();
    var detached = Worker.PreparedContext{ .authority = &authority, .policy = &policy, .frontier = .{ .detached = .{ .before = packet.frontier.root(), .graph = &native } } };
    detached.frontier.detached.before[0] ^= 1;
    try std.testing.expectError(error.InvalidEthereumPreparedFrontier, Worker.provePrepared(fail, detached, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    detached.frontier.detached.before = packet.frontier.root();
    native.phase = .durable;
    try std.testing.expectError(error.InvalidNativeFrontierPhase, Worker.provePrepared(fail, detached, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    native.phase = .prepared;
    detached.frontier.detached.graph = null;
    try std.testing.expectError(error.InvalidEthereumPreparedFrontier, Worker.provePrepared(fail, detached, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    detached.frontier.detached.graph = &native;
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    const input_word = native.io[0].input[0];
    native.io[0].input[0] = input_word.add(@import("stwo_core").fields.m31.M31.one());
    try std.testing.expectError(error.InvalidNativeFrontierIO, Worker.provePrepared(a, detached, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    native.io[0].input[0] = input_word;
    try std.testing.expectEqual(R.native_frontier.Phase.prepared, native.phase);
    try std.testing.expect(packet.finished.openings.?.chunks.len != 0);
    // Valid advice reaches the first real setup allocation. An OOM leaves all
    // input owners deinitializable and publishes no receipt/frontier movement.
    try std.testing.expectError(error.OutOfMemory, Worker.provePrepared(fail, context, options, &packet.tape, &packet.finished, &cursor, temporary.dir, .{}));
    try std.testing.expectEqual(@as(u32, 2), packet.tape.len);
    try std.testing.expectEqual(@as(u32, 0), cursor.batches);
    try std.testing.expectError(error.FileNotFound, temporary.dir.openFile("batch-000000.json", .{}));
}
