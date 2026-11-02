const std = @import("std");
const engine = @import("stwo_prover_engine");
const Capture = @import("capture.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Collect = @import("../../rv64_ethereum_native_prepare.zig");
const Request = @import("../../rv64_ethereum_request.zig");
const a = std.testing.allocator;
fn image() [144]u8 {
    var bytes: [144]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], 4096, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 120, .little);
    std.mem.writeInt(u64, bytes[80..88], 4096, .little);
    std.mem.writeInt(u64, bytes[96..104], 24, .little);
    std.mem.writeInt(u64, bytes[104..112], 24, .little);
    std.mem.writeInt(u64, bytes[112..120], 4, .little);
    // lui x1,0xc00; addi x2,zero,43; sw x2,4(x1);
    // addi x2,zero,1; sw x2,0(x1); terminal: jal zero,0.
    const words = [_]u32{ 0x00c000b7, 0x02b00113, 0x0020a223, 0x00100113, 0x0020a023, 0x0000006f };
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[120 + 4 * i ..][0..4], word, .little);
    return bytes;
}

const Fixture = struct {
    temp: std.testing.TmpDir,
    elf: []u8,
    input: []u8,
    output: []u8,
    elf_hash: [64]u8,
    input_hash: [64]u8,
    fn init() !Fixture {
        var temp = std.testing.tmpDir(.{});
        errdefer temp.cleanup();
        const bytes = image();
        try temp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &bytes });
        try temp.dir.writeFile(.{ .sub_path = "input", .data = &.{1} });
        const elf = try temp.dir.realpathAlloc(a, "guest.elf");
        errdefer a.free(elf);
        const input = try temp.dir.realpathAlloc(a, "input");
        errdefer a.free(input);
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const output = try std.fs.path.join(a, &.{ root, "artifacts" });
        return .{ .temp = temp, .elf = elf, .input = input, .output = output, .elf_hash = std.fmt.bytesToHex(Request.sha(&bytes), .lower), .input_hash = std.fmt.bytesToHex(Request.sha(&.{1}), .lower) };
    }
    fn config(self: *const Fixture) Request.Config {
        return .{ .elf = self.elf, .input = self.input, .elf_sha256 = &self.elf_hash, .input_sha256 = &self.input_hash, .expected_output = "00" ** 43, .symbols = .{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 }, .output_directory = self.output, .terminal_pc = 4116, .batch_steps = 3, .max_steps = 10, .profile_stages = false, .workers = 1 };
    }
    fn deinit(self: *Fixture) void {
        a.free(self.output);
        a.free(self.input);
        a.free(self.elf);
        self.temp.cleanup();
    }
};
fn same(expected: *const Capture.Owner, actual: *const Capture.Owner) !void {
    try std.testing.expectEqual(expected.total_steps, actual.total_steps);
    try std.testing.expectEqual(expected.final_pc, actual.final_pc);
    try std.testing.expectEqualDeep(expected.final_registers, actual.final_registers);
    try std.testing.expectEqual(expected.native.items.len, actual.native.items.len);
    for (expected.native.items, actual.native.items) |left, right| {
        try std.testing.expectEqualDeep(left.raw_counts, right.raw_counts);
        try std.testing.expectEqualDeep(left.alu, right.alu);
        try std.testing.expectEqualDeep(left.binary, right.binary);
        try std.testing.expectEqualDeep(left.shift, right.shift);
        try std.testing.expectEqualDeep(left.shift_weights, right.shift_weights);
        try std.testing.expectEqualDeep(left.division, right.division);
        try std.testing.expectEqualDeep(left.multiplication, right.multiplication);
        try std.testing.expectEqualDeep(left.cpu.?.metadata, right.cpu.?.metadata);
        try std.testing.expectEqualDeep(left.cpu.?.public, right.cpu.?.public);
        try std.testing.expectEqualDeep(left.jalr, right.jalr);
    }
    try std.testing.expectEqualDeep(expected.advice, actual.advice);
}
test "two packet capture equals serial, held lease and budget fallback" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 0);
    defer serial.deinit();
    var parallel = try Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2 });
    defer parallel.deinit();
    try same(&serial, &parallel);
    const D = @import("capture_digest.zig");
    const before = D.digest(image_owner.identity, &serial);
    try std.testing.expectEqualDeep(before, D.digest(image_owner.identity, &parallel));
    try std.testing.expectEqual(@as(u8, 2), parallel.capture_schedule.max_inflight_packets);
    try std.testing.expectEqual(@as(u8, 2), parallel.capture_schedule.max_worker_shards);
    try std.testing.expect(parallel.capture_schedule.max_single_packet_decoded_heap_bytes > 0);
    try std.testing.expect(parallel.capture_schedule.max_single_packet_decoded_heap_bytes <= 512 << 20);
    parallel.native.items[0].cpu.?.metadata[0].values[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &before, &D.digest(image_owner.identity, &parallel)));
    parallel.native.items[0].cpu.?.metadata[0].values[0] ^= 1;
    var altered_identity = image_owner.identity;
    altered_identity[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &before, &D.digest(altered_identity, &parallel)));

    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(2));
    defer lease.deinit();
    var fallback = try Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2, .max_inflight_packet_heap_bytes = 512 << 20 });
    defer fallback.deinit();
    try same(&serial, &fallback);
    try std.testing.expectEqual(@as(u8, 1), fallback.capture_schedule.max_inflight_packets);
    try std.testing.expectEqual(@as(u8, 1), fallback.capture_schedule.max_worker_shards);
    try std.testing.expectError(error.OutOfMemory, Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2, .packet_heap_bytes = 1 }));
    try std.testing.expectError(error.EthereumCaptureWireBudgetExceeded, Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2, .max_inflight_wire_bytes = 1 }));
}
test "prefix joins and discards future packet errors but required packet rejects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    try jobs.writeFile(.{ .sub_path = "job-000001.work", .data = "bad" });
    var prefix = try Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 1, .{ .pool = &pool, .max_inflight_packets = 2 });
    defer prefix.deinit();
    try std.testing.expectEqual(@as(usize, 1), prefix.native.items.len);
    const expected = Capture.Owner.init(a, &image_owner, &program, config, jobs, 0);
    if (expected) |owner| {
        var value = owner;
        value.deinit();
        return error.ExpectedFailure;
    } else |err| {
        try std.testing.expectError(err, Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2 }));
    }
}
test "terminal packet discards joined speculative read failure" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var config = fixture.config();
    config.batch_steps = 8;
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    try jobs.writeFile(.{ .sub_path = "job-000001.work", .data = "bad" });
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 0);
    defer serial.deinit();
    var prefetched = try Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2 });
    defer prefetched.deinit();
    try same(&serial, &prefetched);
}
const OomContext = struct {
    image_owner: *const Image.Owner,
    program: *const Program,
    config: Request.Config,
    jobs: std.fs.Dir,
    pool: *engine.work_pool.WorkPool,
};
fn allocationCase(allocator: std.mem.Allocator, context: OomContext) !void {
    var sync = std.heap.ThreadSafeAllocator{ .child_allocator = allocator };
    var owner = try Capture.Owner.initWithOptions(sync.allocator(), context.image_owner, context.program, context.config, context.jobs, 0, .{ .pool = context.pool, .max_inflight_packets = 2 });
    defer owner.deinit();
}
test "capture allocation failure cleanup across joined packet slots" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    // Deterministic injection order while retaining the same two-slot cleanup
    // path. Actual concurrent jobs are covered by parity/error tests above.
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(2));
    defer lease.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{OomContext{ .image_owner = &image_owner, .program = &program, .config = config, .jobs = jobs, .pool = &pool }});
}

test "valid duplicate packet rejects ordered adjacency after speculative capture" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    const bytes = try jobs.readFileAlloc(a, "job-000000.work", 1 << 20);
    defer a.free(bytes);
    try jobs.writeFile(.{ .sub_path = "job-000001.work", .data = bytes });
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    try std.testing.expectError(error.NonAdjacentEthereumPacket, Capture.Owner.init(a, &image_owner, &program, config, jobs, 0));
    try std.testing.expectError(error.NonAdjacentEthereumPacket, Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 2 }));
}

const Direct = @import("direct.zig");
const PacketCodec = @import("../../word16_execution/packet.zig");
const Header = @import("../../rv64_work_packet_header.zig");
const Walk = Collect.Walk;
fn digestOf(image_owner: *const Image.Owner, owner: *const Capture.Owner) [32]u8 {
    return @import("capture_digest.zig").digest(image_owner.identity, owner);
}
test "windowed capture of up to MAX_INFLIGHT packets equals serial" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var config = fixture.config();
    config.batch_steps = 1;
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 0);
    defer serial.deinit();
    try std.testing.expectEqual(@as(usize, 5), serial.native.items.len);
    for ([_]u8{ 2, 3, 4, 16 }) |window| {
        var parallel = try Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = window, .max_inflight_packet_heap_bytes = @as(usize, window) * (512 << 20), .max_inflight_wire_bytes = @as(u64, window) << 30 });
        defer parallel.deinit();
        try same(&serial, &parallel);
        try std.testing.expectEqualDeep(digestOf(&image_owner, &serial), digestOf(&image_owner, &parallel));
        try std.testing.expectEqual(@min(window, 5), parallel.capture_schedule.max_inflight_packets);
    }
    // A prefix stops at its count even with a wider window.
    var prefix = try Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 2, .{ .pool = &pool, .max_inflight_packets = 4, .max_inflight_packet_heap_bytes = 4 * (512 << 20), .max_inflight_wire_bytes = 4 << 30 });
    defer prefix.deinit();
    try std.testing.expectEqual(@as(usize, 2), prefix.native.items.len);
    var serial_prefix = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 2);
    defer serial_prefix.deinit();
    try same(&serial_prefix, &prefix);
    // A corrupt packet inside the window is still rejected.
    try jobs.writeFile(.{ .sub_path = "job-000002.work", .data = "bad" });
    const serial_err = if (Capture.Owner.init(a, &image_owner, &program, config, jobs, 0)) |owner| blk: {
        var value = owner;
        value.deinit();
        break :blk error.ExpectedFailure;
    } else |e| e;
    try std.testing.expect(serial_err != error.ExpectedFailure);
    try std.testing.expectError(serial_err, Capture.Owner.initWithOptions(a, &image_owner, &program, config, jobs, 0, .{ .pool = &pool, .max_inflight_packets = 4, .max_inflight_packet_heap_bytes = 4 * (512 << 20), .max_inflight_wire_bytes = 4 << 30 }));
}
test "in-process handoff capture equals the on-disk packet capture" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_]u32{ 3, 1, 2 }) |batch_steps| {
        var config = fixture.config();
        config.batch_steps = batch_steps;
        fixture.temp.dir.deleteTree("artifacts") catch {};
        _ = try Collect.run(a, config);
        var image_owner = try Image.Owner.init(a, config);
        defer image_owner.deinit();
        var program = try Program.initWithAuthority(a, &image_owner.authority);
        defer program.deinit();
        var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
        defer jobs.close();
        var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 0);
        defer serial.deinit();
        for ([_]u8{ 1, 2, 3, 16 }) |inflight| {
            var stats: Direct.Stats = .{};
            var direct = try Direct.capture(a, &image_owner, &program, config, 0, inflight, &stats);
            defer direct.deinit();
            try same(&serial, &direct);
            try std.testing.expectEqualDeep(digestOf(&image_owner, &serial), digestOf(&image_owner, &direct));
            try std.testing.expectEqual(@as(u32, @intCast(serial.native.items.len)), stats.batches);
        }
        var serial_prefix = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 1);
        defer serial_prefix.deinit();
        var stats: Direct.Stats = .{};
        var direct_prefix = try Direct.capture(a, &image_owner, &program, config, 1, 2, &stats);
        defer direct_prefix.deinit();
        try same(&serial_prefix, &direct_prefix);
        try std.testing.expectEqual(@as(u32, 1), stats.batches);
    }
}
fn firstBatch(walk: *Walk) !struct { tape: @import("stwo_riscv_frontend").rv64.compact_tape.Tape, finished: @import("../../rv64_ethereum_batch.zig").Finished, metadata: Header.Metadata } {
    var step = (try walk.next()).?;
    errdefer step.finished.deinit();
    const root = walk.request.initial_cache.root();
    const metadata = Header.Metadata{ .identity = walk.identity, .index = step.index, .first_step = walk.tape.initial_clock, .before = root, .after = root };
    const tape = try walk.advanceTakingTape(&step.batch);
    return .{ .tape = tape, .finished = step.finished, .metadata = metadata };
}
test "in-process handoff rejects forged tapes, statements and identities" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    const Case = enum { none, next_pc, memory_index, steps, division, final_pc, identity, first_step, initial_pc, cells };
    inline for (@typeInfo(Case).@"enum".fields) |field| {
        const case: Case = @enumFromInt(field.value);
        var walk = try Walk.create(a, config);
        defer walk.destroy();
        var batch = try firstBatch(walk);
        defer batch.finished.deinit();
        var cells = batch.finished.cells.len;
        switch (case) {
            .none => {},
            .next_pc => batch.tape.storage[0].next_pc += 4,
            .memory_index => batch.tape.storage[0].memory_index = 0,
            .steps => batch.tape.len -= 1,
            .division => batch.finished.public.division_requests += 1,
            .final_pc => batch.finished.public.statement.final_pc += 4,
            .identity => batch.metadata.identity.request[0] ^= 1,
            .first_step => batch.metadata.first_step += 1,
            .initial_pc => batch.tape.initial_pc += 4,
            .cells => cells = 1 << 25,
        }
        if (case == .none) {
            var p = try PacketCodec.fromNative(batch.tape, batch.finished.public, batch.metadata, cells, &image_owner, config);
            p.deinit();
        } else {
            if (PacketCodec.fromNative(batch.tape, batch.finished.public, batch.metadata, cells, &image_owner, config)) |value| {
                var p = value;
                p.deinit();
                std.debug.print("forged case {s} accepted\n", .{field.name});
                return error.ForgedBatchAccepted;
            } else |_| {}
        }
    }
}
test "pipelined native collection writes byte-identical packets and descriptors" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var config = fixture.config();
    config.batch_steps = 1;
    const root = try fixture.temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const serial_dir = try std.fs.path.join(a, &.{ root, "serial" });
    defer a.free(serial_dir);
    const piped_dir = try std.fs.path.join(a, &.{ root, "piped" });
    defer a.free(piped_dir);
    config.output_directory = serial_dir;
    const serial = try Collect.runWithOptions(a, config, .{ .pipeline = false });
    config.output_directory = piped_dir;
    const piped = try Collect.runWithOptions(a, config, .{ .pipeline = true });
    try std.testing.expectEqualDeep(serial, piped);
    try std.testing.expectEqual(@as(u32, 5), piped.collected_batches);
    var names: [6][]const u8 = .{ "jobs.jsonl", "terminal.proof", "jobs/job-000000.work", "jobs/job-000001.work", "jobs/job-000004.work", "collection.json" };
    for (&names) |name| {
        const left = try std.fs.path.join(a, &.{ serial_dir, name });
        defer a.free(left);
        const right = try std.fs.path.join(a, &.{ piped_dir, name });
        defer a.free(right);
        const l = try std.fs.cwd().readFileAlloc(a, left, 1 << 24);
        defer a.free(l);
        const r = try std.fs.cwd().readFileAlloc(a, right, 1 << 24);
        defer a.free(r);
        try std.testing.expectEqualSlices(u8, l, r);
    }
}
