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
    for (expected.native.items, actual.native.items) |left, right| try sameNative(left, right);
    try std.testing.expectEqualDeep(expected.advice, actual.advice);
}
fn sameNative(left: anytype, right: anytype) !void {
    {
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
test "handoff started before image init equals the on-disk capture; unconsumed starts unwind" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_]u32{ 3, 1, 2 }) |batch_steps| {
        var config = fixture.config();
        config.batch_steps = batch_steps;
        fixture.temp.dir.deleteTree("artifacts") catch {};
        _ = try Collect.run(a, config);
        var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
        defer jobs.close();
        for ([_]u32{ 0, 1 }) |prefix| for ([_]u8{ 0, 1, 3 }) |workers| for ([_]u8{ 1, 2, 16 }) |inflight| {
            // The walk (and segment walks) run while the receiver-side image
            // and program are loaded, exactly as in the GKR CLI.
            var stats: Direct.Stats = .{};
            const started = try Direct.Started.start(a, config, prefix, workers);
            defer started.deinit(&stats);
            var image_owner = try Image.Owner.init(a, config);
            defer image_owner.deinit();
            var program = try Program.initWithAuthority(a, &image_owner.authority);
            defer program.deinit();
            var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, prefix);
            defer serial.deinit();
            var direct = try started.capture(&image_owner, &program, inflight, &stats);
            defer direct.deinit();
            try same(&serial, &direct);
            try std.testing.expectEqualDeep(digestOf(&image_owner, &serial), digestOf(&image_owner, &direct));
            try std.testing.expectEqual(@as(u32, @intCast(serial.native.items.len)), stats.batches);
            try std.testing.expect(direct.first_inputs_at != null and direct.last_inputs_at != null);
            try std.testing.expect(direct.timing.first_inputs_ns <= direct.timing.last_inputs_ns);
        };
        // A start whose capture never runs (e.g. image admission failed)
        // joins its first pass and segment walks and frees everything.
        for ([_]u8{ 0, 1, 3 }) |workers| {
            var stats: Direct.Stats = .{};
            const started = try Direct.Started.start(a, config, 0, workers);
            started.deinit(&stats);
        }
    }
}
test "in-process walk skips only the legacy Poseidon cache; packet collection keeps it" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    var with = try Request.Request.init(a, config);
    defer with.deinit();
    var without = try Request.Request.initWithOptions(a, config, .{ .poseidon_initial_cache = false });
    defer without.deinit();
    try std.testing.expect(with.has_initial_cache and !without.has_initial_cache);
    const Ident = @import("../../rv64_work_packet_header.zig");
    try std.testing.expectEqualDeep(try Ident.identityFor(config, &with.authority, &with.policy), try Ident.identityFor(config, &without.authority, &without.policy));
    try std.testing.expectEqualSlices(u8, &with.expected_output, &without.expected_output);
    // The durable collector's walk still builds the frontier seed.
    const walk = try Walk.create(a, config);
    defer walk.destroy();
    try std.testing.expect(walk.request.has_initial_cache);
    try std.testing.expectEqualDeep(with.initial_cache.root(), walk.request.initial_cache.root());
}
test "expected image reads inputs up to the request loader's bound (no 4 MiB cap)" {
    const front = @import("stwo_riscv_frontend");
    try std.testing.expectEqual(@as(usize, front.rv64.ethereum_contract.INPUT_CAPACITY_MAX - 4), Image.MAX_INPUT_BYTES);
    try std.testing.expect(Image.MAX_INPUT_BYTES > 4 << 20);
    var fixture = try Fixture.init();
    defer fixture.deinit();
    // A 4 MiB + 1 input with a matching pin is no longer refused by the read
    // bound; this fixture's 4 MiB guest window then rejects it on load.
    const big = try a.alloc(u8, (4 << 20) + 1);
    defer a.free(big);
    @memset(big, 0);
    try fixture.temp.dir.writeFile(.{ .sub_path = "input", .data = big });
    var config = fixture.config();
    var hash = std.fmt.bytesToHex(Request.sha(big), .lower);
    config.input_sha256 = &hash;
    const result = Image.Owner.init(a, config);
    if (result) |value| {
        var owned = value;
        owned.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expect(err != error.FileTooBig);
    // Over the bound is still refused before hashing.
    const huge = try a.alloc(u8, Image.MAX_INPUT_BYTES + 1);
    defer a.free(huge);
    @memset(huge, 0);
    try fixture.temp.dir.writeFile(.{ .sub_path = "input", .data = huge });
    try std.testing.expectError(error.FileTooBig, Image.Owner.init(a, config));
}
fn expectSameTree(x: std.fs.Dir, y: std.fs.Dir) !void {
    var walker = try x.walk(a);
    defer walker.deinit();
    var files: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const left = try x.readFileAlloc(a, entry.path, 1 << 30);
        defer a.free(left);
        const right = y.readFileAlloc(a, entry.path, 1 << 30) catch |err| {
            std.debug.print("segment tree lacks {s}: {s}\n", .{ entry.path, @errorName(err) });
            return err;
        };
        defer a.free(right);
        try std.testing.expectEqualSlices(u8, left, right);
        files += 1;
    }
    var count: usize = 0;
    var other = try y.walk(a);
    defer other.deinit();
    while (try other.next()) |entry| count += @intFromBool(entry.kind == .file);
    try std.testing.expectEqual(files, count);
    try std.testing.expect(files >= 4);
}
test "fast first pass + parallel segment walks equal the serial walk (native jobs and direct capture)" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_]u32{ 1, 2, 3, 4, 7 }) |batch_steps| for ([_]u32{ 0, 2 }) |max_batches| {
        var config = fixture.config();
        config.batch_steps = batch_steps;
        config.max_batches = max_batches;
        fixture.temp.dir.deleteTree("artifacts") catch {};
        fixture.temp.dir.deleteTree("serial") catch {};
        const serial_summary = try Collect.run(a, config);
        try fixture.temp.dir.rename("artifacts", "serial");
        var serial_dir = try fixture.temp.dir.openDir("serial", .{ .iterate = true });
        defer serial_dir.close();
        for ([_]u8{ 1, 2, 3, 8 }) |workers| {
            fixture.temp.dir.deleteTree("artifacts") catch {};
            const summary = try Collect.runWithOptions(a, config, .{ .segment_workers = workers });
            try std.testing.expectEqualDeep(serial_summary, summary);
            var dir = try fixture.temp.dir.openDir("artifacts", .{ .iterate = true });
            defer dir.close();
            try expectSameTree(serial_dir, dir);
        }
        // Direct capture against the serial on-disk packets (the packet
        // reader admits complete collections; prefixes are cut from those).
        if (max_batches != 0) continue;
        var image_owner = try Image.Owner.init(a, config);
        defer image_owner.deinit();
        var program = try Program.initWithAuthority(a, &image_owner.authority);
        defer program.deinit();
        var jobs = try serial_dir.openDir("jobs", .{});
        defer jobs.close();
        for ([_]u32{ 0, 1 }) |prefix| {
            var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, prefix);
            defer serial.deinit();
            for ([_]u8{ 1, 2, 5 }) |workers| for ([_]u8{ 1, 3 }) |inflight| {
                var stats: Direct.Stats = .{};
                var direct = try Direct.captureWithSegments(a, &image_owner, &program, config, prefix, inflight, workers, &stats);
                defer direct.deinit();
                try same(&serial, &direct);
                try std.testing.expectEqualDeep(digestOf(&image_owner, &serial), digestOf(&image_owner, &direct));
                try std.testing.expectEqual(@as(u32, @intCast(serial.native.items.len)), stats.segments.?.segments);
                if (@import("../../rv64_ethereum_segments.zig").minimalFirstPassEnabled()) {
                    try std.testing.expect(stats.segments.?.minimal_cpu0_checked);
                    try std.testing.expectEqual(@as(u64, @min(batch_steps, serial.total_steps)), stats.segments.?.minimal_cpu0_records);
                    try std.testing.expectEqual(@as(u64, @min(batch_steps, serial.total_steps)) * 16 + 384, stats.segments.?.minimal_cpu0_bytes);
                    try std.testing.expect(stats.segments.?.minimal_cpu0_ready_utc_ns > 0);
                }
            };
        }
    };
}
const FirstBatch = struct {
    tape: @import("stwo_riscv_frontend").rv64.compact_tape.Tape,
    finished: @import("../../rv64_ethereum_batch.zig").Finished,
    metadata: Header.Metadata,
    fn chunks(self: *const FirstBatch) usize {
        return if (self.finished.openings) |o| o.chunks.len else 0;
    }
};
fn firstBatch(walk: *Walk) !FirstBatch {
    var step = (try walk.next()).?;
    errdefer step.finished.deinit();
    const metadata = Header.Metadata{ .identity = walk.identity, .index = step.index, .first_step = walk.tape.initial_clock, .before = PacketCodec.ABSENT_ROOT, .after = PacketCodec.ABSENT_ROOT };
    const tape = try walk.advanceTakingTape(&step.batch);
    return .{ .tape = tape, .finished = step.finished, .metadata = metadata };
}
test "in-process handoff rejects forged tapes, statements and identities" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    const Case = enum { none, next_pc, memory_index, steps, division, final_pc, identity, first_step, initial_pc, cells, chunks, cells_over_chunks, before_root, after_root };
    inline for (@typeInfo(Case).@"enum".fields) |field| {
        const case: Case = @enumFromInt(field.value);
        var walk = try Walk.create(a, config);
        defer walk.destroy();
        var batch = try firstBatch(walk);
        defer batch.finished.deinit();
        var cells = batch.finished.cells.len;
        var chunks = batch.chunks();
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
            .chunks => chunks = 1 << 20,
            .cells_over_chunks => cells = 64 * chunks + 1,
            // Roots are absent on this route; a placeholder root is refused.
            .before_root => batch.metadata.before = walk.request.initial_cache.root(),
            .after_root => batch.metadata.after[0] = 1,
        }
        if (case == .none) {
            var p = try PacketCodec.fromNative(batch.tape, batch.finished.public, batch.metadata, cells, chunks, &image_owner, config);
            p.deinit();
        } else {
            if (PacketCodec.fromNative(batch.tape, batch.finished.public, batch.metadata, cells, chunks, &image_owner, config)) |value| {
                var p = value;
                p.deinit();
                std.debug.print("forged case {s} accepted\n", .{field.name});
                return error.ForgedBatchAccepted;
            } else |_| {}
        }
    }
}
fn readPacket(jobs: std.fs.Dir, image_owner: *const Image.Owner, config: Request.Config, limits: Header.Limits) !void {
    const file = try jobs.openFile("job-000000.work", .{});
    defer file.close();
    var p = try PacketCodec.readWithLimits(a, file, image_owner, config, limits);
    p.deinit();
}
fn handOff(image_owner: *const Image.Owner, config: Request.Config, limits: Header.Limits) !void {
    var walk = try Walk.create(a, config);
    defer walk.destroy();
    var batch = try firstBatch(walk);
    defer batch.finished.deinit();
    var p = try PacketCodec.fromNativeWithLimits(batch.tape, batch.finished.public, batch.metadata, batch.finished.cells.len, batch.chunks(), image_owner, config, limits);
    p.deinit();
}
test "in-process handoff applies the packet reader's resource limits" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    _ = try Collect.run(a, config);
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var jobs = try fixture.temp.dir.openDir("artifacts/jobs", .{});
    defer jobs.close();
    var raw: [Header.BYTES]u8 = undefined;
    {
        const file = try jobs.openFile("job-000000.work", .{});
        defer file.close();
        try std.testing.expectEqual(raw.len, try file.preadAll(&raw, 0));
    }
    const total: usize = @intCast(std.mem.readInt(u64, raw[16..24], .little));
    const cells = std.mem.readInt(u32, raw[24..28], .little);
    const chunks = std.mem.readInt(u32, raw[28..32], .little);
    const graph: usize = @intCast(std.mem.readInt(u64, raw[32..40], .little));
    // The fixture's first batch touches RAM, so the disk packet has a graph.
    try std.testing.expect(cells > 0 and chunks > 0 and graph > 0);
    const base = PacketCodec.limitsFor(config);
    const Case = struct { limits: Header.Limits, disk: bool, direct: bool };
    const cases = [_]Case{
        .{ .limits = base, .disk = true, .direct = true },
        .{ .limits = blk: {
            var l = base;
            l.cells = cells - 1;
            break :blk l;
        }, .disk = false, .direct = false },
        .{ .limits = blk: {
            var l = base;
            l.chunks = chunks - 1;
            break :blk l;
        }, .disk = false, .direct = false },
        .{ .limits = blk: {
            var l = base;
            l.steps = config.batch_steps - 1;
            break :blk l;
        }, .disk = false, .direct = false },
        .{ .limits = blk: {
            var l = base;
            l.bytes = total;
            break :blk l;
        }, .disk = true, .direct = true },
        // The one documented divergence: bytes that only the legacy frontier
        // graph (never built in process) would occupy.
        .{ .limits = blk: {
            var l = base;
            l.bytes = total - graph;
            break :blk l;
        }, .disk = false, .direct = true },
        .{ .limits = blk: {
            var l = base;
            l.bytes = total - graph - 1;
            break :blk l;
        }, .disk = false, .direct = false },
        .{ .limits = blk: {
            var l = base;
            l.allocation_bytes = 512 * 1024;
            break :blk l;
        }, .disk = false, .direct = false },
    };
    for (cases, 0..) |case, i| {
        errdefer std.debug.print("limits case {d}\n", .{i});
        if (case.disk) try readPacket(jobs, &image_owner, config, case.limits) else try std.testing.expectError(error.WorkPacketResourceLimit, readPacket(jobs, &image_owner, config, case.limits));
        if (case.direct) try handOff(&image_owner, config, case.limits) else try std.testing.expectError(error.WorkPacketResourceLimit, handOff(&image_owner, config, case.limits));
    }
}
test "packet roots and transport digest do not reach captured values" {
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
    // Disk packets chain real sparse-cache roots: the stores change them.
    var roots_differ = false;
    for (0..5) |i| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "job-{d:0>6}.work", .{i});
        const file = try jobs.openFile(name, .{});
        defer file.close();
        var p = try PacketCodec.read(a, file, &image_owner, config);
        defer p.deinit();
        if (!std.mem.eql(u32, &p.metadata.before, &p.metadata.after)) roots_differ = true;
        try std.testing.expect(!std.mem.allEqual(u8, &p.content_digest, 0));
        // Same packet with roots/digest replaced by the absent markers.
        var native = try Capture.Owner.captureOne(a, &program, &p, i);
        defer {
            native.deinit();
            a.destroy(native);
        }
        var blank = p;
        blank.metadata.before = PacketCodec.ABSENT_ROOT;
        blank.metadata.after = PacketCodec.ABSENT_ROOT;
        blank.content_digest = @splat(0);
        var other = try Capture.Owner.captureOne(a, &program, &blank, i);
        defer {
            other.deinit();
            a.destroy(other);
        }
        try sameNative(native, other);
    }
    try std.testing.expect(roots_differ);
    // Whole-capture digest: disk (chained roots) == direct (absent roots).
    var serial = try Capture.Owner.init(a, &image_owner, &program, config, jobs, 0);
    defer serial.deinit();
    var stats: Direct.Stats = .{};
    var direct = try Direct.capture(a, &image_owner, &program, config, 0, 2, &stats);
    defer direct.deinit();
    try std.testing.expectEqualDeep(digestOf(&image_owner, &serial), digestOf(&image_owner, &direct));
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

test "concurrent resident walk and expected image share only pinned immutable authority" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    var cache = Image.AuthorityCache.init(a);
    defer cache.deinit();
    var stats = Direct.Stats{};
    const started = try Direct.Started.startWithAuthority(a, config, 0, 2, cache.provider());
    defer started.deinit(&stats);
    var image_owner = try Image.Owner.initShared(a, config, &cache);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var shared = try started.capture(&image_owner, &program, 2, &stats);
    defer shared.deinit();
    var control_stats = Direct.Stats{};
    var control = try Direct.captureWithSegments(a, &image_owner, &program, config, 0, 2, 2, &control_stats);
    defer control.deinit();
    try same(&control, &shared);
    const D = @import("capture_digest.zig");
    try std.testing.expectEqualDeep(D.digest(image_owner.identity, &control), D.digest(image_owner.identity, &shared));
    try std.testing.expect(started.walk.?.request.shared_authority);
    try std.testing.expectEqual(@as(u64, 1), cache.misses);
    try std.testing.expect(cache.hits >= 1);
    try std.testing.expectEqual(@as(usize, 1), cache.provider_leases);
    var altered = config;
    altered.input_sha256 = "ff" ** 32;
    try std.testing.expectError(error.EthereumInputIdentityMismatch, Request.Request.initWithOptions(a, altered, .{ .poseidon_initial_cache = false, .authority_provider = cache.provider() }));
    // Request-specific output remains fresh despite sharing the program.
    altered = config;
    altered.expected_output = "ff" ** 43;
    var fresh = try Request.Request.initWithOptions(a, altered, .{ .poseidon_initial_cache = false, .authority_provider = cache.provider() });
    defer fresh.deinit();
    try std.testing.expectEqualDeep([_]u8{0xff} ** 43, fresh.expected_output);
    try std.testing.expectEqual(@as(u64, 1), cache.misses);
    altered.control_policy = .limbs24_v2;
    try std.testing.expectError(error.ResidentAuthorityProviderKeyChanged, Request.Request.initWithOptions(a, altered, .{ .poseidon_initial_cache = false, .authority_provider = cache.provider() }));
    try std.testing.expectError(error.ResidentAuthorityProviderKeyChanged, Image.Owner.initShared(a, altered, &cache));
    try std.testing.expectEqual(@as(usize, 2), cache.provider_leases);
    altered = config;
    altered.terminal_pc = 4096;
    try std.testing.expectError(error.InvalidEthereumTerminalPc, Request.Request.initWithOptions(a, altered, .{ .poseidon_initial_cache = false, .authority_provider = cache.provider() }));
    try std.testing.expectEqual(@as(usize, 2), cache.provider_leases);
}

const ReadinessBorrow = struct {
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    thread: ?std.Thread = null,
    metadata: []const @import("../../word16_execution/cpu_source.zig").Metadata = &.{},
    expected_row: u32 = 0,
    released: bool = false,
    may_read: bool = false,
    checked: bool = false,
    cancellations: usize = 0,
    fn ready(raw: *anyopaque, index: usize, native: *const @import("../../word16_execution/prepared.zig").Prepared, _: []const @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event, _: u64) void {
        const self: *ReadinessBorrow = @ptrCast(@alignCast(raw));
        if (index != 0) return;
        self.metadata = native.cpu.?.metadata;
        self.expected_row = self.metadata[0].rom_row;
        self.thread = std.Thread.spawn(.{}, reader, .{self}) catch unreachable;
    }
    fn reader(self: *ReadinessBorrow) void {
        self.mutex.lock();
        while (!self.released) self.changed.wait(&self.mutex);
        const may_read = self.may_read;
        self.mutex.unlock();
        if (may_read) self.checked = self.metadata[0].rom_row == self.expected_row;
    }
    fn cancel(raw: *anyopaque) void {
        const self: *ReadinessBorrow = @ptrCast(@alignCast(raw));
        self.finish(true);
    }
    fn finish(self: *ReadinessBorrow, may_read: bool) void {
        if (self.thread) |thread| {
            self.mutex.lock();
            self.released = true;
            self.may_read = may_read;
            self.changed.signal();
            self.mutex.unlock();
            thread.join();
            self.thread = null;
            self.cancellations += 1;
        }
    }
};
test "capture failure joins readiness reader before destroying captured metadata" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var config = fixture.config();
    config.max_batches = 1; // Valid first segment, then missing terminal segment.
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    var stats = Direct.Stats{};
    const started = try Direct.Started.start(a, config, 0, 0);
    defer started.deinit(&stats);
    var borrowed = ReadinessBorrow{};
    // If the production callback is missing, test cleanup still joins the
    // helper WITHOUT dereferencing metadata after the failed capture freed it.
    defer borrowed.finish(false);
    started.ready = .{ .context = &borrowed, .call = ReadinessBorrow.ready, .cancel = ReadinessBorrow.cancel };
    try std.testing.expectError(error.MissingEthereumTerminalPacket, started.capture(&image_owner, &program, 2, &stats));
    try std.testing.expectEqual(@as(usize, 1), borrowed.cancellations);
    try std.testing.expect(borrowed.checked);
}

test "whole fast-pass RAM INITIAL equals final collector including zero-valued words" {
    if (!@import("../../rv64_ethereum_segments.zig").ramFirstPassEnabled()) return;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const config = fixture.config();
    var image_owner = try Image.Owner.init(a, config);
    defer image_owner.deinit();
    var program = try Program.initWithAuthority(a, &image_owner.authority);
    defer program.deinit();
    for ([_]u8{ 1, 3 }) |workers| {
        var stats: Direct.Stats = .{};
        var direct = try Direct.captureWithSegments(a, &image_owner, &program, config, 0, 2, workers, &stats);
        defer direct.deinit();
        try std.testing.expect(stats.fast_ram_compared);
        try std.testing.expectEqual(@as(u64, direct.advice.initial.len), stats.fast_ram_words);
        try std.testing.expect(stats.fast_ram_ready_utc_ns > 0);
    }
}
