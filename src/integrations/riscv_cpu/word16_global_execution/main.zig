//! Explicit two-packet global prefix prototype. No services/full-block claim.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Packet = @import("../word16_execution/packet.zig");
const Driver = @import("../word16_execution/driver.zig");
const Program = @import("../word16_execution/program.zig").Program;
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Setup = @import("../word16_execution/setup.zig").Setup;
const C = @import("../word16_execution/coordinator.zig");
const E = @import("execution.zig");
const P = @import("protocol.zig");
const Wire = @import("wire.zig");

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "migrate")) {
        var source_dir = try std.fs.cwd().openDir(args[2], .{});
        defer source_dir.close();
        var loaded = try Wire.read(a, source_dir);
        defer loaded.deinit(a);
        var target_dir = try newDirectory(args[3]);
        defer target_dir.close();
        try Wire.write(a, target_dir, loaded.geometries, &loaded.bundle);
        return;
    }
    if (args.len != 6) return error.ExpectedModeConfigPacket0Packet1Directory;
    const proving = std.mem.eql(u8, args[1], "produce");
    if (!proving and !std.mem.eql(u8, args[1], "verify")) return error.ExpectedModeConfigPacket0Packet1Directory;
    // Packet0/1 inputs are independently supplied to the fresh receiver. They
    // select the intended prefix; their legacy graph/RAM roots grant no authority.
    const config_bytes = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(config_bytes);
    const config = try std.json.parseFromSlice(Request.Config, a, config_bytes, .{});
    defer config.deinit();
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config.value), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    var f0 = try std.fs.cwd().openFile(args[3], .{});
    defer f0.close();
    var f1 = try std.fs.cwd().openFile(args[4], .{});
    defer f1.close();
    var p0 = try Packet.read(a, f0, &image, config.value);
    defer p0.deinit();
    var p1 = try Packet.read(a, f1, &image, config.value);
    defer p1.deinit();
    try C.requireGenesis(&image, &p0);
    if (p1.metadata.index != 1 or p1.metadata.first_step != p0.tape.len or p0.tape.service_calls.items.len != 0 or p1.tape.service_calls.items.len != 0 or p0.tape.secp_calls.items.len != 0 or p1.tape.secp_calls.items.len != 0) return error.UnqualifiedGlobalPrefix;
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const expected = P.Expected{ .admission = Driver.admission(&image), .program_identity = program.identity, .total_steps = p0.tape.len + p1.tape.len, .max_total_steps = config.value.max_steps, .final_pc = p1.public.statement.final_pc, .final_registers = p1.public.statement.final_registers };
    if (proving) {
        var native0 = try Native.init(a, &program, C.boundary(&p0), 1, try @import("../word16_execution/coverage.zig").minimalPrefixLog(@intCast(p0.tape.len)), &p0.tape, .{});
        defer native0.deinit();
        var native1 = try Native.init(a, &program, C.boundary(&p1), 2, try @import("../word16_execution/coverage.zig").minimalPrefixLog(@intCast(p1.tape.len)), &p1.tape, .{});
        defer native1.deinit();
        var advice = try E.collectAdvice(a, &.{ &native0, &native1 }, expected.admission.image);
        defer advice.deinit();
        var g0 = try native0.geometry();
        var g1 = try native1.geometry();
        const bound = try @import("../word16_execution/coverage.zig").minimalPrefixLog(@intCast(advice.initial.len));
        g0.boundary_log = bound;
        g1.boundary_log = bound;
        g0.initial_log = bound;
        g0.terminal_log = 5;
        g1.initial_log = 5;
        g1.terminal_log = bound;
        var setup0 = try Setup.initWithAuthority(a, &image.authority, g0);
        defer setup0.deinit();
        var setup1 = try Setup.initWithAuthority(a, &image.authority, g1);
        defer setup1.deinit();
        var timer = try std.time.Timer.start();
        var bundle = try E.produceWithAdvice(a, &.{ &setup0, &setup1 }, &.{ &native0, &native1 }, &advice, expected);
        defer bundle.deinit(a);
        const prove_ns = timer.read();
        try E.verify(a, &.{ &setup0, &setup1 }, expected, &bundle);
        const verify_ns = timer.read() - prove_ns;
        var dir = try newDirectory(args[5]);
        defer dir.close();
        try Wire.write(a, dir, .{ g0, g1 }, &bundle);
        try Driver.writeJson(a, dir, "report.json", .{ .scope = "two real CPU shards; global RAM; no services/full-block/recursion claim", .steps = expected.total_steps, .words = advice.initial.len, .physical_proofs = 2, .global_ram_prefix_accepted = true, .produce_after_setup_ns = prove_ns, .same_process_verify_ns = verify_ns, .proof_bytes = .{ bundle.proofs[0].bytes.len, bundle.proofs[1].bytes.len } });
        try std.posix.fsync(dir.fd);
    } else {
        var dir = try std.fs.cwd().openDir(args[5], .{});
        defer dir.close();
        var loaded = try Wire.read(a, dir);
        defer loaded.deinit(a);
        // Geometry is untrusted bounded proof shape. Keys derive afresh from
        // the independently expected pristine program, never a transport hash.
        var setup0 = try Setup.initWithAuthority(a, &image.authority, loaded.geometries[0]);
        defer setup0.deinit();
        var setup1 = try Setup.initWithAuthority(a, &image.authority, loaded.geometries[1]);
        defer setup1.deinit();
        try E.verify(a, &.{ &setup0, &setup1 }, expected, &loaded.bundle);
    }
}

fn newDirectory(path: []const u8) !std.fs.Dir {
    try std.fs.cwd().makeDir(path);
    var parent = try std.fs.cwd().openDir(std.fs.path.dirname(path) orelse ".", .{});
    defer parent.close();
    try std.posix.fsync(parent.fd);
    return std.fs.cwd().openDir(path, .{});
}
