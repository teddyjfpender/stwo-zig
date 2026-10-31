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
const G = @import("../word16_execution/geometry.zig");
const C = @import("../word16_execution/coordinator.zig");
const E = @import("execution.zig");
const P = @import("protocol.zig");
const Meta = struct { schema: u32 = 1, geometries: [2]G.Geometry, requests: [2]P.Old.Request, claims: [2]P.Old.Claims, specs: [2][32]u8, roots: [2]P.Receipt, seal: [32]u8 };
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
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
        try std.fs.cwd().makeDir(args[5]);
        var dir = try std.fs.cwd().openDir(args[5], .{});
        defer dir.close();
        try Driver.writeJson(a, dir, "bundle.json", Meta{ .geometries = .{ g0, g1 }, .requests = .{ bundle.proofs[0].request, bundle.proofs[1].request }, .claims = .{ bundle.proofs[0].claims, bundle.proofs[1].claims }, .specs = .{ bundle.manifest.specs[0], bundle.manifest.specs[1] }, .roots = .{ bundle.manifest.roots[0], bundle.manifest.roots[1] }, .seal = bundle.manifest.digest });
        try dir.writeFile(.{ .sub_path = "proof0.bin", .data = bundle.proofs[0].bytes });
        try dir.writeFile(.{ .sub_path = "proof1.bin", .data = bundle.proofs[1].bytes });
        try Driver.writeJson(a, dir, "report.json", .{ .scope = "two real CPU shards; global RAM; no services/full-block/recursion claim", .steps = expected.total_steps, .words = advice.initial.len, .physical_proofs = 2, .global_ram_prefix_accepted = true, .produce_after_setup_ns = prove_ns, .same_process_verify_ns = verify_ns, .proof_bytes = .{ bundle.proofs[0].bytes.len, bundle.proofs[1].bytes.len } });
    } else {
        var dir = try std.fs.cwd().openDir(args[5], .{});
        defer dir.close();
        const data = try dir.readFileAlloc(a, "bundle.json", 512 * 1024 * 1024);
        defer a.free(data);
        const meta = try std.json.parseFromSlice(Meta, a, data, .{});
        defer meta.deinit();
        if (meta.value.schema != 1) return error.UnsupportedGlobalExecutionBundle;
        // Geometry is untrusted bounded proof shape; every immutable fixed root is
        // derived afresh from the independently pinned program authority.
        try meta.value.geometries[0].validate();
        try meta.value.geometries[1].validate();
        var setup0 = try Setup.initWithAuthority(a, &image.authority, meta.value.geometries[0]);
        defer setup0.deinit();
        var setup1 = try Setup.initWithAuthority(a, &image.authority, meta.value.geometries[1]);
        defer setup1.deinit();
        var manifest = try P.Manifest.init(a, &meta.value.specs, &meta.value.roots);
        defer manifest.deinit();
        if (!std.mem.eql(u8, &manifest.digest, &meta.value.seal)) return error.GlobalExecutionManifestChanged;
        const b0 = try dir.readFileAlloc(a, "proof0.bin", 64 * 1024 * 1024);
        defer a.free(b0);
        const b1 = try dir.readFileAlloc(a, "proof1.bin", 64 * 1024 * 1024);
        defer a.free(b1);
        var proofs = [_]E.Encoded{ .{ .bytes = b0, .request = meta.value.requests[0], .claims = meta.value.claims[0] }, .{ .bytes = b1, .request = meta.value.requests[1], .claims = meta.value.claims[1] } };
        const bundle = E.Bundle{ .manifest = manifest, .proofs = &proofs };
        try E.verify(a, &.{ &setup0, &setup1 }, expected, &bundle);
    }
}
