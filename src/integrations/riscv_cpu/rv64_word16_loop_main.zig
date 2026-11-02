//! Independent-process complete proof comparison; arguments are receiver policy.
const std = @import("std");
const core = @import("stwo_core");
const Wire = @import("stwo_proof_wire");
const CPU = @import("word16/cpu.zig");
const Full = @import("rv64_full.zig");
const F = @import("word16/loop_fixture.zig");
const Claims = @import("word16/cpu_sources.zig").Claims;
const AluClaims = @import("stwo_riscv_frontend").rv64_air.word16_v1.alu_experiment.lookup.Claims;
const Profile = @import("stwo_prover_api").stage_profile;
const ClaimPacket = struct { cpu: Claims, alu: AluClaims };
const A = std.heap.smp_allocator;
pub fn main() !void {
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 1024 * 1024, .backing_allocator = A });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const args = try std.process.argsAlloc(A);
    defer std.process.argsFree(A, args);
    if (args.len != 5) return error.ExpectedProduceOrVerifyEncodingIterationsDirectory;
    const produce = std.mem.eql(u8, args[1], "produce");
    if (!produce and !std.mem.eql(u8, args[1], "verify")) return error.InvalidAction;
    const thin = std.mem.eql(u8, args[2], "word16");
    if (!thin and !std.mem.eql(u8, args[2], "legacy")) return error.InvalidEncoding;
    const public = try F.expected(try std.fmt.parseInt(u32, args[3], 10));
    try std.fs.cwd().makePath(args[4]);
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    var timer = try std.time.Timer.start();
    var recorder = Profile.Recorder.initWithOptions(A, "cpu-simd16", "closed-word16-loop", .{ .capture_tasks = false, .capture_work = false });
    defer recorder.deinit();
    if (thin) {
        var materials = try CPU.Materials.init(A, .{ .base = F.BASE, .words = &F.WORDS }, F.geometry(public));
        defer materials.deinit();
        const setup_ns = timer.lap();
        if (produce) {
            const records = try F.capture(A, public);
            defer A.free(records);
            const capture_ns = timer.lap();
            var encoded = try CPU.produceProfiled(A, &materials, public, records, false, &recorder);
            defer encoded.deinit(A);
            const proving_ns = timer.lap();
            try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded.bytes });
            try json(dir, "claims.json", ClaimPacket{ .cpu = encoded.claims, .alu = encoded.alu_claims });
            var cells: u64 = 0;
            const shapes = materials.shapes();
            for (shapes.slice()) |shape| for (shape.widths) |width| {
                cells += @as(u64, width) << @intCast(shape.log);
            };
            try receipt(dir, "producer.json", public, "word16", encoded.bytes, setup_ns, capture_ns, proving_ns, cells);
            try stages(dir, &recorder);
        } else {
            const bytes = try dir.readFileAlloc(A, "proof.bin", 128 * 1024 * 1024);
            defer A.free(bytes);
            const packet = try readClaims(ClaimPacket, dir);
            defer packet.deinit();
            try CPU.verifyClosed(A, &materials, public, .{ .bytes = bytes, .claims = packet.value.cpu, .alu_claims = packet.value.alu });
            try receipt(dir, "receiver.json", public, "word16", bytes, setup_ns, 0, timer.lap(), 0);
        }
    } else {
        const statement = F.statement(public);
        var setup = try Full.PreparedSetup.initWithControl(A, statement, .limbs24_v2);
        defer setup.deinit();
        const setup_ns = timer.lap();
        if (produce) {
            const records = try F.capture(A, public);
            defer A.free(records);
            const capture_ns = timer.lap();
            var trace = try Full.Trace.init(A, records, statement, &setup.materials.program, &setup.materials.plan);
            defer trace.deinit();
            const witness_ns = timer.lap();
            const main_cells = trace.main.len;
            var bundle = try Full.proveTraceProfiled(A, &setup, statement, &trace, &recorder);
            defer bundle.deinit(A);
            const bytes = try Wire.encodeProofBytesBinary(A, bundle.proof);
            defer A.free(bytes);
            const proving_ns = timer.lap();
            const cells = try legacyCells(&setup, main_cells);
            try dir.writeFile(.{ .sub_path = "proof.bin", .data = bytes });
            try json(dir, "claims.json", bundle.claims);
            try receipt(dir, "producer.json", public, "legacy-packed-control-inverse-state", bytes, setup_ns, capture_ns, witness_ns + proving_ns, cells);
            try stages(dir, &recorder);
        } else {
            const bytes = try dir.readFileAlloc(A, "proof.bin", 128 * 1024 * 1024);
            defer A.free(bytes);
            const packet = try readClaims(Full.Claims, dir);
            defer packet.deinit();
            try setup.verifyOwned(A, statement, packet.value, try Wire.decodeProofBytesBinary(A, bytes));
            try receipt(dir, "receiver.json", public, "legacy-packed-control-inverse-state", bytes, setup_ns, 0, timer.lap(), 0);
        }
    }
}
fn stages(dir: std.fs.Dir, recorder: *Profile.Recorder) !void {
    var snapshot = try recorder.snapshot(A);
    defer snapshot.deinit(A);
    try json(dir, "stages.json", snapshot);
}
fn legacyCells(setup: *const Full.PreparedSetup, main_cells: usize) !u64 {
    const air = @import("stwo_riscv_frontend").rv64_air;
    const m = &setup.materials;
    const fixed = try setup.fixedColumns(A);
    defer A.free(fixed);
    var cells: u64 = main_cells;
    for (fixed) |column| cells += column.values.len;
    const interactions = m.plan.stateInteractionCount() + 8 + air.range.cpu.interactionCount(&m.plan) + air.range.table_cpu.interactionCount(&m.plan, .byte_and) + air.range.table_cpu.interactionCount(&m.plan, .byte_shift);
    cells += @as(u64, interactions) << @intCast(m.log_size);
    // Each admitted standalone provider commits one multiplicity and eight
    // interaction coordinates at its own domain; fixed values counted above.
    cells += 9 * ((@as(u64, 1) << @intCast(m.program.log_size)) + 256);
    if (m.and_table != null) cells += 9 * 65536;
    if (m.shift_table != null) cells += 9 * 2048;
    return cells;
}
fn json(dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(A, value, .{});
    defer A.free(bytes);
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}
fn readClaims(comptime T: type, dir: std.fs.Dir) !std.json.Parsed(T) {
    const bytes = try dir.readFileAlloc(A, "claims.json", 65536);
    defer A.free(bytes);
    return std.json.parseFromSlice(T, A, bytes, .{});
}
fn receipt(dir: std.fs.Dir, name: []const u8, public: CPU.Public, encoding: []const u8, bytes: []const u8, setup_ns: u64, capture_ns: u64, proving_ns: u64, cells: u64) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    try json(dir, name, .{ .scope = "closed-ALU-BINARY-branch-loop-no-RAM-services-or-Ethereum", .encoding = encoding, .statement = public, .setup_ns = setup_ns, .native_capture_ns = capture_ns, .witness_and_proving_or_verification_ns = proving_ns, .source_cells_if_enumerated = cells, .proof_bytes = bytes.len, .proof_sha256 = std.fmt.bytesToHex(digest, .lower), .queries = 70, .pow_bits = 26, .workers = 16 });
}
