//! Known-public BEQ diagnostic. Receiver independently selects both geometries.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("word16/cpu.zig");
const Source = @import("word16/cpu_sources.zig");
const F = @import("word16/weighted_alu_fixture.zig");
const Profile = @import("stwo_prover_api").stage_profile;
const Alu = @import("stwo_riscv_frontend").rv64_air.word16_v1.alu_experiment;
const Packet = struct { cpu: Source.Claims, alu: Alu.lookup.Claims };
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 5) return error.ExpectedProduceOrVerifyCpuLogAluLogDirectory;
    const weighted = std.mem.eql(u8, args[1], "produce");
    const unweighted = std.mem.eql(u8, args[1], "produce-unweighted");
    if (!weighted and !unweighted and !std.mem.eql(u8, args[1], "verify")) return error.InvalidWeightedAluFixtureMode;
    const cpu_log = try std.fmt.parseInt(u32, args[2], 10);
    const alu_log = try std.fmt.parseInt(u32, args[3], 10);
    const public = try F.expected(cpu_log);
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try std.fs.cwd().makePath(args[4]);
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    var timer = try std.time.Timer.start();
    var materials = try CPU.Materials.init(a, .{ .base = F.BASE, .words = &F.WORDS }, F.geometry(cpu_log, alu_log));
    defer materials.deinit();
    const setup_ns = timer.lap();
    var recorder = Profile.Recorder.initWithOptions(a, "cpu-simd16", "closed-weighted-alu-beq", .{ .capture_tasks = false, .capture_work = false });
    defer recorder.deinit();
    if (weighted or unweighted) {
        const records = try F.capture(a, public);
        defer a.free(records);
        const capture_ns = timer.lap();
        var proof = if (weighted) try CPU.produceDeduplicatedProfiled(a, &materials, public, records, false, &recorder) else try CPU.produceProfiled(a, &materials, public, records, false, &recorder);
        defer proof.deinit(a);
        const prove_ns = timer.lap();
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = proof.bytes });
        try json(a, dir, "claims.json", Packet{ .cpu = proof.claims, .alu = proof.alu_claims });
        try receipt(a, dir, "producer.json", &materials, public, proof.bytes, setup_ns, capture_ns, prove_ns, weighted);
        var stages = try recorder.snapshot(a);
        defer stages.deinit(a);
        try json(a, dir, "stages.json", stages);
    } else {
        const bytes = try dir.readFileAlloc(a, "proof.bin", 128 * 1024 * 1024);
        defer a.free(bytes);
        const claims_raw = try dir.readFileAlloc(a, "claims.json", 16384);
        defer a.free(claims_raw);
        const claims = try std.json.parseFromSlice(Packet, a, claims_raw, .{});
        defer claims.deinit();
        try CPU.verifyClosed(a, &materials, public, .{ .bytes = bytes, .claims = claims.value.cpu, .alu_claims = claims.value.alu });
        try receipt(a, dir, "receiver.json", &materials, public, bytes, setup_ns, 0, timer.lap(), null);
    }
}
fn json(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}
fn receipt(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, materials: *const CPU.Materials, public: CPU.Public, bytes: []const u8, setup_ns: u64, capture_ns: u64, prove_or_verify_ns: u64, weighted: ?bool) !void {
    var cells: u64 = 0;
    const shapes = materials.shapes();
    for (shapes.slice()) |shape| for (shape.widths) |width| {
        cells += @as(u64, width) << @intCast(shape.log);
    };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    try json(a, dir, name, .{ .scope = "closed-register-only-word16-native-BEQ-prefix; no RAM or complete-RV64 claim", .steps = public.steps, .cpu_log = materials.geometry.cpu_log, .alu_log = materials.geometry.alu_log, .weighted_witness = weighted, .proof_sha256 = std.fmt.bytesToHex(digest, .lower), .proof_bytes = bytes.len, .source_cells = cells, .source_bytes = 4 * cells, .setup_ns = setup_ns, .capture_ns = capture_ns, .prove_or_verify_ns = prove_or_verify_ns, .queries = 70, .pow_bits = 26, .log_blowup = 1, .nominal_config_bits = 96, .alu_main_columns = Alu.lookup.MAIN, .alu_interaction_columns = Alu.lookup.INTERACTION, .metadata_bytes_per_alu_row = @sizeOf(Alu.source.Metadata), .weighted_alu_fact_count = if (weighted) |value| (if (value) @as(u32, 1) else public.steps) else null, .function_mass = public.steps, .range16_alu_mass = @as(u64, 20) << @intCast(materials.geometry.alu_log) });
}
