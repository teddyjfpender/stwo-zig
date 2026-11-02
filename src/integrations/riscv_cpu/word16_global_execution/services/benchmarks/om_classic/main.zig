//! Benchmark-only ordinary CPU0 prefix. Never a production execution manifest.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Control = @import("control.zig");
const W = @import("../../gkr_local/worker_protocol.zig");
const Wire = @import("../../wire.zig");
const Cells = @import("../../../../word16_execution/cells_wire.zig");
const Driver = @import("../../../../word16_execution/driver.zig");
const Image = @import("../../../../word16_execution/expected_image.zig");
const Program = @import("../../../../word16_execution/program.zig").Program;
const Request = @import("../../../../rv64_ethereum_request.zig");
const E = @import("../../../ethereum/receiver.zig");
const Keys = @import("../../../ethereum/keys.zig").Owner;
const Capture = @import("../../../ethereum/capture.zig").Owner;
const Plan = @import("../../../ethereum/plan.zig");
const C = @import("../../gkr_local/coordinator.zig");
const Suite = @import("../../../../word16_execution/pcs_suite.zig").Suite;
const Recycler = @import("../../../../rv64_large_block_recycler.zig").LargeBlockRecycler;
const NativeCache = @import("../../../../word16_execution/fixed_native_cache.zig");
const MetadataCache = @import("../../../../word16_execution/program_metadata.zig");
const O = W.O;
const PROFILE = "benchmark-only-om31-classic-local-cpu0-q70-p26-fold4";
const Metadata = struct {
    schema: u32 = 1,
    profile: []const u8 = PROFILE,
    declaration: Wire.CpuDeclaration,
    request: Wire.CompactRequest,
    memory_words: u32,
    main_root: [32]u8,
    local_claims: []const [8]u32,
    ram_claims: []const [8]u32,
};
fn config() !W.PcsConfig {
    var c = W.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 70) };
    c.fri_config.fold_step = 4;
    return c;
}
fn pack(a: std.mem.Allocator, values: []const O) ![][8]u32 {
    const out = try a.alloc([8]u32, values.len);
    for (values, out) |v, *dest| for (v.toM31Array(), dest) |m, *n| {
        n.* = m.toU32();
    };
    return out;
}
fn unpack(a: std.mem.Allocator, values: []const [8]u32) ![]O {
    if (values.len > 64) return error.ClassicControlClaimLimit;
    const out = try a.alloc(O, values.len);
    errdefer a.free(out);
    for (values, out) |v, *dest| {
        var m: [8]core.fields.m31.M31 = undefined;
        for (v, &m) |n, *x| {
            if (n >= 2147483647) return error.NoncanonicalClassicClaim;
            x.* = core.fields.m31.M31.fromCanonical(n);
        }
        dest.* = O.fromM31Array(m);
    }
    return out;
}
pub fn main() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, 4 << 30);
    defer recycler.deinit();
    const args = try std.process.argsAlloc(recycler.allocator());
    defer std.process.argsFree(recycler.allocator(), args);
    if (args.len < 4) return error.ExpectedProduceConfigJobsOutOrVerifyConfigOut;
    const produce = std.mem.eql(u8, args[1], "produce");
    if ((!produce and !std.mem.eql(u8, args[1], "verify")) or args.len != (if (produce) @as(usize, 5) else 4)) return error.InvalidClassicControlMode;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(recycler.allocator(), 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const request = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer request.deinit();
    const workers = try Request.effectiveWorkers(request.value);
    if (workers == 0 or workers > 32) return error.InvalidClassicControlWorkerCount;
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1 << 20, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.init(a, request.value);
    defer image.deinit();
    var native_cache = try NativeCache.Cache.init(a, 256 << 20);
    defer native_cache.deinit();
    var metadata_cache = try MetadataCache.Cache.init(a, 64 << 20);
    defer metadata_cache.deinit();
    const caches = @import("../../../../word16_execution/setup.zig").ImmutableCaches{ .native = &native_cache, .program = &metadata_cache };
    var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, &metadata_cache);
    defer program.deinit();
    const pcs = try config();
    if (!produce) {
        var dir = try std.fs.cwd().openDir(args[3], .{});
        defer dir.close();
        const text = try dir.readFileAlloc(a, "control.json", 1 << 20);
        defer a.free(text);
        const metadata = try std.json.parseFromSlice(Metadata, a, text, .{});
        defer metadata.deinit();
        const m = metadata.value;
        if (m.schema != 1 or !std.mem.eql(u8, m.profile, PROFILE) or m.memory_words > 1 << 22) return error.InvalidClassicControlMetadata;
        const cells = try Cells.read(a, dir, m.memory_words);
        defer cells.deinit(a);
        const r = m.request.expand(cells.initial, cells.terminal);
        const expected = try E.expectedFromRequests(&image, program.identity, &.{r}, request.value.max_steps, request.value.batch_steps, false);
        // Bounds and no-service policy are checked before expensive trusted keys.
        _ = try @import("../../gkr_local/source_bounds.zig").validateInventory(1, 0);
        var bounds = try @import("../../gkr_local/source_bounds.zig").derive(a, program.log_size, &.{m.declaration}, &.{}, &.{r});
        defer bounds.deinit();
        if (r.calls[0] != 0 or r.calls[1] != 0 or r.calls[2] != 0 or m.declaration.bridges.keccak != null or m.declaration.bridges.add != null or m.declaration.bridges.double != null) return error.ClassicControlServicesUnsupported;
        var keys = try Keys.initWithSuiteAndCaches(a, &image, &.{m.declaration}, &.{}, true, Suite.experimentalFold4(), caches);
        defer keys.deinit();
        var encoded = try readEncoded(a, dir, m);
        defer encoded.deinit(a);
        const setup_ns = timer.read();
        try Control.verify(a, keys.cpus[0], r, expected, pcs, &encoded);
        return emit(a, .{ .profile = PROFILE, .benchmark_only = true, .production_protocol = false, .security_qualified = false, .accepted_ordinary_cpu_prefix = true, .total_steps = r.base.cpu.steps, .load_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns });
    }
    var jobs = try std.fs.cwd().openDir(args[3], .{});
    defer jobs.close();
    var captured = try Capture.init(a, &image, &program, request.value, jobs, 1);
    defer captured.deinit();
    const cpu = try Plan.cpus(a, &captured);
    defer a.free(cpu);
    const truths = try Plan.truths(a, &captured);
    defer a.free(truths);
    if (cpu.len != 1 or truths.len != 0) return error.ExpectedOneOrdinaryCpuShard;
    try program.releaseFixedWitness();
    const r = try C.requestView(captured.native.items, &captured.advice, 0);
    const expected = try E.expectedFromRequests(&image, program.identity, &.{r}, request.value.max_steps, request.value.batch_steps, false);
    var keys = try Keys.initWithSuiteAndCaches(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches);
    defer keys.deinit();
    const source_start = timer.read();
    const source = try @import("../../pipeline.zig").buildCpuSource(a, keys.cpus[0], r, captured.native.items[0], &captured.advice, 0, .{ 1, 1, 1 }, false, null);
    const source_ns = timer.read() - source_start;
    var observations = try @import("../../../ethereum/observations.zig").Owner.init(a, 1);
    defer observations.deinit();
    var timing: Control.Timing = .{};
    const prove_start = timer.read();
    var encoded = try Control.prove(a, keys.cpus[0], r, expected, pcs, source, 16 << 30, observations.pointers[0], &timing);
    defer encoded.deinit(a);
    const prove_ns = timer.read() - prove_start;
    const verify_start = timer.read();
    try Control.verify(a, keys.cpus[0], r, expected, pcs, &encoded);
    const verify_ns = timer.read() - verify_start;
    try std.fs.cwd().makeDir(args[4]);
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    var proof = try dir.createFile("proof.bin", .{ .exclusive = true });
    defer proof.close();
    try proof.writeAll(encoded.bytes);
    try proof.sync();
    try Cells.write(dir, r.base.memory.initial, r.base.memory.terminal);
    try (@import("../../profiling.zig").Options{ .recorders = observations.pointers, .directory = dir }).finish(a, 0);
    const local = try pack(a, encoded.local_claims);
    defer a.free(local);
    const ram = try pack(a, encoded.ram_claims);
    defer a.free(ram);
    try Driver.writeJson(a, dir, "control.json", Metadata{ .declaration = cpu[0], .request = Wire.CompactRequest.from(r), .memory_words = @intCast(r.base.memory.initial.len), .main_root = encoded.main_root, .local_claims = local, .ram_claims = ram });
    var layout = try Control.Plan.init(a, keys.cpus[0]);
    defer layout.deinit();
    const ilogs = try layout.interLogs(a);
    defer a.free(ilogs);
    var inter_cells: u64 = 0;
    for (ilogs) |log| inter_cells += @as(u64, 1) << @intCast(log);
    var main_cells: u64 = 0;
    for (keys.cpus[0].materials.shapes()) |shape| if (shape.present()) {
        main_cells += @as(u64, @intCast(shape.widths[1])) << @intCast(shape.log);
    };
    try Driver.writeJson(a, dir, "report.json", .{ .profile = PROFILE, .benchmark_only = true, .production_protocol = false, .security_qualified = false, .total_steps = captured.total_steps, .main_root = encoded.main_root, .fixed_root = keys.cpus[0].key.root, .source_ns = source_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .timing = timing, .proof_bytes = encoded.bytes.len, .native_main_cells = main_cells, .native_inter_cells = inter_cells, .inter_columns = ilogs.len, .statement = @import("../../gkr_local/cpu_worker.zig").cpuStatement(keys.cpus[0], r, .{ 1, 1, 1 }, pcs), .requested_budget = budget.snapshot() });
}
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const text = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(text);
    try std.fs.File.stdout().writeAll(text);
    try std.fs.File.stdout().writeAll("\n");
}

fn readEncoded(a: std.mem.Allocator, dir: std.fs.Dir, m: Metadata) !Control.Encoded {
    const bytes = try dir.readFileAlloc(a, "proof.bin", 64 << 20);
    errdefer a.free(bytes);
    const local = try unpack(a, m.local_claims);
    errdefer a.free(local);
    const ram = try unpack(a, m.ram_claims);
    return .{ .bytes = bytes, .local_claims = local, .ram_claims = ram, .main_root = m.main_root };
}

test "benchmark claim codec preserves all eight coordinates and refuses field reduction" {
    const a = std.testing.allocator;
    const M = core.fields.m31.M31;
    const value = O.fromM31Array(.{ M.fromCanonical(1), M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(4), M.fromCanonical(5), M.fromCanonical(6), M.fromCanonical(7), M.fromCanonical(8) });
    const coordinates = try pack(a, &.{value});
    defer a.free(coordinates);
    const decoded = try unpack(a, coordinates);
    defer a.free(decoded);
    try std.testing.expect(decoded[0].eql(value));
    coordinates[0][7] = 2147483647;
    try std.testing.expectError(error.NoncanonicalClassicClaim, unpack(a, coordinates));
}
