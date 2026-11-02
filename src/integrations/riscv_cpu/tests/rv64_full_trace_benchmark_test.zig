//! Opt-in witness benchmark on an actual CSP case. Ordinary tests skip it.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const native = @import("../rv64_full.zig");
const work = @import("stwo_prover_engine").work_pool;
const base = std.heap.smp_allocator;
const Config = struct { guest: rv.csp_contract.Config, expected_steps: u32 };

test "full physical trace benchmark actual CSP witness bytes" {
    const config_path = std.process.getEnvVarOwned(base, "RV64_TRACE_BENCH_CONFIG") catch return error.SkipZigTest;
    defer base.free(config_path);
    const config_bytes = try std.fs.cwd().readFileAlloc(base, config_path, 32768);
    defer base.free(config_bytes);
    const parsed = try std.json.parseFromSlice(Config, base, config_bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const config = parsed.value;
    const elf = try std.fs.cwd().readFileAlloc(base, config.guest.elf, 32 * 1024 * 1024);
    defer base.free(elf);
    const input = try std.fs.cwd().readFileAlloc(base, config.guest.input, 4096);
    defer base.free(input);
    var timer = try std.time.Timer.start();
    var capture = try native.Capture.run(base, config.guest, elf, input, .{ .expected_steps = config.expected_steps });
    defer capture.deinit();
    const capture_ns = timer.lap();
    const public = capture.statement();
    var setup = try native.PreparedSetup.init(base, public);
    defer setup.deinit();
    const setup_ns = timer.lap();
    const workers_text = std.process.getEnvVarOwned(base, "RV64_TRACE_BENCH_WORKERS") catch null;
    defer if (workers_text) |text| base.free(text);
    const workers = if (workers_text) |text| try std.fmt.parseUnsigned(usize, text, 10) else 1;
    var pool: work.WorkPool = undefined;
    var pool_ready = false;
    defer if (pool_ready) pool.deinit();
    if (workers > 1) {
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024, .backing_allocator = base });
        pool_ready = true;
    }
    var trace = try native.Trace.initWithPool(base, capture.records, public, &setup.materials.program, &setup.materials.plan, if (pool_ready) &pool else null);
    defer trace.deinit();
    const init_ns = timer.lap();
    var channel = air.protocol.Channel{};
    const challenges = air.full.component.Challenges{ .state = air.relations.Challenges.draw(&channel), .rom = air.program.compact.draw(&channel), .bytes = channel.drawSecureFelt(), .bitwise = air.providers.tables.Challenges.draw(&channel), .shifts = air.providers.tables.Challenges.draw(&channel) };
    const claims = try trace.generateInteractionWithPool(challenges, if (pool_ready) &pool else null);
    const interaction_ns = timer.lap();
    const Blake = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
    var main_hash: [32]u8 = undefined;
    var interaction_hash: [32]u8 = undefined;
    Blake.hash(std.mem.sliceAsBytes(trace.main), &main_hash, .{});
    Blake.hash(std.mem.sliceAsBytes(trace.interaction), &interaction_hash, .{});
    std.debug.print("RV64_TRACE_BENCH steps={d} main_columns={d} interaction_columns={d} workers={d} capture_ns={d} setup_ns={d} init_ns={d} interaction_ns={d} main_hash={x} interaction_hash={x} state_claim={any}\n", .{ public.steps, trace.main.len / trace.domainSize(), trace.interactionCount(), workers, capture_ns, setup_ns, init_ns, interaction_ns, main_hash, interaction_hash, claims.state.toM31Array() });
}
