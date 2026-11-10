//! Bounded conditional CPU-component measurement, never execution acceptance.
//! Runs only the first 4M real retirements of a pinned heavy guest. INIT covers
//! prefix-touched cells only. All service/end-memory debts remain outstanding.
const std = @import("std");
const E = @import("stwo_prover_engine");
const C = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const Config = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Prepared = @import("../../word16_execution/prepared.zig").Prepared;
const Memory = @import("../../word16_execution/memory/statement.zig");
const Collector = @import("../../word16_global_execution/services/collector.zig");
const Coverage = @import("../../word16_execution/coverage.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Plan = @import("../../word16_global_execution/ethereum/plan.zig");
const Types = @import("../../word16_global_execution/services/types.zig");
const Pipeline = @import("../../word16_global_execution/services/pipeline.zig");
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Frame = @import("frame.zig");
const Security = @import("security.zig");
const Source = @import("source.zig").Source;
const Key = @import("key.zig").Key;
const Worker = @import("worker.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const Profile = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
const Write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
const N = 4_000_000;
const Endpoint = struct { steps: u64, initial_pc: u64, initial_registers: [32]u64, final_pc: u64, final_registers: [32]u64, elf_sha256: []const u8, input_sha256: []const u8, completed: bool };
fn json(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(raw);
    try Write(dir, name, raw);
}
fn cells(logs: []const u32) u64 {
    var out: u64 = 0;
    for (logs) |log| out += @as(u64, 1) << @intCast(log);
    return out;
}
fn run(a: std.mem.Allocator, config: Config.Config, endpoint: Endpoint, dir: std.fs.Dir, prove: bool) !void {
    if (endpoint.steps != N or endpoint.completed or config.workers != 16) return error.ConditionalPrefixOnly;
    try std.testing.expectEqualStrings(config.elf_sha256, endpoint.elf_sha256);
    try std.testing.expectEqualStrings(config.input_sha256, endpoint.input_sha256);
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.initForOp(a, config);
    defer image.deinit();
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    try program.makeCompact();
    const image_program_ns = timer.read();
    const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 64 << 20);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, config.input, rv.ethereum_contract.INPUT_CAPACITY_MAX - 4);
    defer a.free(input);
    try Config.pin(elf, config.elf_sha256);
    try Config.pin(input, config.input_sha256);
    var loaded = try rv.ethereum_contract.load(a, config.symbols, elf, input);
    defer loaded.deinit();
    var session = try rv.ethereum_services.Session.initWithProfile(a, rv.machine.Cpu.init(loaded.info.entry, config.symbols.stack_top), &loaded.memory, .{ .max_retirements = N }, .ethereum_services_op_v1);
    defer session.deinit();
    const cpu = &session.keccak.base.cpu;
    try std.testing.expectEqual(endpoint.initial_pc, cpu.pc);
    try std.testing.expectEqualDeep(endpoint.initial_registers, cpu.regs);
    var tape = try rv.compact_tape.Tape.init(a, N, cpu.pc, cpu.retired, .ethereum_services_op_v1);
    defer tape.deinit();
    var boundary = front.rv64_air.word16_execution.types.Boundary{ .steps = 0, .initial_pc = cpu.pc, .final_pc = undefined, .initial_registers = cpu.regs, .final_registers = undefined, .register_clocks = @splat(0) };
    const execution_begin = timer.read();
    while (boundary.steps < N) {
        if (cpu.pc == config.terminal_pc) return error.PrefixCompletedUnexpectedly;
        var event: rv.ethereum_services.Event = undefined;
        const row = if (try session.step(&event)) |r| blk: {
            try tape.append(r);
            break :blk r;
        } else blk: {
            try tape.appendEvent(event);
            break :blk event.retirement();
        };
        const effects = rv.execution_profile.effects(.ethereum_services_op_v1, row.opcode);
        const tick: u32 = 4 * boundary.steps;
        if (effects.reads_rs1 and row.rs1 != 0) boundary.register_clocks[row.rs1] = tick + 1;
        if (effects.reads_rs2 and row.rs2 != 0) boundary.register_clocks[row.rs2] = tick + 2;
        if (effects.writes_rd and row.rd != 0) boundary.register_clocks[row.rd] = tick + 3;
        boundary.steps += 1;
    }
    boundary.final_pc = cpu.pc;
    boundary.final_registers = cpu.regs;
    try std.testing.expectEqual(endpoint.final_pc, cpu.pc);
    try std.testing.expectEqualDeep(endpoint.final_registers, cpu.regs);
    const execution_ns = timer.read() - execution_begin;
    var native = try Prepared.captureForOpServices(a, &program, boundary, 1, try Coverage.minimalCpuLog(N), &tape, .{ .deduplicate_shift = true });
    defer native.deinit();
    var builder = Collector.Builder.init(a, Memory.fromOwner(&image));
    defer builder.deinit();
    try builder.append(&native, &tape);
    var advice = try builder.finish();
    defer advice.deinit();
    native.cpu.?.releaseCaptureRecords();
    const natives = [_]*Prepared{&native};
    var declaration = try Plan.cpuForSegment(&native, &advice, 0, 2, advice.initial.len, Plan.CpuLayout.forOpGkr());
    declaration.bridges.sponge = .{};
    declaration.geometry.terminal_log = 5;
    var request = try Coordinator.requestView(&natives, &advice, 0);
    request.base.memory.terminal = &.{};
    try Coordinator.routeDword(&request, declaration.bridges, advice.events[0]);
    var requests = [_]@TypeOf(request){request};
    try Coordinator.assignSpongeIds(&requests);
    request = requests[0];
    const span = Types.OpTowerSpan{};
    if (advice.tower[0].len != 0) return error.PrefixTowerRequiresExplicitModel;
    const frontier_log = try Coverage.minimalPrefixLog(request.sponge.calls);
    const DG = @import("../sponge_local_gkr/authority.zig").Geometry;
    const detached = [_]DG{.{ .calls = request.sponge.calls, .permutations = request.sponge.perms, .first_id = request.calls[0] + 1, .detached = true }};
    var totals = request.calls;
    totals[0] += request.sponge.perms;
    const truths = try Plan.truthsForServiceCounts(a, totals, .{ .v3 = true }, 16);
    defer a.free(truths);
    var bounds = try Bounds.deriveForOpDetached(a, program.log_size, &.{declaration}, truths, &.{request}, &.{span}, &.{}, &.{frontier_log}, if (request.sponge.calls == 0) &.{} else &detached);
    defer bounds.deinit();
    const checked = try Security.preflight(Profile, &bounds, &.{}, &.{});
    const capture_ns = timer.read() - image_program_ns;
    // Wide keys are constructed only after source field-mass/security admission.
    var metadata = try @import("../../word16_execution/program_metadata.zig").Cache.init(a, 256 << 20);
    defer metadata.deinit();
    var setup = try @import("../pure_p2_op_source_setup.zig").init(a, &image, declaration, &metadata);
    defer setup.deinit();
    var roster = try Frame.Roster.init(a, &setup, request.sponge.calls, frontier_log, 1, 0);
    defer roster.deinit();
    var numerical = E.lookups.resource.ForField(C.fields.om31.OM31).Plan{};
    var facts: usize = 0;
    for (roster.instances) |instance| {
        facts = try std.math.add(usize, facts, try instance.facts());
        try numerical.add(.{ .kind = .multiplicities, .variables = try instance.variables() });
    }
    try numerical.finish();
    const child_floor = try std.math.add(usize, facts * 52, numerical.metadata_bytes + 65536);
    if (child_floor > 12 << 30) return error.ConditionalPrefixGkrBudget;
    var part_plan = try @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Plan.initForOp(a, &setup);
    defer part_plan.deinit();
    const fixed_logs = try setup.logs(a, 0);
    defer a.free(fixed_logs);
    const main_logs = try setup.logs(a, 1);
    defer a.free(main_logs);
    const inter_logs = try part_plan.interLogs(a);
    defer a.free(inter_logs);
    var init_fixed: u64 = 0;
    var init_main: u64 = 0;
    var init_inter: u64 = 0;
    for (@import("../../word16_execution/geometry.zig").shapesForProgramLog(program.log_size, declaration.geometry)) |shape| if (shape.role == .initial) {
        init_fixed = @as(u64, @intCast(shape.widths[0])) << @intCast(shape.log);
        init_main = @as(u64, @intCast(shape.widths[1])) << @intCast(shape.log);
    };
    for (part_plan.slots, 0..) |slot, i| if (slot.origin == .core and slot.origin.core == .initial) {
        const end = if (i + 1 < part_plan.slots.len) part_plan.slots[i + 1].inter_offset else part_plan.inter_columns;
        init_inter = @as(u64, @intCast(end - slot.inter_offset)) << @intCast(slot.log);
    };
    const plan_at = timer.read();
    const plan_info = .{ .schema = "op-heavy-conditional-prefix-plan/v1", .steps = N, .final_pc = boundary.final_pc, .final_registers = boundary.final_registers, .cpu = declaration, .request = @import("../../word16_global_execution/services/wire.zig").CompactRequest.from(request), .init_words = advice.initial.len, .terminal_words_proved = 0, .init_fixed_cells = init_fixed, .init_main_cells = init_main, .init_interaction_cells = init_inter, .planned_unproved_truths = truths, .unproved_detached = if (request.sponge.calls == 0) @as(usize, 0) else 1, .gkr_facts = facts, .gkr_checkpoint_floor_bytes = child_floor, .fixed_cells = cells(fixed_logs) + 3 * (@as(u64, 1) << @intCast(frontier_log)), .main_cells = cells(main_logs) + 8 * (@as(u64, 1) << @intCast(frontier_log)), .interaction_cells_excluding_frontier = cells(inter_logs), .image_program_ns = image_program_ns, .execution_ns = execution_ns, .capture_prepare_ns = capture_ns, .through_setup_ns = plan_at, .security = checked, .init_scope = "prefix-touched cells only, not full-block touched set", .conditional_cpu_fragment_only = true, .block_accepted = false, .root_accepted = false };
    try json(a, dir, if (prove) "prove-plan.json" else "plan.json", plan_info);
    std.debug.print("OP_HEAVY_PREFIX_PLAN steps={} CPUlog={} facts={} child_floor={} INIT={} services={any} sponge={any} mass_admitted=true block_accepted=false\n", .{ N, declaration.geometry.cpu_log, facts, child_floor, advice.initial.len, request.calls, request.sponge });
    if (!prove) return;
    var key = try Key.init(a, &setup, Profile, frontier_log);
    defer key.deinit();
    // Independently recompute the source key before retiring source FIXED.
    var fresh = try Key.initDigest(a, &setup, Profile, frontier_log);
    defer fresh.deinit();
    try @import("../pure_p2_op_source_setup.zig").retireLegacy(a, &setup);
    const first: [Types.FAMILIES]u32 = @splat(1);
    const Prof = @import("stwo_prover_api").stage_profile;
    var recorder = Prof.Recorder.initWithOptions(a, "cpu", "heavy conditional 4M CPU fragment", .{ .capture_tasks = false, .capture_process_usage = true });
    defer recorder.deinit();
    var source = try Pipeline.buildCpuSourceForOp(a, &setup, request, span, &native, &advice, 0, first, false, &recorder);
    var source_owned = true;
    defer if (source_owned) source.deinit();
    var frontier = try Source.initCalls(a, advice.sponge[0].calls, request.sponge.calls, frontier_log, 1, 0);
    var frontier_owned = true;
    defer if (frontier_owned) frontier.deinit();
    var worker = try Worker.Worker.init(a, &setup, request, span, first, 0, &key, source, frontier, .{ .gkr_bytes = 12 << 30, .global_bytes = 2 << 30 });
    source_owned = false;
    frontier_owned = false;
    defer worker.deinit();
    worker.native_recorder = &recorder;
    const seal_begin = timer.read();
    const stage = try worker.seal();
    const sealed_at = timer.read();
    // A conditional experiment challenge, NOT a complete execution manifest.
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("op-conditional-heavy-prefix/v1");
    h.update(&key.identity);
    h.update(&worker.expected.statement);
    h.update(&stage.main);
    h.update(&stage.receipt);
    const digest = h.finalResult();
    var manifest_words: [16]C.fields.m31.M31 = undefined;
    for (&manifest_words, 0..) |*word, i| word.* = C.fields.m31.M31.fromCanonical(std.mem.readInt(u16, digest[i * 2 ..][0..2], .little));
    const manifest = Protocol.W.H.hashNode(null, &manifest_words);
    var encoded = try worker.complete(manifest);
    defer encoded.deinit(a);
    const proved_at = timer.read();
    try Write(dir, "cpu.pcs.bin", encoded.bytes);
    try Write(dir, "cpu.gkr.bin", encoded.local);
    // Source-only fresh key, never the producer key, verifies this fragment.
    const verify_at = timer.read();
    const debt = try Worker.verify(a, &setup, request, span, first, 0, &fresh, manifest, stage.main, &encoded);
    if (debt.ram.isZero() and debt.kio.isZero() and debt.wire.isZero()) return error.ConditionalDebtUnexpectedlyClosed;
    var profile = try recorder.snapshot(a);
    defer profile.deinit(a);
    try json(a, dir, "stages.json", profile);
    try json(a, dir, "fragment.json", .{ .schema = "op-heavy-conditional-cpu-fragment/v1", .steps = N, .key_identity = key.identity, .manifest = manifest, .stage = stage, .pcs_bytes = encoded.bytes.len, .gkr_bytes = encoded.local.len, .claims = encoded.claims, .outstanding_global_debt = debt, .seal_ns = sealed_at - seal_begin, .complete_ns = proved_at - sealed_at, .fresh_verify_ns = timer.read() - verify_at, .full_elapsed_ns = timer.read(), .conditional_fragment_verified = true, .complete_execution_accepted = false, .root_accepted = false, .owed = "truth KIO/Wire, detached sponge, end memory, remaining CPU execution; not a block proof" });
    std.debug.print("OP_HEAVY_PREFIX_PHYSICAL pcs={} GKR={} seal_ns={} complete_ns={} conditional_fragment_only=true block_accepted=false\n", .{ encoded.bytes.len, encoded.local.len, sealed_at - seal_begin, proved_at - sealed_at });
}
test "OP heavy selected conditional 4M CPU fragment profile" {
    const path = std.posix.getenv("STWO_OP_HEAVY_PREFIX_CONFIG") orelse return error.SkipZigTest;
    const oracle = std.posix.getenv("STWO_OP_HEAVY_PREFIX_ORACLE") orelse return error.MissingPrefixOracle;
    const out = std.posix.getenv("STWO_OP_HEAVY_PREFIX_OUT") orelse return error.MissingPrefixOutput;
    const mode = std.posix.getenv("STWO_OP_HEAVY_PREFIX_MODE") orelse "plan";
    // Optional qualification-only control; default fixture behavior is exact.
    // Existing real two-CPU/serialized-sponge/Keccak join independently closes
    // all global relations before the separate conditional large CPU fragment.
    if (std.process.hasEnvVarConstant("STWO_OP_PREFIX_SMALL_JOIN_CONTROL")) {
        try @import("join_test.zig").exerciseWithHook(false, void);
    }
    const a = std.testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(a, path, 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Config.Config, a, raw, .{});
    defer config.deinit();
    const ref = try std.fs.cwd().readFileAlloc(a, oracle, 16384);
    defer a.free(ref);
    const endpoint = try std.json.parseFromSlice(Endpoint, a, ref, .{ .ignore_unknown_fields = true });
    defer endpoint.deinit();
    var dir = try std.fs.cwd().openDir(out, .{});
    defer dir.close();
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    {
        var pool: E.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 16 });
        defer pool.deinit();
        var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        try run(budget.allocator(), config.value, endpoint.value, dir, std.mem.eql(u8, mode, "prove"));
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    try json(a, dir, if (std.mem.eql(u8, mode, "prove")) "prove-budget.json" else "plan-budget.json", budget.snapshot());
    std.debug.print("OP_HEAVY_PREFIX_DONE peak={} cap={} live=0 external=0\n", .{ budget.snapshot().peak_live_bytes, @as(usize, 32) << 30 });
}
