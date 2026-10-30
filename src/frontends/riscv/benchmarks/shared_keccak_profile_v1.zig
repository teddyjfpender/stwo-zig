//! Daily shared-Keccak execution profiling. Builds one shared caller inventory
//! from complete native windows; every source is closed by one original STARK.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../runner/mod.zig");
const Union = @import("../prover/block_v7_keccak_union_proof_v1.zig");
const Scope = @import("../prover/block_v7_keccak_union_scope_v1.zig");
const Receiver = @import("../prover/block_v7_execution_receiver_v1.zig");
const Native = @import("../prover/block_v7_native_proof_v1.zig");
const Batch = @import("../prover/block_v7_keccak_batch_proof_v1.zig");
const BatchSource = @import("../prover/block_v7_keccak_batch_source_v1.zig");
const ROM = @import("../prover/block_v7_program_provider_v1.zig");
const Lookup = @import("../prover/block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("../prover/block_v7_memory_joint_proof_v1.zig");
const Epoch = @import("../prover/block_v7_execution_epoch_v1.zig");
const Support = @import("../prover/block_v7_execution_test_support.zig");
const Guest = @import("../prover/tests/block_v7_scaling_guest_test_support.zig");
const LP = @import("../prover/block_v5_native_lookup_plan_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const MAX_WINDOWS = 16;
const StageScope = Engine.stage_profile.StageScope;
const Workloads = @import("ethereum_workloads_v1.zig");

pub fn run() !void {
    const benchmark = std.process.hasEnvVarConstant("STWO_V7_BENCHMARK");
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(if (benchmark) std.heap.smp_allocator else std.testing.allocator, 24 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var recorder = Engine.stage_profile.Recorder.initWithOptions(a, "cpu", "ethereum_multiwindow", .{ .capture_tasks = false });
    defer recorder.deinit();
    const recording = if (benchmark) &recorder else null;
    var request_stage = try StageScope.begin(recording, "request", "Input to independently verified proof");
    defer request_stage.end();
    var whole = try std.time.Timer.start();
    var load_stage = try StageScope.begin(recording, "input_loading", "Construct or load independently specified workload input");
    defer load_stage.end();
    const requested_cut = try option(a, "STWO_V7_MULTI_UNION_CUT", 0);
    const iterations = try option(a, "STWO_V7_MULTI_UNION_ITERATIONS", 1);
    if (std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_ISOLATE_CALLERS")) return error.SharedKeccakUnsupportedIsolation;
    if (std.posix.getenv("STWO_V7_MULTI_UNION_CUT") != null and requested_cut == 0) return error.InvalidMultiUnionFixtureCut;
    const kind_text = std.posix.getenv("STWO_V7_BENCH_WORKLOAD") orelse "keccak_heavy";
    if (!std.mem.eql(u8, kind_text, "keccak_heavy")) return error.SharedKeccakUnsupportedWorkload;
    var workload: ?Workloads.Owned = if (std.mem.eql(u8, kind_text, "legacy")) null else try Workloads.make(std.meta.stringToEnum(Workloads.Kind, kind_text) orelse return error.UnknownBenchmarkWorkload, iterations);
    const code = if (workload == null) try Guest.instructions(iterations) else try Guest.instructions(1);
    const legacy_elf = Guest.releaseElf(&code);
    const elf: []const u8 = if (workload) |*w| &w.elf else &legacy_elf;
    const cycles = if (workload) |w| w.cycles else try Guest.cycles(iterations);
    const output = if (workload) |w| w.output else try Guest.output(iterations);
    const desired_windows = try option(a, "STWO_V7_BENCH_WINDOWS", 4);
    if (desired_windows < 2 or desired_windows > MAX_WINDOWS) return error.InvalidBenchmarkWindowCount;
    const cut: u32 = if (requested_cut != 0) requested_cut else if (benchmark) @intCast(try std.math.divCeil(u64, cycles, desired_windows)) else 7;
    load_stage.end();
    const ConfigProfile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
    const selected: ConfigProfile = if (std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0;
    const config = selected.config();
    const native_cache_mib = try option(a, "STWO_V7_NATIVE_MAIN_CACHE_MIB", 256);
    if (native_cache_mib > 2048) return error.InvalidV7QuotientCacheBudget;
    const deep_group_mib = try option(a, "STWO_PCS_DEEP_GROUP_MIB", 1);
    const deep_group_budget = try Engine.pcs.DeepGroupBudget.parseMiB(deep_group_mib);
    const workers = try option(a, "STWO_V7_BENCH_WORKERS", 4);
    if (workers == 0 or workers > Engine.work_pool.MAX_WORKERS) return error.InvalidBenchmarkWorkerCount;
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var initialization = try StageScope.begin(recording, "initialization", "ELF initialization, ROM and runner setup");
    defer initialization.end();
    var initial = try @import("../prover/block_v7_initial_intervals_v1.zig").Owned.derive(a, elf, @import("../prover/block_v5_initial_sources_v1.zig").sha256(elf), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    var image = try @import("../prover/block_v7_program_image_v1.zig").Owned.init(a, elf, &initial, .{});
    defer image.deinit();
    const policy = @import("../prover/block_v7_execution_policy_v1.zig").Policy{ .initialized = &initial, .program_root = image.root.bytes, .terminal = .{ .final_cycle = cycles, .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = output }, .config = config };
    const trusted = Receiver.Trusted{ .elf = elf, .elf_sha256 = initial.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = config };
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    var session_live = true;
    defer if (session_live) session.deinit();
    var counters = try @import("../air/lookups/tables/counter.zig").Set.init(a);
    var counters_live = true;
    defer if (counters_live) counters.deinit(a);
    const runs = try a.alloc(Runner.EthereumShaSegmentResult, MAX_WINDOWS);
    defer a.free(runs);
    var run_count: usize = 0;
    defer for (runs[0..run_count]) |*execution| execution.deinit();
    const segments = try a.alloc(Support.Segment, MAX_WINDOWS);
    defer a.free(segments);
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    var records: std.ArrayList(@import("../runner/guest_precompile/keccakf_call_buffer.zig").Record) = .empty;
    defer records.deinit(a);
    var batch_windows: std.ArrayList(BatchSource.Window) = .empty;
    defer batch_windows.deinit(a);
    const shapes = try a.alloc(Shape, MAX_WINDOWS);
    defer a.free(shapes);
    const native_pins = try a.alloc(Native.Pin, MAX_WINDOWS);
    defer a.free(native_pins);
    const native_stages = try a.alloc(Union.NativeStage, MAX_WINDOWS);
    defer a.free(native_stages);
    var guest: std.ArrayList(Event) = .empty;
    defer guest.deinit(a);
    const multiplicities = try a.alloc(u64, image.leaves.len / 4);
    defer a.free(multiplicities);
    @memset(multiplicities, 0);
    var demand: [6]u64 = @splat(0);
    var fetches: u64 = 0;
    var executed: u64 = 0;
    var continuation: ?@import("../runner/result.zig").ContinuationToken = null;
    initialization.end();
    while (true) {
        if (run_count == MAX_WINDOWS) return error.MultiUnionFixtureWindowLimit;
        const i = run_count;
        const window_cut = cut;
        var execution_stage = try StageScope.begin(recording, "execution", "Execute one native window");
        defer execution_stage.end();
        runs[i] = if (continuation) |token| try session.resumeSegment(token, window_cut) else try session.startSegment(window_cut);
        run_count += 1;
        execution_stage.end();
        var witness_stage = try StageScope.begin(recording, "witness_and_first_commitments", "Native and caller witnesses, source commitments and event collection");
        defer witness_stage.end();
        const execution = &runs[i];
        continuation = execution.base.continuation;
        executed = try std.math.add(u64, executed, execution.base.cycle_count);
        const external = try @import("../prover/block_v5_cpu_execution_source_v1.zig").externalCount(execution);
        segments[i] = try Support.Segment.initProfiled(a, &execution.base, config, image.root.bytes, @intCast(i), .rv32im_zkvm_ethereum_sha_v1, external, &counters, .{ .max_slots = 100, .max_witness_cells = 16 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 }, recording);
        segment_count += 1;
        const segment = &segments[i];
        shapes[i] = segment.owner.statement;
        shapes[i].public_data.io_entries.input_words = &.{};
        shapes[i].public_data.io_entries.output_words = &.{};
        native_pins[i] = segment.pin;
        native_pins[i].shape = &shapes[i];
        native_stages[i] = .{ .allocator = a, .first = &segment.first, .owner = segment.owner, .inputs = segment.source.inputs };
        try collectEvents(a, &guest, segment.source.inputs);
        try LP.addDemand(&demand, try LP.nativeDemand(&shapes[i], external));
        try LP.addDemand(&demand, try LP.sidecarMemoryDemand(native_pins[i].expected_events));
        const program = @import("../air/program/commitment.zig");
        const rows = try program.declaredRows(a, program.DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_sha_v1 }, .{ execution.base.execution_trace.rows.items, execution.extension.keccakf_execution_rows.rows(), execution.extension.signer_recovery_execution_rows.rows(), execution.extension.sha_calls.records() }, execution.base.rw_memory.program_words, @import("../prover/commitment_program_witness.zig").completionFetch(segment.io.data.completion));
        defer a.free(rows);
        for (rows) |row| {
            if (row.multiplicity == 0) continue;
            const base = initial.info.memory_layout.program_base;
            if (row.addr < base or row.addr & 3 != 0 or (row.addr - base) / 4 >= multiplicities.len) return error.BadActualFetch;
            const at = (row.addr - base) / 4;
            multiplicities[at] = try std.math.add(u64, multiplicities[at], row.multiplicity);
            fetches = try std.math.add(u64, fetches, row.multiplicity);
        }
        if (external != 0) {
            const calls = execution.extension.keccakf_calls.records();
            if (calls.len != external or execution.extension.signer_recovery_calls.records().len != 0 or execution.extension.sha_calls.records().len != 0) return error.SharedKeccakUnsupportedCall;
            try records.appendSlice(a, calls);
            try batch_windows.append(a, .{ .execution_index = @intCast(i), .native_identity = (try native_pins[i].entry(a)).identity, .frame = native_pins[i].frame, .calls = external });
        }
        if (continuation == null) {
            try std.testing.expectEqual(.halt_flag, execution.base.completion_reason);
            try std.testing.expectEqualSlices(u8, &output, execution.base.output.?);
            break;
        }
    }
    try std.testing.expectEqual(cycles, executed);
    try std.testing.expect(segment_count > 1);
    try std.testing.expectEqual(cycles + segment_count - 1, fetches);
    const windows = segment_count;
    const callers = batch_windows.items.len;
    if (callers == 0 or records.items.len == 0) return error.EmptySharedKeccakBatch;
    var batch_stage_profile = try StageScope.begin(recording, "shared_keccak_preparation", "Shared caller arithmetic, byte witnesses and first commitments");
    defer batch_stage_profile.end();
    try @import("../prover/block_v7_keccak_window_lookup_v1.zig").register(a, records.items, &counters);
    const batch = try Batch.ForBackend(Cpu).Stage.init(a, records.items, batch_windows.items, 0, config, counters.get(.range_check_8_8), .{});
    var batch_live = true;
    defer if (batch_live) batch.deinit();
    const batch_setup = batch.timings;
    var batch_pin = batch.pin;
    batch_pin.windows = batch_windows.items;
    try LP.addDemand(&demand, try @import("../prover/block_v7_keccak_execution_receiver_v1.zig").batchDemand(a, batch_pin, .{}));
    for (1..51) |slot| {
        const view = try batch.memory.view(slot);
        for (0..view.domainSize()) |row_index| {
            const row = try view.row(row_index);
            if (row.active) try guest.append(a, try @import("../prover/block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
        }
    }
    const expected_events = guest.items.len;
    batch_stage_profile.end();
    var providers_stage = try StageScope.begin(recording, "provider_preparation", "ROM, lookup, sorted memory and source commitments");
    defer providers_stage.end();
    const plan = @import("../prover/block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = fetches, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
    var rom_first = try ROM.ForBackend(Cpu).commit(a, plan, config);
    var rom_live = true;
    defer if (rom_live) rom_first.deinit(a);
    const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(windows), .max_requests = demand };
    var lookup_first = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, config, null, .{});
    var lookup_live = true;
    defer if (lookup_live) lookup_first.deinit();
    const coefficient_inputs = std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_COEFFICIENT_INPUTS");
    const consume_memory = std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_CONSUME_MEMORY");
    const compact_admission = std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_COMPACT_ADMISSION");
    const benchmark_event_limit: usize = 1 << 20;
    const requested_events_per_shard = if (benchmark) @max(@as(usize, 4096), try std.math.divCeil(usize, guest.items.len + @import("../prover/block_v7_terminal_protocol_v1.zig").READS, 8)) else if (iterations == 1) @as(usize, 64) else 4096;
    const events_per_shard: u32 = @intCast(try std.math.ceilPowerOfTwo(usize, requested_events_per_shard));
    var joint_limits: Joint.Limits = .{};
    if (benchmark) joint_limits.memory.max_events = benchmark_event_limit;
    joint_limits.input_storage = if (coefficient_inputs) .{ .coefficients = .{ .minimum_trace_log = 4 } } else .resident;
    joint_limits.interaction_storage = if (std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_COEFFICIENT_INTERACTION")) .{ .coefficients = .{ .minimum_trace_log = 4 } } else .resident;
    joint_limits.ram_quotient = .{ .bounded_tiles = .{ .minimum_trace_log = if (std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_RAM_TILES")) 4 else 18 } };
    const memory = try Joint.For(Cpu).Stage.init(a, policy, guest.items, 0, events_per_shard, joint_limits);
    var memory_live = true;
    defer if (memory_live) memory.deinit();
    if (coefficient_inputs) {
        for (memory.scheme.trees.items) |tree| {
            try std.testing.expect(tree.compact_polynomials);
            for (tree.columns) |column| try std.testing.expectEqual(@as(usize, 0), column.values.len);
        }
        std.debug.print("V7_MULTI_MEMORY_INPUTS coefficient_backed=true input_lde_cells_retained=0 charged_live_bytes={d}\n", .{memory.budget.snapshot().live_bytes});
    }
    const entries = try a.alloc(Epoch.Entry, windows + 4);
    defer a.free(entries);
    for (native_pins[0..windows], entries[0..windows]) |pin, *entry| entry.* = try pin.entry(a);
    entries[windows] = try batch_pin.entry(a, native_pins[0..windows], .{});
    entries[windows + 1] = try ROM.firstEntry(plan, rom_first.roots);
    entries[windows + 2] = try lookup_first.entry();
    entries[windows + 3] = try memory.entry();
    var counts: Epoch.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, entries, entries.len);
    const geometries = try a.alloc(@import("../prover/block_v5_ram_lanes_protocol_v1.zig").Claim, memory.witness.ram.len);
    defer a.free(geometries);
    for (geometries, memory.witness.ram) |*g, item| g.* = item.geometry;
    const input = Scope.Input{ .epoch = epoch, .entries = entries, .natives = native_pins[0..windows], .batches = &.{batch_pin}, .program_plan = plan, .program_roots = rom_first.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup_first.layout, .lookup_roots = lookup_first.roots, .memory_roots = memory.roots, .memory_geometry = geometries, .interval_log = memory.witness.interval.log };
    const limits = Scope.Limits{ .max_retained_pcs_bytes = 8 << 30, .max_windows = MAX_WINDOWS, .max_trace_trees = 128, .receiver = .{ .joint_memory = joint_limits } };
    const admitted = try Scope.Owned.init(a, trusted, input, limits);
    const expected_trees = admitted.placement.trace_trees + 1;
    admitted.deinit();
    providers_stage.end();
    const setup_ns = whole.read();
    var timer = try std.time.Timer.start();
    var producer_stats: Union.ProducerStats = .{};
    var proof = try Union.proveWithOptions(a, trusted, input, .{ .natives = native_stages[0..windows], .batches = &.{batch}, .program = &rom_first, .program_allocator = a, .lookup = &lookup_first, .memory = memory }, &pool, limits, .{ .consume_memory_producer = consume_memory, .compact_storage_admission = compact_admission, .stats = &producer_stats, .recorder = recording, .native_main_cache_bytes = @as(usize, native_cache_mib) * 1024 * 1024, .deep_group_budget = deep_group_budget });
    defer proof.deinit(a);
    const prove_ns = timer.read();
    var destruction_stage = try StageScope.begin(recording, "producer_destruction", "Destroy all source producers before independent verification");
    defer destruction_stage.end();
    batch.deinit();
    batch_live = false;
    for (segments[0..segment_count]) |*segment| segment.deinit();
    segment_count = 0;
    for (runs[0..run_count]) |*execution| execution.deinit();
    run_count = 0;
    session.deinit();
    session_live = false;
    counters.deinit(a);
    counters_live = false;
    rom_first.deinit(a);
    rom_live = false;
    lookup_first.deinit();
    lookup_live = false;
    memory.deinit();
    memory_live = false;
    destruction_stage.end();
    var serialization_stage = try StageScope.begin(recording, "serialization", "Encode canonical public proof envelope");
    defer serialization_stage.end();
    const Codec = @import("../prover/block_v7_keccak_union_codec_v1.zig");
    const transport = try Codec.encode(a, proof.view(), input, .{ .scope = limits });
    defer a.free(transport);
    serialization_stage.end();
    timer.reset();
    var verification_stage = try StageScope.begin(recording, "independent_verification", "Decode and verify original proof after producer destruction");
    defer verification_stage.end();
    const actual = try Codec.verifyBytes(a, transport, trusted, input, .{ .scope = limits });
    const verify_ns = timer.read();
    verification_stage.end();
    try std.testing.expectEqual(cycles, actual.cycles);
    try std.testing.expectEqualDeep(output, actual.output);
    try std.testing.expectEqual(@as(u32, @intCast(windows)), actual.segments);
    try std.testing.expectEqual(@as(u64, expected_events), actual.ram_events);
    try std.testing.expectEqual(fetches, actual.program_fetches);
    try std.testing.expectEqual(expected_trees, proof.stark.commitment_scheme_proof.commitments.items.len);
    const end_to_end_ns = whole.read();
    const rss = try @import("../prover/block_v4_cpu_cli_rss_v1.zig").peakBytes();
    request_stage.end();
    if (std.posix.getenv("STWO_V7_BENCH_REPORT")) |path| {
        var profile = try recorder.snapshot(a);
        defer profile.deinit(a);
        const report = try std.json.Stringify.valueAlloc(a, .{
            .schema = 1,
            .allocator_backend = if (benchmark) "smp" else "testing",
            .worker_count = workers,
            .native_main_cache_mib = native_cache_mib,
            .deep_group_mib = deep_group_mib,
            .workload = kind_text,
            .iterations = iterations,
            .cycles = cycles,
            .window_cut = cut,
            .native_windows = windows,
            .caller_windows = callers,
            .ram_events = expected_events,
            .memory_event_limit = joint_limits.memory.max_events,
            .events_per_ram_shard = events_per_shard,
            .keccak_calls = if (workload) |w| @as(?u32, w.keccak_calls) else null,
            .recovery_calls = if (workload) |w| @as(?u32, w.recovery_calls) else null,
            .first_touch_native_words = if (workload) |w| @as(?u32, w.native_ram_words) else null,
            .native_rounds_per_call = if (workload) |w| @as(?u32, w.native_rounds_per_call) else null,
            .elf_sha256 = std.fmt.bytesToHex(initial.elf_sha256, .lower),
            .canonical_security = selected == .csp_q70_pow26,
            .query_count = config.fri_config.n_queries,
            .pow_bits = config.pow_bits,
            .source = "synthetic_complete_execution",
            .program_fetches = fetches,
            .output_sha256 = std.fmt.bytesToHex(@import("../prover/block_v5_initial_sources_v1.zig").sha256(&output), .lower),
            .proof_contract = "original_complete_stark",
            .architecture = "shared_keccak",
            .shared_keccak_batches = @as(u32, 1),
            .shared_keccak_setup = batch_setup,
            .statement_sha256 = std.fmt.bytesToHex(actual.statement, .lower),
            .output_hex = std.fmt.bytesToHex(actual.output, .lower),
            .end_to_end_ns = end_to_end_ns,
            .setup_ns = setup_ns,
            .prove_ns = prove_ns,
            .verification_ns = verify_ns,
            .oracle_ns = @as(u64, 0),
            .oracle_enabled = false,
            .verified = true,
            .producers_destroyed = true,
            .recursive_reduction_ns = @as(?u64, null),
            .checkpoint_read_bytes = @as(u64, 0),
            .checkpoint_write_bytes = @as(u64, 0),
            .proof_bytes = transport.len,
            .proof_sha256 = std.fmt.bytesToHex(@import("../prover/block_v5_initial_sources_v1.zig").sha256(transport), .lower),
            .tracked_peak_bytes = budget.snapshot().peak_live_bytes,
            .process_peak_rss_bytes = rss,
            .producer_stats = producer_stats,
            .profile = profile,
        }, .{});
        defer a.free(report);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = report });
    }
}

fn collectEvents(a: std.mem.Allocator, out: *std.ArrayList(Event), inputs: anytype) !void {
    for (inputs) |input| for (0..input.trace.domainSize()) |i| {
        const row = try input.trace.row(i);
        if (row.active) try out.append(a, try @import("../prover/block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
    };
}
fn option(a: std.mem.Allocator, name: []const u8, default: u32) !u32 {
    const raw = std.process.getEnvVarOwned(a, name) catch return default;
    defer a.free(raw);
    return std.fmt.parseInt(u32, raw, 10);
}
