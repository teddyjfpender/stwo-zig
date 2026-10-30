//! Actual contiguous execution, same-epoch original-proof oracle, and fresh
//! verification after every runner/producer and original proof is destroyed.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../../runner/mod.zig");
const Union = @import("../block_v7_multi_union_proof_v1.zig");
const Scope = @import("../block_v7_multi_union_scope_v1.zig");
const Receiver = @import("../block_v7_execution_receiver_v1.zig");
const Native = @import("../block_v7_native_proof_v1.zig");
const Caller = @import("../block_v7_caller_active_proof_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("../block_v7_memory_joint_proof_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Witness = @import("../block_v5_precompile_witness_v1.zig").Witness;
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const CallerStatement = @import("../blake3_ethereum_sha_profile.zig").admission.Statement;
const CallerStage = Caller.ForBackend(Cpu).Stage;
const MAX_WINDOWS = 16;
const StageScope = Engine.stage_profile.StageScope;
const Workloads = @import("../../benchmarks/ethereum_workloads_v1.zig");

test "v7 multi union genuine contiguous original STARK with all-provider oracle" {
    if (std.process.hasEnvVarConstant("STWO_V7_BENCH_SHARED_KECCAK")) return @import("../../benchmarks/shared_keccak_profile_v1.zig").run();
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
    const isolate_callers = std.process.hasEnvVarConstant("STWO_V7_MULTI_UNION_ISOLATE_CALLERS");
    if (std.posix.getenv("STWO_V7_MULTI_UNION_CUT") != null and requested_cut == 0) return error.InvalidMultiUnionFixtureCut;
    const kind_text = std.posix.getenv("STWO_V7_BENCH_WORKLOAD") orelse "legacy";
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
    const ConfigProfile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
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
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, elf, @import("../block_v5_initial_sources_v1.zig").sha256(elf), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    var image = try @import("../block_v7_program_image_v1.zig").Owned.init(a, elf, &initial, .{});
    defer image.deinit();
    const policy = @import("../block_v7_execution_policy_v1.zig").Policy{ .initialized = &initial, .program_root = image.root.bytes, .terminal = .{ .final_cycle = cycles, .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = output }, .config = config };
    const trusted = Receiver.Trusted{ .elf = elf, .elf_sha256 = initial.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = config };
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    var session_live = true;
    defer if (session_live) session.deinit();
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    var counters_live = true;
    defer if (counters_live) counters.deinit(a);
    const runs = try a.alloc(Runner.EthereumShaSegmentResult, MAX_WINDOWS);
    defer a.free(runs);
    var run_count: usize = 0;
    defer for (runs[0..run_count]) |*run| run.deinit();
    const segments = try a.alloc(Support.Segment, MAX_WINDOWS);
    defer a.free(segments);
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    const witnesses = try a.alloc(Witness, MAX_WINDOWS);
    defer a.free(witnesses);
    var witness_count: usize = 0;
    defer for (witnesses[0..witness_count]) |*witness| witness.deinit();
    const caller_stages = try a.alloc(*CallerStage, MAX_WINDOWS);
    defer a.free(caller_stages);
    var caller_count: usize = 0;
    defer for (caller_stages[0..caller_count]) |stage| stage.deinit();
    const shapes = try a.alloc(Shape, MAX_WINDOWS);
    defer a.free(shapes);
    const caller_shapes = try a.alloc(CallerStatement, MAX_WINDOWS);
    defer a.free(caller_shapes);
    const native_pins = try a.alloc(Native.Pin, MAX_WINDOWS);
    defer a.free(native_pins);
    const caller_pins = try a.alloc(@import("../block_v7_caller_active_source_v1.zig").Pin, MAX_WINDOWS);
    defer a.free(caller_pins);
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
    var continuation: ?@import("../../runner/result.zig").ContinuationToken = null;
    var no_access: usize = 0;
    var physical_frames: usize = 0;
    initialization.end();
    while (true) {
        if (run_count == MAX_WINDOWS) return error.MultiUnionFixtureWindowLimit;
        const i = run_count;
        // The guest's first six instructions include SHA, Keccak, SHA.
        // Isolating them exercises a genuine zero-SHA caller and its complete
        // global lookup/memory closure without twenty one-instruction windows.
        const window_cut = if (isolate_callers and executed < 6) 1 else cut;
        var execution_stage = try StageScope.begin(recording, "execution", "Execute one native window");
        defer execution_stage.end();
        runs[i] = if (continuation) |token| try session.resumeSegment(token, window_cut) else try session.startSegment(window_cut);
        run_count += 1;
        execution_stage.end();
        var witness_stage = try StageScope.begin(recording, "witness_and_first_commitments", "Native and caller witnesses, source commitments and event collection");
        defer witness_stage.end();
        const run = &runs[i];
        continuation = run.base.continuation;
        executed = try std.math.add(u64, executed, run.base.cycle_count);
        const external = try @import("../block_v5_cpu_execution_source_v1.zig").externalCount(run);
        segments[i] = try Support.Segment.initProfiled(a, &run.base, config, image.root.bytes, @intCast(i), .rv32im_zkvm_ethereum_sha_v1, external, &counters, .{ .max_slots = 100, .max_witness_cells = 16 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 }, recording);
        segment_count += 1;
        const segment = &segments[i];
        shapes[i] = segment.owner.statement;
        shapes[i].public_data.io_entries.input_words = &.{};
        shapes[i].public_data.io_entries.output_words = &.{};
        native_pins[i] = segment.pin;
        native_pins[i].shape = &shapes[i];
        native_stages[i] = .{ .allocator = a, .first = &segment.first, .owner = segment.owner, .inputs = segment.source.inputs };
        no_access += @intFromBool((try native_pins[i].entry(a)).root_count == 2);
        physical_frames += @intFromBool(try @import("../block_v7_native_geometry_v1.zig").classify(&shapes[i], external) == .external_frame);
        try collectEvents(a, &guest, segment.source.inputs);
        try LP.addDemand(&demand, try LP.nativeDemand(&shapes[i], external));
        try LP.addDemand(&demand, try LP.sidecarMemoryDemand(native_pins[i].expected_events));
        const program = @import("../../air/program/commitment.zig");
        const rows = try program.declaredRows(a, program.DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_sha_v1 }, .{ run.base.execution_trace.rows.items, run.extension.keccakf_execution_rows.rows(), run.extension.signer_recovery_execution_rows.rows(), run.extension.sha_calls.records() }, run.base.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(segment.io.data.completion));
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
            const ci = caller_count;
            witnesses[ci] = try Witness.initSegment(a, run);
            witness_count += 1;
            const witness = &witnesses[ci];
            try (@import("../../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = run.extension.keccakf_calls.records(), .recovery = run.extension.signer_recovery_calls.records() }).register(&counters);
            try @import("../block_v7_caller_active_columns_v1.zig").registerLookup(a, witness, &counters);
            caller_stages[ci] = try CallerStage.initProfiled(a, witness, segment.pin.frame, @intCast(ci), config, counters.get(.range_check_8_8), recording);
            caller_count += 1;
            const caller = caller_stages[ci];
            caller_shapes[ci] = witness.statement;
            caller_pins[ci] = caller.pin(@intCast(i), (try native_pins[i].entry(a)).identity);
            caller_pins[ci].statement = &caller_shapes[ci];
            try collectEvents(a, &guest, caller.inputs);
            try @import("../block_v5_precompile_table_demand_v1.zig").add(a, &demand, &caller_shapes[ci], caller_pins[ci].total_steps, config);
            const access = try @import("../block_v5_memory_byte_demand_v1.zig").externalDemandForMode(&caller_shapes[ci], caller.schedule.memory, 1);
            try LP.addDemand(&demand, try LP.sidecarMemoryDemand(access.event_count));
        }
        if (continuation == null) {
            try std.testing.expectEqual(.halt_flag, run.base.completion_reason);
            try std.testing.expectEqualSlices(u8, &output, run.base.output.?);
            break;
        }
    }
    try std.testing.expectEqual(cycles, executed);
    try std.testing.expect(segment_count > 1);
    try std.testing.expectEqual(cycles + segment_count - 1, fetches);
    if (workload == null and iterations == 1 and cut == 7) {
        try std.testing.expectEqual(@as(usize, 3), segment_count);
        try std.testing.expectEqual(@as(usize, 1), caller_count);
        try std.testing.expect(no_access != 0);
    }
    if (workload == null and iterations == 1 and cut == 3) try std.testing.expect(physical_frames != 0);
    const windows = segment_count;
    const callers = caller_count;
    const expected_events = guest.items.len;
    var providers_stage = try StageScope.begin(recording, "provider_preparation", "ROM, lookup, sorted memory and source commitments");
    defer providers_stage.end();
    const plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = fetches, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
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
    const requested_events_per_shard = if (benchmark) @max(@as(usize, 4096), try std.math.divCeil(usize, guest.items.len + @import("../block_v7_terminal_protocol_v1.zig").READS, 8)) else if (iterations == 1) @as(usize, 64) else 4096;
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
    const entries = try a.alloc(Epoch.Entry, windows + callers + 3);
    defer a.free(entries);
    for (native_pins[0..windows], entries[0..windows]) |pin, *entry| entry.* = try pin.entry(a);
    for (caller_pins[0..callers], entries[windows..][0..callers]) |pin, *entry| entry.* = try pin.entry(a);
    entries[windows + callers] = try ROM.firstEntry(plan, rom_first.roots);
    entries[windows + callers + 1] = try lookup_first.entry();
    entries[windows + callers + 2] = try memory.entry();
    var counts: Epoch.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, entries, entries.len);
    const geometries = try a.alloc(@import("../block_v5_ram_lanes_protocol_v1.zig").Claim, memory.witness.ram.len);
    defer a.free(geometries);
    for (geometries, memory.witness.ram) |*g, item| g.* = item.geometry;
    const input = Scope.Input{ .epoch = epoch, .entries = entries, .natives = native_pins[0..windows], .callers = caller_pins[0..callers], .program_plan = plan, .program_roots = rom_first.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup_first.layout, .lookup_roots = lookup_first.roots, .memory_roots = memory.roots, .memory_geometry = geometries, .interval_log = memory.witness.interval.log };
    const limits = Scope.Limits{ .max_retained_pcs_bytes = 8 << 30, .max_windows = MAX_WINDOWS, .max_trace_trees = 128, .receiver = .{ .joint_memory = joint_limits } };
    const admitted = try Scope.Owned.init(a, trusted, input, limits);
    const expected_trees = admitted.placement.trace_trees + 1;
    const retained_estimate = admitted.retained.total_bytes;
    admitted.deinit();
    providers_stage.end();
    const setup_ns = whole.read();
    if (!benchmark and !coefficient_inputs) {
        const Census = @import("../block_v7_fixed_column_census_v1.zig");
        const sources = try a.alloc(Census.Source, windows + callers + 3);
        defer a.free(sources);
        for (native_stages[0..windows], sources[0..windows]) |stage, *source| source.* = .{ .columns = stage.first.scheme.trees.items[0].columns };
        for (caller_stages[0..callers], sources[windows..][0..callers]) |stage, *source| source.* = .{ .columns = stage.first.scheme.trees.items[0].columns };
        sources[windows + callers] = .{ .columns = rom_first.scheme.trees.items[0].columns };
        sources[windows + callers + 1] = .{ .columns = lookup_first.scheme.trees.items[0].columns };
        sources[windows + callers + 2] = .{ .columns = memory.scheme.trees.items[0].columns };
        var census = try Census.measure(a, sources, 65536);
        defer census.deinit();
        std.debug.print("V7_MULTI_FIXED_TOTAL {any}\n", .{census.total});
        for (census.sources, 0..) |stats, i| std.debug.print("V7_MULTI_FIXED_SOURCE index={d} {any}\n", .{ i, stats });
    } else std.debug.print("V7_MULTI_FIXED_TOTAL unavailable=coefficient_backed_inputs_no_census_reconstruction\n", .{});
    var producer_limits = limits;
    var expected_retained: ?u64 = null;
    if (compact_admission) {
        if (!coefficient_inputs) return error.CompactAdmissionFixtureRequiresCompactInputs;
        const model = try Scope.Owned.initForProducer(a, trusted, input, limits, .{ .memory_inputs = memory.limits.input_storage, .memory_interaction = memory.limits.interaction_storage });
        defer model.deinit();
        producer_limits.max_retained_pcs_bytes = @intCast(model.retained.total_bytes);
        expected_retained = model.retained.total_bytes;
        // The producer fits exactly its compact retained model; old materialized
        // admission at that same cap must reject. The receiver's cap is unchanged.
        try std.testing.expectError(error.MultiUnionRetainedPCSExceedsBudget, Scope.Owned.init(a, trusted, input, producer_limits));
    }
    if (std.process.hasEnvVarConstant("STWO_V7_NATIVE_DIAGNOSTIC")) {
        const diagnostics = try Union.diagnoseNativeClaims(a, trusted, input, .{ .natives = native_stages[0..windows], .callers = caller_stages[0..callers], .program = &rom_first, .program_allocator = a, .lookup = &lookup_first, .memory = memory }, &pool, producer_limits);
        defer Union.freeNativeClaimDiagnostics(a, diagnostics);
        const json = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .diagnostic_only = true, .verified = false, .workload = kind_text, .iterations = iterations, .cycles = cycles, .natives = diagnostics }, .{});
        defer a.free(json);
        const path = std.posix.getenv("STWO_V7_NATIVE_DIAGNOSTIC_OUTPUT") orelse "/tmp/v7-native-diagnostic.json";
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = json });
        std.debug.print("V7_NATIVE_DIAGNOSTIC only=true verified=false path={s}\n", .{path});
        return;
    }
    var timer = try std.time.Timer.start();
    var producer_stats: Union.ProducerStats = .{};
    var proof = try Union.proveWithOptions(a, trusted, input, .{ .natives = native_stages[0..windows], .callers = caller_stages[0..callers], .program = &rom_first, .program_allocator = a, .lookup = &lookup_first, .memory = memory }, &pool, producer_limits, .{ .consume_memory_producer = consume_memory, .compact_storage_admission = compact_admission, .stats = &producer_stats, .recorder = recording, .native_main_cache_bytes = @as(usize, native_cache_mib) * 1024 * 1024, .deep_group_budget = deep_group_budget });
    defer proof.deinit(a);
    const prove_ns = timer.read();
    if (expected_retained) |expected| {
        try std.testing.expect(producer_stats.compact_storage_admission);
        try std.testing.expectEqual(expected, producer_stats.retained_pcs_model_bytes);
    }
    const proof_peak_bytes = budget.snapshot().peak_live_bytes;
    std.debug.print("V7_MULTI_PRODUCER_MEMORY consumed={} {any}\n", .{ consume_memory, producer_stats });
    if (consume_memory) {
        try std.testing.expect(!memory.witness_live and !memory.owns_scheme);
        try std.testing.expectError(error.InvalidV7JointPhase, memory.prove(epoch, entries));
        try std.testing.expectError(error.InvalidV7JointPhase, memory.releaseProducerState());
    }
    var expected: ?Receiver.Verified = null;
    const with_oracle = !benchmark;
    timer.reset();
    if (with_oracle) {
        const originals = try a.alloc(Native.Proof, windows);
        defer a.free(originals);
        var ready: usize = 0;
        defer for (originals[0..ready]) |*p| p.deinit(a);
        const original_callers = try a.alloc(Caller.Proof, callers);
        defer a.free(original_callers);
        var callers_ready: usize = 0;
        defer for (original_callers[0..callers_ready]) |*p| p.deinit(a);
        const native_sources = try a.alloc(Receiver.Native, windows);
        defer a.free(native_sources);
        const caller_sources = try a.alloc(Receiver.ActiveCaller, callers);
        defer a.free(caller_sources);
        for (segments[0..windows], native_pins[0..windows], originals, native_sources, 0..) |*segment, pin, *p, *source, i| {
            p.* = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, pin, epoch, entries);
            ready += 1;
            source.* = .{ .pin = pin, .proof = p };
            try std.testing.expectEqualDeep(p.claims, proof.claims.native[i].claims);
            try std.testing.expectEqualDeep(p.memory_claims, proof.claims.native[i].access);
        }
        for (caller_stages[0..callers], caller_pins[0..callers], original_callers, caller_sources, 0..) |stage, pin, *p, *source, i| {
            p.* = try Caller.ForBackend(Cpu).prove(a, stage, pin, epoch, entries, &pool);
            callers_ready += 1;
            source.* = .{ .pin = pin, .proof = p };
            try std.testing.expectEqualDeep(p.arithmetic, proof.claims.callers[i].arithmetic);
            try std.testing.expectEqualDeep(p.relations, proof.claims.callers[i].relations);
        }
        var rom = try ROM.ForBackend(Cpu).prove(a, &rom_first, .{ .plan = plan, .expected_program_root = image.root, .roots = input.program_roots, .epoch = epoch, .entries = entries });
        defer rom.deinit(a);
        var lookup = try lookup_first.prove(epoch, entries);
        defer lookup.deinit(a);
        // Consuming production deliberately destroys the source witness. The
        // differential oracle reconstructs its own original memory Stage only
        // after the measured union proof, from the same execution events.
        const memory_oracle = if (consume_memory) try Joint.For(Cpu).Stage.init(a, policy, guest.items, 0, if (iterations == 1) 64 else 4096, .{}) else memory;
        defer if (consume_memory) memory_oracle.deinit();
        try std.testing.expectEqualDeep(entries[windows + callers + 2], try memory_oracle.entry());
        var mp = try memory_oracle.prove(epoch, entries);
        defer mp.deinit();
        try std.testing.expectEqualDeep(rom.claim, proof.claims.program);
        try std.testing.expectEqualDeep(lookup.claims, proof.claims.lookup);
        try std.testing.expectEqualDeep(mp.claims(), proof.claims.memory());
        expected = try Receiver.For(Cpu).verify(a, trusted, .{ .epoch = epoch, .entries = entries, .natives = native_sources, .active_callers = caller_sources, .program_plan = plan, .program_roots = input.program_roots, .program = &rom, .lookup_plan = lookup_plan, .lookup_roots = input.lookup_roots, .lookup = .{ .compact = .{ .layout = input.lookup_layout, .proof = &lookup } }, .memory = .{ .joint = &mp } }, .{});
    }
    const oracle_ns = if (with_oracle) timer.read() else 0;
    var destruction_stage = try StageScope.begin(recording, "producer_destruction", "Release all original producers and execution witnesses");
    defer destruction_stage.end();
    for (caller_stages[0..caller_count]) |stage| stage.deinit();
    caller_count = 0;
    for (witnesses[0..witness_count]) |*witness| witness.deinit();
    witness_count = 0;
    for (segments[0..segment_count]) |*segment| segment.deinit();
    segment_count = 0;
    for (runs[0..run_count]) |*run| run.deinit();
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
    const Codec = @import("../block_v7_multi_union_codec_v1.zig");
    const transport = try Codec.encode(a, proof.view(), input, .{ .scope = limits });
    defer a.free(transport);
    serialization_stage.end();
    timer.reset();
    var verification_stage = try StageScope.begin(recording, "independent_verification", "Decode and verify original proof after producer destruction");
    defer verification_stage.end();
    const actual = try Codec.verifyBytes(a, transport, trusted, input, .{ .scope = limits });
    const verify_ns = timer.read();
    verification_stage.end();
    if (expected) |oracle| try std.testing.expectEqualDeep(oracle, actual);
    try std.testing.expectEqual(cycles, actual.cycles);
    try std.testing.expectEqualDeep(output, actual.output);
    try std.testing.expectEqual(@as(u32, @intCast(windows)), actual.segments);
    try std.testing.expectEqual(@as(u64, expected_events), actual.ram_events);
    try std.testing.expectEqual(fetches, actual.program_fetches);
    try std.testing.expectEqual(expected_trees, proof.stark.commitment_scheme_proof.commitments.items.len);
    const end_to_end_ns = whole.read();
    const rss = try @import("../block_v4_cpu_cli_rss_v1.zig").peakBytes();
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
            .output_sha256 = std.fmt.bytesToHex(@import("../block_v5_initial_sources_v1.zig").sha256(&output), .lower),
            .proof_contract = "original_complete_stark",
            .architecture = "per_window_callers",
            .statement_sha256 = std.fmt.bytesToHex(actual.statement, .lower),
            .output_hex = std.fmt.bytesToHex(actual.output, .lower),
            .end_to_end_ns = end_to_end_ns,
            .setup_ns = setup_ns,
            .prove_ns = prove_ns,
            .verification_ns = verify_ns,
            .oracle_ns = oracle_ns,
            .oracle_enabled = with_oracle,
            .verified = true,
            .producers_destroyed = true,
            .recursive_reduction_ns = @as(?u64, null),
            .checkpoint_read_bytes = @as(u64, 0),
            .checkpoint_write_bytes = @as(u64, 0),
            .proof_bytes = transport.len,
            .proof_sha256 = std.fmt.bytesToHex(@import("../block_v5_initial_sources_v1.zig").sha256(transport), .lower),
            .tracked_peak_bytes = budget.snapshot().peak_live_bytes,
            .process_peak_rss_bytes = rss,
            .producer_stats = producer_stats,
            .profile = profile,
        }, .{});
        defer a.free(report);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = report });
    }
    if (!benchmark) try hostile(a, trusted, input, &proof, limits);
    var encoded = std.Io.Writer.Allocating.init(a);
    defer encoded.deinit();
    if (!benchmark) try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &encoded.writer, proof.stark);
    const stark_bytes = if (benchmark) std.mem.readInt(u64, transport[Codec.HEADER_BYTES - 8 ..][0..8], .little) else encoded.written().len;
    std.debug.print("V7_MULTI_UNION profile={s} cycles={d} cut={d} native_windows={d} callers={d} no_access={d} physical_frames={d} original_starks=1 oracle_starks={d} trees={d} estimated_trace_pcs_bytes={d} setup_ns={d} prove_ns={d} oracle_prove_verify_ns={d} fresh_verify_ns={d} proof_bytes={d} charged_proof_peak_bytes={d} all_producer_and_oracle_owners_destroyed=true exact_physical_claims={} global_closure=true timing=shared_host_diagnostic\n", .{ @tagName(selected), cycles, cut, windows, callers, no_access, physical_frames, if (with_oracle) windows + callers + 3 else 0, expected_trees, retained_estimate, setup_ns, prove_ns, oracle_ns, verify_ns, stark_bytes, proof_peak_bytes, with_oracle });
    if (std.posix.getenv("STWO_V7_MULTI_UNION_ARTIFACT_DIR")) |path| {
        try @import("block_v7_multi_union_wire_test_support.zig").save(a, path, proof.view(), trusted, input, limits, actual);
    }
}
fn collectEvents(a: std.mem.Allocator, out: *std.ArrayList(Event), inputs: anytype) !void {
    for (inputs) |input| for (0..input.trace.domainSize()) |i| {
        const row = try input.trace.row(i);
        if (row.active) try out.append(a, try @import("../block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
    };
}
fn option(a: std.mem.Allocator, name: []const u8, default: u32) !u32 {
    const raw = std.process.getEnvVarOwned(a, name) catch return default;
    defer a.free(raw);
    return std.fmt.parseInt(u32, raw, 10);
}
fn reject(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Scope.Input, proof: *const Union.Proof, limits: Scope.Limits) !void {
    if (Union.verify(a, trusted, input, proof, limits)) |_| return error.AcceptedMultiUnionForgery else |err| if (err == error.OutOfMemory) return err;
}
fn hostile(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Scope.Input, proof: *Union.Proof, limits: Scope.Limits) !void {
    const one = core.fields.qm31.QM31.one();
    const old_lookup = proof.claims.lookup;
    proof.claims.lookup[0] = old_lookup[0].add(one);
    proof.claims.lookup[1] = old_lookup[1].sub(one);
    try reject(a, trusted, input, proof, limits);
    proof.claims.lookup = old_lookup;
    if (proof.claims.callers.len != 0) {
        const old_sha = proof.claims.callers[0].arithmetic.sha;
        proof.claims.callers[0].arithmetic.sha[0] = old_sha[0].add(one);
        proof.claims.callers[0].arithmetic.sha[1] = old_sha[1].sub(one);
        try reject(a, trusted, input, proof, limits);
        proof.claims.callers[0].arithmetic.sha = old_sha;
    }
    const old_ram = proof.claims.ram[0];
    proof.claims.ram[0].sums[3] = old_ram.sums[3].add(one);
    proof.claims.ram[0].sums[4] = old_ram.sums[4].sub(one);
    try reject(a, trusted, input, proof, limits);
    proof.claims.ram[0] = old_ram;
    const source = proof.claims.native[0];
    proof.claims.native[0] = proof.claims.native[1];
    proof.claims.native[1] = source;
    try reject(a, trusted, input, proof, limits);
    proof.claims.native[1] = proof.claims.native[0];
    proof.claims.native[0] = source;
    var wrong = input;
    wrong.natives = input.natives[0 .. input.natives.len - 1];
    try reject(a, trusted, wrong, proof, limits);
    wrong = input;
    wrong.callers = &.{};
    try reject(a, trusted, wrong, proof, limits);
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    roots[0][0] ^= 1;
    try reject(a, trusted, input, proof, limits);
    roots[0][0] ^= 1;
    std.mem.swap([32]u8, &roots[1], &roots[2]);
    try reject(a, trusted, input, proof, limits);
    std.mem.swap([32]u8, &roots[1], &roots[2]);
    var bad = trusted;
    bad.terminal.output[0] ^= 1;
    try reject(a, bad, input, proof, limits);
    bad = trusted;
    bad.elf_sha256[0] ^= 1;
    try reject(a, bad, input, proof, limits);
    _ = try Union.verify(a, trusted, input, proof, limits);
}
