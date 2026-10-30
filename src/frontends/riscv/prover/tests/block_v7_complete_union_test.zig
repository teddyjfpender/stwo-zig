const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Union = @import("../block_v7_complete_union_proof_v1.zig");
const Receiver = @import("../block_v7_execution_receiver_v1.zig");
const Native = @import("../block_v7_native_proof_v1.zig");
const Caller = @import("../block_v7_caller_active_proof_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("../block_v7_memory_joint_proof_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;

// Same exact ELF generator as the 20,495-cycle recursive scaling campaign.
// Default is a small complete proof; larger run is an explicit experiment.
test "v7 complete union genuine one original proof and five proof oracle" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const iterations = value(a, "STWO_V7_COMPLETE_UNION_ITERATIONS", 1);
    const code = try Guest.instructions(iterations);
    const elf = Guest.releaseElf(&code);
    const cycles = try Guest.cycles(iterations);
    const output = try Guest.output(iterations);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
    const selected: Profile = if (std.process.hasEnvVarConstant("STWO_V7_COMPLETE_UNION_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0;
    const config = selected.config();
    var whole = try std.time.Timer.start();
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, &elf, @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    var image = try @import("../block_v7_program_image_v1.zig").Owned.init(a, &elf, &initial, .{});
    defer image.deinit();
    const policy = @import("../block_v7_execution_policy_v1.zig").Policy{ .initialized = &initial, .program_root = image.root.bytes, .terminal = .{ .final_cycle = cycles, .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = output }, .config = config };
    const trusted = Receiver.Trusted{ .elf = &elf, .elf_sha256 = initial.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = config };
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true });
    var session_live = true;
    defer if (session_live) session.deinit();
    var run = try session.startSegment(@intCast(cycles));
    var run_live = true;
    defer if (run_live) run.deinit();
    try std.testing.expectEqual(cycles, run.base.cycle_count);
    try std.testing.expectEqual(.halt_flag, run.base.completion_reason);
    try std.testing.expectEqualSlices(u8, &output, run.base.output.?);
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    var counters_live = true;
    defer if (counters_live) counters.deinit(a);
    var segment = try Support.Segment.initForUnion(a, &run.base, config, image.root.bytes, 0, .rv32im_zkvm_ethereum_sha_v1, 3, &counters, .{ .max_slots = 100, .max_witness_cells = 16 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 });
    var segment_live = true;
    defer if (segment_live) segment.deinit();
    var witness = try @import("../block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &run);
    var witness_live = true;
    defer if (witness_live) witness.deinit();
    try (@import("../../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = run.extension.keccakf_calls.records(), .recovery = run.extension.signer_recovery_calls.records() }).register(&counters);
    try @import("../block_v7_caller_active_columns_v1.zig").registerLookup(a, &witness, &counters);
    const caller = try Caller.ForBackend(Cpu).Stage.init(a, &witness, segment.pin.frame, 0, config, counters.get(.range_check_8_8));
    var caller_live = true;
    defer if (caller_live) caller.deinit();
    var shape = segment.owner.statement;
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    const caller_statement = witness.statement;
    var np = segment.pin;
    np.shape = &shape;
    var cp = caller.pin(0, (try np.entry(a)).identity);
    cp.statement = &caller_statement;
    var guest: std.ArrayList(Event) = .empty;
    var guest_live = true;
    defer if (guest_live) guest.deinit(a);
    inline for (.{ segment.source.inputs, caller.inputs }) |inputs| for (inputs) |input| for (0..input.trace.domainSize()) |i| {
        const row = try input.trace.row(i);
        if (row.active) try guest.append(a, try @import("../block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple));
    };
    var demand: [6]u64 = @splat(0);
    try LP.addDemand(&demand, try LP.nativeDemand(np.shape, np.template.external_retirements));
    try LP.addDemand(&demand, try LP.sidecarMemoryDemand(np.expected_events));
    try @import("../block_v5_precompile_table_demand_v1.zig").add(a, &demand, &caller_statement, cp.total_steps, config);
    const external_demand = try @import("../block_v5_memory_byte_demand_v1.zig").externalDemandForMode(&caller_statement, caller.schedule.memory, 1);
    try LP.addDemand(&demand, try LP.sidecarMemoryDemand(external_demand.event_count));
    // Decode actual retired/native/caller fetches plus exact completion fetch.
    const program = @import("../../air/program/commitment.zig");
    const rows = try program.declaredRows(a, program.DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_sha_v1 }, .{ run.base.execution_trace.rows.items, run.extension.keccakf_execution_rows.rows(), run.extension.signer_recovery_execution_rows.rows(), run.extension.sha_calls.records() }, run.base.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(segment.io.data.completion));
    defer a.free(rows);
    const multiplicities = try a.alloc(u64, image.leaves.len / 4);
    defer a.free(multiplicities);
    @memset(multiplicities, 0);
    var fetches: u64 = 0;
    for (rows) |row| {
        if (row.multiplicity == 0) continue;
        const base = initial.info.memory_layout.program_base;
        if (row.addr < base or row.addr & 3 != 0 or (row.addr - base) / 4 >= multiplicities.len) return error.BadActualFetch;
        multiplicities[(row.addr - base) / 4] = try std.math.add(u64, multiplicities[(row.addr - base) / 4], row.multiplicity);
        fetches = try std.math.add(u64, fetches, row.multiplicity);
    }
    const plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = fetches, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
    var rom_first = try ROM.ForBackend(Cpu).commit(a, plan, config);
    var rom_live = true;
    defer if (rom_live) rom_first.deinit(a);
    const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
    var lookup_first = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, config, null, .{});
    var lookup_live = true;
    defer if (lookup_live) lookup_first.deinit();
    const factor_ranges = std.process.hasEnvVarConstant("STWO_V7_COMPLETE_UNION_RAM_FACTOR_RANGES");
    const base_rows = factor_ranges or std.process.hasEnvVarConstant("STWO_V7_COMPLETE_UNION_RAM_BASE_ROWS");
    const ram_tiles = base_rows or std.process.hasEnvVarConstant("STWO_V7_COMPLETE_UNION_RAM_TILES");
    const memory = try Joint.For(Cpu).Stage.init(a, policy, guest.items, 0, if (iterations == 1) 64 else 4096, .{ .ram_quotient = if (ram_tiles) .{ .bounded_tiles = .{ .minimum_trace_log = 4, .tile_log = 15, .base_field_rows = base_rows, .factor_range_pairs = factor_ranges } } else .whole_domain });
    var memory_live = true;
    defer if (memory_live) memory.deinit();
    const entries = [_]Epoch.Entry{ try np.entry(a), try cp.entry(a), try ROM.firstEntry(plan, rom_first.roots), try lookup_first.entry(), try memory.entry() };
    var counts: Epoch.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, &entries, 5);
    const input = Union.Input{ .epoch = epoch, .entries = &entries, .native = np, .caller = cp, .program_plan = plan, .program_roots = rom_first.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup_first.layout, .lookup_roots = lookup_first.roots, .memory_roots = memory.roots, .interval_log = memory.witness.interval.log };
    const expected_events = guest.items.len;
    var native_access_cells: usize = 0;
    for (segment.source.slots) |slot| native_access_cells += @import("../block_execution_integer_bridge_v2.zig").COLUMN_COUNT * (@as(usize, 1) << @intCast(slot.log_size));
    std.debug.print("V7_COMPLETE_UNION_GEOMETRY native_access_cells={d} fixture_cell_cap={d} native_slots={d} whole_byte_cap={d}\n", .{ native_access_cells, 16 << 20, segment.source.slots.len, 24 << 30 });
    const setup_ns = whole.read();
    var timer = try std.time.Timer.start();
    const compare_fixed = std.process.hasEnvVarConstant("STWO_V7_COMPLETE_UNION_COMPARE_FIXED");
    var proof = try Union.proveWithOptions(a, trusted, input, .{ .native = &segment.first, .owner = segment.owner, .inputs = segment.source.inputs, .caller = caller, .program = &rom_first, .lookup = &lookup_first, .memory = memory }, &pool, .{}, .{ .fixed = if (compare_fixed) .reuse_required else .reuse_if_available });
    defer proof.deinit(a);
    const union_ns = timer.read();
    const proof_peak_bytes = budget.snapshot().peak_live_bytes;
    if (compare_fixed) {
        timer.reset();
        var raw_fixed = try Union.proveWithOptions(a, trusted, input, .{ .native = &segment.first, .owner = segment.owner, .inputs = segment.source.inputs, .caller = caller, .program = &rom_first, .lookup = &lookup_first, .memory = memory }, &pool, .{}, .{ .fixed = .rebuild });
        defer raw_fixed.deinit(a);
        const rebuild_ns = timer.read();
        var actual = std.Io.Writer.Allocating.init(a);
        defer actual.deinit();
        var control = std.Io.Writer.Allocating.init(a);
        defer control.deinit();
        try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &actual.writer, proof.stark);
        try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &control.writer, raw_fixed.stark);
        try std.testing.expectEqualSlices(u8, control.written(), actual.written());
        try std.testing.expectEqualDeep(raw_fixed.native, proof.native);
        try std.testing.expectEqualDeep(raw_fixed.access, proof.access);
        try std.testing.expectEqualDeep(raw_fixed.arithmetic, proof.arithmetic);
        try std.testing.expectEqualDeep(raw_fixed.relations, proof.relations);
        try std.testing.expectEqualDeep(raw_fixed.memory(), proof.memory());
        try std.testing.expectEqualDeep(raw_fixed.program, proof.program);
        try std.testing.expectEqualDeep(raw_fixed.lookup, proof.lookup);
        std.debug.print("V7_UNION_FIXED_REUSE same_proof=true same_claims=true reuse_prove_ns={d} rebuild_prove_ns={d} comparison=shared_host_single_pair\n", .{ union_ns, rebuild_ns });
    }
    const with_oracle = !std.process.hasEnvVarConstant("STWO_V7_COMPLETE_UNION_NO_ORACLE");
    var expected: ?Receiver.Verified = null;
    var separate_ns: u64 = 0;
    var oracle_oods: usize = 0;
    var oracle_queried: usize = 0;
    if (with_oracle) {
        // Differential original-proof oracle under the EXACT same original epoch,
        // private commitments, source witness and independently selected statement.
        timer.reset();
        var native = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, np, epoch, &entries);
        defer native.deinit(a);
        var caller_proof = try Caller.ForBackend(Cpu).prove(a, caller, cp, epoch, &entries, &pool);
        defer caller_proof.deinit(a);
        var rom = try ROM.ForBackend(Cpu).prove(a, &rom_first, .{ .plan = plan, .expected_program_root = image.root, .roots = input.program_roots, .epoch = epoch, .entries = &entries });
        defer rom.deinit(a);
        var lookup = try lookup_first.prove(epoch, &entries);
        defer lookup.deinit(a);
        var mp = try memory.prove(epoch, &entries);
        defer mp.deinit();
        separate_ns = timer.read();
        const oracle = Receiver.Input{ .epoch = epoch, .entries = &entries, .natives = &.{.{ .pin = np, .proof = &native }}, .active_callers = &.{.{ .pin = cp, .proof = &caller_proof }}, .program_plan = plan, .program_roots = input.program_roots, .program = &rom, .lookup_plan = lookup_plan, .lookup_roots = input.lookup_roots, .lookup = .{ .compact = .{ .layout = input.lookup_layout, .proof = &lookup } }, .memory = .{ .joint = &mp } };
        expected = try Receiver.For(Cpu).verify(a, trusted, oracle, .{});
        try std.testing.expectEqualDeep(native.claims, proof.native);
        try std.testing.expectEqualDeep(native.memory_claims, proof.access);
        try std.testing.expectEqualDeep(caller_proof.arithmetic, proof.arithmetic);
        try std.testing.expectEqualDeep(caller_proof.relations, proof.relations);
        try std.testing.expectEqualDeep(rom.claim, proof.program);
        try std.testing.expectEqualDeep(lookup.claims, proof.lookup);
        try std.testing.expectEqualDeep(mp.claims(), proof.memory());
        oracle_oods = samples(native.stark) + samples(caller_proof.stark) + samples(rom.stark) + samples(lookup.stark) + samples(mp.stark);
        oracle_queried = queried(native.stark) + queried(caller_proof.stark) + queried(rom.stark) + queried(lookup.stark) + queried(mp.stark);
    }
    timer.reset();
    caller.deinit();
    caller_live = false;
    segment.deinit();
    segment_live = false;
    witness.deinit();
    witness_live = false;
    rom_first.deinit(a);
    rom_live = false;
    lookup_first.deinit();
    lookup_live = false;
    memory.deinit();
    memory_live = false;
    run.deinit();
    run_live = false;
    session.deinit();
    session_live = false;
    counters.deinit(a);
    counters_live = false;
    guest.deinit(a);
    guest_live = false;
    const destruction_ns = timer.lap();
    try Support.roundTrip(a, &proof.stark);
    const encode_decode_ns = timer.lap();
    timer.reset();
    const actual = try Union.verify(a, trusted, input, &proof, .{});
    const verify_ns = timer.read();
    // A second proof for byte-parity is qualification work, never part of an
    // input-to-proof performance sample.
    const contiguous_ns: ?u64 = if (with_oracle or compare_fixed) null else whole.read();
    const direct_peak_bytes = budget.snapshot().peak_live_bytes;
    if (expected) |want| try std.testing.expectEqualDeep(want, actual);
    try std.testing.expectEqual(cycles, actual.cycles);
    try std.testing.expectEqual(@as(u64, expected_events), actual.ram_events);
    try std.testing.expectEqual(fetches, actual.program_fetches);
    const one = core.fields.qm31.QM31.one();
    const saved = proof.native[0];
    proof.native[0].sum = saved.sum.add(one);
    try reject(a, trusted, input, &proof);
    proof.native[0] = saved;
    const old_lookup = proof.lookup;
    proof.lookup[0] = old_lookup[0].add(one);
    proof.lookup[1] = old_lookup[1].sub(one);
    try reject(a, trusted, input, &proof);
    proof.lookup = old_lookup;
    const old_ram = proof.ram[0];
    proof.ram[0].sums[3] = old_ram.sums[3].add(one);
    proof.ram[0].sums[4] = old_ram.sums[4].sub(one);
    try reject(a, trusted, input, &proof);
    proof.ram[0] = old_ram;
    const old_sha = proof.arithmetic.sha;
    proof.arithmetic.sha[0] = old_sha[0].add(one);
    proof.arithmetic.sha[1] = old_sha[1].sub(one);
    try reject(a, trusted, input, &proof);
    proof.arithmetic.sha = old_sha;
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    roots[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedUnionFixedRoot, Union.verify(a, trusted, input, &proof, .{}));
    roots[0][0] ^= 1;
    std.mem.swap([32]u8, &roots[6], &roots[7]);
    try reject(a, trusted, input, &proof);
    std.mem.swap([32]u8, &roots[6], &roots[7]);
    std.mem.swap([32]u8, &roots[11], &roots[12]);
    try reject(a, trusted, input, &proof);
    std.mem.swap([32]u8, &roots[11], &roots[12]);
    var wrong = input;
    wrong.entries = entries[0..4];
    try reject(a, trusted, wrong, &proof);
    wrong = input;
    wrong.interval_log += 1;
    try reject(a, trusted, wrong, &proof);
    var bad = trusted;
    bad.terminal.output[0] ^= 1;
    try reject(a, bad, input, &proof);
    bad = trusted;
    bad.elf_sha256[0] ^= 1;
    try reject(a, bad, input, &proof);
    _ = try Union.verify(a, trusted, input, &proof, .{});
    var bytes = std.Io.Writer.Allocating.init(a);
    defer bytes.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &bytes.writer, proof.stark);
    std.debug.print("V7_COMPLETE_UNION profile={s} cycles={d} iterations={d} native_windows=1 original_starks=1 oracle_enabled={} trees=15 oracle_trees=23 ram_shards={d} events={d} fetches={d} union_oods={d} oracle_oods={d} union_queried={d} oracle_queried={d} setup_ns={d} union_prove_ns={d} oracle_prove_ns={d} fresh_verify_ns={d} proof_bytes={d} proof_peak_bytes={d} direct_peak_bytes={d} contiguous_ns={?d} destruction_ns={d} encode_decode_ns={d} all_producer_owners_destroyed=true global_closure=true timing=shared_host_diagnostic\n", .{ @tagName(selected), cycles, iterations, with_oracle, proof.ram.len, actual.ram_events, fetches, samples(proof.stark), oracle_oods, queried(proof.stark), oracle_queried, setup_ns, union_ns, separate_ns, verify_ns, bytes.written().len, proof_peak_bytes, direct_peak_bytes, contiguous_ns, destruction_ns, encode_decode_ns });
    if (std.process.getEnvVarOwned(a, "STWO_V7_COMPLETE_UNION_ARTIFACT_DIR")) |path| {
        defer a.free(path);
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "proof.stark.postcard", .data = bytes.written() });
        try dir.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
        // This finite terminal export cannot serialize an owning Window
        // object (including its allocator) as public statement metadata.
        if (trusted.window != null) return error.UnsupportedUnionWindowMetadata;
        const public_trusted = .{ .elf = trusted.elf, .elf_sha256 = trusted.elf_sha256, .profile = trusted.profile, .terminal = trusted.terminal, .config = trusted.config, .window = @as(?u8, null) };
        const metadata = try std.json.Stringify.valueAlloc(a, .{ .version = Union.VERSION, .tag = Union.TAG, .input = input, .trusted = public_trusted, .native = proof.native, .access = proof.access, .arithmetic = proof.arithmetic, .relations = proof.relations, .program = proof.program, .lookup = proof.lookup, .memory = proof.memory() }, .{});
        defer a.free(metadata);
        try dir.writeFile(.{ .sub_path = "public-metadata.json", .data = metadata });
        const receipt = try std.json.Stringify.valueAlloc(a, .{ .profile = @tagName(selected), .verified = actual, .iterations = iterations, .proof_bytes = bytes.written().len, .proof_peak_bytes = proof_peak_bytes, .test_peak_bytes = budget.snapshot().peak_live_bytes, .setup_ns = setup_ns, .union_prove_ns = union_ns, .oracle_prove_ns = separate_ns, .fresh_verify_ns = verify_ns, .phase_sum_ns = setup_ns + union_ns + verify_ns, .input_to_verified_root_ns = contiguous_ns, .destruction_ns = destruction_ns, .encode_decode_ns = encode_decode_ns, .direct_peak_bytes = direct_peak_bytes, .oracle_enabled = with_oracle, .all_physical_claims_equal = if (with_oracle) @as(?bool, true) else null, .producers_destroyed = true, .timing = "shared_host_diagnostic", .scope = "finite_one_window_direct_original_stark", .public_wire_decoder_implemented = false }, .{});
        defer a.free(receipt);
        try dir.writeFile(.{ .sub_path = "receipt.json", .data = receipt });
    } else |err| if (err != error.EnvironmentVariableNotFound) return err;
}
fn value(a: std.mem.Allocator, name: []const u8, default: u32) u32 {
    const raw = std.process.getEnvVarOwned(a, name) catch return default;
    defer a.free(raw);
    return std.fmt.parseInt(u32, raw, 10) catch 0;
}
fn reject(a: std.mem.Allocator, t: Receiver.Trusted, i: Union.Input, p: *const Union.Proof) !void {
    if (Union.verify(a, t, i, p, .{})) |_| return error.AcceptedCompleteUnionForgery else |err| if (err == error.OutOfMemory) return err;
}
fn samples(p: core.proof_suites.Blake3.Proof) usize {
    var n: usize = 0;
    for (p.commitment_scheme_proof.sampled_values.items) |tree| for (tree) |column| {
        n += column.len;
    };
    return n;
}
fn queried(p: core.proof_suites.Blake3.Proof) usize {
    var n: usize = 0;
    for (p.commitment_scheme_proof.queried_values.items) |tree| for (tree) |column| {
        n += column.len;
    };
    return n;
}
