//! Fully recommitted sparse RAM forgery after an actual synthetic clock gap.
//! Every native row is locally valid; independent global WORD closure is required.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../../runner/mod.zig");
const Guest = @import("block_v7_high_gap_guest_test_support.zig");
const Native = @import("../block_v7_native_proof_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const Joint = @import("../block_v7_memory_joint_proof_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Receiver = @import("../block_v7_execution_receiver_v1.zig");
const Union = @import("../block_v7_multi_union_proof_v1.zig");

const Attack = enum { none, before_value, current_clock };
fn qualify(comptime attack: Attack) !void {
    const backing = std.testing.allocator;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(backing, 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const canonical = std.process.hasEnvVarConstant("STWO_V7_HIGH_GAP_CANONICAL");
    const elf = Guest.elf();
    const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
    const config = (if (canonical) Profile.csp_q70_pow26 else Profile.diagnostic_q8_pow0).config();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var initial = try @import("../block_v7_initial_intervals_v1.zig").Owned.derive(a, &elf, @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_ethereum_sha_v1, .{});
    defer initial.deinit();
    var image = try @import("../block_v7_program_image_v1.zig").Owned.init(a, &elf, &initial, .{});
    defer image.deinit();
    const policy = @import("../block_v7_execution_policy_v1.zig").Policy{ .initialized = &initial, .program_root = image.root.bytes, .terminal = .{ .final_cycle = Guest.cycles, .halt_address = initial.info.halt_flag, .length_address = initial.info.output_len, .data_address = initial.info.output_data, .output_end = initial.info.output_end, .output = Guest.output }, .config = config };
    const trusted = @import("../block_v7_execution_receiver_v1.zig").Trusted{ .elf = &elf, .elf_sha256 = initial.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = config };
    var session = try Runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    var session_live = true;
    defer if (session_live) session.deinit();
    var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
    var counters_live = true;
    defer if (counters_live) counters.deinit(a);
    var runs: [2]Runner.EthereumShaSegmentResult = undefined;
    var run_count: usize = 0;
    defer for (runs[0..run_count]) |*r| r.deinit();
    var segments: [2]Support.Segment = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*s| s.deinit();
    var shapes: [2]Shape = undefined;
    var native_pins: [2]Native.Pin = undefined;
    var native_stages: [2]Union.NativeStage = undefined;
    var load_events: usize = 0;
    var memory_gap_rows: usize = 0;
    var load_clock: u64 = 0;
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(a);
    const multiplicities = try a.alloc(u64, image.leaves.len / 4);
    defer a.free(multiplicities);
    @memset(multiplicities, 0);
    var demand: [6]u64 = @splat(0);
    var fetches: u64 = 0;
    var token: ?@import("../../runner/result.zig").ContinuationToken = null;
    for ([_]u32{ Guest.prefix_cycles, Guest.suffix_cycles }, 0..) |cut, i| {
        if (i == 1 and attack == .before_value) session.memory.writeU32(Guest.address, Guest.forged_value);
        runs[i] = if (token) |t| try session.resumeSegment(t, cut) else try session.startSegment(cut);
        run_count += 1;
        const run = &runs[i];
        token = run.base.continuation;
        const external = try @import("../block_v5_cpu_execution_source_v1.zig").externalCount(run);
        try std.testing.expectEqual(@as(u32, 0), external);
        for (run.base.state_chain_tracker.clock_updates_mem.items) |gap| if (gap.addr == Guest.address) {
            memory_gap_rows += 1;
            try std.testing.expectEqual(if (attack == .before_value) Guest.forged_value else Guest.value, gap.value);
        };
        segments[i] = try Support.Segment.initWithSourceLimits(a, &run.base, config, image.root.bytes, @intCast(i), .rv32im_zkvm_ethereum_sha_v1, external, &counters, .{ .max_slots = 100, .max_witness_cells = 16 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 });
        segment_count += 1;
        const segment = &segments[i];
        shapes[i] = segment.owner.statement;
        shapes[i].public_data.io_entries.input_words = &.{};
        shapes[i].public_data.io_entries.output_words = &.{};
        native_pins[i] = segment.pin;
        native_pins[i].shape = &shapes[i];
        native_stages[i] = .{ .allocator = a, .first = &segment.first, .owner = segment.owner, .inputs = segment.source.inputs };
        for (segment.source.inputs) |input| for (0..input.trace.domainSize()) |r| {
            const row = try input.trace.row(r);
            if (row.active) {
                var event = try @import("../block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple);
                if (i == 1 and event.address == Guest.address) {
                    load_events += 1;
                    load_clock = event.clock;
                    try std.testing.expect(event.clock > @import("../../runner/state_chain.zig").MAX_ACCESS_CLOCK_DIFF);
                    const expected_value = if (attack == .before_value) Guest.forged_value else Guest.value;
                    try std.testing.expectEqual(expected_value, event.before);
                    try std.testing.expectEqual(expected_value, event.after);
                    // This is an independently proved provider proposal, not
                    // a host success receipt or a mutation of an existing proof.
                    // Value attack uses the honest store/load chain. Clock attack
                    // moves the provider read into the subsequent guest cycle.
                    event.before = Guest.value;
                    event.after = Guest.value;
                    if (attack == .current_clock) event.clock += 4;
                }
                try events.append(a, event);
            }
        };
        try LP.addDemand(&demand, try LP.nativeDemand(&shapes[i], external));
        try LP.addDemand(&demand, try LP.sidecarMemoryDemand(native_pins[i].expected_events));
        const Program = @import("../../air/program/commitment.zig");
        const rows = try Program.declaredRows(a, Program.DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_sha_v1 }, .{ run.base.execution_trace.rows.items, run.extension.keccakf_execution_rows.rows(), run.extension.signer_recovery_execution_rows.rows(), run.extension.sha_calls.records() }, run.base.rw_memory.program_words, @import("../commitment_program_witness.zig").completionFetch(segment.io.data.completion));
        defer a.free(rows);
        for (rows) |row| if (row.multiplicity != 0) {
            const at = (row.addr - initial.info.memory_layout.program_base) / 4;
            multiplicities[at] += row.multiplicity;
            fetches += row.multiplicity;
        };
    }
    try std.testing.expect(token == null);
    try std.testing.expectEqualSlices(u8, &Guest.output, runs[1].base.output.?);
    try std.testing.expectEqual(@as(usize, 1), load_events);
    try std.testing.expect(memory_gap_rows > 0);
    try std.testing.expectEqual(Guest.cycles, runs[0].base.cycle_count + runs[1].base.cycle_count);
    const plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = fetches, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
    var first = try ROM.ForBackend(Cpu).commit(a, plan, config);
    var first_live = true;
    defer if (first_live) first.deinit(a);
    const lookup_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 2, .max_requests = demand };
    var lookup_stage = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, config, null, .{});
    var lookup_live = true;
    defer if (lookup_live) lookup_stage.deinit();
    const memory_stage = try Joint.For(Cpu).Stage.init(a, policy, events.items, 0, 64, .{});
    var memory_live = true;
    defer if (memory_live) memory_stage.deinit();
    var entries: [5]Epoch.Entry = undefined;
    for (native_pins, entries[0..2]) |np, *entry| entry.* = try np.entry(a);
    entries[2] = try ROM.firstEntry(plan, first.roots);
    entries[3] = try lookup_stage.entry();
    entries[4] = try memory_stage.entry();
    var counts: Epoch.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try Epoch.Epoch.init(try policy.digest(), config, counts, &entries, 5);
    const geometries = try a.alloc(@import("../block_v5_ram_lanes_protocol_v1.zig").Claim, memory_stage.witness.ram.len);
    defer a.free(geometries);
    for (geometries, memory_stage.witness.ram) |*g, row| g.* = row.geometry;
    const input = Union.Input{ .epoch = epoch, .entries = &entries, .natives = &native_pins, .callers = &.{}, .program_plan = plan, .program_roots = first.roots, .lookup_plan = lookup_plan, .lookup_layout = lookup_stage.layout, .lookup_roots = lookup_stage.roots, .memory_roots = memory_stage.roots, .memory_geometry = geometries, .interval_log = memory_stage.witness.interval.log };
    const limits = Union.Limits{ .max_retained_pcs_bytes = 8 << 30 };
    const setup_ns = phase.lap();
    var proof = try Union.prove(a, trusted, input, .{ .natives = &native_stages, .callers = &.{}, .program = &first, .program_allocator = a, .lookup = &lookup_stage, .memory = memory_stage }, &pool, limits);
    defer proof.deinit(a);
    const prove_ns = phase.lap();
    for (segments[0..segment_count]) |*segment| segment.deinit();
    segment_count = 0;
    for (runs[0..run_count]) |*run| run.deinit();
    run_count = 0;
    session.deinit();
    session_live = false;
    counters.deinit(a);
    counters_live = false;
    first.deinit(a);
    first_live = false;
    lookup_stage.deinit();
    lookup_live = false;
    memory_stage.deinit();
    memory_live = false;
    const Codec = @import("../block_v7_multi_union_codec_v1.zig");
    const encoded = try Codec.encode(a, proof.view(), input, .{ .scope = limits });
    defer a.free(encoded);
    if (attack == .none) {
        const verified = try Codec.verifyBytes(a, encoded, trusted, input, .{ .scope = limits });
        try std.testing.expectEqual(Guest.cycles, verified.cycles);
        try std.testing.expectEqualDeep(Guest.output, verified.output);
    } else {
        try std.testing.expectError(error.UnclosedV7ExecutionRelations, Codec.verifyBytes(a, encoded, trusted, input, .{ .scope = limits }));
    }
    // Diagnostic attribution AFTER the actual complete verifier above. These
    // arithmetic checks grant no authority; they identify the exact rejection
    // among the residuals sharing UnclosedV7ExecutionRelations.
    const drawn = try epoch.draw(a);
    const memory_open = try @import("../block_v7_memory_claim_closure_v1.zig").close(proof.claims.memory());
    var closure = try @import("../block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, 2, 0, proof.claims.program, fetches, proof.claims.lookup, memory_open);
    defer closure.deinit();
    for (proof.claims.native, native_pins, 0..) |claims, pin, index| try closure.addNative(index, try @import("../block_v7_native_source_v1.zig").exportsFromClaims(a, pin, claims.claims, claims.access, &drawn));
    for (closure.states, closure.registers) |state, register| {
        try std.testing.expect(state.isZero());
        try std.testing.expect(register.isZero());
    }
    for (closure.tables) |sum| try std.testing.expect(sum.isZero());
    try std.testing.expect(closure.program.isZero());
    try std.testing.expectEqual(closure.expected_fetches, closure.fetches);
    try std.testing.expectEqual(closure.expected_events, closure.events);
    try std.testing.expectEqual(attack == .none, closure.transition.isZero());
    std.debug.print("V7_HIGH_GAP attack={s} cycles={d} load_clock={d} ram_gap_rows={d} all_commitments_rebuilt=true producers_destroyed=true only_word_residual_changes=true setup_ns={d} prove_ns={d} whole_ns={d} charged_peak={d} proof_bytes={d}\n", .{ @tagName(attack), Guest.cycles, load_clock, memory_gap_rows, setup_ns, prove_ns, whole.read(), budget.snapshot().peak_live_bytes, encoded.len });
}
test "v7 actual high-gap RAM execution closes without a ghost provider" {
    try qualify(.none);
}
test "v7 recommitted high-gap RAM before-value forgery rejects in global WORD closure" {
    try qualify(.before_value);
}
test "v7 recommitted high-gap RAM current-clock forgery rejects in global WORD closure" {
    try qualify(.current_clock);
}
