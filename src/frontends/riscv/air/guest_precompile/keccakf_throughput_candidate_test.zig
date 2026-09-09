//! Semantic parity and exact cost tests for the adaptive Keccak candidate.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const authority = @import("keccakf_authority.zig");
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const compact_plan = @import("keccakf_interaction_plan.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const profile = @import("keccakf_adaptive_profile_v1.zig");
const projection = @import("keccakf_adaptive_corpus_projection_v1.zig");
const relations_mod = @import("keccakf_relations.zig");
const throughput_plan = @import("keccakf_throughput_interaction_plan_v1.zig");
const throughput_interaction = @import("keccakf_throughput_interaction_v1.zig");
const throughput_counters = @import("keccakf_throughput_multiplicities_v1.zig");
const throughput_table_interaction = @import("keccakf_throughput_table_interaction_v1.zig");
const throughput_tables = @import("keccakf_throughput_tables_v1.zig");
const trace_mod = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");
const xor_throughput_counters = @import("keccakf_xor_throughput_multiplicities_v1.zig");
const xor_throughput_interaction = @import("keccakf_xor_throughput_interaction_v1.zig");
const xor_throughput_plan = @import("keccakf_xor_throughput_interaction_plan_v1.zig");
const xor_throughput_table_interaction = @import("keccakf_xor_throughput_table_interaction_v1.zig");

test "keccak throughput candidate: table tuples round-trip exact authority" {
    const chi_rows = [_]usize{ 0, 1, 0x12345, authority.geometry.chi_table_rows - 1 };
    for (chi_rows) |row| {
        const tuple = try throughput_tables.semanticTupleAt(.chi, row);
        try std.testing.expectEqual(row, try throughput_tables.index(.chi, &tuple));
    }
    const xor_rows = [_]usize{ 0, 1, 12_345, authority.geometry.xor5_table_rows - 1 };
    for (xor_rows) |row| {
        const tuple = try throughput_tables.semanticTupleAt(.xor5, row);
        try std.testing.expectEqual(row, try throughput_tables.index(.xor5, &tuple));
    }
    const padded = try throughput_tables.tupleAt(
        .xor5,
        authority.geometry.xor5_table_rows,
    );
    for (padded) |value| try std.testing.expect(value.isZero());

    var forged = try throughput_tables.semanticTupleAt(.chi, 7);
    forged[5] = forged[5].add(M31.one());
    try std.testing.expectError(
        error.InvalidTuple,
        throughput_tables.index(.chi, &forged),
    );
}

test "keccak throughput candidate: active row tuples preserve permutation semantics" {
    const records = [_]call_buffer.Record{ makeRecord(3), makeRecord(7) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try trace_mod.generateShard(
        std.testing.allocator,
        &records,
        0,
        &counters,
    );
    defer trace.deinit();
    const relations = relations_mod.Relations.dummy();

    const logical_row: usize = 2;
    const main = readMain(&trace, logical_row);
    const next = readState(&trace, logical_row + 1);
    const output = readState(&trace, logical_row + 27);
    const selectors = readSelectors(&trace, logical_row);
    _ = try compact_plan.rowPairsBase(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
    );
    const candidate_pairs = try throughput_plan.rowPairsBase(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
    );
    try std.testing.expectEqual(
        @as(usize, throughput_plan.batch_count),
        candidate_pairs.len,
    );

    for (0..throughput_plan.chi_event_count) |event| {
        const tuple = try throughput_plan.chiTuple(
            M31,
            &main,
            &next,
            &selectors,
            event,
        );
        _ = try throughput_tables.index(.chi, &tuple);
    }
    for (0..throughput_plan.xor5_event_count) |event| {
        const tuple = try throughput_plan.xor5Tuple(M31, &main, event);
        _ = try throughput_tables.index(.xor5, &tuple);
    }

    var mutated = next;
    mutated[0] = mutated[0].add(M31.one());
    const forged = try throughput_plan.chiTuple(
        M31,
        &main,
        &mutated,
        &selectors,
        0,
    );
    try std.testing.expectError(
        error.InvalidTuple,
        throughput_tables.index(.chi, &forged),
    );
}

test "keccak throughput candidate: materialized shard and tables cancel exactly" {
    const records = [_]call_buffer.Record{
        makeRecord(19),
        makeRecord(23),
        makeRecord(29),
    };
    var compact_counters = try counters_mod.Counters.init(std.testing.allocator);
    defer compact_counters.deinit();
    var trace = try trace_mod.generateShard(
        std.testing.allocator,
        &records,
        0,
        &compact_counters,
    );
    defer trace.deinit();

    var counters = try throughput_counters.Counters.init(std.testing.allocator);
    defer counters.deinit();
    try recordThroughputSlots(&counters, &records);
    try counters.validateTotals();
    try std.testing.expectEqual(@as(usize, 2), counters.slots);
    try std.testing.expectEqual(
        @as(usize, 2 * authority.geometry.chi_lookups_per_slot),
        sumCounters(counters.chi),
    );
    try std.testing.expectEqual(
        @as(usize, 2 * authority.geometry.xor5_lookups_per_slot),
        sumCounters(counters.xor5),
    );

    const relations = relations_mod.Relations.dummy();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var shard = try throughput_interaction.generate(
        std.testing.allocator,
        &trace,
        &relations,
        &pool,
    );
    defer shard.deinit(std.testing.allocator);
    var chi_table = try throughput_table_interaction.generate(
        std.testing.allocator,
        .chi,
        &counters,
        &relations,
        &pool,
    );
    defer chi_table.deinit(std.testing.allocator);
    var xor_table = try throughput_table_interaction.generate(
        std.testing.allocator,
        .xor5,
        &counters,
        &relations,
        &pool,
    );
    defer xor_table.deinit(std.testing.allocator);

    // `permutationTotal` also owns the two state-I/O requests.  Remove their
    // independently reconstructed exact contribution before closing the two
    // table buses; treating I/O as table multiplicity would be a false claim.
    const table_requests = shard.permutationTotal().sub(
        try ioRequestTotal(&trace, &relations),
    );
    const closed = table_requests.add(chi_table.claim).add(
        xor_table.claim,
    );
    try std.testing.expect(closed.isZero());

    const first_slot = try witness.buildSlot(
        trace_mod.stateFromWords(records[0].input),
        trace_mod.stateFromWords(records[1].input),
    );
    const forged_row = try witness.chiLookupRow(&first_slot, 0, 0, 0);
    counters.chi[forged_row] = counters.chi[forged_row].add(M31.one());
    var forged_table = try throughput_table_interaction.generate(
        std.testing.allocator,
        .chi,
        &counters,
        &relations,
        &pool,
    );
    defer forged_table.deinit(std.testing.allocator);
    try std.testing.expect(!table_requests.add(forged_table.claim).add(
        xor_table.claim,
    ).isZero());
}

test "keccak xor-throughput candidate: hybrid materialization closes exact buses" {
    const records = [_]call_buffer.Record{
        makeRecord(31),
        makeRecord(37),
        makeRecord(41),
    };
    var compact_counters = try counters_mod.Counters.init(std.testing.allocator);
    defer compact_counters.deinit();
    var trace = try trace_mod.generateShard(
        std.testing.allocator,
        &records,
        0,
        &compact_counters,
    );
    defer trace.deinit();

    var counters = try xor_throughput_counters.Counters.init(
        std.testing.allocator,
    );
    defer counters.deinit();
    try recordHybridSlots(&counters, &records);
    try counters.validateTotals();
    try std.testing.expectEqual(@as(usize, 2), counters.slots);
    try std.testing.expectEqual(
        @as(usize, 2 * authority.geometry.compact.chi_lookups_per_slot),
        sumCounters(counters.chi),
    );
    try std.testing.expectEqual(
        @as(usize, 2 * authority.geometry.xor5_lookups_per_slot),
        sumCounters(counters.xor5),
    );

    const relations = relations_mod.Relations.dummy();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var shard = try xor_throughput_interaction.generate(
        std.testing.allocator,
        &trace,
        &relations,
        &pool,
    );
    defer shard.deinit(std.testing.allocator);
    var chi_table = try xor_throughput_table_interaction.generate(
        std.testing.allocator,
        .chi,
        &counters,
        &relations,
        &pool,
    );
    defer chi_table.deinit(std.testing.allocator);
    var xor_table = try xor_throughput_table_interaction.generate(
        std.testing.allocator,
        .xor5,
        &counters,
        &relations,
        &pool,
    );
    defer xor_table.deinit(std.testing.allocator);
    try std.testing.expect(shard.tableTotal().add(chi_table.claim).add(
        xor_table.claim,
    ).isZero());

    const first_slot = try witness.buildSlot(
        trace_mod.stateFromWords(records[0].input),
        trace_mod.stateFromWords(records[1].input),
    );
    const forged_row = try witness.xor5LookupRow(&first_slot, 0, 0);
    counters.xor5[forged_row] = counters.xor5[forged_row].add(M31.one());
    var forged_table = try xor_throughput_table_interaction.generate(
        std.testing.allocator,
        .xor5,
        &counters,
        &relations,
        &pool,
    );
    defer forged_table.deinit(std.testing.allocator);
    try std.testing.expect(!shard.tableTotal().add(chi_table.claim).add(
        forged_table.claim,
    ).isZero());
    try std.testing.expectEqual(
        @as(usize, 854),
        xor_throughput_plan.table_batch_count,
    );
}

test "keccak throughput candidate: public count chooses exact minimum-cell profile" {
    const empty = try profile.compile(0);
    try std.testing.expectEqual(profile.Mode.inactive_zero_count, empty.mode);
    try std.testing.expectEqual(@as(u64, 0), empty.costs.total_cells);

    const tiny = try profile.compile(1);
    try std.testing.expectEqual(profile.Mode.compact_v2, tiny.mode);
    try std.testing.expectEqual(@as(u32, 5), tiny.log_size);

    const medium = try profile.compile(72);
    try std.testing.expectEqual(profile.Mode.throughput_xor_v1, medium.mode);
    try std.testing.expectEqual(@as(u32, 11), medium.log_size);

    const large = try profile.compile(565);
    try std.testing.expectEqual(profile.Mode.throughput_chi_xor_v1, large.mode);
    try std.testing.expectEqual(@as(u32, 14), large.log_size);
    try std.testing.expect(large.costs.total_cells <
        (try profile.compile(564)).costs.total_cells * 4);

    var forged = large;
    forged.shard_interaction_columns += 4;
    try std.testing.expectError(error.PlanMismatch, forged.validate());
    try large.validate();
    try std.testing.expect(!std.mem.eql(
        u8,
        &tiny.verifier_program_identity,
        &large.verifier_program_identity,
    ));
    try std.testing.expect(!profile.production_active);

    const compact_log5 = try profile.compileMode(1, .compact_v2);
    const compact_log6 = try profile.compileMode(3, .compact_v2);
    try std.testing.expect(!std.mem.eql(
        u8,
        &compact_log5.verifier_program_identity,
        &compact_log6.verifier_program_identity,
    ));
    const empty_baseline = try profile.compileCompactBaseline(0);
    try std.testing.expectEqual(profile.Mode.compact_v2, empty_baseline.mode);
    try std.testing.expectEqual(@as(u32, 5), empty_baseline.log_size);
    try std.testing.expect(empty_baseline.costs.total_cells > 0);
}

test "keccak adaptive corpus projection: journal bytes own executable mode savings" {
    const allocator = std.testing.allocator;
    const header_digest = "1111111111111111111111111111111111111111111111111111111111111111";
    const segment0_digest = "2222222222222222222222222222222222222222222222222222222222222222";
    const segment1_digest = "3333333333333333333333333333333333333333333333333333333333333333";
    const summary_digest = "4444444444444444444444444444444444444444444444444444444444444444";
    const elf_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const header =
        "{\"payload\":{\"schema\":\"stwo.riscv.segmented-execution-header.v3\"," ++
        "\"profile\":\"rv32im-zkvm-ethereum-v1\",\"elf_sha256\":\"" ++
        elf_digest ++ "\"},\"content_sha256\":\"" ++ header_digest ++ "\"}\n";
    const line0 = try segmentLineAlloc(allocator, 0, header_digest, segment0_digest, 10, 0);
    defer allocator.free(line0);
    const line1 = try segmentLineAlloc(allocator, 1, segment0_digest, segment1_digest, 20, 100);
    defer allocator.free(line1);
    const line2 = try segmentLineAlloc(allocator, 2, segment1_digest, header_digest, 30, 600);
    defer allocator.free(line2);
    const summary = try summaryLineAlloc(
        allocator,
        header_digest,
        summary_digest,
        3,
        60,
        700,
    );
    defer allocator.free(summary);
    const journal = try std.mem.concat(
        allocator,
        u8,
        &.{ header, line0, line1, line2, summary },
    );
    defer allocator.free(journal);
    var receipt = try projection.project(allocator, journal, .{
        .executable_sha256 = @splat(7),
        .executable_bytes = 123,
    });
    try projection.bindRuntime(&receipt, 456, 789);
    try receipt.validate();
    try std.testing.expectEqual(@as(u32, 3), receipt.leaf_count);
    try std.testing.expectEqual(@as(u64, 60), receipt.total_core_rows);
    try std.testing.expectEqual(@as(u64, 700), receipt.total_keccak_calls);
    try std.testing.expectEqual(@as(u32, 1), receipt.modes[0].leaves);
    try std.testing.expectEqual(@as(u32, 1), receipt.modes[2].leaves);
    try std.testing.expectEqual(@as(u32, 1), receipt.modes[3].leaves);
    try std.testing.expect(receipt.saved_cells > 0);
    const encoded = try projection.encodeAlloc(allocator, receipt);
    defer allocator.free(encoded);
    var decoded = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        encoded,
        .{},
    );
    defer decoded.deinit();
    try std.testing.expectEqualStrings(
        projection.schema,
        decoded.value.object.get("schema").?.string,
    );

    const missing_summary = try std.mem.concat(allocator, u8, &.{ header, line0 });
    defer allocator.free(missing_summary);
    try std.testing.expectError(
        error.MissingSummary,
        projection.project(allocator, missing_summary, .{
            .executable_sha256 = @splat(7),
            .executable_bytes = 123,
        }),
    );

    const mismatched_summary = try summaryLineAlloc(
        allocator,
        header_digest,
        summary_digest,
        4,
        60,
        700,
    );
    defer allocator.free(mismatched_summary);
    const mismatched = try std.mem.concat(
        allocator,
        u8,
        &.{ header, line0, line1, line2, mismatched_summary },
    );
    defer allocator.free(mismatched);
    try std.testing.expectError(
        error.SummaryMismatch,
        projection.project(allocator, mismatched, .{
            .executable_sha256 = @splat(7),
            .executable_bytes = 123,
        }),
    );

    const early_summary = try summaryLineAlloc(
        allocator,
        segment0_digest,
        summary_digest,
        1,
        10,
        0,
    );
    defer allocator.free(early_summary);
    const nonterminal = try std.mem.concat(
        allocator,
        u8,
        &.{ header, line0, early_summary, line1 },
    );
    defer allocator.free(nonterminal);
    try std.testing.expectError(
        error.NonterminalSummary,
        projection.project(allocator, nonterminal, .{
            .executable_sha256 = @splat(7),
            .executable_bytes = 123,
        }),
    );

    const broken_line = try segmentLineAlloc(
        allocator,
        0,
        segment0_digest,
        segment1_digest,
        10,
        0,
    );
    defer allocator.free(broken_line);
    const broken = try std.mem.concat(allocator, u8, &.{ header, broken_line });
    defer allocator.free(broken);
    try std.testing.expectError(
        error.InvalidJournalChain,
        projection.project(allocator, broken, .{
            .executable_sha256 = @splat(7),
            .executable_bytes = 123,
        }),
    );
}

test "keccak throughput candidate: bounded row-pair microbenchmark" {
    if (builtin.mode != .ReleaseFast) return;

    const records = [_]call_buffer.Record{ makeRecord(11), makeRecord(17) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try trace_mod.generateShard(
        std.testing.allocator,
        &records,
        0,
        &counters,
    );
    defer trace.deinit();
    const relations = relations_mod.Relations.dummy();
    const logical_row: usize = 2;
    const main = readMain(&trace, logical_row);
    const next = readState(&trace, logical_row + 1);
    const output = readState(&trace, logical_row + 27);
    const selectors = readSelectors(&trace, logical_row);

    const warmup_iterations: usize = 4;
    const measured_iterations: usize = 64;
    _ = try measureCompact(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
        warmup_iterations,
    );
    _ = try measureThroughput(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
        warmup_iterations,
    );

    // ABBA ordering limits one-way thermal bias without turning this focused
    // evaluator benchmark into a proof-throughput claim.
    const compact_first = try measureCompact(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
        measured_iterations,
    );
    const throughput_first = try measureThroughput(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
        measured_iterations,
    );
    const throughput_second = try measureThroughput(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
        measured_iterations,
    );
    const compact_second = try measureCompact(
        &main,
        &next,
        &output,
        &selectors,
        &relations,
        measured_iterations,
    );
    const samples: u64 = 2 * measured_iterations;
    const compact_ns = compact_first + compact_second;
    const throughput_ns = throughput_first + throughput_second;
    const compact_ns_per_row = compact_ns / samples;
    const throughput_ns_per_row = throughput_ns / samples;
    try std.testing.expect(compact_ns_per_row > 0);
    try std.testing.expect(throughput_ns_per_row > 0);

    std.debug.print(
        "keccak-adaptive-benchmark-v1 " ++
            "production_active=false workload=paired_active_round_row " ++
            "iterations={} compact_events={} compact_batches={} " ++
            "compact_interaction_columns={} compact_ns_per_row={} " ++
            "throughput_events={} throughput_batches={} " ++
            "throughput_interaction_columns={} throughput_ns_per_row={}\n",
        .{
            samples,
            compact_plan.event_count,
            compact_plan.batch_count,
            compact_plan.interaction_column_count,
            compact_ns_per_row,
            throughput_plan.permutation_event_count +
                @import("keccakf_caller.zig").event_count,
            throughput_plan.batch_count,
            throughput_plan.interaction_column_count,
            throughput_ns_per_row,
        },
    );
}

fn measureCompact(
    main: []const M31,
    next: []const M31,
    output: []const M31,
    selectors: []const M31,
    relations: *const relations_mod.Relations,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const pairs = try compact_plan.rowPairsBase(
            main,
            next,
            output,
            selectors,
            relations,
        );
        std.mem.doNotOptimizeAway(&pairs);
    }
    return timer.read();
}

fn measureThroughput(
    main: []const M31,
    next: []const M31,
    output: []const M31,
    selectors: []const M31,
    relations: *const relations_mod.Relations,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const pairs = try throughput_plan.rowPairsBase(
            main,
            next,
            output,
            selectors,
            relations,
        );
        std.mem.doNotOptimizeAway(&pairs);
    }
    return timer.read();
}

fn makeRecord(seed: u32) call_buffer.Record {
    var input: [call_buffer.word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = seed +%
        @as(u32, @intCast(index * 29));
    var state = trace_mod.stateFromWords(input);
    authority.permute(&state);
    var output: [call_buffer.word_count]u32 = undefined;
    for (state, 0..) |lane, index| {
        output[2 * index] = @truncate(lane);
        output[2 * index + 1] = @truncate(lane >> 32);
    }
    return .{
        .execution_clock = seed + 1,
        .pc = seed + 4,
        .state_ptr = 0x4000,
        .pointer_register = 6,
        .pointer_previous_clock = 0,
        .input = input,
        .output = output,
        .memory_previous_clocks = @splat(0),
    };
}

fn recordThroughputSlots(
    counters: *throughput_counters.Counters,
    records: []const call_buffer.Record,
) !void {
    var first: usize = 0;
    while (first < records.len) : (first += 2) {
        const second = if (first + 1 < records.len)
            trace_mod.stateFromWords(records[first + 1].input)
        else
            null;
        const slot = try witness.buildSlot(
            trace_mod.stateFromWords(records[first].input),
            second,
        );
        try counters.recordSlot(&slot);
    }
}

fn recordHybridSlots(
    counters: *xor_throughput_counters.Counters,
    records: []const call_buffer.Record,
) !void {
    var first: usize = 0;
    while (first < records.len) : (first += 2) {
        const second = if (first + 1 < records.len)
            trace_mod.stateFromWords(records[first + 1].input)
        else
            null;
        const slot = try witness.buildSlot(
            trace_mod.stateFromWords(records[first].input),
            second,
        );
        try counters.recordSlot(&slot);
    }
}

fn sumCounters(values: []const M31) usize {
    var result: usize = 0;
    for (values) |value| result += value.toU32();
    return result;
}

fn segmentLineAlloc(
    allocator: std.mem.Allocator,
    index: u32,
    previous: []const u8,
    content: []const u8,
    core_rows: u32,
    calls: u32,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"payload\":{{\"schema\":\"stwo.riscv.segmented-execution-segment.v3\"," ++
            "\"previous_record_sha256\":\"{s}\",\"segment_index\":{}," ++
            "\"core_trace_rows\":{},\"external_family_rows\":[" ++
            "{{\"family\":\"stwo.keccakf-1600.permute-in-place@1\"," ++
            "\"calls\":{}}}] }},\"content_sha256\":\"{s}\"}}\n",
        .{ previous, index, core_rows, calls, content },
    );
}

fn summaryLineAlloc(
    allocator: std.mem.Allocator,
    previous: []const u8,
    content: []const u8,
    segment_count: u32,
    total_core_rows: u64,
    calls: u64,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"payload\":{{\"schema\":\"stwo.riscv.segmented-execution-summary.v3\"," ++
            "\"previous_record_sha256\":\"{s}\",\"segment_count\":{}," ++
            "\"total_core_trace_rows\":{},\"external_family_rows\":[" ++
            "{{\"family\":\"stwo.keccakf-1600.permute-in-place@1\"," ++
            "\"calls\":{}}}] }},\"content_sha256\":\"{s}\"}}\n",
        .{ previous, segment_count, total_core_rows, calls, content },
    );
}

fn ioRequestTotal(
    trace: *const trace_mod.Shard,
    relations: *const relations_mod.Relations,
) !QM31 {
    var result = QM31.zero();
    for (0..trace.domainSize()) |logical_row| {
        const main = readMain(trace, logical_row);
        const selectors = readSelectors(trace, logical_row);
        var io_a: relations_mod.IoTuple = undefined;
        var io_b: relations_mod.IoTuple = undefined;
        for (&io_a, &io_b, 0..) |*a, *b, field| {
            a.* = main[trace_mod.Layout.io_a + field];
            b.* = main[trace_mod.Layout.io_b + field];
        }
        const numerator_a = selectors[0];
        const numerator_b = selectors[1].mul(
            main[trace_mod.Layout.in_use_b],
        );
        if (!numerator_a.isZero()) result = result.sub(
            QM31.fromBase(numerator_a).mul(try relations.io.combineBase(io_a).inv()),
        );
        if (!numerator_b.isZero()) result = result.sub(
            QM31.fromBase(numerator_b).mul(try relations.io.combineBase(io_b).inv()),
        );
    }
    return result;
}

fn readMain(trace: *const trace_mod.Shard, logical: usize) [trace_mod.Layout.main_columns]M31 {
    var result: [trace_mod.Layout.main_columns]M31 = undefined;
    for (&result, 0..) |*value, column| value.* = trace.mainAt(column, logical);
    return result;
}

fn readState(trace: *const trace_mod.Shard, logical: usize) [authority.width_bits]M31 {
    var result: [authority.width_bits]M31 = undefined;
    for (&result, 0..) |*value, cell| value.* =
        trace.mainAt(trace_mod.Layout.state + cell, logical);
    return result;
}

fn readSelectors(trace: *const trace_mod.Shard, logical: usize) [authority.geometry.rows_per_slot]M31 {
    var result: [authority.geometry.rows_per_slot]M31 = undefined;
    const row = trace_mod.committedRow(logical, trace.log_size);
    for (&result, 0..) |*value, group| value.* = trace.preprocessedColumn(
        trace_mod.Layout.row_group + group,
    )[row];
    return result;
}
