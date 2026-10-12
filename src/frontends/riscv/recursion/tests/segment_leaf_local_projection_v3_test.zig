//! Existing-V2 proof projection for leaf-local large-execution segments.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

const runner = @import("../../runner/mod.zig");
const public_data_v2 = @import("../../air/public_data_v2.zig");
const channel = @import("../poseidon2_channel.zig");
const protocol = @import("../protocol.zig");
const span = @import("../span_statement.zig");
const segment_v2 = @import("../segment_statement_v2.zig");
const global_v3 = @import("../segment_leaf_local_authority_v3.zig");
const projection_v3 = @import("../segment_leaf_local_projection_v3.zig");

test "leaf-local V3: deterministic local projection enters authenticated V2 custody" {
    const instructions = [_]u32{
        0x0010_0137,
        0x0550_0093,
        0x0011_2023,
        0x0001_2183,
        0x0010_8193,
        0x0000_006f,
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);
    var session = try runner.BaseExecutionSession.init(std.testing.allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left_result = try session.startSegment(3);
    defer left_result.deinit();
    var right_result = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_result.deinit();

    const states = States{
        .entry = try machineFromCpu(left_result.entry_cpu, segment_v2.snapshotDigest(left_result.rw_memory.words, .initial_word).id),
        .shared = try machineFromCpu(left_result.exit_cpu, segment_v2.snapshotDigest(left_result.rw_memory.words, .final_word).id),
        .exit = try machineFromCpu(right_result.exit_cpu, segment_v2.snapshotDigest(right_result.rw_memory.words, .final_word).id),
    };
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("program"),
            states.entry,
            states.exit,
            digest("input"),
            digest("output"),
            5,
        ),
        2,
    );
    const left_statement = try leafStatement(
        job,
        &left_result,
        states.entry,
        states.shared,
        try span.EdgeClaim.present(job.complete.public_input),
        span.EdgeClaim.absent(),
    );
    const right_statement = try leafStatement(
        job,
        &right_result,
        states.shared,
        states.exit,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(job.complete.public_output),
    );
    const left_global = try global_v3.SourceV3.fromSegmentResult(
        left_statement,
        &left_result,
    );
    const right_global = try global_v3.SourceV3.fromSegmentResult(
        right_statement,
        &right_result,
    );
    try global_v3.requireAdjacentSources(&left_global, &right_global);

    var left_projection = try projection_v3.ProjectionV3.init(&left_global);
    var right_projection = try projection_v3.ProjectionV3.init(&right_global);
    const session_id = digest("local-proof-session");
    const left_source = try left_projection.sourceV2(&left_global, session_id);
    const right_source = try right_projection.sourceV2(&right_global, session_id);

    const left_words = try encode(std.testing.allocator, &left_source);
    defer std.testing.allocator.free(left_words);
    const right_words = try encode(std.testing.allocator, &right_source);
    defer std.testing.allocator.free(right_words);
    const left_public = try public_data_v2.PublicDataV2.authenticate(left_words);
    const right_public = try public_data_v2.PublicDataV2.authenticate(right_words);
    const left_metadata = try left_public.metadata();
    const right_metadata = try right_public.metadata();
    try std.testing.expectEqual(@as(u32, 0), left_metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u32, 3), left_metadata.global_cycle_end);
    try std.testing.expectEqual(@as(u32, 0), right_metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u32, 2), right_metadata.global_cycle_end);
    try std.testing.expectEqual(@as(u32, 1), right_metadata.segment_index);
    try std.testing.expectError(
        error.JobMismatch,
        segment_v2.requireAdjacentSources(&left_source, &right_source),
    );

    left_projection.local_result.global_first_cycle = 2;
    try std.testing.expectError(
        error.LocalProjectionMismatch,
        left_projection.validateAgainst(&left_global),
    );
    left_projection.local_result.global_first_cycle = 1;
    right_projection.local_result.clock_frame = .leaf_local;
    try std.testing.expectError(
        error.LocalProjectionMismatch,
        right_projection.validateAgainst(&right_global),
    );
}

test "leaf-local V3: a globally positioned nonfinal leaf projects without a resume capability" {
    const instructions = [_]u32{
        0x0010_0137,
        0x0550_0093,
        0x0011_2023,
        0x0001_2183,
        0x0010_8193,
        0x0000_006f,
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);
    var session = try runner.BaseExecutionSession.init(std.testing.allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var first = try session.startSegment(2);
    defer first.deinit();
    var middle = try session.resumeSegment(first.continuation.?, 2);
    defer middle.deinit();
    var final = try session.resumeSegment(middle.continuation.?, 16);
    defer final.deinit();

    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("middle-program"),
            try machineFromCpu(first.entry_cpu, segment_v2.snapshotDigest(first.rw_memory.words, .initial_word).id),
            try machineFromCpu(final.exit_cpu, segment_v2.snapshotDigest(final.rw_memory.words, .final_word).id),
            digest("middle-input"),
            digest("middle-output"),
            5,
        ),
        3,
    );
    const statement = try leafStatement(
        job,
        &middle,
        try machineFromCpu(middle.entry_cpu, segment_v2.snapshotDigest(middle.rw_memory.words, .initial_word).id),
        try machineFromCpu(middle.exit_cpu, segment_v2.snapshotDigest(middle.rw_memory.words, .final_word).id),
        span.EdgeClaim.absent(),
        span.EdgeClaim.absent(),
    );
    const global = try global_v3.SourceV3.fromSegmentResult(statement, &middle);
    var projection = try projection_v3.ProjectionV3.init(&global);
    const local = try projection.sourceV2(&global, digest("middle-session"));
    try local.validate();
    try std.testing.expect(middle.global_first_cycle > 1);
    try std.testing.expect(middle.continuation != null);
    try std.testing.expect(projection.local_result.continuation != null);
    try std.testing.expectEqual(
        runner.SegmentClockFrame.global_continuous,
        projection.local_result.continuation.?.clock_frame,
    );
    try std.testing.expectEqual(@as(u64, 1), projection.local_result.global_first_cycle);
}

const States = struct {
    entry: span.MachineState,
    shared: span.MachineState,
    exit: span.MachineState,
};

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit,
            input,
            output,
        ),
    );
}

fn machineFromCpu(cpu: runner.Cpu, rw: span.Digest) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw, .{0} ** 8);
}

fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4c50_5633); // "LPV3"
}

test "leaf-local V3: shared canonical projection preserves native and AIR words" {
    const link_program = @import("../ethereum_leaf_link_program_v1.zig");
    const source_air = @import("../air/ethereum_leaf_link_source_v1.zig");
    const leaf_v2 = @import("../segment_leaf_authority_v2.zig");
    const metadata = try largePositionMetadata();
    const global = try span.SpanStatement.fromCanonicalWords(&metadata.base_statement_words);
    const executed = global.body.executed;
    // Retain the original semantic construction as an independent parity oracle.
    var complete = global.job.complete;
    complete.total_cycles = metadata.local_cycle_count;
    const expected = try span.SpanStatement.segmentLeaf(
        try span.JobContext.init(complete, global.job.segment_count),
        metadata.segment_index,
        try span.ExecutedSpan.init(metadata.segment_index, 1, 0, metadata.local_cycle_count, executed.entry, executed.exit, executed.input, executed.output),
    );
    const expected_words = try expected.canonicalWords();
    const local = try projection_v3.localStatementFromMetadata(&metadata);
    try std.testing.expectEqualDeep(expected_words, try local.canonicalWords());
    try std.testing.expectEqual(@as(u16, 1), projection_v3.CANONICAL_WORD_MAP_VERSION);
    try std.testing.expect(metadata.global_cycle_start > std.math.maxInt(u32));

    var program = try link_program.ProgramV1.init(std.testing.allocator);
    defer program.deinit();
    const metadata_words = try metadata.identityWords();
    var source_counts = [_]usize{0} ** 3;
    for (expected_words, 0..) |expected_word, index| {
        const row = program.projection_rows[span.SPAN_STATEMENT_CANONICAL_WORDS + index];
        try std.testing.expectEqual(@as(u32, 1), row.local_statement_mask);
        try std.testing.expectEqual(leaf_v2.WIRE_SCOPE, row.statement_scope);
        try std.testing.expectEqual(@as(u32, @intCast(segment_v2.fixed_layout.base_statement + index)), row.statement_index);
        if (row.raw_mask == 1) {
            try std.testing.expectEqual(source_air.METADATA_SCOPE, row.raw_scope);
            try std.testing.expectEqual(expected_word, metadata_words[row.raw_index]);
        } else {
            try std.testing.expectEqual(@as(u32, 1), row.constant_source_mask);
            try std.testing.expectEqual(M31.zero(), expected_word);
            try std.testing.expectEqual(@as(u32, 0), row.expected);
        }
        switch (try projection_v3.canonicalWordSourceV1(index)) {
            .global_word => source_counts[0] += 1,
            .local_cycle_count_limb => source_counts[1] += 1,
            .zero => source_counts[2] += 1,
        }
    }
    try std.testing.expectEqualDeep([_]usize{ 400, 4, 8 }, source_counts);
    // Exact existing routing geometry/claim and hash schedules remain unchanged.
    try std.testing.expectEqual(@as(usize, 42), link_program.TRANSCRIPT_CLAIM_COUNT);
    try std.testing.expectEqual(@as(usize, 84), link_program.POSEIDON_CALL_COUNT);
}

test "leaf-local V3: shared canonical projection rejects position and route mutations" {
    const link_program = @import("../ethereum_leaf_link_program_v1.zig");
    const metadata = try largePositionMetadata();
    var changed = metadata;
    changed.global_cycle_start += 1;
    try std.testing.expectError(error.GlobalPositionMismatch, projection_v3.localStatementFromMetadata(&changed));
    changed = metadata;
    changed.local_cycle_count += 1;
    changed.global_cycle_end += 1;
    try std.testing.expectError(error.GlobalPositionMismatch, projection_v3.localStatementFromMetadata(&changed));
    try std.testing.expectError(error.LocalProjectionMismatch, projection_v3.canonicalWordSourceV1(span.SPAN_STATEMENT_CANONICAL_WORDS));

    var program = try link_program.ProgramV1.init(std.testing.allocator);
    defer program.deinit();
    const row_index = span.SPAN_STATEMENT_CANONICAL_WORDS + span.canonical_layout.total_cycles_start;
    const original = program.projection_rows[row_index];
    // A global count word cannot substitute for the bounded native local count.
    program.projection_rows[row_index].raw_index = link_program.METADATA_BASE_START + span.canonical_layout.total_cycles_start;
    try std.testing.expectError(error.InvalidEthereumLeafLinkProgram, program.validate());
    program.projection_rows[row_index] = original;
    const count_source = link_program.METADATA_LOCAL_COUNT_START;
    program.source_rows[count_source].use_count -= 1;
    try std.testing.expectError(error.InvalidEthereumLeafLinkProgram, program.validate());
}

test "leaf-local V3: link schedule joins every directly equal V2 boundary field" {
    const link_program = @import("../ethereum_leaf_link_program_v1.zig");
    const source_air = @import("../air/ethereum_leaf_link_source_v1.zig");
    const leaf_v2 = @import("../segment_leaf_authority_v2.zig");

    var program = try link_program.ProgramV1.init(std.testing.allocator);
    defer program.deinit();
    const first = 2 * span.SPAN_STATEMENT_CANONICAL_WORDS +
        @import("../segment_leaf_local_verified_link_v3.zig").IDENTITY_WORDS;
    try std.testing.expectEqual(@as(usize, 168), link_program.BOUNDARY_JOIN_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 1117), link_program.PROJECTION_ROW_COUNT);
    for (0..2) |side| {
        const metadata_start = if (side == 0)
            link_program.METADATA_ENTRY_BOUNDARY_START
        else
            link_program.METADATA_EXIT_BOUNDARY_START;
        const wire_snapshot = if (side == 0)
            segment_v2.fixed_layout.entry_snapshot_id
        else
            segment_v2.fixed_layout.exit_snapshot_id;
        const wire_snapshot_count = if (side == 0)
            segment_v2.fixed_layout.entry_snapshot_count
        else
            segment_v2.fixed_layout.exit_snapshot_count;
        const wire_registers = if (side == 0)
            segment_v2.fixed_layout.entry_register_clocks
        else
            segment_v2.fixed_layout.exit_register_clocks;
        const wire_memory = if (side == 0)
            segment_v2.fixed_layout.entry_memory_clock_id
        else
            segment_v2.fixed_layout.exit_memory_clock_id;
        const wire_memory_count = if (side == 0)
            segment_v2.fixed_layout.entry_memory_clock_count
        else
            segment_v2.fixed_layout.exit_memory_clock_count;
        const pairs = [_]struct { metadata: usize, wire: usize, count: usize }{
            .{ .metadata = metadata_start, .wire = wire_snapshot, .count = 8 },
            .{ .metadata = metadata_start + 8, .wire = wire_snapshot_count, .count = 2 },
            .{ .metadata = metadata_start + 11, .wire = wire_registers, .count = 64 },
            .{ .metadata = metadata_start + 75, .wire = wire_memory, .count = 8 },
            .{ .metadata = metadata_start + 83, .wire = wire_memory_count, .count = 2 },
        };
        var at = first + side * 84;
        for (pairs) |pair| {
            for (0..pair.count) |offset| {
                const row = program.projection_rows[at];
                try std.testing.expectEqual(@as(u32, 1), row.raw_mask);
                try std.testing.expectEqual(@as(u32, 1), row.local_statement_mask);
                try std.testing.expectEqual(source_air.METADATA_SCOPE, row.raw_scope);
                try std.testing.expectEqual(leaf_v2.WIRE_SCOPE, row.statement_scope);
                try std.testing.expectEqual(@as(u32, @intCast(pair.metadata + offset)), row.raw_index);
                try std.testing.expectEqual(@as(u32, @intCast(pair.wire + offset)), row.statement_index);
                try std.testing.expectEqual(@as(u32, 2), program.source_rows[pair.metadata + offset].use_count);
                at += 1;
            }
        }
        try std.testing.expectEqual(first + (side + 1) * 84, at);
    }

    const target = first + 10; // first entry-register clock limb
    program.projection_rows[target].statement_index =
        segment_v2.fixed_layout.exit_register_clocks;
    try std.testing.expectError(error.InvalidEthereumLeafLinkProgram, program.validate());
}

test "leaf-local V3: typed position and completion routes are fixed" {
    const link_program = @import("../ethereum_leaf_link_program_v1.zig");
    const source_air = @import("../air/ethereum_leaf_link_source_v1.zig");
    const leaf_v2 = @import("../segment_leaf_authority_v2.zig");
    var program = try link_program.ProgramV1.init(std.testing.allocator);
    defer program.deinit();
    const first = 2 * span.SPAN_STATEMENT_CANONICAL_WORDS +
        @import("../segment_leaf_local_verified_link_v3.zig").IDENTITY_WORDS +
        link_program.BOUNDARY_JOIN_ROW_COUNT;
    try std.testing.expectEqual(@as(usize, 19), link_program.POSITION_AND_COMPLETION_JOIN_ROW_COUNT);
    try std.testing.expectEqual(@as(u32, 3), program.source_rows[link_program.METADATA_ENTRY_CONTINUATION_ROOT].use_count);
    try std.testing.expectEqual(@as(u32, 3), program.source_rows[link_program.METADATA_EXIT_CONTINUATION_ROOT].use_count);
    try std.testing.expectEqual(@as(u32, 2), program.source_rows[link_program.METADATA_COMPLETION_START].use_count);
    try std.testing.expectEqual(@as(u32, 4), program.source_rows[link_program.METADATA_GLOBAL_START].use_count);
    for (0..7) |offset| {
        const row = program.projection_rows[first + 12 + offset];
        try std.testing.expectEqual(@as(u32, 1), row.raw_mask);
        try std.testing.expectEqual(@as(u32, 1), row.local_statement_mask);
        try std.testing.expectEqual(source_air.METADATA_SCOPE, row.raw_scope);
        try std.testing.expectEqual(leaf_v2.WIRE_SCOPE, row.statement_scope);
        try std.testing.expectEqual(@as(u32, @intCast(link_program.METADATA_COMPLETION_START + 1 + offset)), row.raw_index);
        try std.testing.expectEqual(@as(u32, @intCast(segment_v2.fixed_layout.completion + 1 + offset)), row.statement_index);
    }
    const first_start_row = first + 4;
    try std.testing.expectEqual(@as(u32, @intCast(link_program.METADATA_GLOBAL_START)), program.projection_rows[first_start_row].raw_index);
    program.projection_rows[first_start_row].raw_join_index += 1;
    try std.testing.expectError(error.InvalidEthereumLeafLinkProgram, program.validate());
}

test "leaf-local V3: typed arithmetic pins semantic graph and accepts wide positions" {
    const arithmetic = @import("../air/ethereum_leaf_link_arithmetic_v1.zig");
    const witness = @import("../air/ethereum_leaf_link_arithmetic_witness_v1.zig");
    const lang = @import("../../air/lang/mod.zig");
    var definition = try arithmetic.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try arithmetic.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 28), plan.events.len);
    var degrees = try lang.degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(arithmetic.MAXIMUM_CONSTRAINT_DEGREE, degrees.maximumConstraintDegree());
    const actual_digest = try arithmetic.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualStrings(arithmetic.SEMANTIC_DIGEST_HEX, &std.fmt.bytesToHex(actual_digest, .lower));
    try std.testing.expectEqual(@as(usize, 31), definition.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 28), definition.arena.effectsView().len);
    for ([_]u32{ 0, 65535, 65536, 0x7fff_fffe }) |root| {
        const entry = try witness.logicalRow(.entry_root, root, false, 0, 0);
        const exit = try witness.logicalRow(.exit_root, root, false, 0, 0);
        try evaluateV3Arithmetic(&definition, &entry, true);
        try evaluateV3Arithmetic(&definition, &exit, true);
    }
    for ([_]bool{ false, true }) |present| {
        const row = try witness.logicalRow(.completion, 0, present, 0, 0);
        try evaluateV3Arithmetic(&definition, &row, true);
    }
    for ([_]struct { start: u64, count: u32 }{
        .{ .start = 0, .count = 1 },
        .{ .start = 0xffff, .count = 1 },
        .{ .start = (@as(u64, 1) << 40) + 0xffff_fffe, .count = 65539 },
        .{ .start = std.math.maxInt(u64) - 2, .count = 2 },
    }) |case| {
        const row = try witness.logicalRow(.position, 0, false, case.start, case.count);
        try evaluateV3Arithmetic(&definition, &row, true);
    }
    try std.testing.expectError(error.NonCanonicalContinuationRoot, witness.logicalRow(.entry_root, 0x7fff_ffff, false, 0, 0));
    try std.testing.expectError(error.GlobalCycleOverflow, witness.logicalRow(.position, 0, false, std.math.maxInt(u64), 1));
}

test "leaf-local V3: typed arithmetic rejects root, completion and carry mutations" {
    const arithmetic = @import("../air/ethereum_leaf_link_arithmetic_v1.zig");
    const witness = @import("../air/ethereum_leaf_link_arithmetic_witness_v1.zig");
    var definition = try arithmetic.build(std.testing.allocator);
    defer definition.deinit();
    var root = try witness.logicalRow(.entry_root, 0x1234_ffff, false, 0, 0);
    root[0] = root[0].add(M31.one());
    try evaluateV3Arithmetic(&definition, &root, false);
    root = try witness.logicalRow(.entry_root, 0x1234_ffff, false, 0, 0);
    root[2] = root[2].add(M31.one());
    try evaluateV3Arithmetic(&definition, &root, false);
    root = try witness.logicalRow(.exit_root, 0x7fff_fffe, false, 0, 0);
    root[7] = M31.zero(); // loses the 15-bit high-limb range certificate
    try evaluateV3Arithmetic(&definition, &root, false);
    root = try witness.logicalRow(.entry_root, 0, false, 0, 0);
    // 0x7fff_ffff reduces to zero in M31. The inverse-gap constraint must
    // reject this otherwise valid-looking pair of 16-bit wire limbs.
    root[1] = M31.fromCanonical(65535);
    root[2] = M31.fromCanonical(32767);
    root[3] = M31.fromCanonical(255);
    root[4] = M31.fromCanonical(255);
    root[5] = M31.fromCanonical(255);
    root[6] = M31.fromCanonical(127);
    root[7] = M31.fromCanonical(254);
    root[8] = M31.zero();
    try evaluateV3Arithmetic(&definition, &root, false);

    var completion = try witness.logicalRow(.completion, 0, true, 0, 0);
    completion[10] = M31.fromCanonical(@intFromEnum(segment_v2.Tag.completion_absent));
    try evaluateV3Arithmetic(&definition, &completion, false);
    completion = try witness.logicalRow(.completion, 0, true, 0, 0);
    completion[9] = M31.fromCanonical(2);
    try evaluateV3Arithmetic(&definition, &completion, false);

    var position = try witness.logicalRow(.position, 0, false, (@as(u64, 1) << 40) + 0xffff, 3);
    position[15] = position[15].add(M31.one()); // end low limb
    try evaluateV3Arithmetic(&definition, &position, false);
    position = try witness.logicalRow(.position, 0, false, (@as(u64, 1) << 40) + 0xffff, 3);
    position[21] = M31.zero(); // carry from first 16-bit limb
    try evaluateV3Arithmetic(&definition, &position, false);
    position = try witness.logicalRow(.position, 0, false, (@as(u64, 1) << 40) + 0xffff, 3);
    position[24] = position[24].add(M31.one()); // start byte
    try evaluateV3Arithmetic(&definition, &position, false);
}

fn evaluateV3Arithmetic(
    definition: *const @import("../air/ethereum_leaf_link_arithmetic_v1.zig").Definition,
    row: *const @import("../air/ethereum_leaf_link_arithmetic_v1.zig").Row,
    valid: bool,
) !void {
    const support = @import("../air/test_support.zig");
    const lang = @import("../../air/lang/mod.zig");
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, row);
    defer std.testing.allocator.free(values);
    var satisfied = true;
    for (definition.arena.constraintsView()) |constraint| {
        satisfied = satisfied and values[lang.types.idIndex(constraint.root)].isZero();
    }
    try std.testing.expectEqual(valid, satisfied);
}

fn largePositionMetadata() !global_v3.MetadataV3 {
    const first_cycle: u64 = (@as(u64, 1) << 40) + 0xfffe;
    const cycle_count: u32 = 0x10003;
    const entry = try span.MachineState.init(11, .{0} ** 32, digest("map-entry"), .{0} ** 8);
    const exit = try span.MachineState.init(12, .{0} ** 32, digest("map-exit"), .{0} ** 8);
    const job = try span.JobContext.init(try span.CompleteExecution.init(
        protocol.PROTOCOL_ID_WORDS,
        digest("map-program"),
        entry,
        exit,
        digest("map-input"),
        digest("map-output"),
        first_cycle + cycle_count + 9,
    ), 3);
    const statement = try span.SpanStatement.segmentLeaf(job, 1, try span.ExecutedSpan.init(
        1,
        1,
        first_cycle,
        cycle_count,
        entry,
        exit,
        span.EdgeClaim.absent(),
        span.EdgeClaim.absent(),
    ));
    const boundary: global_v3.BoundaryV3 = .{
        .snapshot_id = digest("map-snapshot"),
        .snapshot_count = 0,
        .continuation_root = 0,
        .register_clocks = .{0} ** 32,
        .memory_clock_id = segment_v2.memoryClockIdentity(&.{}),
        .memory_clock_count = 0,
    };
    const result: global_v3.MetadataV3 = .{
        .base_statement_words = try statement.canonicalWords(),
        .segment_index = 1,
        .segment_count = 3,
        .global_cycle_start = first_cycle,
        .global_cycle_end = first_cycle + cycle_count,
        .local_cycle_count = cycle_count,
        .entry = boundary,
        .exit = boundary,
        .completion = null,
    };
    try result.validate();
    return result;
}
