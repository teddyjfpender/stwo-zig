//! Two owned, consecutive memory witnesses for a complete tiny execution.
//! This materializes inputs only; it does not prove either child or a parent.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const runner = frontend.runner;
const recursion = frontend.recursion;
const span = recursion.span_statement;
const wire = recursion.segment_statement_v2;
const model = @import("recursive_segment_v2_memory_workload_test_support.zig");
const fixture = frontend.testing.guest_precompile_test_elf;

pub const first_steps = model.native_steps;
pub const total_steps: usize = 2 + 3 * fixture.recursion_memory_updates;
pub const second_steps = total_steps - first_steps;
// The existing final JAL x0,0 is an unretired completion observation. A budget
// of 34 stops before observing it; 35 returns 34 retired rows and completion.
pub const second_budget = second_steps + 1;

pub const Admission = struct {
    /// Borrow the pair's owned memory/clock arrays. Do not retain after pair
    /// destruction or mutate the pair while consuming these sources.
    sources: [2]wire.SourceV2,
    folded: span.SpanStatement,
};

pub const OwnedPair = struct {
    first: runner.Poseidon2SegmentResult,
    second: runner.Poseidon2SegmentResult,
    address_count: usize,
    initial_memory_word: u32,

    pub fn init(allocator: std.mem.Allocator, address_count: usize) !OwnedPair {
        return initWithMemorySeed(allocator, address_count, 0);
    }

    pub fn initWithMemorySeed(allocator: std.mem.Allocator, address_count: usize, initial_word: u32) !OwnedPair {
        const segments = try model.materialize(2, allocator, address_count, initial_word);
        var first = segments[0];
        errdefer first.deinit();
        var second = segments[1];
        errdefer second.deinit();
        var result = OwnedPair{ .first = first, .second = second, .address_count = address_count, .initial_memory_word = initial_word };
        try result.validate();
        // Runner publication transfers trace, tracker, frozen call/row buffers,
        // captured IO, snapshots and copied access clocks into each result.
        // Snapshot.program_words owns copied WordStates, not ELF/session memory.
        // No session/ELF pointer survives; checkWorkload validates after teardown.
        return result;
    }

    pub fn deinit(self: *OwnedPair) void {
        self.second.deinit();
        self.first.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedPair) !void {
        try validateSegments(2, .{ &self.first.base, &self.second.base }, self.address_count, self.initial_memory_word);
    }

    /// Full mutable-input admission, using the canonical V2 and span owners.
    /// Keys, circuit profiles, canonical wire allocation and proofs belong to
    /// the caller. No cached validation state is published by this helper.
    pub fn admitStatements(self: *const OwnedPair, session_id: span.Digest, statements: [2]span.SpanStatement) !Admission {
        try self.validate();
        const admitted = try admitSegments(2, .{ &self.first.base, &self.second.base }, session_id, statements);
        return .{ .sources = admitted.sources, .folded = admitted.folded };
    }
};

/// Execution/source-admission gate, deliberately requiring no native proof.
pub fn checkWorkload(allocator: std.mem.Allocator) !void {
    var reference_pair: ?OwnedPair = null;
    defer if (reference_pair) |*pair| pair.deinit();
    for ([_]u32{ 13, 14, 269 }) |seed| {
        var pair = try OwnedPair.initWithMemorySeed(allocator, 1, seed);
        defer pair.deinit();
        try pair.validate();
        const statements = try fixtureStatements(allocator, &pair);
        const admission = try pair.admitStatements(digest("two-segment-seeded-memory-session"), statements);
        _ = try span.RootStatement.init(admission.folded);
        if (reference_pair) |*reference| {
            try std.testing.expectEqualDeep(reference.first.base.rw_memory.program_words, pair.first.base.rw_memory.program_words);
        } else {
            reference_pair = try OwnedPair.initWithMemorySeed(allocator, 1, seed);
        }
        for (pair.first.base.rw_memory.words) |*word| {
            if (word.addr != fixture.recursion_memory_base) continue;
            const saved = word.initial_word;
            defer word.initial_word = saved;
            word.initial_word ^= 1;
            try std.testing.expectError(error.TestExpectedEqual, pair.validate());
            break;
        }
        std.debug.print("SEGMENT_V2_SEEDED_MEMORY_EXECUTION initial_word={d} address_count=1 elf_unchanged=true completed=true canonical_adjacent=true proofs_created=0\n", .{seed});
    }
    for (fixture.recursion_memory_address_counts) |address_count| {
        var pair = try OwnedPair.init(allocator, address_count);
        defer pair.deinit();
        // init's session and stack ELF have already been destroyed here.
        try pair.validate();
        const statements = try fixtureStatements(allocator, &pair);
        const session_id = digest("two-segment-memory-session");
        const admitted = try pair.admitStatements(session_id, statements);
        _ = try span.RootStatement.init(admitted.folded);
        try std.testing.expectEqual(@as(u64, total_steps), admitted.folded.body.executed.cycle_count);
        try std.testing.expectError(error.SlotsNotAdjacent, span.SpanStatement.fold(statements[1], statements[0]));
        try std.testing.expectError(error.SlotsNotAdjacent, span.SpanStatement.fold(statements[0], statements[0]));
        try std.testing.expectError(error.NonAdjacentPosition, wire.requireAdjacentSources(&admitted.sources[1], &admitted.sources[0]));
        try std.testing.expectError(error.NonAdjacentPosition, wire.requireAdjacentSources(&admitted.sources[0], &admitted.sources[0]));
        var gap = statements[0];
        gap.body.executed.cycle_count -= 1;
        try gap.validate();
        try std.testing.expectError(error.CycleDiscontinuity, span.SpanStatement.fold(gap, statements[1]));
        var changed_state = statements[1];
        changed_state.body.executed.entry.registers[5] ^= 1;
        try changed_state.validate();
        try std.testing.expectError(error.StateDiscontinuity, span.SpanStatement.fold(statements[0], changed_state));
        try std.testing.expectError(error.BaseStatementMismatch, wire.SourceV2.fromSegmentResult(session_id, changed_state, &pair.second.base));
        // The old prefix validator must not bless a terminal child, and the
        // explicit completed validator must not bless the first prefix.
        try std.testing.expectError(error.TestUnexpectedResult, model.validateSegment(&pair.second.base, address_count, total_steps, second_steps));
        try std.testing.expectError(error.TestExpectedEqual, model.validateCompletedSegment(&pair.first.base, address_count, first_steps, first_steps));
        {
            const original = pair.second.base.execution_trace.rows.items[0].mem_val;
            defer pair.second.base.execution_trace.rows.items[0].mem_val = original;
            // Step 64 is the pending store after the first segment's load/add.
            pair.second.base.execution_trace.rows.items[0].mem_val ^= 1;
            try std.testing.expectError(error.TestExpectedEqual, pair.validate());
        }
        std.debug.print("SEGMENT_V2_TWO_SEGMENT_WORKLOAD address_count={d} first_retired={d} second_retired={d} second_budget={d} completed=true canonical_adjacent=true session_destroyed=true proofs_created=0\n", .{ address_count, first_steps, second_steps, second_budget });
    }
}

// Test-only statement construction uses existing canonical identities and
// constructors. It does not supply an admitted verifier key or a proof.
pub fn fixtureStatements(allocator: std.mem.Allocator, pair: *const OwnedPair) ![2]span.SpanStatement {
    return fixtureStatementsForSegments(2, allocator, .{ &pair.first.base, &pair.second.base });
}

pub fn validateSegments(comptime count: usize, results: [count]*const runner.SegmentResult, address_count: usize, seed: u32) !void {
    const updates = model.updatesForSegments(count);
    var cumulative: usize = 0;
    for (results, 0..) |result, index| {
        const steps = if (index + 1 == count) 2 + 3 * updates - model.native_steps * (count - 1) else model.native_steps;
        cumulative += steps;
        try model.validateSeededSegmentWithUpdates(result, address_count, cumulative, steps, index + 1 == count, seed, updates);
        try std.testing.expectEqual(@as(u32, @intCast(index)), result.segment_index);
        try std.testing.expectEqual(index == 0, result.segment_role.is_first);
        try std.testing.expectEqualDeep(results[0].rw_memory.program_words, result.rw_memory.program_words);
        if (index != 0) try std.testing.expectEqualDeep(results[index - 1].exit_cpu, result.entry_cpu);
    }
}

pub fn fixtureStatementsForSegments(comptime count: usize, allocator: std.mem.Allocator, results: [count]*const runner.SegmentResult) ![count]span.SpanStatement {
    var program = try frontend.air.program.commitment.buildDeclared(allocator, results[0].execution_trace.rows.items, results[0].rw_memory.program_words, null);
    defer program.deinit(allocator);
    // Preserve the original fixture identities, including the two-segment key.
    const io = digest("two-segment-memory-empty-io");
    const input = digest("two-segment-memory-input");
    const output = digest("two-segment-memory-output");
    var states: [count + 1]span.MachineState = undefined;
    states[0] = try span.MachineState.init(results[0].entry_cpu.pc, results[0].entry_cpu.regs, wire.snapshotDigest(results[0].rw_memory.words, .initial_word).id, io);
    var cycles: u64 = 0;
    for (results, 0..) |result, index| {
        states[index + 1] = try span.MachineState.init(result.exit_cpu.pc, result.exit_cpu.regs, wire.snapshotDigest(result.rw_memory.words, .final_word).id, io);
        cycles += result.cycle_count;
    }
    var program_digest: span.Digest = @splat(0);
    program_digest[0] = program.tree.root;
    const job = try span.JobContext.init(try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, program_digest, states[0], states[count], input, output, cycles), count);
    var statements: [count]span.SpanStatement = undefined;
    for (results, 0..) |result, index| {
        statements[index] = try span.SpanStatement.segmentLeaf(job, result.segment_index, try span.ExecutedSpan.init(result.segment_index, 1, result.global_first_cycle - 1, result.cycle_count, states[index], states[index + 1], if (index == 0) try span.EdgeClaim.present(input) else span.EdgeClaim.absent(), if (index + 1 == count) try span.EdgeClaim.present(output) else span.EdgeClaim.absent()));
    }
    return statements;
}

pub fn SegmentAdmission(comptime count: usize) type {
    return struct { sources: [count]wire.SourceV2, folded: span.SpanStatement };
}

pub fn admitSegments(comptime count: usize, results: [count]*const runner.SegmentResult, session_id: span.Digest, statements: [count]span.SpanStatement) !SegmentAdmission(count) {
    var sources: [count]wire.SourceV2 = undefined;
    for (results, statements, 0..) |result, statement, index| {
        sources[index] = try wire.SourceV2.fromSegmentResult(session_id, statement, result);
        if (index != 0) try wire.requireAdjacentSources(&sources[index - 1], &sources[index]);
    }
    var level = statements;
    var width: usize = count;
    while (width > 1) : (width /= 2) {
        for (0..width / 2) |index| level[index] = try span.SpanStatement.fold(level[2 * index], level[2 * index + 1]);
    }
    _ = try span.RootStatement.init(level[0]);
    return .{ .sources = sources, .folded = level[0] };
}

pub fn checkSegmentLadder(allocator: std.mem.Allocator) !void {
    try checkWorkload(allocator);
    inline for (.{ 1, 2, 4, 8 }) |count| {
        for ([_]usize{ 1, 4, 16 }) |addresses| {
            var segments = try model.materialize(count, allocator, addresses, 13);
            defer for (&segments) |*segment| segment.deinit();
            var results: [count]*const runner.SegmentResult = undefined;
            for (&segments, 0..) |*segment, index| results[index] = &segment.base;
            try validateSegments(count, results, addresses, 13);
            const statements = try fixtureStatementsForSegments(count, allocator, results);
            const admitted = try admitSegments(count, results, digest("recursive-v2-session"), statements);
            for (1..count) |index| {
                const left_words = try allocator.alloc(@import("stwo_core").fields.m31.M31, try admitted.sources[index - 1].canonicalWordCount());
                defer allocator.free(left_words);
                const right_words = try allocator.alloc(@import("stwo_core").fields.m31.M31, try admitted.sources[index].canonicalWordCount());
                defer allocator.free(right_words);
                _ = try admitted.sources[index - 1].encodeCanonical(left_words);
                _ = try admitted.sources[index].encodeCanonical(right_words);
                _ = try wire.authenticateAdjacentCanonicalWires(left_words, right_words);
                if (index % 2 == 0) try std.testing.expectError(error.SlotsMisaligned, span.SpanStatement.fold(statements[index - 1], statements[index]));
                try std.testing.expectError(error.NonAdjacentPosition, wire.requireAdjacentSources(&admitted.sources[index], &admitted.sources[index - 1]));
                try std.testing.expectError(error.NonAdjacentPosition, wire.requireAdjacentSources(&admitted.sources[index], &admitted.sources[index]));
            }
            // Change an actual middle segment boundary after session teardown.
            const saved = segments[count / 2].base.entry_cpu.regs[5];
            segments[count / 2].base.entry_cpu.regs[5] ^= 1;
            try std.testing.expectError(error.BaseStatementMismatch, wire.SourceV2.fromSegmentResult(digest("recursive-v2-session"), statements[count / 2], &segments[count / 2].base));
            segments[count / 2].base.entry_cpu.regs[5] = saved;
            std.debug.print("SEGMENT_V2_SEGMENT_LADDER segments={d} addresses={d} retired={d} session_destroyed=true canonical_root=true proofs_created=0\n", .{ count, addresses, admitted.folded.body.executed.cycle_count });
        }
    }
}

fn digest(label: []const u8) span.Digest {
    return recursion.poseidon2_channel.hashBytes(label, 0x5632_504f);
}

test "two-segment memory witnesses close a complete execution with canonical admission" {
    try checkWorkload(std.testing.allocator);
}
