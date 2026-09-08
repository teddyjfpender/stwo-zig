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

    pub fn init(allocator: std.mem.Allocator, address_count: usize) !OwnedPair {
        const elf = try fixture.buildRecursionMemory(address_count);
        var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
        defer session.deinit();
        var first = try session.startSegment(first_steps);
        errdefer first.deinit();
        const continuation = first.base.continuation orelse return error.ExpectedFirstSegmentContinuation;
        var second = try session.resumeSegment(continuation, second_budget);
        errdefer second.deinit();
        var result = OwnedPair{ .first = first, .second = second, .address_count = address_count };
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
        try model.validateSegment(&self.first.base, self.address_count, first_steps, first_steps);
        try model.validateCompletedSegment(&self.second.base, self.address_count, total_steps, second_steps);
        try std.testing.expectEqual(@as(u32, 0), self.first.base.segment_index);
        try std.testing.expectEqual(@as(u32, 1), self.second.base.segment_index);
        try std.testing.expect(self.first.base.segment_role.is_first);
        try std.testing.expect(!self.second.base.segment_role.is_first);
        try std.testing.expectEqualDeep(self.first.base.exit_cpu, self.second.base.entry_cpu);
        try std.testing.expectEqualDeep(self.first.base.rw_memory.program_words, self.second.base.rw_memory.program_words);
    }

    /// Full mutable-input admission, using the canonical V2 and span owners.
    /// Keys, circuit profiles, canonical wire allocation and proofs belong to
    /// the caller. No cached validation state is published by this helper.
    pub fn admitStatements(self: *const OwnedPair, session_id: span.Digest, statements: [2]span.SpanStatement) !Admission {
        try self.validate();
        const sources = [2]wire.SourceV2{
            try wire.SourceV2.fromSegmentResult(session_id, statements[0], &self.first.base),
            try wire.SourceV2.fromSegmentResult(session_id, statements[1], &self.second.base),
        };
        try wire.requireAdjacentSources(&sources[0], &sources[1]);
        return .{ .sources = sources, .folded = try span.SpanStatement.fold(statements[0], statements[1]) };
    }
};

/// Execution/source-admission gate, deliberately requiring no native proof.
pub fn checkWorkload(allocator: std.mem.Allocator) !void {
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
    var program = try frontend.air.program.commitment.buildDeclared(allocator, pair.first.base.execution_trace.rows.items, pair.first.base.rw_memory.program_words, null);
    defer program.deinit(allocator);
    const io = digest("two-segment-memory-empty-io");
    const input = digest("two-segment-memory-input");
    const output = digest("two-segment-memory-output");
    const initial = try span.MachineState.init(pair.first.base.entry_cpu.pc, pair.first.base.entry_cpu.regs, wire.snapshotDigest(pair.first.base.rw_memory.words, .initial_word).id, io);
    const shared = try span.MachineState.init(pair.first.base.exit_cpu.pc, pair.first.base.exit_cpu.regs, wire.snapshotDigest(pair.first.base.rw_memory.words, .final_word).id, io);
    const final = try span.MachineState.init(pair.second.base.exit_cpu.pc, pair.second.base.exit_cpu.regs, wire.snapshotDigest(pair.second.base.rw_memory.words, .final_word).id, io);
    var program_digest: span.Digest = @splat(0);
    program_digest[0] = program.tree.root;
    const job = try span.JobContext.init(try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, program_digest, initial, final, input, output, total_steps), 2);
    return .{
        try span.SpanStatement.segmentLeaf(job, pair.first.base.segment_index, try span.ExecutedSpan.init(pair.first.base.segment_index, 1, pair.first.base.global_first_cycle - 1, first_steps, initial, shared, try span.EdgeClaim.present(input), span.EdgeClaim.absent())),
        try span.SpanStatement.segmentLeaf(job, pair.second.base.segment_index, try span.ExecutedSpan.init(pair.second.base.segment_index, 1, pair.second.base.global_first_cycle - 1, second_steps, shared, final, span.EdgeClaim.absent(), try span.EdgeClaim.present(output))),
    };
}

fn digest(label: []const u8) span.Digest {
    return recursion.poseidon2_channel.hashBytes(label, 0x5632_504f);
}

test "two-segment memory witnesses close a complete execution with canonical admission" {
    try checkWorkload(std.testing.allocator);
}
