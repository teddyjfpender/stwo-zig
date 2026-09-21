//! Shared, deterministic two-segment fixture for PublicDataV2 tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const public_data = @import("public_data.zig");
const memory_state = @import("../runner/memory_state.zig");
const runner_result = @import("../runner/result.zig");
const Cpu = @import("../runner/cpu.zig").Cpu;
const channel = @import("../recursion/poseidon2_channel.zig");
const protocol = @import("../recursion/protocol.zig");
const segment_v2 = @import("../recursion/segment_statement_v2.zig");
const span = @import("../recursion/span_statement.zig");

pub const Fixture = struct {
    job: span.JobContext,
    statements: [2]span.SpanStatement,
    left_words: [2]memory_state.WordState,
    right_words: [2]memory_state.WordState,
    left_exit_memory_clocks: [1]runner_result.MemoryAccessClock,
    right_entry_memory_clocks: [1]runner_result.MemoryAccessClock,
    right_exit_memory_clocks: [2]runner_result.MemoryAccessClock,
    left_entry_register_clocks: [32]u32,
    left_exit_register_clocks: [32]u32,
    right_exit_register_clocks: [32]u32,

    pub fn init() !Fixture {
        return initWithRegister7(0);
    }

    /// Same program, clocks and sparse-memory topology; x7 is unchanged by
    /// this execution. Build every statement identity from the selected state.
    pub fn initWithRegister7(value: u32) !Fixture {
        const left_words: [2]memory_state.WordState = .{
            .{
                .addr = 0x2000,
                .initial_word = 11,
                .final_word = 12,
                .final_clock = 3,
            },
            .{
                .addr = 0x2004,
                .initial_word = 0,
                .final_word = 0,
                .final_clock = 0,
            },
        };
        const right_words: [2]memory_state.WordState = .{
            .{
                .addr = 0x2000,
                .initial_word = 12,
                .final_word = 13,
                .final_clock = 7,
            },
            .{
                .addr = 0x2004,
                .initial_word = 0,
                .final_word = 9,
                .final_clock = 6,
            },
        };
        var state0 = try machineState(0x1000, 0, segment_v2.snapshotDigest(&left_words, .initial_word).id);
        var state1 = try machineState(0x1008, 1, segment_v2.snapshotDigest(&left_words, .final_word).id);
        var state2 = try machineState(0x1010, 2, segment_v2.snapshotDigest(&right_words, .final_word).id);
        state0.registers[7] = value;
        state1.registers[7] = value;
        state2.registers[7] = value;
        const job = try span.JobContext.init(
            try span.CompleteExecution.init(
                protocol.PROTOCOL_ID_WORDS,
                scalarDigest(123),
                state0,
                state2,
                id("input"),
                id("output"),
                4,
            ),
            2,
        );
        const entry_register_clocks = [_]u32{0} ** 32;
        var middle_register_clocks = entry_register_clocks;
        middle_register_clocks[1] = 2;
        var exit_register_clocks = middle_register_clocks;
        exit_register_clocks[1] = 5;
        return .{
            .job = job,
            .statements = .{
                try span.SpanStatement.segmentLeaf(
                    job,
                    0,
                    try span.ExecutedSpan.init(
                        0,
                        1,
                        0,
                        2,
                        state0,
                        state1,
                        try span.EdgeClaim.present(id("input")),
                        span.EdgeClaim.absent(),
                    ),
                ),
                try span.SpanStatement.segmentLeaf(
                    job,
                    1,
                    try span.ExecutedSpan.init(
                        1,
                        1,
                        2,
                        2,
                        state1,
                        state2,
                        span.EdgeClaim.absent(),
                        try span.EdgeClaim.present(id("output")),
                    ),
                ),
            },
            .left_words = left_words,
            .right_words = right_words,
            .left_exit_memory_clocks = .{.{ .addr = 0x2000, .clock = 3 }},
            .right_entry_memory_clocks = .{.{ .addr = 0x2000, .clock = 3 }},
            .right_exit_memory_clocks = .{
                .{ .addr = 0x2000, .clock = 7 },
                .{ .addr = 0x2004, .clock = 6 },
            },
            .left_entry_register_clocks = entry_register_clocks,
            .left_exit_register_clocks = middle_register_clocks,
            .right_exit_register_clocks = exit_register_clocks,
        };
    }

    pub fn leftSource(self: *const Fixture) segment_v2.SourceV2 {
        return .{
            .session_id = id("session"),
            .base_statement = self.statements[0],
            .segment_index = 0,
            .segment_role = .{ .is_first = true, .is_last = false },
            .global_first_cycle = 1,
            .cycle_count = 2,
            .entry_cpu = cpuFromMachine(self.job.complete.initial_state),
            .exit_cpu = cpuFromMachine(self.statements[0].body.executed.exit),
            .completion = null,
            .continuation_present = true,
            .public_input_custody = true,
            .public_output_custody = false,
            .memory_words = &self.left_words,
            .entry_register_clocks = self.left_entry_register_clocks,
            .exit_register_clocks = self.left_exit_register_clocks,
            .entry_memory_clocks = &.{},
            .exit_memory_clocks = &self.left_exit_memory_clocks,
        };
    }

    /// Rebuild the job and Span when a test substitutes untouched sparse memory.
    pub fn leftSourceWithUntouchedMemory(self: *const Fixture, words: []const memory_state.WordState) !segment_v2.SourceV2 {
        for (words) |word| {
            if (word.initial_word != word.final_word or word.final_clock != 0)
                return error.InvalidUntouchedMemoryFixture;
        }
        const old = self.job.complete;
        const executed = self.statements[0].body.executed;
        var entry = executed.entry;
        var exit = executed.exit;
        entry.rw_memory = segment_v2.snapshotDigest(words, .initial_word).id;
        exit.rw_memory = segment_v2.snapshotDigest(words, .final_word).id;
        const job = try span.JobContext.init(try span.CompleteExecution.init(
            old.protocol_id,
            old.program,
            entry,
            old.final_state,
            old.public_input,
            old.public_output,
            old.total_cycles,
        ), self.job.segment_count);
        var source = self.leftSource();
        source.base_statement = try span.SpanStatement.segmentLeaf(job, 0, try span.ExecutedSpan.init(
            executed.first_segment,
            executed.segment_count,
            executed.first_cycle,
            executed.cycle_count,
            entry,
            exit,
            executed.input,
            executed.output,
        ));
        source.memory_words = words;
        source.entry_memory_clocks = &.{};
        source.exit_memory_clocks = &.{};
        try source.validate();
        return source;
    }

    pub fn rightSource(self: *const Fixture) segment_v2.SourceV2 {
        return .{
            .session_id = id("session"),
            .base_statement = self.statements[1],
            .segment_index = 1,
            .segment_role = .{ .is_first = false, .is_last = true },
            .global_first_cycle = 3,
            .cycle_count = 2,
            .entry_cpu = cpuFromMachine(self.statements[1].body.executed.entry),
            .exit_cpu = cpuFromMachine(self.job.complete.final_state),
            .completion = .{
                .kind = .unretired_self_loop,
                .address = self.job.complete.final_state.pc,
                .value = public_data.CANONICAL_SELF_LOOP_WORD,
                .clock = 0,
            },
            .continuation_present = false,
            .public_input_custody = false,
            .public_output_custody = true,
            .memory_words = &self.right_words,
            .entry_register_clocks = self.left_exit_register_clocks,
            .exit_register_clocks = self.right_exit_register_clocks,
            .entry_memory_clocks = &self.right_entry_memory_clocks,
            .exit_memory_clocks = &self.right_exit_memory_clocks,
        };
    }
};

pub fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

pub fn id(label: []const u8) segment_v2.Digest {
    return channel.hashBytes(label, 0x5032_5453); // "P2TS"
}

pub fn scalarDigest(value: u32) segment_v2.Digest {
    var digest = [_]u32{0} ** channel.RATE;
    digest[0] = value;
    return digest;
}

pub fn writeU32(words: *[2]M31, value: u32) void {
    words[0] = M31.fromCanonical(value & 0xffff);
    words[1] = M31.fromCanonical(value >> 16);
}

fn machineState(pc: u32, value: u32, rw_digest: channel.Digest) !span.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = value;
    return span.MachineState.init(pc, registers, rw_digest, .{0} ** 8);
}

fn cpuFromMachine(machine: span.MachineState) Cpu {
    return .{ .pc = machine.pc, .regs = machine.registers };
}

/// Rebuild the complete job and terminal Span after changing actual sparse
/// memory. This uses canonical admission, never a forged wire or native receipt.
pub fn sparseValueCanonicalWords(allocator: std.mem.Allocator, value: u32) ![]M31 {
    var fixture = try Fixture.init();
    fixture.right_words[0].final_word = value;
    const old = fixture.job.complete;
    var final_state = old.final_state;
    final_state.rw_memory = segment_v2.snapshotDigest(&fixture.right_words, .final_word).id;
    fixture.job = try span.JobContext.init(try span.CompleteExecution.init(
        old.protocol_id,
        old.program,
        old.initial_state,
        final_state,
        old.public_input,
        old.public_output,
        old.total_cycles,
    ), fixture.job.segment_count);
    const executed = fixture.statements[1].body.executed;
    fixture.statements[1] = try span.SpanStatement.segmentLeaf(fixture.job, 1, try span.ExecutedSpan.init(
        executed.first_segment,
        executed.segment_count,
        executed.first_cycle,
        executed.cycle_count,
        executed.entry,
        final_state,
        executed.input,
        executed.output,
    ));
    const source = fixture.rightSource();
    try source.validate();
    const words = try encode(allocator, &source);
    errdefer allocator.free(words);
    _ = try segment_v2.authenticateCanonicalWire(words);
    return words;
}
