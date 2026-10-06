//! Shared two-leaf real-runner source for native V3 ingress gates.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const runner = frontend.runner;
const recursion = frontend.recursion;
const span = recursion.span_statement;
const segment_v2 = recursion.segment_statement_v2;
const channel = recursion.poseidon2_channel;

pub fn rightGlobal(
    allocator: std.mem.Allocator,
    left_result: *const runner.SegmentResult,
    right_result: *const runner.SegmentResult,
) !recursion.segment_leaf_local_authority_v3.SourceV3 {
    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        right_result.execution_trace.rows.items,
        right_result.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);
    const public_input = digest("native-local-v3-input");
    const public_output = digest("native-local-v3-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .initial_word).id,
        digest("native-local-v3-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .final_word).id,
        digest("native-local-v3-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotIdentity(right_result.rw_memory.words, .final_word).id,
        digest("native-local-v3-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const statement = try span.SpanStatement.segmentLeaf(
        job,
        right_result.segment_index,
        try span.ExecutedSpan.init(
            right_result.segment_index,
            1,
            right_result.global_first_cycle - 1,
            @intCast(right_result.cycle_count),
            shared_state,
            final_state,
            span.EdgeClaim.absent(),
            try span.EdgeClaim.present(public_output),
        ),
    );
    return recursion.segment_leaf_local_authority_v3.SourceV3.fromSegmentResult(
        statement,
        right_result,
    );
}

fn machineState(cpu: runner.Cpu, rw_memory: span.Digest, public_io_state: span.Digest) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4e56_3250); // "NV2P"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}
