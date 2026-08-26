//! Soundness, determinism, allocation, and hot-replay tests for row 11.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const circuit_mod = @import("statement_semantics_circuit.zig");
const row11 = @import("air/statement_semantics_input_witness.zig");
const statement = @import("span_statement.zig");
const layout = statement.canonical_layout;

test "R-012 statement semantics circuit has exact sealed row-11 geometry" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    try circuit.validate();

    try std.testing.expectEqual(circuit_mod.INPUT_COUNT, circuit.inputBindings().len);
    try std.testing.expectEqual(circuit_mod.NODE_COUNT, circuit.nodeCount());
    try std.testing.expectEqual(circuit_mod.OUTPUT_COUNT, circuit.outputCount());
    try std.testing.expectEqualSlices(
        u8,
        &circuit_mod.IDENTITY_DIGEST,
        &circuit.identity_digest,
    );

    var statement_count: usize = 0;
    var selector_count: usize = 0;
    var private_count: usize = 0;
    for (circuit.inputBindings(), 0..) |binding, input_id| {
        try std.testing.expectEqual(
            circuit.graph().inputNodes()[input_id],
            binding.node_id,
        );
        try std.testing.expectEqual(
            try circuit.graph().inputUseCount(@intCast(input_id)),
            binding.use_count,
        );
        switch (binding.source) {
            .statement => statement_count += 1,
            .selector => selector_count += 1,
            .private => private_count += 1,
        }
    }
    try std.testing.expectEqual(circuit_mod.STATEMENT_INPUT_COUNT, statement_count);
    try std.testing.expectEqual(circuit_mod.SELECTOR_INPUT_COUNT, selector_count);
    try std.testing.expectEqual(circuit_mod.PRIVATE_INPUT_COUNT, private_count);

    var preprocessing = try row11.Preprocessed.init(
        std.testing.allocator,
        11,
        circuit.inputBindings(),
    );
    defer preprocessing.deinit();
    try preprocessing.validate();
}

test "R-012 statement semantics graph identity and use counts are deterministic" {
    var first = try circuit_mod.build(std.testing.allocator);
    defer first.deinit();
    var second = try circuit_mod.build(std.testing.allocator);
    defer second.deinit();

    try std.testing.expectEqualSlices(u8, &first.identity_digest, &second.identity_digest);
    try std.testing.expectEqualSlices(u32, first.graph().outputs(), second.graph().outputs());
    try std.testing.expectEqualSlices(u32, first.graph().useCounts(), second.graph().useCounts());
    for (first.graph().nodes(), second.graph().nodes()) |lhs, rhs| {
        try std.testing.expect(std.meta.eql(lhs, rhs));
    }
    for (first.inputBindings(), second.inputBindings()) |lhs, rhs| {
        try std.testing.expect(std.meta.eql(lhs, rhs));
    }

    first.identity_digest[0] ^= 1;
    try std.testing.expectError(error.CircuitIdentityMismatch, first.validate());
}

test "R-012 every canonical segment empty and binary body mode satisfies row 11" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);

    const job3 = try fixtureJob(3, 12);
    for ([_]u32{ 0, 1, 2 }) |index| {
        const leaf = try fixtureLeaf(
            job3,
            index,
            @as(u64, index) * 4,
            4,
            try fixtureState(index),
            try fixtureState(index + 1),
        );
        const leaf_words = try leaf.canonicalWords();
        try expectSatisfied(
            &circuit,
            circuit_mod.Witness.forSegment(&leaf_words),
            inputs,
            values,
        );
    }

    const empty = try statement.SpanStatement.emptyLeaf(job3, 3);
    const empty_words = try empty.canonicalWords();
    try expectSatisfied(
        &circuit,
        circuit_mod.Witness.forEmpty(&empty_words),
        inputs,
        values,
    );

    const executed = try twoExecuted();
    try expectTripleSatisfied(&circuit, executed, inputs, values);
    const padded = try executedAndEmpty();
    try expectTripleSatisfied(&circuit, padded, inputs, values);
    const empty_pair = try twoEmpty();
    try expectTripleSatisfied(&circuit, empty_pair, inputs, values);
}

test "R-012 binary statement mutations cannot cross any fold boundary" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);

    for (std.enums.values(BinaryMutation)) |mutation| {
        const triple = try twoExecuted();
        var left = try triple.left.canonicalWords();
        var right = try triple.right.canonicalWords();
        var parent = try triple.parent.canonicalWords();
        switch (mutation) {
            .right_job => right[layout.protocol_start] = word(99),
            .right_node => right[layout.slot_node_index_start] = word(2),
            .parent_node => parent[layout.slot_node_index_start] = word(1),
            .right_height => right[layout.slot_height] = word(1),
            .parent_height => parent[layout.slot_height] = word(2),
            .right_first_segment => right[layout.first_segment_start] = word(2),
            .right_first_cycle => right[layout.first_cycle_start] = word(5),
            .right_entry_state => right[
                layout.entry_state_start + layout.machine_state_pc_start_offset
            ] = word(99),
            .left_output => left[layout.output_edge_tag] = word(
                @intFromEnum(statement.Tag.present_edge),
            ),
            .right_input => right[layout.input_edge_tag] = word(
                @intFromEnum(statement.Tag.present_edge),
            ),
            .parent_segment_count => parent[layout.executed_segment_count_start] = word(3),
            .swapped_children => std.mem.swap(statement.StatementWords, &left, &right),
        }
        try expectUnsatisfied(
            &circuit,
            circuit_mod.Witness.forBinary(&left, &right, &parent),
            inputs,
            values,
        );
    }
}

test "R-012 adversarial leaf mutations fail their explicit equations" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);

    for (std.enums.values(LeafMutation)) |mutation| {
        if (mutation == .empty_payload or mutation == .empty_before_padding) {
            const job3 = try fixtureJob(3, 12);
            const empty = try statement.SpanStatement.emptyLeaf(job3, 3);
            var parent = try empty.canonicalWords();
            switch (mutation) {
                .empty_payload => parent[layout.executed_tag] = word(1),
                .empty_before_padding => parent[layout.slot_node_index_start] = word(2),
                else => unreachable,
            }
            try expectUnsatisfied(
                &circuit,
                circuit_mod.Witness.forEmpty(&parent),
                inputs,
                values,
            );
            continue;
        }

        const job1 = try fixtureJob(1, 4);
        const leaf = try fixtureLeaf(
            job1,
            0,
            0,
            4,
            try fixtureState(0),
            try fixtureState(1),
        );
        var parent = try leaf.canonicalWords();
        switch (mutation) {
            .span_tag => parent[layout.span_tag] = word(99),
            .initial_zero_register => parent[
                layout.initial_state_start + layout.machine_state_registers_start_offset
            ] = word(1),
            .zero_total_cycles => @memset(
                parent[layout.total_cycles_start..][0..4],
                M31.zero(),
            ),
            .zero_segment_count => @memset(
                parent[layout.job_segment_count_start..][0..2],
                M31.zero(),
            ),
            .job_height => parent[layout.job_slot_height] = word(1),
            .slot_height => parent[layout.slot_height] = word(1),
            .node_outside_capacity => parent[layout.slot_node_index_start] = word(1),
            .first_segment => parent[layout.first_segment_start] = word(1),
            .segment_count => parent[layout.executed_segment_count_start] = word(2),
            .zero_cycle_count => @memset(
                parent[layout.executed_cycle_count_start..][0..4],
                M31.zero(),
            ),
            .cycle_outside_job => parent[layout.first_cycle_start] = word(1),
            .cycle_overflow => @memset(
                parent[layout.first_cycle_start..][0..4],
                word(std.math.maxInt(u16)),
            ),
            .initial_state => parent[
                layout.entry_state_start + layout.machine_state_pc_start_offset
            ] = word(1),
            .final_state => parent[
                layout.exit_state_start + layout.machine_state_pc_start_offset
            ] = word(1),
            .input_edge => parent[layout.input_edge_tag] = word(
                @intFromEnum(statement.Tag.absent_edge),
            ),
            .output_edge => parent[layout.output_edge_tag] = word(
                @intFromEnum(statement.Tag.absent_edge),
            ),
            .empty_payload, .empty_before_padding => unreachable,
        }
        try expectUnsatisfied(
            &circuit,
            circuit_mod.Witness.forSegment(&parent),
            inputs,
            values,
        );
    }
}

test "R-012 segment transcript and parent scopes cannot diverge" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);

    const job3 = try fixtureJob(3, 12);
    const leaf = try fixtureLeaf(
        job3,
        1,
        4,
        4,
        try fixtureState(1),
        try fixtureState(2),
    );
    const segment_words = try leaf.canonicalWords();
    var parent_words = segment_words;
    parent_words[layout.protocol_start] = word(99);
    var witness = circuit_mod.Witness.forSegment(&segment_words);
    witness.parent = &parent_words;
    try expectUnsatisfied(&circuit, witness, inputs, values);
}

test "R-012 selector overlap is rejected and inactive reference remains zero padded" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);

    const job1 = try fixtureJob(1, 1);
    const leaf = try fixtureLeaf(
        job1,
        0,
        0,
        1,
        try fixtureState(0),
        try fixtureState(1),
    );
    const words = try leaf.canonicalWords();
    var overlap = circuit_mod.Witness.forSegment(&words);
    overlap.empty_selector = true;
    try expectUnsatisfied(&circuit, overlap, inputs, values);
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        circuit.evaluate(std.testing.allocator, overlap),
    );

    var inactive = circuit_mod.Witness.forSegment(&words);
    inactive.segment_selector = false;
    try expectSatisfied(&circuit, inactive, inputs, values);
    for (inputs) |input| try std.testing.expect(input.isZero());
}

test "R-012 statement semantics construction is leak-free under every OOM point" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildAllocationFailureCase,
        .{},
    );
}

test "R-012 statement semantics owned evaluation is failure atomic under OOM" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const job1 = try fixtureJob(1, 1);
    const leaf = try fixtureLeaf(
        job1,
        0,
        0,
        1,
        try fixtureState(0),
        try fixtureState(1),
    );
    const words = try leaf.canonicalWords();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        evaluationAllocationFailureCase,
        .{ &circuit, circuit_mod.Witness.forSegment(&words) },
    );
}

test "R-012 ReleaseFast hot replay is allocation-free and stable" {
    var circuit = try circuit_mod.build(std.testing.allocator);
    defer circuit.deinit();
    const inputs = try std.testing.allocator.alloc(QM31, circuit_mod.INPUT_COUNT);
    defer std.testing.allocator.free(inputs);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodeCount());
    defer std.testing.allocator.free(values);

    const triple = try twoExecuted();
    const left = try triple.left.canonicalWords();
    const right = try triple.right.canonicalWords();
    const parent = try triple.parent.canonicalWords();
    const witness = circuit_mod.Witness.forBinary(&left, &right, &parent);
    const input_address = @intFromPtr(inputs.ptr);
    const value_address = @intFromPtr(values.ptr);
    const iterations: usize = if (builtin.mode == .ReleaseFast) 256 else 32;
    for (0..iterations) |_| {
        try circuit.evaluateIntoAssumeValid(witness, inputs, values);
    }
    try std.testing.expectEqual(input_address, @intFromPtr(inputs.ptr));
    try std.testing.expectEqual(value_address, @intFromPtr(values.ptr));
}

const BinaryMutation = enum {
    right_job,
    right_node,
    parent_node,
    right_height,
    parent_height,
    right_first_segment,
    right_first_cycle,
    right_entry_state,
    left_output,
    right_input,
    parent_segment_count,
    swapped_children,
};

const LeafMutation = enum {
    span_tag,
    initial_zero_register,
    zero_total_cycles,
    zero_segment_count,
    job_height,
    slot_height,
    node_outside_capacity,
    first_segment,
    segment_count,
    zero_cycle_count,
    cycle_outside_job,
    cycle_overflow,
    initial_state,
    final_state,
    input_edge,
    output_edge,
    empty_payload,
    empty_before_padding,
};

const Triple = struct {
    left: statement.SpanStatement,
    right: statement.SpanStatement,
    parent: statement.SpanStatement,
};

fn twoExecuted() !Triple {
    const job2 = try fixtureJob(2, 10);
    const left = try fixtureLeaf(
        job2,
        0,
        0,
        4,
        try fixtureState(0),
        try fixtureState(1),
    );
    const right = try fixtureLeaf(
        job2,
        1,
        4,
        6,
        try fixtureState(1),
        try fixtureState(2),
    );
    return .{ .left = left, .right = right, .parent = try statement.SpanStatement.fold(left, right) };
}

fn executedAndEmpty() !Triple {
    const job3 = try fixtureJob(3, 12);
    const left = try fixtureLeaf(
        job3,
        2,
        8,
        4,
        try fixtureState(2),
        try fixtureState(3),
    );
    const right = try statement.SpanStatement.emptyLeaf(job3, 3);
    return .{ .left = left, .right = right, .parent = try statement.SpanStatement.fold(left, right) };
}

fn twoEmpty() !Triple {
    const job5 = try fixtureJob(5, 20);
    const left = try statement.SpanStatement.emptyLeaf(job5, 6);
    const right = try statement.SpanStatement.emptyLeaf(job5, 7);
    return .{ .left = left, .right = right, .parent = try statement.SpanStatement.fold(left, right) };
}

fn fixtureJob(segment_count: u32, total_cycles: u64) !statement.JobContext {
    const complete = try statement.CompleteExecution.init(
        fixtureDigest(1),
        fixtureDigest(2),
        try fixtureState(0),
        try fixtureState(segment_count),
        fixtureDigest(3),
        fixtureDigest(4),
        total_cycles,
    );
    return statement.JobContext.init(complete, segment_count);
}

fn fixtureLeaf(
    job: statement.JobContext,
    index: u32,
    first_cycle: u64,
    cycle_count: u64,
    entry: statement.MachineState,
    exit_state: statement.MachineState,
) !statement.SpanStatement {
    const input = if (index == 0)
        try statement.EdgeClaim.present(job.complete.public_input)
    else
        statement.EdgeClaim.absent();
    const output = if (@as(u64, index) + 1 == job.segment_count)
        try statement.EdgeClaim.present(job.complete.public_output)
    else
        statement.EdgeClaim.absent();
    const span = try statement.ExecutedSpan.init(
        index,
        1,
        first_cycle,
        cycle_count,
        entry,
        exit_state,
        input,
        output,
    );
    return statement.SpanStatement.segmentLeaf(job, index, span);
}

fn fixtureState(seed: u32) !statement.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = seed;
    return statement.MachineState.init(
        seed *% 4,
        registers,
        fixtureDigest(seed + 10),
        fixtureDigest(seed + 20),
    );
}

fn fixtureDigest(seed: u32) statement.Digest {
    var result: statement.Digest = undefined;
    for (&result, 0..) |*value, index| value.* = seed + @as(u32, @intCast(index));
    return result;
}

fn expectTripleSatisfied(
    circuit: *const circuit_mod.Circuit,
    triple: Triple,
    inputs: []QM31,
    values: []QM31,
) !void {
    const left = try triple.left.canonicalWords();
    const right = try triple.right.canonicalWords();
    const parent = try triple.parent.canonicalWords();
    try expectSatisfied(
        circuit,
        circuit_mod.Witness.forBinary(&left, &right, &parent),
        inputs,
        values,
    );
}

fn expectSatisfied(
    circuit: *const circuit_mod.Circuit,
    witness: circuit_mod.Witness,
    inputs: []QM31,
    values: []QM31,
) !void {
    try circuit.evaluateIntoAssumeValid(witness, inputs, values);
}

fn expectUnsatisfied(
    circuit: *const circuit_mod.Circuit,
    witness: circuit_mod.Witness,
    inputs: []QM31,
    values: []QM31,
) !void {
    try std.testing.expect(!try circuit.checkIntoAssumeValid(witness, inputs, values));
}

fn word(value: u32) M31 {
    return M31.fromCanonical(value);
}

fn buildAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var circuit = try circuit_mod.build(allocator);
    defer circuit.deinit();
    try circuit.validate();
}

fn evaluationAllocationFailureCase(
    allocator: std.mem.Allocator,
    circuit: *const circuit_mod.Circuit,
    witness: circuit_mod.Witness,
) !void {
    var evaluation = try circuit.evaluate(allocator, witness);
    defer evaluation.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &circuit.identity_digest,
        &evaluation.circuit_identity,
    );
}
