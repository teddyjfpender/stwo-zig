//! Determinism, evaluation, limits, and ownership gates for arithmetic circuits.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit_mod = @import("arithmetic_circuit.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

test "R-012 arithmetic builder interns canonically and folds total identities" {
    var forward = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer forward.deinit();
    try forward.reserve(2, 8, 1);
    const x = try forward.input(0);
    const y = try forward.input(1);
    try std.testing.expect(std.meta.eql(x, try forward.input(0)));

    const zero_added = try forward.add(x, circuit_mod.Value.zero());
    const one_multiplied = try forward.mul(circuit_mod.Value.one(), zero_added);
    try std.testing.expect(std.meta.eql(x, one_multiplied));
    try std.testing.expect(std.meta.eql(
        circuit_mod.Value.zero(),
        try forward.sub(y, y),
    ));

    const seven = QM31.fromBase(M31.fromU64(7));
    const first = try forward.add(one_multiplied, forward.constant(seven));
    const repeated = try forward.add(forward.constant(seven), x);
    try std.testing.expect(std.meta.eql(first, repeated));
    const sum = try forward.add(first, y);
    const negated = try forward.neg(sum);
    try std.testing.expect(std.meta.eql(sum, try forward.neg(negated)));
    _ = try forward.markOutput(negated);
    var forward_circuit = try forward.finish();
    defer forward_circuit.deinit();

    var reversed = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer reversed.deinit();
    try reversed.reserve(2, 8, 1);
    const rx = try reversed.input(0);
    const ry = try reversed.input(1);
    const rfirst = try reversed.add(reversed.constant(seven), rx);
    const rsum = try reversed.add(ry, rfirst);
    _ = try reversed.markOutput(try reversed.neg(rsum));
    var reversed_circuit = try reversed.finish();
    defer reversed_circuit.deinit();

    try std.testing.expectEqualDeep(forward_circuit.nodes(), reversed_circuit.nodes());
    try std.testing.expectEqualSlices(
        circuit_mod.NodeId,
        forward_circuit.inputNodes(),
        reversed_circuit.inputNodes(),
    );
    try std.testing.expectEqualSlices(
        circuit_mod.NodeId,
        forward_circuit.outputs(),
        reversed_circuit.outputs(),
    );
    try std.testing.expectEqualSlices(
        u32,
        forward_circuit.useCounts(),
        reversed_circuit.useCounts(),
    );
}

test "R-012 constant outputs materialize once and builder reuse is isolated" {
    var builder = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer builder.deinit();
    try builder.reserve(0, 1, 2);

    const folded = try builder.add(
        builder.baseConstant(M31.fromU64(2)),
        builder.baseConstant(M31.fromU64(3)),
    );
    const first_output = try builder.markOutput(folded);
    const second_output = try builder.markOutput(folded);
    try std.testing.expectEqual(first_output, second_output);

    var constant_circuit = try builder.finish();
    defer constant_circuit.deinit();
    try std.testing.expectEqual(@as(usize, 1), constant_circuit.nodes().len);
    try std.testing.expectEqual(@as(u32, 2), constant_circuit.useCounts()[0]);
    var constant_values: [1]QM31 = undefined;
    try constant_circuit.evaluateInto(&.{}, &constant_values);
    try std.testing.expect((try constant_circuit.outputValue(
        &constant_values,
        0,
    )).eql(base(5)));

    const input = try builder.input(0);
    _ = try builder.markOutput(input);
    var input_circuit = try builder.finish();
    defer input_circuit.deinit();
    try std.testing.expectEqual(@as(usize, 1), input_circuit.nodes().len);
    try std.testing.expectEqual(@as(usize, 1), input_circuit.inputNodes().len);
    var input_values: [1]QM31 = undefined;
    try input_circuit.evaluateInto(&.{base(8)}, &input_values);
    try std.testing.expect((try input_circuit.outputValue(
        &input_values,
        0,
    )).eql(base(8)));
}

test "R-012 arithmetic circuit derives semantic-input uses and evaluates exactly" {
    var builder = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer builder.deinit();
    try builder.reserve(5, 12, 2);

    // This shape mirrors the authority-spine circuits: a selector gates a
    // public word/challenge expression and the result is compared with a
    // verifier-owned expected value.
    const selector = try builder.input(0);
    const word = try builder.input(1);
    const challenge = try builder.input(2);
    const claimed_sum = try builder.input(3);
    const expected = try builder.input(4);
    const product = try builder.mul(word, challenge);
    const shared = try builder.add(product, claimed_sum);
    const doubled = try builder.add(shared, shared);
    const gated = try builder.mul(selector, doubled);
    const difference = try builder.sub(gated, expected);
    _ = try builder.markOutput(difference);
    _ = try builder.markOutput(shared);

    var circuit = try builder.finish();
    defer circuit.deinit();
    try circuit.validate();
    try std.testing.expectEqual(@as(u32, 1), try circuit.inputUseCount(0));
    try std.testing.expectEqual(@as(u32, 1), try circuit.inputUseCount(1));
    try std.testing.expectEqual(@as(u32, 1), try circuit.inputUseCount(2));
    try std.testing.expectEqual(@as(u32, 1), try circuit.inputUseCount(3));
    try std.testing.expectEqual(@as(u32, 1), try circuit.inputUseCount(4));
    const shared_id = switch (shared) {
        .node => |node_id| node_id,
        .constant => unreachable,
    };
    // Two operands of `shared + shared`, plus the second public output.
    try std.testing.expectEqual(@as(u32, 3), circuit.useCounts()[shared_id]);

    const inputs = [_]QM31{
        base(1),
        base(3),
        base(5),
        base(7),
        base(44),
    };
    var values: [12]QM31 = undefined;
    try circuit.evaluateInto(&inputs, values[0..circuit.nodes().len]);
    var trusted_values: [12]QM31 = undefined;
    try circuit.evaluateIntoAssumeValid(
        &inputs,
        trusted_values[0..circuit.nodes().len],
    );
    try std.testing.expectEqualDeep(
        values[0..circuit.nodes().len],
        trusted_values[0..circuit.nodes().len],
    );
    try std.testing.expect((try circuit.outputValue(
        values[0..circuit.nodes().len],
        0,
    )).isZero());
    try std.testing.expect((try circuit.outputValue(
        values[0..circuit.nodes().len],
        1,
    )).eql(base(22)));
    try std.testing.expect(!(try circuit.outputsAreZero(
        values[0..circuit.nodes().len],
    )));

    var owned = try circuit.evaluate(std.testing.allocator, &inputs);
    defer owned.deinit();
    try std.testing.expectEqualDeep(
        values[0..circuit.nodes().len],
        owned.values,
    );
}

test "R-012 arithmetic circuit retains partial inverse checks" {
    var builder = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer builder.deinit();
    const x = try builder.input(0);
    const inverse = try builder.inverse(x);
    const inverse_twice = try builder.inverse(inverse);
    try std.testing.expect(!std.meta.eql(x, inverse_twice));
    _ = try builder.markOutput(inverse_twice);
    var circuit = try builder.finish();
    defer circuit.deinit();

    var values: [3]QM31 = undefined;
    try std.testing.expectError(
        error.DivisionByZero,
        circuit.evaluateInto(&.{QM31.zero()}, &values),
    );
    try circuit.evaluateInto(&.{base(9)}, &values);
    try std.testing.expect((try circuit.outputValue(&values, 0)).eql(base(9)));
    try std.testing.expectError(
        error.DivisionByZero,
        builder.inverse(builder.constant(QM31.zero())),
    );
}

test "R-012 arithmetic circuit rejects explicit construction limits" {
    try std.testing.expectError(
        error.InvalidLimits,
        circuit_mod.Builder.init(std.testing.allocator, .{ .max_nodes = 0 }),
    );

    var builder = try circuit_mod.Builder.init(std.testing.allocator, .{
        .max_nodes = 3,
        .max_inputs = 2,
        .max_outputs = 1,
        .max_use_count = 3,
    });
    defer builder.deinit();
    try std.testing.expectError(error.InputOrderNotCanonical, builder.input(1));
    const x = try builder.input(0);
    const y = try builder.input(1);
    const sum = try builder.add(x, y);
    try std.testing.expectError(error.NodeLimitExceeded, builder.neg(sum));
    _ = try builder.markOutput(sum);
    try std.testing.expectError(error.OutputLimitExceeded, builder.markOutput(sum));

    var missing = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer missing.deinit();
    _ = try missing.input(0);
    try std.testing.expectError(error.MissingOutput, missing.finish());

    var uses = try circuit_mod.Builder.init(std.testing.allocator, .{
        .max_nodes = 4,
        .max_inputs = 1,
        .max_outputs = 1,
        .max_use_count = 1,
    });
    defer uses.deinit();
    const input = try uses.input(0);
    _ = try uses.markOutput(try uses.add(input, input));
    try std.testing.expectError(error.UseCountLimitExceeded, uses.finish());
}

test "R-012 arithmetic circuit detects use-count and structure mutation" {
    var builder = circuit_mod.Builder.initDefault(std.testing.allocator);
    defer builder.deinit();
    const x = try builder.input(0);
    const y = try builder.input(1);
    _ = try builder.markOutput(try builder.mul(x, y));
    var circuit = try builder.finish();
    defer circuit.deinit();

    var scratch: [3]u32 = undefined;
    try circuit.validateInto(&scratch);
    circuit.use_counts_storage[0] += 1;
    try std.testing.expectError(error.UseCountMismatch, circuit.validateInto(&scratch));
    circuit.use_counts_storage[0] -= 1;
    try circuit.validateInto(&scratch);

    const original = circuit.nodes_storage.items[2];
    circuit.nodes_storage.items[2] = .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 2 } } };
    try std.testing.expectError(error.InvalidOperand, circuit.validateInto(&scratch));
    circuit.nodes_storage.items[2] = original;
    try circuit.validateInto(&scratch);

    circuit.outputs_storage.items[0] = 99;
    var values: [3]QM31 = undefined;
    try std.testing.expectError(error.InvalidNodeId, circuit.outputValue(&values, 0));
    try std.testing.expectError(error.InvalidNodeId, circuit.outputsAreZero(&values));
    try std.testing.expectError(error.InvalidNodeId, circuit.validateInto(&scratch));
    circuit.outputs_storage.items[0] = 2;

    circuit.input_nodes_storage.items[0] = 99;
    try std.testing.expectError(error.InvalidInputLayout, circuit.inputUseCount(0));
    circuit.input_nodes_storage.items[0] = 0;
    try circuit.validateInto(&scratch);

    try std.testing.expectError(
        error.InvalidLimits,
        circuit_mod.deriveUseCounts(
            circuit.nodes(),
            circuit.outputs(),
            &scratch,
            0,
        ),
    );
}

test "R-012 reserved arithmetic construction is allocation-free and ownership-safe" {
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var builder = circuit_mod.Builder.initDefault(measured.allocator());
        defer builder.deinit();
        try builder.reserve(5, 12, 2);
        const after_reserve = measured.alloc_index;
        const selector = try builder.input(0);
        const word = try builder.input(1);
        const challenge = try builder.input(2);
        const claimed_sum = try builder.input(3);
        const expected = try builder.input(4);
        const value = try builder.mul(
            selector,
            try builder.add(try builder.mul(word, challenge), claimed_sum),
        );
        _ = try builder.markOutput(try builder.sub(value, expected));
        _ = try builder.markOutput(value);
        try std.testing.expectEqual(after_reserve, measured.alloc_index);

        var circuit = try builder.finish();
        defer circuit.deinit();
        try std.testing.expectEqual(after_reserve + 1, measured.alloc_index);
        var evaluation = try circuit.evaluate(measured.allocator(), &.{
            base(1), base(2), base(3), base(4), base(10),
        });
        defer evaluation.deinit();
        try std.testing.expectEqual(after_reserve + 2, measured.alloc_index);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var builder = circuit_mod.Builder.initDefault(allocator);
    defer builder.deinit();
    try builder.reserve(4, 10, 1);
    const selector = try builder.input(0);
    const word = try builder.input(1);
    const challenge = try builder.input(2);
    const expected = try builder.input(3);
    const product = try builder.mul(word, challenge);
    _ = try builder.markOutput(try builder.sub(try builder.mul(selector, product), expected));
    var circuit = try builder.finish();
    defer circuit.deinit();
    try circuit.validate();
    var evaluation = try circuit.evaluate(allocator, &.{
        base(1), base(2), base(3), base(6),
    });
    defer evaluation.deinit();
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}
