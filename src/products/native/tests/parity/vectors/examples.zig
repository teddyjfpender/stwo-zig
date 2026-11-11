//! Example AIR oracle vectors.

const std = @import("std");
const example_plonk_mod = @import("stwo_native_examples").plonk;
const example_state_machine_mod = @import("stwo_native_examples").state_machine;
const example_wide_fibonacci_mod = @import("stwo_native_examples").wide_fibonacci;
const example_xor_mod = @import("stwo_native_examples").xor;
const m31_mod = @import("stwo_core").fields.m31;
const qm31_mod = @import("stwo_core").fields.qm31;
const fixtures = @import("fixtures.zig");

const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;
const parseVectors = fixtures.parseVectors;
const m31From = fixtures.m31From;
const qm31From = fixtures.qm31From;

test "field vectors: examples state machine trace parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_state_machine_trace.len > 0);
    for (parsed.value.example_state_machine_trace, 0..) |v, vec_idx| {
        try std.testing.expectEqual(@as(usize, 2), v.columns.len);

        var trace = try example_state_machine_mod.genTrace(
            alloc,
            v.log_size,
            .{ m31From(v.initial_state[0]), m31From(v.initial_state[1]) },
            v.inc_index,
        );
        defer example_state_machine_mod.deinitTrace(alloc, &trace);

        try std.testing.expectEqual(v.columns[0].len, trace[0].len);
        try std.testing.expectEqual(v.columns[1].len, trace[1].len);
        for (v.columns[0], 0..) |expected, i| {
            try std.testing.expect(trace[0][i].eql(m31From(expected)));
        }
        for (v.columns[1], 0..) |expected, i| {
            try std.testing.expect(trace[1][i].eql(m31From(expected)));
        }

        if (vec_idx == 0) {
            const alt_inc_index = (v.inc_index + 1) % 2;
            var alt_trace = try example_state_machine_mod.genTrace(
                alloc,
                v.log_size,
                .{ m31From(v.initial_state[0]), m31From(v.initial_state[1]) },
                alt_inc_index,
            );
            defer example_state_machine_mod.deinitTrace(alloc, &alt_trace);

            var differs = false;
            for (alt_trace[0], 0..) |value, i| {
                if (!value.eql(trace[0][i]) or !alt_trace[1][i].eql(trace[1][i])) {
                    differs = true;
                    break;
                }
            }
            try std.testing.expect(differs);
        }
    }
}

test "field vectors: examples state machine transitions parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_state_machine_transitions.len > 0);
    for (parsed.value.example_state_machine_transitions, 0..) |v, vec_idx| {
        const initial: example_state_machine_mod.State = .{
            m31From(v.initial_state[0]),
            m31From(v.initial_state[1]),
        };
        const states = try example_state_machine_mod.transitionStates(v.log_n_rows, initial);

        try std.testing.expect(states.intermediate[0].eql(m31From(v.intermediate_state[0])));
        try std.testing.expect(states.intermediate[1].eql(m31From(v.intermediate_state[1])));
        try std.testing.expect(states.final[0].eql(m31From(v.final_state[0])));
        try std.testing.expect(states.final[1].eql(m31From(v.final_state[1])));

        if (vec_idx == 0) {
            const mutated_initial: example_state_machine_mod.State = .{
                initial[0].add(M31.one()),
                initial[1],
            };
            const mutated_states = try example_state_machine_mod.transitionStates(v.log_n_rows, mutated_initial);
            const equal_intermediate = mutated_states.intermediate[0].eql(states.intermediate[0]) and
                mutated_states.intermediate[1].eql(states.intermediate[1]);
            const equal_final = mutated_states.final[0].eql(states.final[0]) and
                mutated_states.final[1].eql(states.final[1]);
            try std.testing.expect(!equal_intermediate or !equal_final);
        }
    }
}

test "field vectors: examples state machine claimed-sum parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_state_machine_claimed_sum.len > 0);
    for (parsed.value.example_state_machine_claimed_sum, 0..) |v, vec_idx| {
        const initial: example_state_machine_mod.State = .{
            m31From(v.initial_state[0]),
            m31From(v.initial_state[1]),
        };
        const elements: example_state_machine_mod.Elements = .{
            .z = qm31From(v.z),
            .alpha = qm31From(v.alpha),
        };

        const claimed_sum = try example_state_machine_mod.claimedSumFromInitial(
            v.log_size,
            initial,
            v.inc_index,
            elements,
        );
        const telescoping_claim = try example_state_machine_mod.claimedSumTelescoping(
            v.log_size,
            initial,
            v.inc_index,
            elements,
        );
        try std.testing.expect(claimed_sum.eql(qm31From(v.claimed_sum)));
        try std.testing.expect(telescoping_claim.eql(qm31From(v.telescoping_claim)));
        try std.testing.expect(claimed_sum.eql(telescoping_claim));

        if (vec_idx == 0) {
            const mutated_elements: example_state_machine_mod.Elements = .{
                .z = elements.z,
                .alpha = elements.alpha.add(QM31.one()),
            };
            const mutated_result = example_state_machine_mod.claimedSumFromInitial(
                v.log_size,
                initial,
                v.inc_index,
                mutated_elements,
            );
            if (mutated_result) |mutated_claim| {
                try std.testing.expect(!mutated_claim.eql(claimed_sum));
            } else |_| {
                // Degenerate denominator after perturbation is an expected differential failure mode.
                try std.testing.expect(true);
            }
        }
    }
}

test "field vectors: examples state machine lookup draw parity" {
    const alloc = std.testing.allocator;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_state_machine_lookup_draw.len > 0);
    for (parsed.value.example_state_machine_lookup_draw, 0..) |v, vec_idx| {
        var channel = Channel{};
        channel.mixU64(v.mix_u64);
        channel.mixU32s(v.mix_u32s);
        const elements = try example_state_machine_mod.Elements.draw(alloc, &channel);
        try std.testing.expect(elements.z.eql(qm31From(v.z)));
        try std.testing.expect(elements.alpha.eql(qm31From(v.alpha)));

        if (vec_idx == 0) {
            var altered_channel = Channel{};
            altered_channel.mixU64(v.mix_u64 +% 1);
            altered_channel.mixU32s(v.mix_u32s);
            const altered = try example_state_machine_mod.Elements.draw(alloc, &altered_channel);
            try std.testing.expect(!altered.z.eql(elements.z) or !altered.alpha.eql(elements.alpha));
        }
    }
}

test "field vectors: examples state machine statement parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_state_machine_statement.len > 0);
    for (parsed.value.example_state_machine_statement, 0..) |v, vec_idx| {
        const initial: example_state_machine_mod.State = .{
            m31From(v.initial_state[0]),
            m31From(v.initial_state[1]),
        };
        const intermediate: example_state_machine_mod.State = .{
            m31From(v.intermediate_state[0]),
            m31From(v.intermediate_state[1]),
        };
        const final: example_state_machine_mod.State = .{
            m31From(v.final_state[0]),
            m31From(v.final_state[1]),
        };
        const elements: example_state_machine_mod.Elements = .{
            .z = qm31From(v.z),
            .alpha = qm31From(v.alpha),
        };

        const transitions = try example_state_machine_mod.transitionStates(v.log_n_rows, initial);
        try std.testing.expect(transitions.intermediate[0].eql(intermediate[0]));
        try std.testing.expect(transitions.intermediate[1].eql(intermediate[1]));
        try std.testing.expect(transitions.final[0].eql(final[0]));
        try std.testing.expect(transitions.final[1].eql(final[1]));

        const x_claim = try example_state_machine_mod.claimedSumTelescoping(
            v.log_n_rows,
            initial,
            0,
            elements,
        );
        const y_claim = try example_state_machine_mod.claimedSumTelescoping(
            v.log_n_rows - 1,
            intermediate,
            1,
            elements,
        );
        try std.testing.expect(x_claim.eql(qm31From(v.x_axis_claimed_sum)));
        try std.testing.expect(y_claim.eql(qm31From(v.y_axis_claimed_sum)));

        const prepared = try example_state_machine_mod.prepareStatement(
            v.log_n_rows,
            initial,
            elements,
        );
        try std.testing.expect(prepared.public_input[0][0].eql(initial[0]));
        try std.testing.expect(prepared.public_input[0][1].eql(initial[1]));
        try std.testing.expect(prepared.public_input[1][0].eql(final[0]));
        try std.testing.expect(prepared.public_input[1][1].eql(final[1]));
        try std.testing.expectEqual(v.log_n_rows, prepared.stmt0.n);
        try std.testing.expectEqual(v.log_n_rows - 1, prepared.stmt0.m);
        try std.testing.expect(prepared.stmt1.x_axis_claimed_sum.eql(x_claim));
        try std.testing.expect(prepared.stmt1.y_axis_claimed_sum.eql(y_claim));
        try example_state_machine_mod.verifyStatement(prepared, elements);

        const satisfies = try example_state_machine_mod.claimsSatisfyStatement(
            initial,
            final,
            x_claim,
            y_claim,
            elements,
        );
        try std.testing.expect(satisfies);

        if (vec_idx == 0) {
            const bad = y_claim.add(QM31.one());
            try std.testing.expectError(
                example_state_machine_mod.Error.StatementNotSatisfied,
                example_state_machine_mod.verifyStatement(
                    .{
                        .public_input = .{ initial, final },
                        .stmt0 = .{ .n = v.log_n_rows, .m = v.log_n_rows - 1 },
                        .stmt1 = .{
                            .x_axis_claimed_sum = x_claim,
                            .y_axis_claimed_sum = bad,
                        },
                    },
                    elements,
                ),
            );
        }
    }
}

test "field vectors: examples xor is_first parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_xor_is_first.len > 0);
    for (parsed.value.example_xor_is_first, 0..) |v, vec_idx| {
        const values = try example_xor_mod.genIsFirstColumn(alloc, v.log_size);
        defer alloc.free(values);

        try std.testing.expectEqual(v.values.len, values.len);
        for (v.values, 0..) |expected, i| {
            try std.testing.expect(values[i].eql(m31From(expected)));
        }

        if (vec_idx == 0) {
            const alt_values = try example_xor_mod.genIsFirstColumn(alloc, v.log_size + 1);
            defer alloc.free(alt_values);
            try std.testing.expect(alt_values.len != values.len);
        }
    }
}

test "field vectors: examples xor is_step_with_offset parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_xor_is_step_with_offset.len > 0);
    for (parsed.value.example_xor_is_step_with_offset, 0..) |v, vec_idx| {
        const values = try example_xor_mod.genIsStepWithOffsetColumn(
            alloc,
            v.log_size,
            v.log_step,
            v.offset,
        );
        defer alloc.free(values);

        try std.testing.expectEqual(v.values.len, values.len);
        for (v.values, 0..) |expected, i| {
            try std.testing.expect(values[i].eql(m31From(expected)));
        }

        if (vec_idx == 0) {
            var alt_log_step = v.log_step;
            var alt_offset = v.offset +% 1;
            if (v.log_step == 0) {
                alt_log_step = 1;
                alt_offset = v.offset;
            }
            const alt_values = try example_xor_mod.genIsStepWithOffsetColumn(
                alloc,
                v.log_size,
                alt_log_step,
                alt_offset,
            );
            defer alloc.free(alt_values);

            var differs = false;
            for (alt_values, 0..) |value, i| {
                if (!value.eql(values[i])) {
                    differs = true;
                    break;
                }
            }
            try std.testing.expect(differs);
        }
    }
}

test "field vectors: examples wide_fibonacci trace parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_wide_fibonacci_trace.len > 0);
    for (parsed.value.example_wide_fibonacci_trace, 0..) |v, vec_idx| {
        const statement: example_wide_fibonacci_mod.Statement = .{
            .log_n_rows = v.log_n_rows,
            .sequence_len = v.sequence_len,
        };
        const trace = try example_wide_fibonacci_mod.genTrace(alloc, statement);
        defer example_wide_fibonacci_mod.deinitTrace(alloc, trace);

        try std.testing.expectEqual(v.columns.len, trace.len);
        for (v.columns, 0..) |expected_col, col_idx| {
            try std.testing.expectEqual(expected_col.len, trace[col_idx].len);
            for (expected_col, 0..) |expected, row_idx| {
                try std.testing.expect(trace[col_idx][row_idx].eql(m31From(expected)));
            }
        }

        if (vec_idx == 0) {
            var alt_statement = statement;
            alt_statement.sequence_len += 1;
            const alt_trace = try example_wide_fibonacci_mod.genTrace(alloc, alt_statement);
            defer example_wide_fibonacci_mod.deinitTrace(alloc, alt_trace);

            if (alt_trace.len != trace.len) {
                try std.testing.expect(true);
            } else {
                var differs = false;
                for (alt_trace, 0..) |col, col_idx| {
                    if (col.len != trace[col_idx].len) {
                        differs = true;
                        break;
                    }
                    for (col, 0..) |value, row_idx| {
                        if (!value.eql(trace[col_idx][row_idx])) {
                            differs = true;
                            break;
                        }
                    }
                    if (differs) break;
                }
                try std.testing.expect(differs);
            }
        }
    }
}

test "field vectors: examples plonk trace parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.example_plonk_trace.len > 0);
    for (parsed.value.example_plonk_trace, 0..) |v, vec_idx| {
        const statement: example_plonk_mod.Statement = .{
            .log_n_rows = v.log_n_rows,
        };
        var trace = try example_plonk_mod.genTrace(alloc, statement);
        defer example_plonk_mod.deinitTrace(alloc, &trace);

        try std.testing.expectEqual(@as(usize, 4), v.preprocessed.len);
        try std.testing.expectEqual(@as(usize, 4), v.main.len);
        for (v.preprocessed, 0..) |expected_col, col_idx| {
            try std.testing.expectEqual(expected_col.len, trace.preprocessed[col_idx].len);
            for (expected_col, 0..) |expected, row_idx| {
                try std.testing.expect(trace.preprocessed[col_idx][row_idx].eql(m31From(expected)));
            }
        }
        for (v.main, 0..) |expected_col, col_idx| {
            try std.testing.expectEqual(expected_col.len, trace.main[col_idx].len);
            for (expected_col, 0..) |expected, row_idx| {
                try std.testing.expect(trace.main[col_idx][row_idx].eql(m31From(expected)));
            }
        }

        if (vec_idx == 0) {
            var alt_statement = statement;
            alt_statement.log_n_rows += 1;
            var alt_trace = try example_plonk_mod.genTrace(alloc, alt_statement);
            defer example_plonk_mod.deinitTrace(alloc, &alt_trace);
            try std.testing.expect(alt_trace.main[0].len != trace.main[0].len);
        }
    }
}
