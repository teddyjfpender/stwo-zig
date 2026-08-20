test {
    _ = @import("recursion/air/fri_verifier_circuit_test.zig");
    _ = @import("recursion/air/fri_verifier_lowering.zig");
    _ = @import("recursion/air/fri_verifier_lowering_test.zig");
    _ = @import("recursion/air/fri_verifier_input_witness.zig");
    _ = @import("recursion/air/merkle_path.zig");
    _ = @import("recursion/air/merkle_path_witness.zig");
    _ = @import("recursion/air/merkle_path_test.zig");
    _ = @import("recursion/air/merkle_path_poseidon_bridge_test.zig");
}

test "temporary row33 binding identity" {
    const std = @import("std");
    const component = @import("recursion/air/merkle_path.zig");
    const witness = @import("recursion/air/merkle_path_witness.zig");
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    std.debug.print("row33 binding={s}\n", .{
        std.fmt.bytesToHex(binding.identityDigest(), .lower),
    });
}

test "temporary row33 semantic identity" {
    const std = @import("std");
    const component = @import("recursion/air/merkle_path.zig");
    const value = try component.identity(std.testing.allocator);
    std.debug.print("row33 semantic={s}\n", .{std.fmt.bytesToHex(value.bytes, .lower)});
}

test "temporary row29 witness API instantiation" {
    const std = @import("std");
    const stwo_core = @import("stwo_core");
    const M31 = stwo_core.fields.m31.M31;
    const QM31 = stwo_core.fields.qm31.QM31;
    const circuit = @import("recursion/air/fri_verifier_circuit.zig");
    const component = @import("recursion/air/fri_verifier_input.zig");
    const witness = @import("recursion/air/fri_verifier_input_witness.zig");
    const widths = [_]u32{4};
    const profile = circuit.Profile{
        .lifting_log_size = 4,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 1,
        .fold_widths = &widths,
        .query_count = 1,
    };
    var circuits = [_]circuit.Circuit{
        try circuit.build(std.testing.allocator, profile),
        try circuit.build(std.testing.allocator, profile),
        try circuit.build(std.testing.allocator, profile),
    };
    defer for (&circuits) |*item| item.deinit();
    var deep = [_]QM31{QM31.zero()};
    var authenticated = [_]QM31{QM31.zero()} ** 4;
    const authenticated_layers = [_][]const QM31{&authenticated};
    var alphas = [_]QM31{QM31.zero()};
    var queries = [_]M31{M31.zero()};
    var positions = [_]M31{M31.zero()};
    const position_layers = [_][]const M31{&positions};
    var offsets = [_]M31{M31.zero()};
    const offset_layers = [_][]const M31{&offsets};
    var last_positions = [_]M31{M31.zero()};
    var coefficients = [_]QM31{QM31.zero()} ** 2;
    const circuit_witness = circuit.Witness{
        .active = false,
        .deep_answers = &deep,
        .authenticated_values = &authenticated_layers,
        .fri_alphas = &alphas,
        .raw_queries = &queries,
        .fri_positions = &position_layers,
        .fri_offsets = &offset_layers,
        .last_layer_positions = &last_positions,
        .last_layer_coefficients = &coefficients,
    };
    var evaluations = [_]circuit.Evaluation{
        try circuits[0].evaluate(std.testing.allocator, circuit_witness),
        try circuits[1].evaluate(std.testing.allocator, circuit_witness),
        try circuits[2].evaluate(std.testing.allocator, circuit_witness),
    };
    defer for (&evaluations) |*item| item.deinit();
    const reference = try witness.Reference.seal(.{
        .{ .verifier_id = 0, .circuit_id = 301, .circuit = &circuits[0] },
        .{ .verifier_id = 1, .circuit_id = 302, .circuit = &circuits[1] },
        .{ .verifier_id = 2, .circuit_id = 303, .circuit = &circuits[2] },
    });
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 201), preprocessing.rows.len);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const evaluation_set = witness.Evaluations{
        .segment = &evaluations[0],
        .left = &evaluations[1],
        .right = &evaluations[2],
    };
    _ = try witness.logicalRow(reference, &preprocessing, 0, evaluation_set, .empty_leaf);
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const storage = try std.testing.allocator.alloc(M31, 2 * size);
    defer std.testing.allocator.free(storage);
    var columns = [2][]M31{ storage[0..size], storage[size .. 2 * size] };
    try executor.generateMainInto(
        &preprocessing,
        reference,
        &columns,
        evaluation_set,
        .empty_leaf,
    );
}
