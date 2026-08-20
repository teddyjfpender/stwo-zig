//! Exact graph, input order, evaluation, and mutation gates for the FRI circuit.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const circuit = @import("fri_verifier_circuit.zig");

const WIDTHS = [_]u32{4};
const PROFILE = circuit.Profile{
    .lifting_log_size = 4,
    .log_blowup_factor = 1,
    .log_last_layer_degree_bound = 1,
    .fold_widths = &WIDTHS,
    .query_count = 1,
};

test "R-012 FRI circuit admits the exact twenty-layer recursive outer schedule" {
    const widths = [_]u32{2} ** 20;
    const outer_profile = circuit.Profile{
        .lifting_log_size = 21,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .fold_widths = &widths,
        .query_count = 3,
    };
    try outer_profile.validate();
    try std.testing.expectEqual(@as(usize, 1), try outer_profile.lastLayerCoefficientCount());

    var wrong_fold_sum = widths;
    wrong_fold_sum[0] = 4;
    const mismatched_profile = circuit.Profile{
        .lifting_log_size = outer_profile.lifting_log_size,
        .log_blowup_factor = outer_profile.log_blowup_factor,
        .log_last_layer_degree_bound = outer_profile.log_last_layer_degree_bound,
        .fold_widths = &wrong_fold_sum,
        .query_count = outer_profile.query_count,
    };
    try std.testing.expectError(error.FoldCountMismatch, mismatched_profile.validate());

    const too_many_widths = [_]u32{2} ** (circuit.MAX_FRI_LAYERS + 1);
    const oversized_profile = circuit.Profile{
        .lifting_log_size = circuit.MAX_DOMAIN_LOG,
        .log_blowup_factor = 0,
        .log_last_layer_degree_bound = 0,
        .fold_widths = &too_many_widths,
        .query_count = 1,
    };
    try std.testing.expectError(error.InvalidProfile, oversized_profile.validate());
}

test "R-012 canonical FRI circuit builds exact input order and graph-derived uses" {
    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    try built.validate();
    try std.testing.expectEqual(@as(usize, 67), built.bindings.len);
    try std.testing.expect(built.nodes.len > built.bindings.len);
    try std.testing.expectEqual(@as(usize, 37), built.outputs.len);
    try std.testing.expect(std.meta.eql(
        circuit.InputSource.active_selector,
        built.bindings[0].source,
    ));
    try std.testing.expect(std.meta.eql(
        circuit.InputSource{ .deep_answer_word = .{ .query = 0, .word = 0 } },
        built.bindings[1].source,
    ));
    try std.testing.expect(std.meta.eql(
        circuit.InputSource{ .authenticated_value_word = .{
            .layer = 0,
            .query = 0,
            .offset = 0,
            .word = 0,
        } },
        built.bindings[5].source,
    ));
    try std.testing.expect(std.meta.eql(
        circuit.InputSource{ .query_bit = .{ .query = 0, .bit = 0 } },
        built.bindings[25].source,
    ));
    const uses = try std.testing.allocator.alloc(u32, built.nodes.len);
    defer std.testing.allocator.free(uses);
    _ = try circuit.computeUseCountsInto(&built, uses);
    for (built.bindings) |binding| try std.testing.expect(uses[binding.node_id] > 0);
}

test "R-012 FRI circuit preserves per-layer position-offset input order" {
    const widths = [_]u32{ 2, 8 };
    const profile = circuit.Profile{
        .lifting_log_size = 5,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .fold_widths = &widths,
        .query_count = 2,
    };
    var built = try circuit.build(std.testing.allocator, profile);
    defer built.deinit();

    var cursor: usize = 1 + 2 * 4 + (2 * 2 + 2 * 8) * 4 + 2 * 4 + 2 * 31;
    const expected = [_]circuit.InputSource{
        .{ .fri_position = .{ .layer = 0, .query = 0 } },
        .{ .fri_position = .{ .layer = 0, .query = 1 } },
        .{ .fri_offset = .{ .layer = 0, .query = 0 } },
        .{ .fri_offset = .{ .layer = 0, .query = 1 } },
        .{ .fri_position = .{ .layer = 1, .query = 0 } },
        .{ .fri_position = .{ .layer = 1, .query = 1 } },
        .{ .fri_offset = .{ .layer = 1, .query = 0 } },
        .{ .fri_offset = .{ .layer = 1, .query = 1 } },
    };
    for (expected) |source| {
        try std.testing.expect(std.meta.eql(source, built.bindings[cursor].source));
        cursor += 1;
    }
}

test "R-012 canonical FRI circuit evaluates inactive and active zero assignments" {
    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    var fixture = zeroWitness(false);
    var inactive = try built.evaluate(std.testing.allocator, fixture.witness());
    defer inactive.deinit();
    try inactive.validateAgainst(&built);
    fixture.active = true;
    var active = try built.evaluate(std.testing.allocator, fixture.witness());
    defer active.deinit();
    try active.validateAgainst(&built);

    const mutable_node = for (built.nodes, 0..) |node, node_id| switch (node.op) {
        .add, .sub, .mul, .neg, .inverse => break node_id,
        else => continue,
    } else unreachable;
    active.values[mutable_node] = active.values[mutable_node].add(QM31.one());
    try std.testing.expectError(error.InvalidWitness, built.validateEvaluationHot(&active));
    active.values[mutable_node] = active.values[mutable_node].sub(QM31.one());
    for (built.bindings, 0..) |binding, index| {
        const lhs = inactive.values[binding.node_id];
        const rhs = active.values[binding.node_id];
        if (index == 0) {
            try std.testing.expect(lhs.isZero());
            try std.testing.expect(rhs.eql(QM31.one()));
        } else {
            try std.testing.expect(lhs.isZero());
            try std.testing.expect(rhs.isZero());
        }
    }
}

test "R-012 canonical FRI circuit rejects profile graph and witness drift" {
    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    built.identity_digest[0] ^= 1;
    try std.testing.expectError(error.CircuitIdentityMismatch, built.validate());
    built.identity_digest[0] ^= 1;
    try built.validate();

    var fixture = zeroWitness(false);
    fixture.positions[0] = M31.one();
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        built.evaluate(std.testing.allocator, fixture.witness()),
    );
}

const ZeroFixture = struct {
    active: bool,
    deep: [1]QM31,
    authenticated: [4]QM31,
    authenticated_layers: [1][]const QM31,
    alphas: [1]QM31,
    raw_queries: [1]M31,
    positions: [1]M31,
    position_layers: [1][]const M31,
    offsets: [1]M31,
    offset_layers: [1][]const M31,
    last_positions: [1]M31,
    coefficients: [2]QM31,

    fn witness(self: *ZeroFixture) circuit.Witness {
        self.authenticated_layers = .{&self.authenticated};
        self.position_layers = .{&self.positions};
        self.offset_layers = .{&self.offsets};
        return .{
            .active = self.active,
            .deep_answers = &self.deep,
            .authenticated_values = &self.authenticated_layers,
            .fri_alphas = &self.alphas,
            .raw_queries = &self.raw_queries,
            .fri_positions = &self.position_layers,
            .fri_offsets = &self.offset_layers,
            .last_layer_positions = &self.last_positions,
            .last_layer_coefficients = &self.coefficients,
        };
    }
};

fn zeroWitness(active: bool) ZeroFixture {
    const result = ZeroFixture{
        .active = active,
        .deep = .{QM31.zero()},
        .authenticated = [_]QM31{QM31.zero()} ** 4,
        .authenticated_layers = undefined,
        .alphas = .{QM31.zero()},
        .raw_queries = .{M31.zero()},
        .positions = .{M31.zero()},
        .position_layers = undefined,
        .offsets = .{M31.zero()},
        .offset_layers = undefined,
        .last_positions = .{M31.zero()},
        .coefficients = [_]QM31{QM31.zero()} ** 2,
    };
    return result;
}
