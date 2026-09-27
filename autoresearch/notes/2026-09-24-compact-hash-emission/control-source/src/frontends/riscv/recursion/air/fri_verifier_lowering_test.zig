//! Schedule, wire-closure, materialization, mutation, and allocation gates for
//! fixed FRI verifier graph lowering into rows 30--32.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const circuit = @import("fri_verifier_circuit.zig");
const lowering = @import("fri_verifier_lowering.zig");
const input = @import("fri_verifier_input_witness.zig");
const linear = @import("linear_ops_witness.zig");
const inverse = @import("qm31_inv_witness.zig");
const multiply = @import("qm31_mul_full_witness.zig");
const universal = @import("universal_challenges.zig");

const WIDTHS = [_]u32{4};
const PROFILE = circuit.Profile{
    .lifting_log_size = 4,
    .log_blowup_factor = 1,
    .log_last_layer_degree_bound = 1,
    .fold_widths = &WIDTHS,
    .query_count = 1,
};

test "R-012 FRI lowering derives exact mode schedules and public anchors" {
    var fixture = try Fixture.init(std.testing.allocator, .segment_leaf);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var plan = try lowering.Plan.init(std.testing.allocator, reference);
    defer plan.deinit();
    try plan.validateAgainstAuthority(std.testing.allocator, reference);

    try std.testing.expect(plan.lane_counts[0].multiply > 0);
    try std.testing.expect(plan.lane_counts[0].inverse > 0);
    try std.testing.expect(plan.lane_counts[0].linear > 0);
    try std.testing.expect(plan.lane_counts[0].public > 0);
    try std.testing.expectEqual(plan.lane_counts[0], plan.lane_counts[1]);
    try std.testing.expectEqual(plan.lane_counts[1], plan.lane_counts[2]);
    try std.testing.expectEqual(
        plan.lane_counts[1].multiply + plan.lane_counts[2].multiply,
        plan.multiply_rows.len,
    );
    try std.testing.expectEqual(
        plan.lane_counts[1].inverse + plan.lane_counts[2].inverse,
        plan.inverse_rows.len,
    );
    try std.testing.expectEqual(
        plan.lane_counts[1].linear + plan.lane_counts[2].linear,
        plan.linear_rows.len,
    );
    for (plan.multiply_rows, 0..) |row, index| {
        try std.testing.expect(row.binary != null);
        try std.testing.expectEqual(index < plan.lane_counts[0].multiply, row.segment != null);
        try std.testing.expect(row.empty == null);
    }
    for (plan.inverse_rows, 0..) |row, index| {
        try std.testing.expect(row.binary != null);
        try std.testing.expectEqual(index < plan.lane_counts[0].inverse, row.segment != null);
        try std.testing.expect(row.empty == null);
    }
    for (plan.linear_rows, 0..) |row, index| {
        try std.testing.expect(row.binary != null);
        try std.testing.expectEqual(index < plan.lane_counts[0].linear, row.segment != null);
        try std.testing.expect(row.empty == null);
    }

    const segment_terms = plan.publicTerms(.segment_leaf);
    try std.testing.expectEqual(plan.lane_counts[0].public, segment_terms.first.len);
    try std.testing.expectEqual(@as(usize, 0), segment_terms.second.len);
    for (segment_terms.first) |term| try std.testing.expectEqual(@as(u8, 0), term.lane);
    const binary_terms = plan.publicTerms(.binary_node);
    try std.testing.expectEqual(plan.lane_counts[1].public, binary_terms.first.len);
    try std.testing.expectEqual(plan.lane_counts[2].public, binary_terms.second.len);
    for (binary_terms.first) |term| try std.testing.expectEqual(@as(u8, 1), term.lane);
    for (binary_terms.second) |term| try std.testing.expectEqual(@as(u8, 2), term.lane);
    const empty_terms = plan.publicTerms(.empty_leaf);
    try std.testing.expectEqual(@as(usize, 0), empty_terms.first.len);
    try std.testing.expectEqual(@as(usize, 0), empty_terms.second.len);
}

test "R-012 FRI lowering closes every graph wire multiplicity" {
    var fixture = try Fixture.init(std.testing.allocator, .segment_leaf);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var plan = try lowering.Plan.init(std.testing.allocator, reference);
    defer plan.deinit();

    for (reference.lanes, 0..) |lane, lane_index| {
        const balances = try std.testing.allocator.alloc(i64, lane.circuit.nodes.len);
        defer std.testing.allocator.free(balances);
        @memset(balances, 0);
        const uses = try std.testing.allocator.alloc(u32, lane.circuit.nodes.len);
        defer std.testing.allocator.free(uses);
        _ = try circuit.computeUseCountsInto(lane.circuit, uses);

        for (lane.circuit.nodes, 0..) |node, node_id| switch (node.op) {
            .input => balances[node_id] += uses[node_id],
            .constant => {},
            .add, .sub, .mul => |op| {
                balances[op.lhs] -= 1;
                balances[op.rhs] -= 1;
                balances[node_id] += uses[node_id];
            },
            .neg, .inverse => |operand| {
                balances[operand] -= 1;
                balances[node_id] += uses[node_id];
            },
        };
        for (plan.public_terms[plan.public_offsets[lane_index]..plan.public_offsets[lane_index + 1]]) |term| {
            const signed: i64 = @intCast(term.multiplicity);
            switch (term.role) {
                .emit => balances[term.node_id] += signed,
                .consume => balances[term.node_id] -= signed,
                .request => unreachable,
            }
        }
        for (balances) |balance| try std.testing.expectEqual(@as(i64, 0), balance);
    }
}

test "R-012 FRI lowering public boundary claim is exact and mutation sensitive" {
    var fixture = try Fixture.init(std.testing.allocator, .segment_leaf);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var plan = try lowering.Plan.init(std.testing.allocator, reference);
    defer plan.deinit();
    const relations = universal.UniversalRelations.dummy();

    const expected = try directPublicBoundary(&plan, .segment_leaf, &relations);
    const actual = try plan.publicBoundaryClaim(.segment_leaf, &relations);
    try std.testing.expect(actual.eql(expected));
    try std.testing.expect((try plan.publicBoundaryClaim(
        .empty_leaf,
        &relations,
    )).isZero());

    plan.public_terms[0].multiplicity += 1;
    const mutated = try plan.publicBoundaryClaim(.segment_leaf, &relations);
    try std.testing.expect(!mutated.eql(actual));
    plan.public_terms[0].multiplicity = 0;
    try std.testing.expectError(
        error.InvalidPublicAnchor,
        plan.publicBoundaryClaim(.segment_leaf, &relations),
    );
}

test "R-012 FRI lowering materializes concrete evaluations for every proof mode" {
    for (std.enums.values(input.ProofKind)) |kind| {
        var fixture = try Fixture.init(std.testing.allocator, kind);
        defer fixture.deinit();
        const reference = try fixture.reference();
        var plan = try lowering.Plan.init(std.testing.allocator, reference);
        defer plan.deinit();
        const counts = plan.counts(kind);
        var buffers = try Buffers.init(std.testing.allocator, counts);
        defer buffers.deinit();
        try plan.materializeInto(reference, fixture.evaluationSet(), kind, buffers.view());
        try verifyInvocations(&fixture, kind, buffers.view());
    }
}

test "R-012 FRI lowering hot materialization is allocation-free and failure atomic" {
    var fixture = try Fixture.init(std.testing.allocator, .segment_leaf);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var plan = try lowering.Plan.init(measured.allocator(), reference);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 5), measured.alloc_index);
    const counts = plan.counts(.segment_leaf);
    var buffers = try Buffers.init(std.testing.allocator, counts);
    defer buffers.deinit();
    buffers.fillSentinel();
    const before = measured.alloc_index;
    try plan.materializeInto(
        reference,
        fixture.evaluationSet(),
        .segment_leaf,
        buffers.view(),
    );
    try std.testing.expectEqual(before, measured.alloc_index);

    buffers.fillSentinel();
    const first_input = fixture.circuits[0].bindings[1].node_id;
    fixture.evaluations[0].values[first_input] = QM31.one();
    try std.testing.expectError(
        error.InvalidWitness,
        plan.materializeInto(
            reference,
            fixture.evaluationSet(),
            .segment_leaf,
            buffers.view(),
        ),
    );
    try buffers.expectSentinel();
    fixture.evaluations[0].values[first_input] = QM31.zero();

    var short = buffers.view();
    short.multiply = short.multiply[0 .. short.multiply.len - 1];
    try std.testing.expectError(
        error.BufferShapeMismatch,
        plan.materializeInto(reference, fixture.evaluationSet(), .segment_leaf, short),
    );
    try buffers.expectSentinel();

    const alias_ptr: [*]multiply.Invocation = @ptrCast(@alignCast(plan.multiply_rows.ptr));
    var aliased = buffers.view();
    aliased.multiply = alias_ptr[0..counts.multiply];
    try std.testing.expectError(
        error.AliasedInput,
        plan.materializeInto(reference, fixture.evaluationSet(), .segment_leaf, aliased),
    );
    try buffers.expectSentinel();

    plan.public_terms[0].multiplicity += 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        plan.materializeInto(
            reference,
            fixture.evaluationSet(),
            .segment_leaf,
            buffers.view(),
        ),
    );
    try buffers.expectSentinel();
}

test "R-012 FRI lowering construction releases every allocation failure" {
    var fixture = try Fixture.init(std.testing.allocator, .empty_leaf);
    defer fixture.deinit();
    const reference = try fixture.reference();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        loweringFailureCase,
        .{reference},
    );
}

fn directPublicBoundary(
    plan: *const lowering.Plan,
    kind: input.ProofKind,
    relations: *const universal.UniversalRelations,
) !QM31 {
    const challenge = try relations.getExact(.recursion_wire);
    const terms = plan.publicTerms(kind);
    var result = QM31.zero();
    for ([_][]const lowering.PublicWireTerm{ terms.first, terms.second }) |slice| {
        for (slice) |term| {
            const words = term.value.toM31Array();
            const denominator = try challenge.combineBase(&.{
                M31.fromCanonical(term.circuit_id),
                M31.fromCanonical(term.node_id),
                words[0],
                words[1],
                words[2],
                words[3],
            });
            var numerator = QM31.fromBase(M31.fromCanonical(term.multiplicity));
            if (term.role == .consume) numerator = numerator.neg();
            result = result.add(numerator.mul(try denominator.inv()));
        }
    }
    return result;
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    circuits: [3]circuit.Circuit,
    evaluations: [3]circuit.Evaluation,

    fn init(allocator: std.mem.Allocator, kind: input.ProofKind) !Fixture {
        var circuits: [3]circuit.Circuit = undefined;
        var circuit_count: usize = 0;
        errdefer for (circuits[0..circuit_count]) |*item| item.deinit();
        while (circuit_count < circuits.len) : (circuit_count += 1)
            circuits[circuit_count] = try circuit.build(allocator, PROFILE);

        var evaluations: [3]circuit.Evaluation = undefined;
        var evaluation_count: usize = 0;
        errdefer for (evaluations[0..evaluation_count]) |*item| item.deinit();
        while (evaluation_count < evaluations.len) : (evaluation_count += 1) {
            var assignment = ZeroAssignment.init(laneActive(evaluation_count, kind));
            evaluations[evaluation_count] = try circuits[evaluation_count].evaluate(
                allocator,
                assignment.witness(),
            );
        }
        return .{ .allocator = allocator, .circuits = circuits, .evaluations = evaluations };
    }

    fn deinit(self: *Fixture) void {
        for (&self.evaluations) |*item| item.deinit();
        for (&self.circuits) |*item| item.deinit();
        self.* = undefined;
    }

    fn reference(self: *const Fixture) !input.Reference {
        return input.Reference.seal(.{
            .{ .verifier_id = 0, .circuit_id = 301, .circuit = &self.circuits[0] },
            .{ .verifier_id = 1, .circuit_id = 302, .circuit = &self.circuits[1] },
            .{ .verifier_id = 2, .circuit_id = 303, .circuit = &self.circuits[2] },
        });
    }

    fn evaluationSet(self: *const Fixture) input.Evaluations {
        return .{
            .segment = &self.evaluations[0],
            .left = &self.evaluations[1],
            .right = &self.evaluations[2],
        };
    }
};

const ZeroAssignment = struct {
    active: bool,
    deep: [1]QM31,
    authenticated: [4]QM31,
    authenticated_layers: [1][]const QM31,
    alphas: [1]QM31,
    queries: [1]M31,
    positions: [1]M31,
    position_layers: [1][]const M31,
    offsets: [1]M31,
    offset_layers: [1][]const M31,
    last_positions: [1]M31,
    coefficients: [2]QM31,

    fn init(active: bool) ZeroAssignment {
        return .{
            .active = active,
            .deep = .{QM31.zero()},
            .authenticated = [_]QM31{QM31.zero()} ** 4,
            .authenticated_layers = undefined,
            .alphas = .{QM31.zero()},
            .queries = .{M31.zero()},
            .positions = .{M31.zero()},
            .position_layers = undefined,
            .offsets = .{M31.zero()},
            .offset_layers = undefined,
            .last_positions = .{M31.zero()},
            .coefficients = [_]QM31{QM31.zero()} ** 2,
        };
    }

    fn witness(self: *ZeroAssignment) circuit.Witness {
        self.authenticated_layers = .{&self.authenticated};
        self.position_layers = .{&self.positions};
        self.offset_layers = .{&self.offsets};
        return .{
            .active = self.active,
            .deep_answers = &self.deep,
            .authenticated_values = &self.authenticated_layers,
            .fri_alphas = &self.alphas,
            .raw_queries = &self.queries,
            .fri_positions = &self.position_layers,
            .fri_offsets = &self.offset_layers,
            .last_layer_positions = &self.last_positions,
            .last_layer_coefficients = &self.coefficients,
        };
    }
};

const Buffers = struct {
    allocator: std.mem.Allocator,
    multiply_values: []multiply.Invocation,
    inverse_values: []inverse.Invocation,
    linear_values: []linear.Invocation,

    fn init(allocator: std.mem.Allocator, counts: lowering.Counts) !Buffers {
        const multiply_values = try allocator.alloc(multiply.Invocation, counts.multiply);
        errdefer allocator.free(multiply_values);
        const inverse_values = try allocator.alloc(inverse.Invocation, counts.inverse);
        errdefer allocator.free(inverse_values);
        return .{
            .allocator = allocator,
            .multiply_values = multiply_values,
            .inverse_values = inverse_values,
            .linear_values = try allocator.alloc(linear.Invocation, counts.linear),
        };
    }

    fn deinit(self: *Buffers) void {
        self.allocator.free(self.linear_values);
        self.allocator.free(self.inverse_values);
        self.allocator.free(self.multiply_values);
        self.* = undefined;
    }

    fn view(self: *Buffers) lowering.InvocationBuffers {
        return .{
            .multiply = self.multiply_values,
            .inverse = self.inverse_values,
            .linear = self.linear_values,
        };
    }

    fn fillSentinel(self: *Buffers) void {
        for (self.multiply_values) |*item| item.* = .{ .a = QM31.one(), .b = QM31.one() };
        for (self.inverse_values) |*item| item.* = .{ .a = QM31.one() };
        const metadata = linear.CircuitMetadata{
            .circuit_id = M31.one(),
            .node_id = M31.one(),
            .lhs_id = M31.one(),
            .rhs_id = M31.one(),
            .uses = M31.one(),
        };
        for (self.linear_values) |*item| item.* = .{
            .operation = .add,
            .lhs = QM31.one(),
            .rhs = QM31.one(),
            .circuit = metadata,
        };
    }

    fn expectSentinel(self: *const Buffers) !void {
        for (self.multiply_values) |item| {
            try std.testing.expect(item.a.eql(QM31.one()));
            try std.testing.expect(item.b.eql(QM31.one()));
            try std.testing.expect(item.circuit == null);
        }
        for (self.inverse_values) |item| {
            try std.testing.expect(item.a.eql(QM31.one()));
            try std.testing.expect(item.circuit == null);
        }
        for (self.linear_values) |item| {
            try std.testing.expectEqual(linear.Operation.add, item.operation);
            try std.testing.expect(item.lhs.eql(QM31.one()));
            try std.testing.expect(item.rhs.eql(QM31.one()));
            try std.testing.expect(item.circuit.circuit_id.eql(M31.one()));
        }
    }
};

fn verifyInvocations(
    fixture: *const Fixture,
    kind: input.ProofKind,
    buffers: lowering.InvocationBuffers,
) !void {
    const lanes = switch (kind) {
        .segment_leaf => [_]?usize{ 0, null },
        .binary_node => [_]?usize{ 1, 2 },
        .empty_leaf => [_]?usize{ null, null },
    };
    for (buffers.multiply) |invocation| {
        const metadata = invocation.circuit.?;
        const lane = laneForCircuit(metadata.circuit_id.toU32(), lanes);
        try std.testing.expect(invocation.a.mul(invocation.b).eql(
            fixture.evaluations[lane].values[metadata.node_id.toU32()],
        ));
    }
    for (buffers.inverse) |invocation| {
        const metadata = invocation.circuit.?;
        const lane = laneForCircuit(metadata.circuit_id.toU32(), lanes);
        try std.testing.expect((try invocation.a.inv()).eql(
            fixture.evaluations[lane].values[metadata.node_id.toU32()],
        ));
    }
    for (buffers.linear) |invocation| {
        const lane = laneForCircuit(invocation.circuit.circuit_id.toU32(), lanes);
        try std.testing.expect(invocation.operation.apply(invocation.lhs, invocation.rhs).eql(
            fixture.evaluations[lane].values[invocation.circuit.node_id.toU32()],
        ));
    }
}

fn laneForCircuit(circuit_id: u32, lanes: [2]?usize) usize {
    for (lanes) |maybe_lane| if (maybe_lane) |lane| {
        if (circuit_id == 301 + lane) return lane;
    };
    unreachable;
}

fn laneActive(lane: usize, kind: input.ProofKind) bool {
    return switch (kind) {
        .segment_leaf => lane == 0,
        .binary_node => lane == 1 or lane == 2,
        .empty_leaf => false,
    };
}

fn loweringFailureCase(allocator: std.mem.Allocator, reference: input.Reference) !void {
    var plan = try lowering.Plan.init(allocator, reference);
    defer plan.deinit();
}
