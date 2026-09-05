const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const fixed_profile = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const composition = @import("air/composition_circuit.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");
const schedule = @import("air/verifier_schedule.zig");
const subject = @import("binary_composition_rows_heterogeneous_v2.zig");
const trusted = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");

test "heterogeneous rows 18 and 19 compile a native leaf beside a recursive child" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var authority = try subject.CompositionRowsAuthorityV2.init(
        std.testing.allocator,
        fixture.program(),
        fixture.witness(),
    );
    defer authority.deinit();

    try authority.validateAgainst(fixture.program(), fixture.witness());
    try std.testing.expectEqual(schedule.Schema.vm, fixture.left_plan.schema);
    try std.testing.expectEqual(
        schedule.Schema.recursion,
        fixture.right_plan.schema,
    );
    try std.testing.expect(
        fixture.left.graph.nodes.len != fixture.right.graph.nodes.len,
    );
    try std.testing.expect(
        fixture.left.profile.sampled_value_count !=
            fixture.right.profile.sampled_value_count,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &fixture.left.graph.identity_digest,
        &fixture.right.graph.identity_digest,
    ));
    try std.testing.expect(!std.mem.allEqual(u8, &authority.program_sha256, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &authority.instance_sha256, 0));
}

test "heterogeneous rows 18 and 19 separate program and proof instance identity" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var first = try subject.CompositionRowsAuthorityV2.init(
        std.testing.allocator,
        fixture.program(),
        fixture.witness(),
    );
    defer first.deinit();

    fixture.left.values[1] = QM31.one();
    var second = try subject.CompositionRowsAuthorityV2.init(
        std.testing.allocator,
        fixture.program(),
        fixture.witness(),
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &first.program_sha256,
        &second.program_sha256,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.instance_sha256,
        &second.instance_sha256,
    ));
}

test "heterogeneous rows 18 and 19 reject order schedule graph and value mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var authority = try subject.CompositionRowsAuthorityV2.init(
        std.testing.allocator,
        fixture.program(),
        fixture.witness(),
    );
    defer authority.deinit();

    var swapped = fixture.program();
    swapped.children = .{ swapped.children[1], swapped.children[0] };
    try std.testing.expectError(
        error.InvalidHeterogeneousCompositionAuthority,
        authority.validateProgramAgainst(swapped),
    );

    authority.schedule_values[0] = authority.schedule_values[0].add(M31.one());
    try std.testing.expectError(
        error.SourceAuthorityMismatch,
        authority.validateAgainst(fixture.program(), fixture.witness()),
    );
    authority.schedule_values[0] = authority.schedule_values[0].sub(M31.one());

    authority.control_preprocessing.rows[0].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        authority.validateProgramAgainst(fixture.program()),
    );
    authority.control_preprocessing.rows[0].tag -= 1;

    fixture.left.nodes[0] = .{ .op = .{ .constant = .{ 0, 0, 0, 0 } } };
    try std.testing.expectError(
        error.GraphSealMismatch,
        authority.validateProgramAgainst(fixture.program()),
    );
}

const Child = struct {
    allocator: std.mem.Allocator,
    verifier_id: u32,
    circuit_id: u32,
    statement_scope: u32,
    profile: composition.InputProfile,
    nodes: []composition.Node,
    outputs: []u32,
    bindings: []composition.RecursionInputBinding,
    values: []QM31,
    graph: composition.CircuitGraph,

    fn init(
        allocator: std.mem.Allocator,
        verifier_id: u32,
        circuit_id: u32,
        statement_scope: u32,
        profile: composition.InputProfile,
        extra_zero_nodes: usize,
    ) !Child {
        const input_count = try composition.recursionInputCount(profile);
        const nodes = try allocator.alloc(
            composition.Node,
            input_count + 1 + extra_zero_nodes,
        );
        errdefer allocator.free(nodes);
        for (nodes[0..input_count]) |*node| node.* = .{ .op = .input };
        nodes[input_count] = .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 0 } } };
        for (nodes[input_count + 1 ..], 0..) |*node, index| node.* =
            .{ .op = .{ .neg = @intCast(input_count + index) } };
        const outputs = try allocator.alloc(u32, 1);
        errdefer allocator.free(outputs);
        outputs[0] = @intCast(nodes.len - 1);
        const graph_digest = composition.computeGraphDigest(nodes, outputs);
        const graph = try composition.CircuitGraph.authenticate(
            nodes,
            outputs,
            graph_digest,
        );
        const bindings = try allocator.alloc(
            composition.RecursionInputBinding,
            input_count,
        );
        errdefer allocator.free(bindings);
        for (bindings, 0..) |*binding, index| binding.* = .{
            .node_id = @intCast(index),
            .source = composition.expectedRecursionSource(profile, index).?,
        };
        const values = try allocator.alloc(QM31, nodes.len);
        errdefer allocator.free(values);
        @memset(values, QM31.zero());
        return .{
            .allocator = allocator,
            .verifier_id = verifier_id,
            .circuit_id = circuit_id,
            .statement_scope = statement_scope,
            .profile = profile,
            .nodes = nodes,
            .outputs = outputs,
            .bindings = bindings,
            .values = values,
            .graph = graph,
        };
    }

    fn deinit(self: *Child) void {
        self.allocator.free(self.values);
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    fn lane(self: *const Child) composition.RecursionLane {
        return .{
            .verifier_id = self.verifier_id,
            .circuit_id = self.circuit_id,
            .statement_scope = self.statement_scope,
            .graph = self.graph,
            .profile = self.profile,
            .bindings = self.bindings,
        };
    }

    fn evaluation(self: *const Child) lowering.Evaluation {
        return .{
            .circuit_identity = self.graph.identity_digest,
            .values = self.values,
        };
    }
};

pub const Fixture = struct {
    vm_plan: schedule.Plan,
    left_plan: schedule.Plan,
    right_plan: schedule.Plan,
    left: Child,
    right: Child,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        return initWithSampleCounts(allocator, 1, 2);
    }

    pub fn initWithSampleCounts(
        allocator: std.mem.Allocator,
        left_sampled_value_count: u32,
        right_sampled_value_count: u32,
    ) !Fixture {
        const left_profile = composition.InputProfile{
            .sampled_value_count = left_sampled_value_count,
            .claimed_sum_count = 3,
            .relation_challenge_count = 4,
        };
        const right_profile = composition.InputProfile{
            .sampled_value_count = right_sampled_value_count,
            .claimed_sum_count = 5,
            .relation_challenge_count = 3,
        };
        var vm_plan = try testPlan(allocator, .vm, 1, 3, 3, 2);
        errdefer vm_plan.deinit();
        var left_plan = try testPlan(allocator, .vm, 2, 1, 5, 4);
        errdefer left_plan.deinit();
        var right_plan = try testPlan(allocator, .recursion, 3, 2, 6, 3);
        errdefer right_plan.deinit();
        var left = try Child.init(
            allocator,
            subject.LEFT_VERIFIER_ID,
            501,
            trusted.compositionStatementScope(0),
            left_profile,
            0,
        );
        errdefer left.deinit();
        return .{
            .vm_plan = vm_plan,
            .left_plan = left_plan,
            .right_plan = right_plan,
            .left = left,
            .right = try Child.init(
                allocator,
                subject.RIGHT_VERIFIER_ID,
                502,
                trusted.compositionStatementScope(1),
                right_profile,
                1,
            ),
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.right.deinit();
        self.left.deinit();
        self.right_plan.deinit();
        self.left_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }

    pub fn program(self: *const Fixture) subject.ProgramInputV2 {
        return self.programWithPlans(
            &self.vm_plan,
            &self.left_plan,
            &self.right_plan,
        );
    }

    pub fn programWithPlans(
        self: *const Fixture,
        vm_plan: *const schedule.Plan,
        left_plan: *const schedule.Plan,
        right_plan: *const schedule.Plan,
    ) subject.ProgramInputV2 {
        return .{
            .vm_plan = vm_plan,
            .vm_sampled_value_count = 3,
            .children = .{
                .{ .plan = left_plan, .composition = self.left.lane() },
                .{ .plan = right_plan, .composition = self.right.lane() },
            },
        };
    }

    pub fn witness(self: *const Fixture) subject.WitnessInputV2 {
        return .{ .evaluations = .{
            self.left.evaluation(),
            self.right.evaluation(),
        } };
    }
};

fn testPlan(
    allocator: std.mem.Allocator,
    schema: schedule.Schema,
    seed: u32,
    sampled_value_count: u32,
    air_instruction_count: u32,
    relation_challenge_count: u32,
) !schedule.Plan {
    const shape = try testShape(seed, sampled_value_count);
    return schedule.Plan.init(
        allocator,
        try schedule.ProgramSpec.init(
            schema,
            relation_challenge_count,
            if (schema == .vm) 3 else 0,
            air_instruction_count,
            relation_challenge_count,
        ),
        shape,
    );
}

pub fn testShape(
    seed: u32,
    sampled_value_count: u32,
) !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(
        8 + seed,
        protocol.PCS_CONFIG.fri_config,
    );
    const height = 8 + seed +
        protocol.PCS_CONFIG.fri_config.log_blowup_factor;
    return .{
        .air_program_id = channel.hashBytes(
            std.mem.asBytes(&seed),
            0x4332_4101,
        ),
        .preprocessing_id = channel.hashBytes(
            std.mem.asBytes(&seed),
            0x4332_5001,
        ),
        .table_layout_id = channel.hashBytes(
            std.mem.asBytes(&seed),
            0x4332_4c01,
        ),
        .table_count = 16 + seed,
        .claimed_sum_count = 2 + seed,
        .sampled_value_count = sampled_value_count,
        .preprocessed_column_count = 4 + seed,
        .tree_column_counts = .{ 4 + seed, 4, 4, 4 },
        .tree_heights = .{ height, height, height, height },
        .column_log_degree = 8 + seed,
        .proof_wire_bytes = 2_048 + seed,
        .fri = fri,
    };
}
