//! Instantiation, seal, mutation, and allocation gates for the row-18 graph compiler.

const std = @import("std");
const circuit = @import("composition_circuit.zig");
const witness = @import("vm_air_composition_input_witness.zig");

const PROFILE = circuit.InputProfile{
    .sampled_value_count = 0,
    .claimed_sum_count = 0,
    .relation_challenge_count = 0,
};
const VM_CIRCUIT_ID: u32 = 7;
const RECURSION_CIRCUIT_ID: u32 = 9;
const RECURSION_VERIFIER_ID: u32 = 1;
const RECURSION_STATEMENT_SCOPE: u32 = 1;
const VM_OUTPUTS = [_]u32{11};
const RECURSION_OUTPUTS = [_]u32{426};
const VM_GRAPH_DIGEST = hexDigest(
    "6704a7ee0c0f0181c996b6938884afe33c2811f77ef3e349c96b762d5acb5bd7",
);
const RECURSION_GRAPH_DIGEST = hexDigest(
    "c51858633f02f8a929723b487a865b298236458ea1a33d9cb4c6d1dfd97ee96d",
);
const REFERENCE_DIGEST = hexDigest(
    "ca25ecaf8498e12f790ffc243b42a002300753834a2728d3a5cb16d2eb8b2c1a",
);
const SCHEDULE_DIGEST = hexDigest(
    "154b8f6897285657726a8b7e3c9e4b68de306bc26e7620e1aebbcdfd36fe8fad",
);

const Fixture = struct {
    allocator: std.mem.Allocator,
    vm_nodes: []circuit.Node,
    recursion_nodes: []circuit.Node,
    vm_bindings: []circuit.VmInputBinding,
    recursion_bindings: []circuit.RecursionInputBinding,
    vm_graph: circuit.CircuitGraph,
    recursion_graph: circuit.CircuitGraph,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const vm_count = try circuit.vmInputCount(PROFILE);
        const recursion_count = try circuit.recursionInputCount(PROFILE);
        const vm_nodes = try allocator.alloc(circuit.Node, vm_count + 3);
        errdefer allocator.free(vm_nodes);
        const recursion_nodes = try allocator.alloc(circuit.Node, recursion_count + 3);
        errdefer allocator.free(recursion_nodes);
        fillGraph(vm_nodes, vm_count, .{ 7, 8, 9, 10 });
        fillGraph(recursion_nodes, recursion_count, .{ 11, 12, 13, 14 });

        const vm_bindings = try allocator.alloc(circuit.VmInputBinding, vm_count);
        errdefer allocator.free(vm_bindings);
        for (vm_bindings, 0..) |*binding, index| binding.* = .{
            .node_id = @intCast(index),
            .source = circuit.expectedVmSource(PROFILE, index).?,
        };
        const recursion_bindings = try allocator.alloc(
            circuit.RecursionInputBinding,
            recursion_count,
        );
        errdefer allocator.free(recursion_bindings);
        for (recursion_bindings, 0..) |*binding, index| binding.* = .{
            .node_id = @intCast(index),
            .source = circuit.expectedRecursionSource(PROFILE, index).?,
        };

        return .{
            .allocator = allocator,
            .vm_nodes = vm_nodes,
            .recursion_nodes = recursion_nodes,
            .vm_bindings = vm_bindings,
            .recursion_bindings = recursion_bindings,
            .vm_graph = try circuit.CircuitGraph.authenticate(
                vm_nodes,
                &VM_OUTPUTS,
                VM_GRAPH_DIGEST,
            ),
            .recursion_graph = try circuit.CircuitGraph.authenticate(
                recursion_nodes,
                &RECURSION_OUTPUTS,
                RECURSION_GRAPH_DIGEST,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.recursion_bindings);
        self.allocator.free(self.vm_bindings);
        self.allocator.free(self.recursion_nodes);
        self.allocator.free(self.vm_nodes);
        self.* = undefined;
    }

    fn vmLane(self: *const Fixture) circuit.VmLane {
        return .{
            .circuit_id = VM_CIRCUIT_ID,
            .graph = self.vm_graph,
            .profile = PROFILE,
            .bindings = self.vm_bindings,
        };
    }

    fn recursionLane(self: *const Fixture) circuit.RecursionLane {
        return .{
            .verifier_id = RECURSION_VERIFIER_ID,
            .circuit_id = RECURSION_CIRCUIT_ID,
            .statement_scope = RECURSION_STATEMENT_SCOPE,
            .graph = self.recursion_graph,
            .profile = PROFILE,
            .bindings = self.recursion_bindings,
        };
    }
};

test "R-012 authenticated composition DAG compiles exact row-18 authority" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const recursion_lanes = [_]circuit.RecursionLane{fixture.recursionLane()};
    const anchors = [_]circuit.AnchorLane{.{
        .circuit_id = RECURSION_CIRCUIT_ID,
        .graph = fixture.recursion_graph,
        .active_in = .BINARY,
    }};
    const reference = try circuit.Reference.authenticate(
        fixture.vmLane(),
        &recursion_lanes,
        &anchors,
        REFERENCE_DIGEST,
    );
    try reference.validate();
    const actual_vm_digest = circuit.computeGraphDigest(fixture.vm_nodes, &VM_OUTPUTS);
    const actual_recursion_digest = circuit.computeGraphDigest(
        fixture.recursion_nodes,
        &RECURSION_OUTPUTS,
    );
    const actual_reference_digest = circuit.computeReferenceDigest(
        fixture.vmLane(),
        &recursion_lanes,
        &anchors,
    );
    try std.testing.expectEqualSlices(u8, &VM_GRAPH_DIGEST, &actual_vm_digest);
    try std.testing.expectEqualSlices(u8, &RECURSION_GRAPH_DIGEST, &actual_recursion_digest);
    try std.testing.expectEqualSlices(u8, &REFERENCE_DIGEST, &actual_reference_digest);

    var compiled = try circuit.compile(std.testing.allocator, &reference);
    defer compiled.deinit();
    try std.testing.expectEqual(@as(usize, 437), compiled.rows.len);
    try std.testing.expectEqualSlices(
        u8,
        &reference.identity_digest,
        &compiled.reference_digest,
    );
    const expected_schedule_digest = circuit.computeScheduleDigest(
        reference.identity_digest,
        compiled.rows,
    );
    try std.testing.expectEqualSlices(u8, &SCHEDULE_DIGEST, &expected_schedule_digest);
    try std.testing.expectEqualSlices(u8, &expected_schedule_digest, &compiled.authority_digest);
    try circuit.validateCompiledRows(compiled.rows);
    try std.testing.expect(std.meta.eql(
        circuit.Classification{ .vm_input = .segment_selector },
        compiled.rows[0].classification,
    ));
    try std.testing.expectEqual(@as(u32, 1), compiled.rows[0].use_count);
    try std.testing.expect(std.meta.eql(
        circuit.Classification{ .recursion_input = .{
            .verifier_id = RECURSION_VERIFIER_ID,
            .statement_scope = RECURSION_STATEMENT_SCOPE,
            .source = .parent_binary_selector,
        } },
        compiled.rows[9].classification,
    ));
    try std.testing.expectEqual(@as(u32, 1), compiled.rows[433].use_count);
    try std.testing.expectEqualSlices(u32, &.{ 7, 8, 9, 10 }, &compiled.rows[433].fixed_value);
    try std.testing.expectEqual(@as(u32, 1), compiled.rows[435].use_count);
    try std.testing.expectEqualSlices(u32, &.{ 11, 12, 13, 14 }, &compiled.rows[435].fixed_value);

    var preprocessing = try witness.Preprocessed.initFromReference(
        std.testing.allocator,
        &reference,
    );
    defer preprocessing.deinit();
    try preprocessing.validate();
    try std.testing.expectEqual(@as(usize, 437), preprocessing.rows.len);
}

test "R-012 composition compiler rejects graph reference and schedule mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var bad_graph_digest = VM_GRAPH_DIGEST;
    bad_graph_digest[0] ^= 1;
    try std.testing.expectError(
        error.GraphSealMismatch,
        circuit.CircuitGraph.authenticate(fixture.vm_nodes, &VM_OUTPUTS, bad_graph_digest),
    );

    const original_constant = fixture.vm_nodes[9];
    fixture.vm_nodes[9] = .{ .op = .{ .constant = .{ 8, 8, 9, 10 } } };
    try std.testing.expectError(error.GraphSealMismatch, fixture.vm_graph.validate());
    fixture.vm_nodes[9] = original_constant;
    try fixture.vm_graph.validate();

    const recursion_lanes = [_]circuit.RecursionLane{fixture.recursionLane()};
    var anchors = [_]circuit.AnchorLane{.{
        .circuit_id = RECURSION_CIRCUIT_ID,
        .graph = fixture.recursion_graph,
        .active_in = .BINARY,
    }};
    const reference = try circuit.Reference.authenticate(
        fixture.vmLane(),
        &recursion_lanes,
        &anchors,
        REFERENCE_DIGEST,
    );
    fixture.vm_bindings[0].node_id = 1;
    try std.testing.expectError(error.InputBindingNodeMismatch, reference.validate());
    fixture.vm_bindings[0].node_id = 0;
    try reference.validate();

    anchors[0].active_in = .ALL;
    try std.testing.expectError(
        error.AnchorGraphMismatch,
        circuit.Reference.authenticate(
            fixture.vmLane(),
            &recursion_lanes,
            &anchors,
            REFERENCE_DIGEST,
        ),
    );
    anchors[0].active_in = .BINARY;

    var preprocessing = try witness.Preprocessed.initFromReference(
        std.testing.allocator,
        &reference,
    );
    defer preprocessing.deinit();
    preprocessing.rows[0].use_count += 1;
    try std.testing.expectError(error.AuthorityMismatch, preprocessing.validate());
}

test "R-012 repeated graph outputs preserve exact public consumption multiplicity" {
    var nodes: [10]circuit.Node = undefined;
    for (nodes[0..9]) |*node| node.* = .{ .op = .input };
    nodes[9] = .{ .op = .{ .neg = 0 } };
    const outputs = [_]u32{ 9, 9 };
    const graph_digest = circuit.computeGraphDigest(&nodes, &outputs);
    const graph = try circuit.CircuitGraph.authenticate(&nodes, &outputs, graph_digest);
    var bindings: [9]circuit.VmInputBinding = undefined;
    for (&bindings, 0..) |*binding, index| binding.* = .{
        .node_id = @intCast(index),
        .source = circuit.expectedVmSource(PROFILE, index).?,
    };
    const lane = circuit.VmLane{
        .circuit_id = 7,
        .graph = graph,
        .profile = PROFILE,
        .bindings = &bindings,
    };
    const reference_digest = circuit.computeReferenceDigest(lane, &.{}, &.{});
    const reference = try circuit.Reference.authenticate(lane, &.{}, &.{}, reference_digest);
    var preprocessing = try witness.Preprocessed.initFromReference(
        std.testing.allocator,
        &reference,
    );
    defer preprocessing.deinit();
    try preprocessing.validate();
    try std.testing.expectEqual(@as(usize, 11), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[0].use_count);
    try std.testing.expectEqual(@as(u32, 9), preprocessing.rows[9].node_id);
    try std.testing.expectEqual(@as(u32, 9), preprocessing.rows[10].node_id);
}

test "R-012 composition compiler stays two-allocation bounded and failure atomic" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        fixtureFailureCase,
        .{},
    );
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const recursion_lanes = [_]circuit.RecursionLane{fixture.recursionLane()};
    const anchors = [_]circuit.AnchorLane{.{
        .circuit_id = RECURSION_CIRCUIT_ID,
        .graph = fixture.recursion_graph,
        .active_in = .BINARY,
    }};
    const reference = try circuit.Reference.authenticate(
        fixture.vmLane(),
        &recursion_lanes,
        &anchors,
        REFERENCE_DIGEST,
    );

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var compiled = try circuit.compile(measured.allocator(), &reference);
        defer compiled.deinit();
        try std.testing.expectEqual(@as(usize, 2), measured.alloc_index);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        compileFailureCase,
        .{&reference},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{&reference},
    );
}

fn fillGraph(nodes: []circuit.Node, input_count: usize, limbs: [4]u32) void {
    for (nodes[0..input_count]) |*node| node.* = .{ .op = .input };
    nodes[input_count] = .{ .op = .{ .constant = limbs } };
    nodes[input_count + 1] = .{ .op = .{ .add = .{
        .lhs = 0,
        .rhs = @intCast(input_count),
    } } };
    nodes[input_count + 2] = .{ .op = .{ .neg = @intCast(input_count + 1) } };
}

fn fixtureFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
}

fn compileFailureCase(
    allocator: std.mem.Allocator,
    reference: *const circuit.Reference,
) !void {
    var compiled = try circuit.compile(allocator, reference);
    defer compiled.deinit();
}

fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    reference: *const circuit.Reference,
) !void {
    var preprocessing = try witness.Preprocessed.initFromReference(allocator, reference);
    defer preprocessing.deinit();
}

fn hexDigest(comptime value: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError("invalid composition test seal");
    return result;
}
